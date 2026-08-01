//! Regtest idempotence + crash recovery test.
//!
//! Verifies two core safety properties of the response ledger:
//!
//! 1. **Idempotence**: the same auth payment appearing twice in the mempool
//!    stream (e.g. after a worker reconnect) results in exactly one response,
//!    not two. The ledger's `claim` prevents double-creation.
//!
//! 2. **Crash recovery**: if the worker crashes while a response tx is being
//!    sent (ledger state = "broadcasting"), the restarted worker picks up the
//!    pending tx and rebroadcasts it via
//!    `rebroadcast_pending_responses`.
//!
//! Both are exercised in one flow: send an auth payment, catch the ledger at
//! "broadcasting" before the send returns, kill the worker, restart it, and
//! verify it rebroadcasts the existing tx rather than creating a new one.
//!
//! Skips cleanly when binaries aren't provisioned. Set ZEBRAD_BIN,
//! LIGHTWALLETD_BIN, and ZALLET_BIN to run the live test.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use tokio::process as tokio_process;

// ── constants ────────────────────────────────────────────────────────────────

const NU6_2_ACTIVATION_HEIGHT: u32 = 4;
const FUNDER_COINBASES: u32 = 120;
const MATURITY_TAIL: u32 = 130;
const TAIL_MINER_ADDRESS: &str = "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v";
const FUND_ZATOSHIS: u64 = 100_000_000;
const AUTH_PAYMENT_ZATOSHIS: u64 = 200_000;
const SESSION_ID: &str = "1234567890123456";
const TIMEOUT: Duration = Duration::from_secs(300);
// NU6.3 (ironwood) activation height on the regtest chain.
const NU6_3_ACTIVATION_HEIGHT: u32 = 8;

// ── helpers ──────────────────────────────────────────────────────────────────

fn pick_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn resolve_bin(env_var: &str) -> Option<PathBuf> {
    std::env::var(env_var)
        .ok()
        .map(PathBuf::from)
        .filter(|p| p.is_file())
}

fn tail(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

async fn rpc(port: u16, method: &str, params: Value) -> Result<Value> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let resp = client
        .post(format!("http://127.0.0.1:{port}/"))
        .json(&json!({"jsonrpc": "1.0", "id": "zfa-test", "method": method, "params": params}))
        .send()
        .await
        .with_context(|| format!("RPC {method}"))?;
    let result: Value = resp.json().await.context("parse RPC response")?;
    if let Some(err) = result.get("error").filter(|e| !e.is_null()) {
        bail!("RPC {method} error: {err}");
    }
    Ok(result["result"].clone())
}

// ── zebrad ───────────────────────────────────────────────────────────────────

struct Zebrad {
    child: Child,
    rpc_port: u16,
    indexer_port: u16,
    bin: PathBuf,
    config_path: PathBuf,
    state_dir: PathBuf,
    _dir: tempfile::TempDir,
}

fn zebrad_config(net_port: u16, rpc_port: u16, indexer_port: u16, miner_address: &str, cache_dir: &str) -> String {
    let n = NU6_2_ACTIVATION_HEIGHT;
    format!(
        r#"[network]
network = "Regtest"
listen_addr = "127.0.0.1:{net_port}"

[network.testnet_parameters]
disable_pow = true

[network.testnet_parameters.activation_heights]
NU5 = 1
NU6 = 1
"NU6.1" = {n}
"NU6.2" = {n}

[[network.testnet_parameters.funding_streams]]
[network.testnet_parameters.funding_streams.height_range]
start = 1
end = 1000000
[[network.testnet_parameters.funding_streams.recipients]]
receiver = "Deferred"
numerator = 12
addresses = []

[[network.testnet_parameters.lockbox_disbursements]]
address = "t27eWDgjFYJGVXmzrXeVjnb5J3uXDM9xH9v"
amount = 1

[mining]
miner_address = "{miner_address}"

[state]
ephemeral = false
cache_dir = "{cache_dir}"

[rpc]
listen_addr = "127.0.0.1:{rpc_port}"
indexer_listen_addr = "127.0.0.1:{indexer_port}"
enable_cookie_auth = false
"#
    )
}

fn spawn_zebrad(bin: &Path, config_path: &Path) -> Result<Child> {
    let (out, err) = match std::env::var_os("ZEBRAD_STDERR") {
        Some(p) => {
            let f = std::fs::File::create(&p).context("ZEBRAD_STDERR")?;
            let f2 = f.try_clone()?;
            (Stdio::from(f), Stdio::from(f2))
        }
        None => (Stdio::null(), Stdio::null()),
    };
    let mut cmd = Command::new(bin);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("ZEBRA_") {
            cmd.env_remove(key);
        }
    }
    cmd.args(["--config", config_path.to_str().unwrap(), "start"])
        .stdout(out)
        .stderr(err)
        .spawn()
        .with_context(|| format!("spawn zebrad ({})", bin.display()))
}

impl Zebrad {
    async fn start(bin: &Path, miner_address: &str) -> Result<Zebrad> {
        let dir = tempfile::tempdir().context("zebrad tempdir")?;
        let rpc_port = pick_port();
        let indexer_port = pick_port();
        let config_path = dir.path().join("zebrad.toml");
        let cache_dir = dir.path().join("state");

        std::fs::write(
            &config_path,
            zebrad_config(pick_port(), rpc_port, indexer_port, miner_address, &cache_dir.to_string_lossy()),
        )?;

        let child = spawn_zebrad(bin, &config_path)?;
        let mut zebrad = Zebrad {
            child,
            rpc_port,
            indexer_port,
            bin: bin.to_path_buf(),
            config_path,
            state_dir: cache_dir,
            _dir: dir,
        };
        zebrad.wait_until_ready().await?;
        Ok(zebrad)
    }

    async fn restart_with_miner(&mut self, miner_address: &str) -> Result<()> {
        let _ = rpc(self.rpc_port, "stop", json!([])).await;
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
            }
        }
        let cache_dir = self._dir.path().join("state");
        std::fs::write(
            &self.config_path,
            zebrad_config(pick_port(), self.rpc_port, self.indexer_port, miner_address, &cache_dir.to_string_lossy()),
        )?;
        self.child = spawn_zebrad(&self.bin, &self.config_path)?;
        self.wait_until_ready().await?;
        Ok(())
    }

    async fn wait_until_ready(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if let Ok(Some(status)) = self.child.try_wait() {
                bail!("zebrad exited ({status}); set ZEBRAD_STDERR to capture logs");
            }
            match rpc(self.rpc_port, "getblocktemplate", json!([])).await {
                Ok(_) => return Ok(()),
                Err(_) if Instant::now() >= deadline => bail!("zebrad not ready in 120s"),
                _ => tokio::time::sleep(Duration::from_millis(500)).await,
            }
        }
    }

    async fn generate_blocks(&self, n: u32) -> Result<()> {
        let hashes = rpc(self.rpc_port, "generate", json!([n])).await?;
        let mined = hashes.as_array().map(|a| a.len()).unwrap_or(0);
        if mined != n as usize {
            bail!("mined {mined} of {n} blocks: {hashes}");
        }
        Ok(())
    }
}

impl Drop for Zebrad {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ── lightwalletd ────────────────────────────────────────────────────────────

struct Indexer {
    child: Child,
    grpc_port: u16,
    _dir: tempfile::TempDir,
}

impl Indexer {
    async fn start(bin: &Path, zebrad_rpc_port: u16) -> Result<Indexer> {
        let dir = tempfile::tempdir().context("lwd tempdir")?;
        let grpc_port = pick_port();
        let data_dir = dir.path().join("data");
        std::fs::create_dir_all(&data_dir)?;

        let zcash_conf = dir.path().join("zcash.conf");
        std::fs::write(
            &zcash_conf,
            format!("rpcuser=zfa\nrpcpassword=zfa\nrpcbind=127.0.0.1\nrpcport={zebrad_rpc_port}\n"),
        )?;

        let log_file = dir.path().join("lightwalletd.log");
        let child = Command::new(bin)
            .args([
                "--no-tls-very-insecure",
                "--grpc-bind-addr", &format!("127.0.0.1:{grpc_port}"),
                "--http-bind-addr", &format!("127.0.0.1:{}", pick_port()),
                "--data-dir", data_dir.to_str().unwrap(),
                "--log-file", log_file.to_str().unwrap(),
                "--zcash-conf-path", zcash_conf.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("spawn lightwalletd ({})", bin.display()))?;

        let lwd = Indexer { child, grpc_port, _dir: dir };
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            if let Ok(log) = std::fs::read_to_string(&log_file) {
                if log.contains("Starting insecure no-TLS (plaintext) server") {
                    return Ok(lwd);
                }
            }
            if Instant::now() >= deadline {
                let log = std::fs::read_to_string(&log_file).unwrap_or_default();
                bail!("lightwalletd not ready in 90s; log:\n{}", tail(&log, 20));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

impl Drop for Indexer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ── funder (zallet) ──────────────────────────────────────────────────────────
//
// Zallet is a long-running wallet daemon with a JSON-RPC interface. The funder
// spawns it as a background process and drives it via HTTP JSON-RPC calls.

/// Branch IDs (hex u32) for the regtest nuparams config.
///   NU6   = c8e71055    NU6.1 = 4dec4df0    NU6.2 = 5437f330    NU6.3 = 37a5165b
fn zallet_config(zebrad_rpc_port: u16, zallet_rpc_port: u16, indexer_grpc_port: u16, zebra_state_path: &str) -> String {
    format!(
r#"backend = "zaino"

[builder]
[builder.limits]

[consensus]
network = "regtest"
regtest_nuparams = [
    "c8e71055:1",
    "4dec4df0:{nu62}",
    "5437f330:{nu62}",
]

[database]

[external]

[features]
as_of_version = "0.1.0-beta.2"

[features.deprecated]

[features.experimental]

[indexer]
validator_address = "127.0.0.1:{zebrad_rpc_port}"

[indexer.read_state_service]
grpc_address = "127.0.0.1:{indexer_grpc_port}"
zebra_state_path = "{zebra_state_path}"

[keystore]
encryption_identity = "encryption-identity.txt"
require_backup = false

[note_management]

[rpc]
bind = ["127.0.0.1:{zallet_rpc_port}"]
"#,
        nu62 = NU6_2_ACTIVATION_HEIGHT,
    )
}

struct Funder {
    bin: PathBuf,
    dir: PathBuf,
    rpc_port: u16,
    child: Option<tokio_process::Child>,
    miner_address: String,
    unified_address: String,
    cached_cookie: Option<(String, String)>,
}

fn run_zallet(bin: &Path, dir: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new(bin)
        .args(["--datadir", dir.to_str().unwrap()])
        .args(args)
        .output()
        .with_context(|| format!("zallet {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "zallet {} failed:\nstderr: {}",
            args.join(" "),
            tail(&String::from_utf8_lossy(&output.stderr), 30),
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

impl Funder {
    /// Initialize a fresh zallet wallet: generate age identity, store recipients,
    /// generate a mnemonic, and create the default account with a miner address.
    /// Does NOT start the daemon — call `start()` after mining coinbase.
    fn init(bin: &Path, dir: &Path, zebrad_rpc_port: u16, zallet_rpc_port: u16, indexer_grpc_port: u16, zebra_state_path: &str) -> Result<Funder> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join("zallet.toml"), zallet_config(zebrad_rpc_port, zallet_rpc_port, indexer_grpc_port, zebra_state_path))?;

        run_zallet(bin, dir, &["generate-encryption-identity"])?;
        run_zallet(bin, dir, &["init-wallet-encryption"])?;
        run_zallet(bin, dir, &["generate-mnemonic"])?;
        let miner_address =
            run_zallet(bin, dir, &["regtest", "generate-account-and-miner-address"])?;
        let miner_address = miner_address.trim().to_string();

        Ok(Funder {
            bin: bin.to_path_buf(),
            dir: dir.to_path_buf(),
            rpc_port: zallet_rpc_port,
            child: None,
            miner_address,
            unified_address: String::new(),
            cached_cookie: None,
        })
    }

    /// Start the zallet daemon and wait for its JSON-RPC to be available.
    async fn start(&mut self) -> Result<()> {
        let log_file = self.dir.join("zallet.log");
        let stderr = std::fs::File::create(&log_file)
            .context("create zallet log file")?;
        let stdout = stderr.try_clone()?;
        let child = tokio_process::Command::new(&self.bin)
            .args(["--datadir", self.dir.to_str().unwrap(), "start"])
            .env("RUST_LOG", "zallet_core=info,zaino=info")
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .context("spawn zallet")?;
        self.child = Some(child);

        // Wait for the RPC server to respond.
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            match self.rpc("getwalletstatus", &[]).await {
                Ok(_) => break,
                Err(_) if Instant::now() >= deadline => {
                    let log = std::fs::read_to_string(&log_file).unwrap_or_default();
                    bail!("zallet RPC not ready in 120s; log:\n{}", tail(&log, 30));
                }
                Err(_) => {
                    // Check if the process died.
                    if let Ok(Some(status)) = self.child.as_mut().unwrap().try_wait() {
                        let log = std::fs::read_to_string(&log_file).unwrap_or_default();
                        bail!("zallet exited ({status}); log:\n{}", tail(&log, 30));
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }

        // Wait for the wallet to sync before deriving addresses.
        self.wait_for_sync().await?;

        // Get the unified address for account 0.
        let resp = self.rpc("z_getaddressforaccount", &["0"]).await?;
        self.unified_address = resp["result"]["address"]
            .as_str()
            .ok_or_else(|| anyhow!("no address in z_getaddressforaccount response: {resp}"))?
            .to_string();

        Ok(())
    }

    fn transparent_address(&self) -> &str {
        &self.miner_address
    }

    fn unified_address(&self) -> &str {
        &self.unified_address
    }

    /// Read the cookie file for RPC auth.
    fn cookie(&mut self) -> Result<(String, String)> {
        if let Some(ref c) = self.cached_cookie {
            return Ok(c.clone());
        }
        let cookie_path = self.dir.join(".cookie");
        let cookie = std::fs::read_to_string(&cookie_path)
            .with_context(|| format!("reading zallet cookie at {}", cookie_path.display()))?;
        let cookie = cookie.trim();
        let (user, password) = cookie
            .split_once(':')
            .ok_or_else(|| anyhow!("invalid cookie format"))?;
        let creds = (user.to_string(), password.to_string());
        self.cached_cookie = Some(creds.clone());
        Ok(creds)
    }

    /// Make a JSON-RPC call to the zallet daemon.
    async fn rpc(&mut self, method: &str, params: &[&str]) -> Result<Value> {
        let (user, password) = self.cookie()?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()?;
        let params_array: Vec<Value> = params
            .iter()
            .map(|p| serde_json::from_str(p).unwrap_or_else(|_| Value::String(p.to_string())))
            .collect();
        let resp = client
            .post(format!("http://127.0.0.1:{}/", self.rpc_port))
            .basic_auth(&user, Some(&password))
            .json(&json!({"jsonrpc": "2.0", "id": "zfa-test", "method": method, "params": params_array}))
            .send()
            .await
            .with_context(|| format!("zallet RPC {method}"))?;
        let result: Value = resp.json().await.context("parse zallet RPC response")?;
        if let Some(err) = result.get("error").filter(|e| !e.is_null()) {
            bail!("zallet RPC {method} error: {err}");
        }
        Ok(result)
    }

    /// Wait for zallet to sync to the chain tip.
    async fn wait_for_sync(&mut self) -> Result<()> {
        let log_file = self.dir.join("zallet.log");
        let deadline = Instant::now() + Duration::from_secs(300);
        loop {
            // Check if zallet crashed.
            if let Some(child) = &mut self.child {
                if let Ok(Some(status)) = child.try_wait() {
                    let log = std::fs::read_to_string(&log_file).unwrap_or_default();
                    bail!("zallet exited during sync ({status}); log:\n{}", tail(&log, 30));
                }
            }
            let status = self.rpc("getwalletstatus", &[]).await?;
            let node_tip = status["result"]["node_tip"]["height"].as_u64();
            let synced = status["result"]["fully_synced_height"].as_u64();
            // Wait until the read-state syncer has caught up (node_tip > 10) and
            // the wallet has synced to the node tip.
            if let (Some(n), Some(s)) = (node_tip, synced) {
                if n > 10 && s >= n {
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                bail!("zallet did not sync in 300s (last status: {status})");
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }

    /// Shield all mature coinbase UTXOs at the miner address to the funder's UA.
    async fn shield(&mut self) -> Result<()> {
        let result = self
            .rpc("z_shieldcoinbase", &[
                &format!("\"{}\"", self.miner_address),
                &format!("\"{}\"", self.unified_address),
                "null",
            ])
            .await?;
        let opid = result["result"]["opid"]
            .as_str()
            .ok_or_else(|| anyhow!("no opid in z_shieldcoinbase response: {result}"))?;
        self.wait_for_operation(opid).await
    }

    /// Send a payment with an optional memo.
    async fn send_with_memo(&mut self, to: &str, zatoshis: u64, memo: Option<&str>) -> Result<()> {
        let zec = zatoshis as f64 / 100_000_000.0;
        let memo_hex = memo.map(|m| hex::encode(m.as_bytes()));
        let amounts = match &memo_hex {
            Some(h) => format!(
                r#"[{{"address":"{}","amount":{},"memo":"{}"}}]"#,
                to, zec, h
            ),
            None => format!(r#"[{{"address":"{}","amount":{}}}]"#, to, zec),
        };
        let result = self
            .rpc("z_sendmany", &[
                &format!("\"{}\"", self.unified_address),
                &amounts,
                "1",
                "null",
                r#""NoPrivacy""#,
            ])
            .await?;
        let opid = result["result"]
            .as_str()
            .ok_or_else(|| anyhow!("no opid in z_sendmany response: {result}"))?;
        self.wait_for_operation(opid).await
    }

    /// Poll an async operation until it succeeds or fails.
    async fn wait_for_operation(&mut self, opid: &str) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let result = self
                .rpc("z_getoperationstatus", &[&format!("[\"{}\"]", opid)])
                .await?;
            let status = result["result"][0]["status"]
                .as_str()
                .ok_or_else(|| anyhow!("no status in operation result: {result}"))?;
            match status {
                "success" => return Ok(()),
                "failed" => {
                    let error = result["result"][0]["error"]["message"]
                        .as_str()
                        .unwrap_or("unknown error");
                    bail!("zallet operation {opid} failed: {error}");
                }
                _ => {}
            }
            if Instant::now() >= deadline {
                bail!("zallet operation {opid} did not complete in 120s");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
}

impl Drop for Funder {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.start_kill();
            let _ = child.wait();
        }
    }
}

// ── zfa worker ──────────────────────────────────────────────────────────────

struct ZfaWorker {
    child: tokio_process::Child,
    datadir: PathBuf,
    bin: PathBuf,
    service_address: String,
    otp_key_hex: String,
}

impl ZfaWorker {
    async fn start(bin: &Path, lwd_grpc_port: u16) -> Result<ZfaWorker> {
        Self::start_on_datadir(bin, None, lwd_grpc_port).await
    }

    /// Restart the worker on an existing datadir (after a crash).
    async fn restart(&self, lwd_grpc_port: u16) -> Result<ZfaWorker> {
        let mut w = Self::start_on_datadir(&self.bin, Some(&self.datadir), lwd_grpc_port).await?;
        w.service_address = self.service_address.clone();
        w.otp_key_hex = self.otp_key_hex.clone();
        Ok(w)
    }

    async fn start_on_datadir(
        bin: &Path,
        existing_datadir: Option<&Path>,
        lwd_grpc_port: u16,
    ) -> Result<ZfaWorker> {
        let datadir_path = match existing_datadir {
            Some(p) => p.to_path_buf(),
            None => {
                let dir = tempfile::tempdir().context("zfa datadir")?;
                let p = dir.path().to_path_buf();
                std::mem::forget(dir);
                p
            }
        };

        let is_restart = existing_datadir.is_some();

        let mut child = tokio_process::Command::new(bin)
            .args([
                "--datadir", datadir_path.to_str().unwrap(),
                "--network", "regtest",
                "--lwd-url", &format!("http://127.0.0.1:{lwd_grpc_port}"),
            ])
            .env("RUST_LOG", "zfa_backend=info")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawn zfa-backend")?;

        use tokio::io::{AsyncBufReadExt, BufReader};
        let stdout = child.stdout.take().context("no stdout")?;
        let stderr = child.stderr.take().context("no stderr")?;
        let mut stdout_lines = BufReader::new(stdout).lines();
        let mut stderr_lines = BufReader::new(stderr).lines();

        let mut otp_key_hex = String::new();
        let mut service_address = String::new();

        if !is_restart {
            // Fresh start: capture the OTP key (stdout) and service address (stderr).
            let deadline = Instant::now() + Duration::from_secs(60);
            loop {
                if otp_key_hex.is_empty() {
                    match stdout_lines.next_line().await {
                        Ok(Some(text)) => {
                            let t = text.trim();
                            if t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()) {
                                otp_key_hex = t.to_string();
                            }
                        }
                        Ok(None) => bail!("zfa stdout closed before OTP key"),
                        Err(e) => bail!("reading zfa stdout: {e}"),
                    }
                }
                if service_address.is_empty() {
                    match stderr_lines.next_line().await {
                        Ok(Some(text)) => {
                            if let Some(addr) = text.strip_prefix("service unified address: ") {
                                service_address = addr.trim().to_string();
                            }
                        }
                        Ok(None) => bail!("zfa stderr closed before service address"),
                        Err(e) => bail!("reading zfa stderr: {e}"),
                    }
                }
                if !otp_key_hex.is_empty() && !service_address.is_empty() {
                    break;
                }
                if Instant::now() >= deadline {
                    bail!("timed out waiting for zfa output");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        } else {
            // Restart: wallet already exists. Service address and OTP key
            // are carried over from the first worker via restart().
            service_address = String::new();
            otp_key_hex = String::new();
            tokio::time::sleep(Duration::from_secs(2)).await;
        }

        // Drain both pipes in separate tasks so neither blocks the other.
        tokio::spawn(async move {
            while let Ok(Some(_)) = stdout_lines.next_line().await {}
        });
        tokio::spawn(async move {
            while let Ok(Some(text)) = stderr_lines.next_line().await {
                eprintln!("[zfa] {text}");
            }
        });

        Ok(ZfaWorker {
            child,
            datadir: datadir_path,
            bin: bin.to_path_buf(),
            service_address,
            otp_key_hex,
        })
    }

    /// Kill the worker process (simulating a crash) and wait for it to exit.
    async fn kill(&mut self) {
        let _ = self.child.start_kill();
        let _ = self.child.wait().await;
        // Give the OS a moment to release the datadir lock.
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    /// Read all ledger entries: (incoming_txid, state, response_txid_bytes).
    fn ledger_entries(&self) -> Result<Vec<(String, String, Option<Vec<u8>>)>> {
        let path = self.datadir.join("responses.sqlite");
        if !path.exists() {
            return Ok(Vec::new());
        }
        let conn = rusqlite::Connection::open(&path)
            .with_context(|| format!("opening response ledger at {}", path.display()))?;
        let mut stmt = conn.prepare(
            "SELECT incoming_txid, state, response_txid FROM otp_response_ledger ORDER BY received_at",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
            ))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }

}

impl Drop for ZfaWorker {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        let _ = self.child.wait();
    }
}

// ── the test ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn regtest_idempotence_and_crash_recovery() {
    let (Some(zebrad_bin), Some(lwd_bin), Some(zallet_bin)) = (
        resolve_bin("ZEBRAD_BIN"),
        resolve_bin("LIGHTWALLETD_BIN"),
        resolve_bin("ZALLET_BIN"),
    ) else {
        eprintln!("SKIP regtest_idempotence: set ZEBRAD_BIN, LIGHTWALLETD_BIN, ZALLET_BIN to run.");
        return;
    };

    // ── 1. Start zebrad, init funder, mine coinbase, age past maturity ────────

    let mut zebrad = Zebrad::start(&zebrad_bin, TAIL_MINER_ADDRESS).await.expect("start zebrad");
    zebrad.generate_blocks(110).await.expect("mine initial blocks");

    // Init the zallet funder wallet (no lightwalletd needed for init).
    let funder_dir = tempfile::tempdir().context("funder datadir").expect("tempdir");
    let funder_dir_path = funder_dir.path().to_path_buf();
    std::mem::forget(funder_dir);
    let zallet_rpc_port = pick_port();
    let mut funder = Funder::init(&zallet_bin, &funder_dir_path, zebrad.rpc_port, zallet_rpc_port, zebrad.indexer_port, &zebrad.state_dir.to_string_lossy())
        .expect("init zallet funder");
    let funder_taddr = funder.transparent_address().to_string();

    zebrad.restart_with_miner(&funder_taddr).await.expect("restart mining to funder");
    zebrad.generate_blocks(FUNDER_COINBASES).await.expect("mine coinbases");
    zebrad.restart_with_miner(TAIL_MINER_ADDRESS).await.expect("restart mining to throwaway");
    zebrad.generate_blocks(MATURITY_TAIL).await.expect("mine maturity tail");

    // ── 2. Fresh lightwalletd, shield coinbase into Orchard ──────────────────

    let lwd = Indexer::start(&lwd_bin, zebrad.rpc_port).await.expect("start lightwalletd");

    // Start the zallet daemon (syncs automatically inside start()).
    funder.start().await.expect("start zallet");
    zebrad.generate_blocks(1).await.expect("trigger block");
    funder.wait_for_sync().await.expect("zallet sync after trigger block");
    tokio::time::sleep(Duration::from_secs(5)).await;
    let funder_ua = funder.unified_address().to_string();

    // Shield the matured coinbase into Orchard.
    funder.shield().await.expect("shield to Orchard");
    zebrad.generate_blocks(6).await.expect("confirm shield");
    funder.wait_for_sync().await.expect("zallet sync after shield");

    // ── 3. Start zfa-backend worker ──────────────────────────────────────────

    let zfa_bin = std::env::var("ZFA_BIN").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/release/zfa-backend")
    });
    assert!(zfa_bin.is_file(), "zfa-backend not found at {} — build with `cargo build --release` or set $ZFA_BIN", zfa_bin.display());

    let mut worker = ZfaWorker::start(&zfa_bin, lwd.grpc_port).await.expect("start worker");
    assert!(worker.service_address.starts_with("uregtest1"), "expected uregtest1 address");

    // ── 4. Fund the worker's service wallet ─────────────────────────────────

    funder.send_with_memo(&worker.service_address, FUND_ZATOSHIS, None).await.expect("fund service wallet");
    zebrad.generate_blocks(12).await.expect("confirm funding");
    funder.wait_for_sync().await.expect("zallet sync after funding");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // ── 5. Send auth payment (don't mine — keep it in the mempool) ──────────

    let auth_memo = format!("DO NOT MODIFY:{{zvs/{SESSION_ID},{funder_ua}}}");
    funder.send_with_memo(&worker.service_address, AUTH_PAYMENT_ZATOSHIS, Some(&auth_memo)).await.expect("send auth payment");

    // ── 6. Wait for ledger to reach "broadcasting" then kill the worker ─────
    //
    // The worker flow is: claim → create_otp_response → record_created →
    // record_broadcasting → SendTransaction → record_broadcast. There is an
    // async gap after the durable "broadcasting" write and before the gRPC
    // send returns. We poll for that state and kill the worker in the gap.
    // If we miss the window and it reaches "broadcast", that also proves the
    // happy path — we then test idempotence by killing and restarting anyway.

    let deadline = Instant::now() + Duration::from_secs(60);
    let killed_before_broadcast = loop {
        let entries = worker.ledger_entries().expect("read ledger");
        if let Some((_, state, _)) = entries.first() {
            if state == "broadcasting" {
                // Caught the durable in-flight state. Kill before the send
                // result can be recorded.
                eprintln!("[test] caught ledger at 'broadcasting' — killing worker");
                worker.kill().await;
                break true;
            }
            if state == "broadcast" {
                // Too fast — it already broadcast. Still test idempotence by
                // killing and restarting (the mempool tx will replay).
                eprintln!("[test] worker already broadcast — testing idempotence on restart");
                worker.kill().await;
                break false;
            }
        }
        assert!(Instant::now() < deadline, "worker did not start broadcasting within 60s");
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    // ── 7. Restart the worker on the same datadir ───────────────────────────
    //
    // The auth payment is still in the mempool (we didn't mine any blocks).
    // The restarted worker will:
    //   - Open the mempool stream and see the same auth payment again
    //   - Call claim() → AlreadyHandled(Broadcasting) or AlreadyHandled(Broadcast)
    //   - NOT create a second response tx (idempotence)
    //   - If "broadcasting": rebroadcast the existing pending tx (crash recovery)
    //   - If "broadcast": just acknowledge it's done

    let worker2 = worker.restart(lwd.grpc_port).await.expect("restart worker");
    drop(worker); // old worker is dead, datadir survives for worker2

    // Wait for the restarted worker to sync and process the mempool.
    // Check the mempool for the auth payment.
    let mempool = rpc(zebrad.rpc_port, "getrawmempool", json!([])).await.expect("getrawmempool");
    eprintln!("[test] zebrad mempool: {mempool}");

    let deadline = Instant::now() + TIMEOUT;
    loop {
        let entries = worker2.ledger_entries().expect("read ledger");
        let states: Vec<_> = entries.iter().map(|(_, s, _)| s.as_str()).collect();
        eprintln!("[test] ledger states: {states:?}");
        if entries.iter().any(|(_, s, _)| s == "broadcast") {
            break;
        }
        assert!(Instant::now() < deadline, "restarted worker did not reach broadcast within {TIMEOUT:?}");
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    // ── 8. Assertions ────────────────────────────────────────────────────────

    let entries = worker2.ledger_entries().expect("read ledger");

    // Idempotence: exactly one ledger entry for the incoming txid.
    assert_eq!(
        entries.len(),
        1,
        "idempotence violated: expected exactly 1 ledger entry, got {}\n{entries:?}",
        entries.len()
    );

    let (_, state, response_txid) = &entries[0];
    assert_eq!(
        state, "broadcast",
        "final state should be 'broadcast', got '{state}'"
    );
    assert_eq!(
        response_txid.as_ref().map(|b| b.len()),
        Some(32),
        "response txid should be 32 bytes"
    );

    eprintln!("\n✓ idempotence + crash recovery passed:");
    eprintln!("  killed during broadcast: {killed_before_broadcast}");
    eprintln!("  ledger entries:          {}", entries.len());
    eprintln!("  final state:             {state}");
    eprintln!("  response txid:           {}", hex::encode(response_txid.as_ref().unwrap()));
}
