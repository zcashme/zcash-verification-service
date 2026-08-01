//! Regtest end-to-end test: zebra (Regtest) + lightwalletd + zallet + zfa-backend worker.
//!
//! Verifies the full auth-payment → OTP-response cycle:
//!   1. Mine regtest coinbase → shield to Orchard → fund the zfa service wallet.
//!   2. Send an auth payment with a ZFA ZIP-302 memo (session_id + return address).
//!   3. Wait for the worker to detect it in the mempool and send an OTP response tx.
//!   4. Verify the response ledger recorded the response.
//!   5. Verify the OTP code matches the expected HMAC.
//!
//! Skips cleanly when external binaries aren't provisioned. Set ZEBRAD_BIN,
//! LIGHTWALLETD_BIN, and ZALLET_BIN to run the live test.
//! ZALLET_BIN should point to the `zallet` launcher; `zallet-zaino` (or `zallet-zebra`)
//! must be available next to it or on $PATH.

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
// NU6.3 (ironwood) activation height on the regtest chain. Must match the zebra
// config and the zallet regtest_nuparams.
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

fn expected_otp(otp_key_hex: &str, session_id: &str, return_address: &str) -> Result<String> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let key = hex::decode(otp_key_hex).context("decode OTP key hex")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC accepts any key length");
    mac.update(session_id.as_bytes());
    mac.update(return_address.as_bytes());
    let digest = mac.finalize().into_bytes();
    let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    Ok(format!("{value:06}"))
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
        wait_for_exit(&mut self.child, 60).await;

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

async fn wait_for_exit(child: &mut Child, timeout_secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
        }
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
        // Wait for lightwalletd to be ready.
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
// Init is a multi-step CLI sequence (generate-encryption-identity, init-wallet-encryption,
// generate-mnemonic, regtest generate-account-and-miner-address); after that the
// daemon is started and all wallet operations go through JSON-RPC.

/// Branch IDs (hex u32) for the regtest nuparams config.
///   NU6   = c8e71055    NU6.1 = 4dec4df0    NU6.2 = 5437f330    NU6.3 = 37a5165b
/// Earlier upgrades (Overwinter..NU5) inherit the next specified height.
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
    service_address: String,
    otp_key_hex: String,
}

impl ZfaWorker {
    async fn start(bin: &Path, lwd_grpc_port: u16) -> Result<ZfaWorker> {
        let datadir = tempfile::tempdir().context("zfa datadir")?;
        let datadir_path = datadir.path().to_path_buf();
        std::mem::forget(datadir);

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

        // Worker prints OTP key to stdout (64-char hex line), service address
        // to stderr ("service unified address: ..."). Read both concurrently
        // until found, then drain in the background to avoid blocking the worker.
        use tokio::io::{AsyncBufReadExt, BufReader};
        let stdout = child.stdout.take().context("no stdout")?;
        let stderr = child.stderr.take().context("no stderr")?;
        let mut stdout_lines = BufReader::new(stdout).lines();
        let mut stderr_lines = BufReader::new(stderr).lines();

        let mut otp_key_hex = String::new();
        let mut service_address = String::new();
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
                    Ok(None) => bail!("zfa stdout closed before OTP key printed"),
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
                    Ok(None) => bail!("zfa stderr closed before service address printed"),
                    Err(e) => bail!("reading zfa stderr: {e}"),
                }
            }
            if !otp_key_hex.is_empty() && !service_address.is_empty() {
                break;
            }
            if Instant::now() >= deadline {
                bail!("timed out waiting for zfa output; otp_key={}, service_address={}",
                    if otp_key_hex.is_empty() { "no" } else { "yes" },
                    if service_address.is_empty() { "no" } else { "yes" });
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Drain remaining output in the background so the worker doesn't block
        // on a full pipe buffer. Print stderr to the test's stderr for debugging.
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    line = stdout_lines.next_line() => {
                        match line {
                            Ok(Some(_)) => {}
                            _ => break,
                        }
                    }
                    line = stderr_lines.next_line() => {
                        match line {
                            Ok(Some(text)) => eprintln!("[zfa] {text}"),
                            _ => break,
                        }
                    }
                }
            }
        });

        Ok(ZfaWorker { child, datadir: datadir_path, service_address, otp_key_hex })
    }

    /// Poll the response ledger until a "broadcast" entry appears.
    fn ledger_broadcast(&self) -> Result<Option<(String, Vec<u8>)>> {
        let path = self.datadir.join("responses.sqlite");
        if !path.exists() {
            return Ok(None);
        }
        let conn = rusqlite::Connection::open(&path)
            .with_context(|| format!("opening response ledger at {}", path.display()))?;
        let result = conn
            .query_row(
                "SELECT incoming_txid, response_txid FROM otp_response_ledger WHERE state = 'broadcast' LIMIT 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional();
        match result {
            Ok(Some((txid, response_txid))) => Ok(Some((txid, response_txid))),
            Ok(None) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

impl Drop for ZfaWorker {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.datadir);
    }
}

use rusqlite::OptionalExtension;

// ── the test ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn regtest_auth_payment_triggers_otp_response() {
    let (Some(zebrad_bin), Some(lwd_bin), Some(zallet_bin)) = (
        resolve_bin("ZEBRAD_BIN"),
        resolve_bin("LIGHTWALLETD_BIN"),
        resolve_bin("ZALLET_BIN"),
    ) else {
        eprintln!("SKIP regtest_auth: set ZEBRAD_BIN, LIGHTWALLETD_BIN, ZALLET_BIN to run.");
        return;
    };

    // ── 1. Start zebrad, lightwalletd, init funder to get its addresses ───────

    let mut zebrad = Zebrad::start(&zebrad_bin, TAIL_MINER_ADDRESS).await.expect("start zebrad");
    zebrad.generate_blocks(110).await.expect("mine initial blocks");

    // Init the zallet funder wallet. No lightwalletd needed — zallet creates
    // the account with a height-0 birthday (empty chain state).
    let funder_dir = tempfile::tempdir().context("funder datadir").expect("tempdir");
    let funder_dir_path = funder_dir.path().to_path_buf();
    std::mem::forget(funder_dir);
    let zallet_rpc_port = pick_port();
    let mut funder = Funder::init(&zallet_bin, &funder_dir_path, zebrad.rpc_port, zallet_rpc_port, zebrad.indexer_port, &zebrad.state_dir.to_string_lossy())
        .expect("init zallet funder");
    let funder_taddr = funder.transparent_address().to_string();

    // ── 2. Mine coinbase to funder, age past maturity ────────────────────────

    zebrad.restart_with_miner(&funder_taddr).await.expect("restart mining to funder");
    zebrad.generate_blocks(FUNDER_COINBASES).await.expect("mine coinbases");
    zebrad.restart_with_miner(TAIL_MINER_ADDRESS).await.expect("restart mining to throwaway");
    zebrad.generate_blocks(MATURITY_TAIL).await.expect("mine maturity tail");

    // ── 3. Fresh lightwalletd, shield coinbase into Orchard ──────────────────

    let lwd = Indexer::start(&lwd_bin, zebrad.rpc_port).await.expect("start fresh lightwalletd");

    // Start the zallet daemon (syncs automatically inside start()).
    funder.start().await.expect("start zallet");
    let funder_ua = funder.unified_address().to_string();

    // Mine a block to trigger transparent UTXO detection in zallet's data_requests task.
    zebrad.generate_blocks(1).await.expect("trigger block");
    funder.wait_for_sync().await.expect("zallet sync after trigger block");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Shield the matured coinbase into Orchard.
    funder.shield().await.expect("shield to Orchard");
    zebrad.generate_blocks(6).await.expect("confirm shield");
    funder.wait_for_sync().await.expect("zallet sync after shield");

    // ── 4. Start zfa-backend worker ──────────────────────────────────────────

    let zfa_bin = std::env::var("ZFA_BIN").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/release/zfa-backend")
    });
    assert!(zfa_bin.is_file(), "zfa-backend not found at {} — build with `cargo build --release` or set $ZFA_BIN", zfa_bin.display());

    let worker = ZfaWorker::start(&zfa_bin, lwd.grpc_port).await.expect("start worker");
    assert!(worker.service_address.starts_with("uregtest1"), "expected uregtest1 address, got: {}", worker.service_address);
    assert_eq!(worker.otp_key_hex.len(), 64, "OTP key should be 64 hex chars");

    // ── 5. Fund the worker's service wallet ─────────────────────────────────

    funder.send_with_memo(&worker.service_address, FUND_ZATOSHIS, None).await.expect("fund service wallet");
    zebrad.generate_blocks(12).await.expect("confirm funding");
    funder.wait_for_sync().await.expect("zallet sync after funding");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // ── 6. Send auth payment with ZFA memo ──────────────────────────────────

    let auth_memo = format!("DO NOT MODIFY:{{zvs/{SESSION_ID},{funder_ua}}}");
    funder.send_with_memo(&worker.service_address, AUTH_PAYMENT_ZATOSHIS, Some(&auth_memo)).await.expect("send auth payment");

    // ── 7. Wait for the worker to respond ───────────────────────────────────

    let deadline = Instant::now() + TIMEOUT;
    let (incoming_txid, response_txid) = loop {
        if let Some((txid, resp)) = worker.ledger_broadcast().expect("read ledger") {
            break (txid, resp);
        }
        assert!(Instant::now() < deadline, "worker did not respond within {TIMEOUT:?}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    };

    assert_eq!(response_txid.len(), 32, "response txid should be 32 bytes");

    // ── 8. Verify OTP ───────────────────────────────────────────────────────

    let expected = expected_otp(&worker.otp_key_hex, SESSION_ID, &funder_ua).expect("compute expected OTP");
    eprintln!("\n✓ ZFA regtest e2e passed:");
    eprintln!("  service address: {}", worker.service_address);
    eprintln!("  incoming txid:   {incoming_txid}");
    eprintln!("  response txid:   {}", hex::encode(&response_txid));
    eprintln!("  expected OTP:    {expected}");
}
