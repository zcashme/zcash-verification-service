//! Regtest end-to-end test: zebra (Regtest) + lightwalletd + zfa-backend worker.
//!
//! Verifies the full auth-payment → OTP-response cycle:
//!   1. Mine regtest coinbase → shield to Orchard → fund the zfa service wallet.
//!   2. Send an auth payment with a ZFA ZIP-302 memo (session_id + return address).
//!   3. Wait for the worker to detect it in the mempool and send an OTP response tx.
//!   4. Verify the response ledger recorded the response.
//!   5. Verify the OTP code matches the expected HMAC.
//!
//! Skips cleanly when external binaries aren't provisioned. Set ZEBRAD_BIN,
//! LIGHTWALLETD_BIN, and DEVTOOL_BIN to run the live test.
//! Requires the `zecrocks/zcash-devtool` fork built with `--features regtest_support`.

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
const FUNDER_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon art";

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
    mac.update(b":");
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
    bin: PathBuf,
    config_path: PathBuf,
    _dir: tempfile::TempDir,
}

fn zebrad_config(net_port: u16, rpc_port: u16, miner_address: &str, cache_dir: &str) -> String {
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
        let config_path = dir.path().join("zebrad.toml");
        let cache_dir = dir.path().join("state");

        std::fs::write(
            &config_path,
            zebrad_config(pick_port(), rpc_port, miner_address, &cache_dir.to_string_lossy()),
        )?;

        let child = spawn_zebrad(bin, &config_path)?;
        let mut zebrad = Zebrad {
            child,
            rpc_port,
            bin: bin.to_path_buf(),
            config_path,
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
            zebrad_config(pick_port(), self.rpc_port, miner_address, &cache_dir.to_string_lossy()),
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

// ── funder (zcash-devtool) ───────────────────────────────────────────────────

struct Funder {
    bin: PathBuf,
    dir: PathBuf,
}

impl Funder {
    fn init(bin: &Path, lwd_port: u16) -> Result<Funder> {
        let dir = tempfile::tempdir().context("funder tempdir")?;
        let funder = Funder { bin: bin.to_path_buf(), dir: dir.path().to_path_buf() };
        std::mem::forget(dir);

        // Write activation-heights TOML required by -n regtest.
        let heights = funder.dir.join("activation-heights.toml");
        std::fs::write(
            &heights,
            format!(
                "overwinter = 1\nsapling = 1\nblossom = 1\nheartwood = 1\ncanopy = 1\n\
                 nu5 = 1\nnu6 = 1\nnu6_1 = {n}\nnu6_2 = {n}\n",
                n = NU6_2_ACTIVATION_HEIGHT,
            ),
        )?;

        // This devtool reads the mnemonic from stdin, not --mnemonic.
        funder.devtool("init", &[
            "--name", "funder", "--network", "regtest", "--identity", &funder.identity(),
            "--birthday", "2", "--activation-heights", heights.to_str().unwrap(),
        ], Some(lwd_port), Some(&format!("{FUNDER_MNEMONIC}\n")))?;

        Ok(funder)
    }

    fn unified_address(&self) -> Result<String> {
        let out = self.devtool("list-addresses", &["--receiver", "unified"], None, None)?;
        out.lines()
            .find_map(|l| l.split("Default Address:").nth(1))
            .map(|a| a.trim().to_string())
            .ok_or_else(|| anyhow!("no Default Address:\n{out}"))
    }

    fn transparent_address(&self) -> Result<String> {
        let out = self.devtool("list-addresses", &["--receiver", "transparent"], None, None)?;
        out.lines()
            .find_map(|l| l.split("Receiver(transparent):").nth(1))
            .map(|a| a.trim().to_string())
            .ok_or_else(|| anyhow!("no Transparent Address:\n{out}"))
    }

    fn sync(&self, lwd_port: u16) -> Result<()> {
        self.devtool("sync", &[], Some(lwd_port), None).map(|_| ())
    }

    fn shield(&self, lwd_port: u16) -> Result<()> {
        self.devtool("shield", &["--identity", &self.identity()], Some(lwd_port), None).map(|_| ())
    }

    fn send_with_memo(&self, lwd_port: u16, to: &str, zatoshis: u64, memo: Option<&str>) -> Result<()> {
        let v = zatoshis.to_string();
        let identity = self.identity();
        let mut extra = vec!["--identity", &identity, "--address", to, "--value", &v];
        if let Some(m) = memo {
            extra.push("--memo");
            extra.push(m);
        }
        self.devtool("send", &extra, Some(lwd_port), None).map(|_| ())
    }

    fn identity(&self) -> String {
        self.dir.join("identity.txt").to_string_lossy().into_owned()
    }

    fn devtool(&self, sub: &str, extra: &[&str], lwd_port: Option<u16>, stdin: Option<&str>) -> Result<String> {
        let mut args: Vec<String> = vec![
            "wallet".into(), "-w".into(), self.dir.to_string_lossy().into_owned(), sub.into(),
        ];
        args.extend(extra.iter().map(|s| s.to_string()));
        if let Some(p) = lwd_port {
            args.extend(["--server".into(), format!("127.0.0.1:{p}"), "--connection".into(), "direct".into()]);
        }

        let output = match stdin {
            Some(data) => {
                use std::io::Write;
                let mut child = Command::new(&self.bin)
                    .args(&args)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .with_context(|| format!("devtool {sub}"))?;
                if let Some(mut pipe) = child.stdin.take() {
                    pipe.write_all(data.as_bytes())?;
                }
                child.wait_with_output().with_context(|| format!("devtool {sub}"))?
            }
            None => Command::new(&self.bin)
                .args(&args)
                .output()
                .with_context(|| format!("devtool {sub}"))?,
        };

        if !output.status.success() {
            bail!("devtool {sub} failed:\nstderr: {}", tail(&String::from_utf8_lossy(&output.stderr), 30));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
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
    let (Some(zebrad_bin), Some(lwd_bin), Some(devtool_bin)) = (
        resolve_bin("ZEBRAD_BIN"),
        resolve_bin("LIGHTWALLETD_BIN"),
        resolve_bin("DEVTOOL_BIN"),
    ) else {
        eprintln!("SKIP regtest_auth: set ZEBRAD_BIN, LIGHTWALLETD_BIN, DEVTOOL_BIN to run.");
        return;
    };

    // ── 1. Start zebrad, lightwalletd, init funder to get its addresses ───────

    let mut zebrad = Zebrad::start(&zebrad_bin, TAIL_MINER_ADDRESS).await.expect("start zebrad");
    zebrad.generate_blocks(110).await.expect("mine initial blocks");

    // Start lightwalletd just long enough to init the funder wallet (needs
    // tree state for the birthday). Don't sync — the chain will change after
    // the restarts below, and we don't want the wallet synced to a stale chain.
    let lwd_init = Indexer::start(&lwd_bin, zebrad.rpc_port).await.expect("start lightwalletd");
    let funder = Funder::init(&devtool_bin, lwd_init.grpc_port).expect("init funder");
    drop(lwd_init); // Kill lightwalletd — we'll start a fresh one after mining.

    // Addresses are deterministic from the mnemonic and don't need a sync.
    let funder_taddr = funder.transparent_address().expect("funder transparent address");
    let funder_ua = funder.unified_address().expect("funder unified address");

    // ── 2. Mine coinbase to funder, age past maturity ────────────────────────

    zebrad.restart_with_miner(&funder_taddr).await.expect("restart mining to funder");
    zebrad.generate_blocks(FUNDER_COINBASES).await.expect("mine coinbases");
    zebrad.restart_with_miner(TAIL_MINER_ADDRESS).await.expect("restart mining to throwaway");
    zebrad.generate_blocks(MATURITY_TAIL).await.expect("mine maturity tail");

    // ── 3. Fresh lightwalletd, shield coinbase into Orchard ──────────────────

    let lwd = Indexer::start(&lwd_bin, zebrad.rpc_port).await.expect("start fresh lightwalletd");
    funder.sync(lwd.grpc_port).expect("funder sync");
    funder.shield(lwd.grpc_port).expect("shield to Orchard");
    zebrad.generate_blocks(6).await.expect("confirm shield");
    funder.sync(lwd.grpc_port).expect("funder sync");

    // ── 4. Start zfa-backend worker ──────────────────────────────────────────

    let zfa_bin = std::env::var("ZFA_BIN").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/release/zfa-backend")
    });
    assert!(zfa_bin.is_file(), "zfa-backend not found at {} — build with `cargo build --release` or set $ZFA_BIN", zfa_bin.display());

    let worker = ZfaWorker::start(&zfa_bin, lwd.grpc_port).await.expect("start worker");
    assert!(worker.service_address.starts_with("uregtest1"), "expected uregtest1 address, got: {}", worker.service_address);
    assert_eq!(worker.otp_key_hex.len(), 64, "OTP key should be 64 hex chars");

    // ── 5. Fund the worker's service wallet ─────────────────────────────────

    funder.send_with_memo(lwd.grpc_port, &worker.service_address, FUND_ZATOSHIS, None).expect("fund service wallet");
    zebrad.generate_blocks(12).await.expect("confirm funding");
    funder.sync(lwd.grpc_port).expect("funder sync");
    tokio::time::sleep(Duration::from_secs(5)).await;

    // ── 6. Send auth payment with ZFA memo ──────────────────────────────────

    let auth_memo = format!("(DO NOT MODIFY){{zfa/{SESSION_ID},{funder_ua}}}");
    funder.send_with_memo(lwd.grpc_port, &worker.service_address, AUTH_PAYMENT_ZATOSHIS, Some(&auth_memo)).expect("send auth payment");

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