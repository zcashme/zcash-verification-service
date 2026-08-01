//! Worker configuration: a single `zfa.toml` holding the `[seed]` section
//! (age-encrypted mnemonic + birthday), plus hardcoded operational defaults
//! overridable by a small set of CLI flags.
//!
//! There is no operational TOML — network, LWD URL, sync intervals, and logging
//! are hardcoded constants. The only on-disk config is the wallet's encrypted
//! seed. An optional `--keys-file` escape hatch lets the `[seed]` table live in
//! a separate file (e.g. a Kubernetes Secret) while `zfa.toml` remains the
//! ConfigMap-friendly operational stub.

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use serde::{Deserialize, Serialize};

use crate::network::ZNetwork;

// ── Hardcoded operational defaults ──────────────────────────────────────────

/// ZIP-32 account index (zfa uses a single account).
pub const ACCOUNT_INDEX: u32 = 0;
/// Account label (required by librustzcash's create_account API; zfa never reads it back).
pub const ACCOUNT_NAME: &str = "primary";

/// Default lightwalletd gRPC endpoint (mainnet) — zec.rocks public instance.
pub const LWD_DEFAULT_URL_MAIN: &str = "https://zec.rocks:443";
/// Default lightwalletd gRPC endpoint (testnet) — zec.rocks public testnet instance.
pub const LWD_DEFAULT_URL_TEST: &str = "https://testnet.zec.rocks:443";

/// Sync poll interval.
pub const SYNC_INTERVAL_SECS: u64 = 20;
/// Reconnect backoff base delay.
pub const RECONNECT_BASE_SECS: u64 = 1;
/// Reconnect backoff maximum delay.
pub const RECONNECT_MAX_SECS: u64 = 60;
/// Per-attempt LWD connect timeout.
pub const CONNECT_TIMEOUT_SECS: u64 = 10;

/// Default data directory.
pub const DEFAULT_DATADIR: &str = "./zfa-data";

// ── Resolved config ─────────────────────────────────────────────────────────

/// The resolved worker configuration. Operational fields are hardcoded;
/// `conf_path` and `seed_path` locate the on-disk `[seed]` table.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Zcash network: mainnet (default), testnet, or regtest.
    pub network: ZNetwork,
    /// Data directory (wallet DB, response ledger, identity.txt, blocks/).
    pub datadir: PathBuf,
    /// lightwalletd (or Zaino) gRPC endpoint URL.
    pub lwd_url: String,
    /// Path to the TOML file containing the `[seed]` table.
    pub conf_path: PathBuf,
    /// Path to the file containing the `[seed]` table (escape hatch: may differ
    /// from `conf_path` when `--keys-file` points at a Secret mount).
    pub seed_path: PathBuf,
    /// Path to the age identity file that decrypts the mnemonic.
    pub identity_path: PathBuf,
}

impl AppConfig {
    /// Default LWD URL for a given network.
    pub fn default_lwd_url(network: &ZNetwork) -> String {
        match network {
            ZNetwork::Main => LWD_DEFAULT_URL_MAIN.to_string(),
            ZNetwork::Test | ZNetwork::Regtest(_) => LWD_DEFAULT_URL_TEST.to_string(),
        }
    }

    /// Hardcoded sync interval.
    pub fn sync_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(SYNC_INTERVAL_SECS)
    }

    /// Hardcoded connect timeout.
    pub fn connect_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(CONNECT_TIMEOUT_SECS)
    }

    /// Hardcoded reconnect base delay.
    pub fn reconnect_base(&self) -> std::time::Duration {
        std::time::Duration::from_secs(RECONNECT_BASE_SECS)
    }

    /// Hardcoded reconnect max delay.
    pub fn reconnect_max(&self) -> std::time::Duration {
        std::time::Duration::from_secs(RECONNECT_MAX_SECS)
    }
}

// ── CLI ──────────────────────────────────────────────────────────────────────

/// `zfa-backend` — the ZFA authentication worker.
#[derive(Debug, Parser)]
#[command(name = "zfa-backend", version)]
pub struct Cli {
    /// Path to the TOML config file (default: <datadir>/zfa.toml).
    #[arg(long, value_name = "FILE")]
    pub conf: Option<PathBuf>,

    /// Escape hatch: path to a separate file containing the `[seed]` table,
    /// e.g. a Kubernetes Secret mount. Overrides the `[seed]` section in the
    /// main config file.
    #[arg(long, value_name = "FILE")]
    pub keys_file: Option<PathBuf>,

    /// Data directory (wallet DB, response ledger, identity.txt, blocks/).
    #[arg(long, value_name = "DIR")]
    pub datadir: Option<PathBuf>,

    /// Network: "main" (default), "test", or "regtest".
    #[arg(long, value_name = "NET")]
    pub network: Option<String>,

    /// lightwalletd (or Zaino) gRPC URL. Default: https://zec.rocks:443 (mainnet)
    /// or https://testnet.zec.rocks:443 (testnet).
    #[arg(long, value_name = "URL")]
    pub lwd_url: Option<String>,

    /// Mnemonic phrase to restore from. If omitted, a fresh wallet is generated.
    #[arg(long, value_name = "PHRASE")]
    pub mnemonic: Option<String>,

    /// Earliest block that may contain funds. Required when --mnemonic is provided;
    /// new wallets default to the chain tip.
    #[arg(long, value_name = "HEIGHT")]
    pub birthday: Option<u32>,
}

/// Wallet initialization parameters, derived from CLI flags.
/// Not a clap subcommand — constructed by `main` from `Cli` fields.
#[derive(Debug, Clone)]
pub struct InitArgs {
    /// Mnemonic phrase to restore from, or `None` to generate a fresh wallet.
    pub mnemonic: Option<String>,
    /// Birthday block height. Required when restoring; ignored for fresh wallets.
    pub birthday: Option<u32>,
}

// ── On-disk TOML: only the [seed] table ──────────────────────────────────────

/// The on-disk `zfa.toml` — just a `[seed]` table.
#[derive(Debug, Default, Deserialize, Serialize)]
pub struct ConfigFile {
    pub seed: Option<SeedTable>,
}

/// The `[seed]` table inside `zfa.toml` (or a `--keys-file` Secret mount).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SeedTable {
    /// Birthday block height.
    pub birthday: u32,
    /// Age-armored encrypted BIP-39 mnemonic phrase.
    pub mnemonic: String,
}

impl ConfigFile {
    /// Read and parse a `zfa.toml` (or `--keys-file`). A missing file yields
    /// an empty `ConfigFile` (the worker will refuse to run without a seed,
    /// but `init` handles that path).
    pub fn read(path: &std::path::Path) -> anyhow::Result<ConfigFile> {
        if !path.exists() {
            return Ok(ConfigFile::default());
        }
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing config {}", path.display()))
    }

    /// Write the `[seed]` table to `path`, creating the file `0600`.
    pub fn write_seed(
        path: &std::path::Path,
        birthday: u32,
        mnemonic_ciphertext: &str,
    ) -> anyhow::Result<()> {
        let config = ConfigFile {
            seed: Some(SeedTable {
                birthday,
                mnemonic: mnemonic_ciphertext.to_string(),
            }),
        };
        let text =
            toml::to_string(&config).map_err(|e| anyhow::anyhow!("serializing zfa.toml: {e}"))?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        use std::io::Write as _;
        let mut file = opts
            .open(path)
            .map_err(|e| anyhow::anyhow!("creating {}: {e}", path.display()))?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }
}

// ── Resolution ───────────────────────────────────────────────────────────────

impl AppConfig {
    /// Resolve the effective configuration from CLI flags.
    pub fn resolve(cli: &Cli) -> anyhow::Result<AppConfig> {
        // Datadir: CLI > default.
        let datadir = cli
            .datadir
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DATADIR));

        // Config file: explicit --conf, else <datadir>/zfa.toml.
        let conf_path = cli.conf.clone().unwrap_or_else(|| datadir.join("zfa.toml"));

        // Seed file: explicit --keys-file (escape hatch), else same as conf_path.
        let seed_path = cli.keys_file.clone().unwrap_or_else(|| conf_path.clone());

        // Age identity: always <datadir>/identity.txt.
        let identity_path = datadir.join("identity.txt");

        // Network: CLI > default (mainnet).
        let network = if let Some(n) = &cli.network {
            ZNetwork::parse(n)?
        } else {
            ZNetwork::Main
        };

        // LWD URL: CLI > default per network.
        let lwd_url = cli
            .lwd_url
            .clone()
            .unwrap_or_else(|| AppConfig::default_lwd_url(&network));

        Ok(AppConfig {
            network,
            datadir,
            lwd_url,
            conf_path,
            seed_path,
            identity_path,
        })
    }
}

// ── OTP key derivation ────────────────────────────────────────────────────────

/// Derive the 32-byte OTP HMAC key from the wallet seed.
///
/// `HMAC-SHA256(seed, "zvs-otp")` — deterministic, so the consumer
/// application's server can derive the same key from the same seed (exported
/// once during `init`). No env var, no config file entry, no shared secret to
/// rotate independently.
pub fn derive_otp_key(seed: &[u8]) -> secrecy::SecretVec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(seed).expect("HMAC accepts any key length");
    mac.update(b"zvs-otp");
    let result = mac.finalize().into_bytes();
    secrecy::SecretVec::new(result.to_vec())
}

// ── Tracing ──────────────────────────────────────────────────────────────────

/// Initialize tracing. The filter defaults to `info` and is overridden by
/// `RUST_LOG`.
pub fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}
