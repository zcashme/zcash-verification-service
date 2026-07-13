//! Worker configuration: a TOML file plus CLI overrides, resolved into [`AppConfig`].

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use serde::Deserialize;

use crate::network::ZNetwork;

/// Default lightwalletd gRPC port (mainnet).
pub const LWD_DEFAULT_PORT_MAIN: u16 = 9067;
/// Default lightwalletd gRPC port (testnet).
pub const LWD_DEFAULT_PORT_TEST: u16 = 19067;

/// The resolved worker configuration.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Zcash network: mainnet, testnet, or regtest.
    pub network: ZNetwork,
    /// Data directory (wallet DB, zfa.db, keys.toml).
    pub datadir: PathBuf,
    /// lightwalletd (or Zaino) gRPC endpoint URL.
    pub lwd_url: String,
    /// Session TTL in seconds: a pending session expires after this.
    pub session_ttl_secs: u64,
    /// Poll interval for the sync loop (seconds).
    pub sync_interval_secs: u64,
    /// Reconnect backoff base delay (seconds).
    pub reconnect_base_secs: u64,
    /// Reconnect backoff maximum delay (seconds).
    pub reconnect_max_secs: u64,
    /// Logging configuration.
    pub log: LogConfig,
}

#[derive(Debug, Clone)]
pub struct LogConfig {
    pub level: String,
    pub format: String,
}

/// `zfa-backend` — the ZFA authentication worker.
#[derive(Debug, Parser)]
#[command(name = "zfa-backend", version)]
pub struct Cli {
    /// Path to the TOML config file (default: <datadir>/zfa.toml).
    #[arg(long, value_name = "FILE")]
    pub conf: Option<PathBuf>,

    /// Data directory holding the wallet DB, zfa.db, and keys.toml.
    #[arg(long, value_name = "DIR")]
    pub datadir: Option<PathBuf>,

    /// Use testnet.
    #[arg(long)]
    pub testnet: bool,

    /// Use regtest.
    #[arg(long)]
    pub regtest: bool,

    /// Network: "main", "test", or "regtest".
    #[arg(long, value_name = "NET")]
    pub network: Option<String>,

    /// lightwalletd (or Zaino) gRPC URL, e.g. "http://localhost:9067".
    #[arg(long, value_name = "URL")]
    pub lwd_url: Option<String>,

    /// Subcommand. When omitted, runs the worker daemon.
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Create and initialize a new wallet (mnemonic + account), then exit.
    Init(InitArgs),
}

#[derive(Debug, clap::Args)]
pub struct InitArgs {
    /// Restore from an existing mnemonic instead of generating a new one.
    /// Read from ZFA_MNEMONIC env var or stdin.
    #[arg(long)]
    pub restore: bool,
}

/// On-disk TOML representation.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    network: Option<String>,
    datadir: Option<PathBuf>,
    lwd_url: Option<String>,
    session_ttl_secs: Option<u64>,
    sync_interval_secs: Option<u64>,
    reconnect_base_secs: Option<u64>,
    reconnect_max_secs: Option<u64>,
    log: Option<LogFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogFile {
    level: Option<String>,
    format: Option<String>,
}

impl AppConfig {
    /// Resolve the effective configuration from CLI flags and the TOML file.
    pub fn resolve(cli: &Cli) -> anyhow::Result<AppConfig> {
        // Datadir precedence: CLI > default.
        let datadir = cli
            .datadir
            .clone()
            .unwrap_or_else(|| PathBuf::from("./zfa-data"));

        // Config file: explicit --conf, else <datadir>/zfa.toml.
        let conf_path = cli.conf.clone().unwrap_or_else(|| datadir.join("zfa.toml"));

        let file: ConfigFile = if conf_path.exists() {
            let text = std::fs::read_to_string(&conf_path)
                .with_context(|| format!("reading config {}", conf_path.display()))?;
            toml::from_str(&text)
                .with_context(|| format!("parsing config {}", conf_path.display()))?
        } else {
            ConfigFile::default()
        };

        // Network: CLI > file > default (testnet).
        let network = if cli.regtest {
            crate::network::regtest()
        } else if cli.testnet {
            ZNetwork::Test
        } else if let Some(n) = &cli.network {
            ZNetwork::parse(n)?
        } else if let Some(n) = &file.network {
            ZNetwork::parse(n)?
        } else {
            ZNetwork::Test
        };

        let datadir = file.datadir.unwrap_or(datadir);

        // lightwalletd URL: CLI > file > default per network.
        let lwd_url = cli
            .lwd_url
            .clone()
            .or(file.lwd_url)
            .unwrap_or_else(|| {
                let port = match network {
                    ZNetwork::Main => LWD_DEFAULT_PORT_MAIN,
                    ZNetwork::Test | ZNetwork::Regtest(_) => LWD_DEFAULT_PORT_TEST,
                };
                format!("http://localhost:{port}")
            });

        let log_file = file.log.unwrap_or(LogFile {
            level: None,
            format: None,
        });
        let log = LogConfig {
            level: log_file.level.unwrap_or_else(|| "info".to_string()),
            format: log_file.format.unwrap_or_else(|| "text".to_string()),
        };

        let reconnect_base = file.reconnect_base_secs.unwrap_or(1).max(1);
        Ok(AppConfig {
            network,
            datadir,
            lwd_url,
            session_ttl_secs: file.session_ttl_secs.unwrap_or(120),
            sync_interval_secs: file.sync_interval_secs.unwrap_or(20).max(1),
            reconnect_base_secs: reconnect_base,
            reconnect_max_secs: file
                .reconnect_max_secs
                .unwrap_or(60)
                .max(reconnect_base),
            log,
        })
    }
}

/// Initialize tracing. The filter defaults to `[log] level` and is overridden
/// by `RUST_LOG`.
pub fn init_tracing(log: &LogConfig) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&log.level));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    if log.format.eq_ignore_ascii_case("json") {
        builder.json().init();
    } else {
        builder.init();
    }
}