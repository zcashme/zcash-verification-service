//! `zfa-backend` — the ZFA authentication worker binary.

use clap::Parser;
use zfa_backend::config::{AppConfig, Cli, Command};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Handle init subcommand before resolving full config.
    if let Some(Command::Init(args)) = &cli.command {
        let config = AppConfig::resolve(&cli)?;
        zfa_backend::config::init_tracing(&config.log);
        zfa_backend::hardening::harden_process();
        return zfa_backend::init_wallet(&config, args).await;
    }

    let config = AppConfig::resolve(&cli)?;
    zfa_backend::config::init_tracing(&config.log);
    zfa_backend::hardening::harden_process();

    let _datadir_lock = zfa_backend::lock::lock_datadir(&config.datadir)?;
    zfa_backend::run(config).await
}