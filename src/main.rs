//! `zfa-backend` — the ZFA authentication worker binary.

use clap::Parser;
use zfa_backend::config::{AppConfig, Cli, InitArgs};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let config = AppConfig::resolve(&cli)?;
    zfa_backend::config::init_tracing();
    zfa_backend::hardening::harden_process();
    let _datadir_lock = zfa_backend::lock::lock_datadir(&config.datadir)?;

    let init_args = InitArgs {
        mnemonic: cli.mnemonic,
        birthday: cli.birthday,
    };

    zfa_backend::run(config, init_args).await
}