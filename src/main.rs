//! `zfa-backend` — the ZFA authentication worker binary.
//!
//! A thin CLI wrapper around [`zfa_backend::run`]. The worker is a background
//! process: it connects to a lightwalletd gRPC endpoint, watches the mempool
//! stream for shielded auth payments, and updates session status in `zfa.db`.
//! It does not serve HTTP — the frontend reads session status from the shared
//! database.

use clap::Parser;
use zfa_backend::config::{AppConfig, Cli};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = AppConfig::resolve(&cli)?;

    zfa_backend::config::init_tracing(&config.log);
    // Disable core dumps + ptrace before any seed is decrypted (best-effort).
    zfa_backend::hardening::harden_process();

    // Single-instance guard: two workers writing one data directory would
    // corrupt both the wallet DB and zfa.db. This makes the second refuse to
    // start instead.
    let _datadir_lock = zfa_backend::lock::lock_datadir(&config.datadir)?;

    zfa_backend::run(config).await
}