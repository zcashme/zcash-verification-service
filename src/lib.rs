//! The ZFA authentication worker: a background process that watches the Zcash
//! mempool for shielded login payments and authenticates sessions.
//!
//! The worker is not an API server. It communicates with the web frontend
//! through a shared SQLite database (`zfa.db`): the frontend creates pending
//! sessions and polls their status; the worker watches the mempool, decrypts
//! auth payments, and updates session status to `authenticated`.
//!
//! ## Architecture
//!
//! ```text
//! Web frontend (SDK)               zfa.db               ZFA worker
//! ──────────────────               ────────             ──────────
//! POST /login →                    sessions             connects to lightwalletd gRPC
//!   INSERT session (pending)  ──→  ┌─────────┐    ←──   watches GetMempoolStream
//!                                        │              decrypts each tx
//! GET /status/:id →                     │              extracts memo
//!   SELECT session status      ←──        │         ──→  UPDATE → authenticated
//!                                        │              INSERT processed_txids
//!                                   processed_txids
//! ```
//!
//! The worker owns one service wallet (a single shielded Zcash account) used
//! to decrypt incoming auth payments and send OTP response transactions. It
//! connects to a lightwalletd (or Zaino) gRPC endpoint — both serve the same
//! `CompactTxStreamer` proto, so the backend is selected by a config URL.
//!
//! ## Dependencies (librustzcash ironwood line)
//!
//! Pinned to the same crate versions as zecd: `zcash_client_backend 0.24.0-rc.1`,
//! `zcash_client_sqlite 0.22.0-rc.1`, `zcash_keys 0.15`, `zcash_primitives 0.29`,
//! `orchard 0.15`. These carry NU6.3/Ironwood support unconditionally.

pub mod backoff;
pub mod config;
pub mod error;
pub mod hardening;
pub mod lock;
pub mod lwd;
pub mod memo;
pub mod network;
pub mod otp;
pub mod session;
pub mod sync;
pub mod wallet;
pub mod watcher;

use std::path::Path;
use tracing::info;

/// Run the ZFA authentication worker until graceful shutdown.
///
/// This is the main entry point called by `main.rs`. It:
///
/// 1. Initializes `zfa.db` (sessions + processed_txids).
/// 2. Opens the service wallet (zcash_client_sqlite wallet DB).
/// 3. Connects to the lightwalletd gRPC endpoint.
/// 4. Spawns the single-writer actor (sync loop + mempool watcher).
/// 5. Waits for SIGINT/SIGTERM, then shuts down gracefully.
pub async fn run(config: config::AppConfig) -> anyhow::Result<()> {
    info!(
        network = config.network.name(),
        lwd_url = %config.lwd_url,
        datadir = %config.datadir.display(),
        "starting ZFA authentication worker"
    );

    // Initialize the session database (zfa.db) — separate from the wallet DB.
    let zfa_db_path = config.datadir.join("zfa.db");
    let _zfa_db = session::init_db(&zfa_db_path)?;

    info!("zfa.db initialized at {}", zfa_db_path.display());

    // TODO: open wallet, connect to lightwalletd, spawn actor, run until shutdown.

    // For now, wait for shutdown signal.
    wait_for_shutdown().await;
    info!("shutting down");
    Ok(())
}

/// Await SIGINT or SIGTERM.
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => info!("received Ctrl-C"),
            _ = term.recv() => info!("received SIGTERM"),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        info!("received Ctrl-C");
    }
}