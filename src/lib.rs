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

use std::time::Duration;
use tracing::{error, info, warn};

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

    // Shutdown signal.
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);

    // Spawn the wallet actor.
    let wallet_dir = config.datadir.clone();
    let keys_path = config.datadir.join("keys.toml");
    let age_identity = config.datadir.join("identity.txt");

    let actor_cfg = wallet::actor::ActorConfig {
        network: config.network,
        wallet_dir,
        keys_path,
        lwd_url: config.lwd_url.clone(),
        session_ttl_secs: config.session_ttl_secs,
        sync_interval: Duration::from_secs(config.sync_interval_secs),
        connect_timeout: Duration::from_secs(10),
        reconnect_base: Duration::from_secs(config.reconnect_base_secs),
        reconnect_max: Duration::from_secs(config.reconnect_max_secs),
        age_identity: if age_identity.exists() { Some(age_identity) } else { None },
        zfa_db_path,
        shutdown: shutdown_tx.subscribe(),
    };

    let actor_task = wallet::actor::spawn(actor_cfg).await?;

    // Wait for shutdown signal.
    wait_for_shutdown().await;
    shutdown_tx.send_replace(true);

    // Wait for the actor to stop.
    let stop_deadline = Duration::from_secs(30);
    match tokio::time::timeout(stop_deadline, actor_task).await {
        Ok(Ok(())) => info!("wallet actor stopped"),
        Ok(Err(e)) => error!("wallet actor task panicked: {e}"),
        Err(_) => warn!("wallet actor did not stop within {stop_deadline:?}; exiting anyway"),
    }

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