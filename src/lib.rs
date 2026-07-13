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

/// Initialize a new wallet: generate (or restore) a mnemonic, create an age
/// identity, derive the UFVK, write keys.toml, and create the wallet account.
pub async fn init_wallet(
    config: &config::AppConfig,
    args: &config::InitArgs,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use bip0039::{Count, English, Mnemonic};
    use secrecy::{ExposeSecret, Zeroize};
    use zcash_client_backend::data_api::{Account as _, AccountBirthday, WalletRead as _, WalletWrite as _};
    use zcash_keys::keys::UnifiedSpendingKey;
    use age::secrecy::ExposeSecret as _;

    let keys_path = config.datadir.join("keys.toml");
    if wallet::store::WalletStore::exists(&keys_path) {
        anyhow::bail!("wallet already initialized ({} exists)", keys_path.display());
    }

    std::fs::create_dir_all(&config.datadir)?;

    // Generate or restore mnemonic.
    let mnemonic = if args.restore {
        let phrase = std::env::var("ZFA_MNEMONIC")
            .map(|p| p.trim().to_string())
            .or_else(|_| {
                use std::io::Read;
                eprintln!("Enter the mnemonic phrase to restore:");
                let mut line = String::new();
                std::io::stdin().read_to_string(&mut line)?;
                Ok::<String, anyhow::Error>(line.trim().to_string())
            })?;
        <Mnemonic<English>>::from_phrase(&phrase)?
    } else {
        Mnemonic::generate(Count::Words24)
    };

    // Generate age identity.
    let identity_path = config.datadir.join("identity.txt");
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();

    {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&identity_path)?;
        writeln!(f, "# zfa-backend age identity (KEEP SECRET)")?;
        writeln!(f, "# public key: {recipient}")?;
        writeln!(f, "{}", identity.to_string().expose_secret())?;
    }

    // Derive the seed and UFVK.
    let seed_bytes = {
        let mut seed = mnemonic.to_seed("");
        let secret = secrecy::SecretVec::new(seed.to_vec());
        seed.zeroize();
        secret
    };

    let account_index = zip32::AccountId::try_from(0u32).unwrap();
    let usk = UnifiedSpendingKey::from_seed(&config.network, seed_bytes.expose_secret(), account_index)
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
    let ufvk = usk.to_unified_full_viewing_key();
    let ufvk_encoded = ufvk.encode(&config.network);

    // Write keys.toml.
    wallet::store::WalletStore::init_with_mnemonic(
        &keys_path,
        std::iter::once(&recipient as &dyn age::Recipient),
        &mnemonic,
        zcash_protocol::consensus::BlockHeight::from_u32(1),
        config.network,
        &ufvk_encoded,
    )?;

    // Create the wallet account.
    let mut db = wallet::open::init_dbs(config.network, &config.datadir)?;

    // Fetch birthday tree state from lightwalletd.
    let birthday = {
        let mut client = lwd::LwdClient::connect(&config.lwd_url).await?;
        let tree_state = client.get_tree_state(1).await?;
        AccountBirthday::from_treestate(tree_state, None)
            .map_err(|_| anyhow::anyhow!("failed to derive birthday from tree state"))?
    };

    let (account_id, _) = db
        .create_account("primary", &seed_bytes, &birthday, None)
        .context("creating wallet account")?;

    // Verify the account matches the pin.
    let created_ufvk = db
        .get_account(account_id)
        .map_err(|e| anyhow::anyhow!("get_account: {e}"))?
        .and_then(|a: zcash_client_sqlite::wallet::Account| {
            a.ufvk().map(|u| u.encode(&config.network))
        });
    if created_ufvk.as_deref() != Some(ufvk_encoded.as_str()) {
        anyhow::bail!("internal error: created account UFVK does not match keys.toml pin");
    }

    eprintln!("Wallet initialized at {}", config.datadir.display());
    eprintln!("age identity: {}", identity_path.display());
    if !args.restore {
        eprintln!("\nIMPORTANT — record this mnemonic and keep it safe:\n");
        println!("{}", mnemonic.phrase());
        eprintln!();
    }

    // Also init zfa.db.
    let zfa_db_path = config.datadir.join("zfa.db");
    session::init_db(&zfa_db_path)?;

    Ok(())
}

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

    // Build the wallet actor (does not spawn — runs on a LocalSet to avoid
    // the Send requirement on WalletDb which contains RefCell from rusqlite).
    let actor = wallet::actor::build(actor_cfg).await?;

    // Spawn the shutdown signal handler on the regular runtime.
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        wait_for_shutdown().await;
        shutdown_tx_clone.send_replace(true);
    });

    // Run the actor on a LocalSet (allows !Send futures).
    let local = tokio::task::LocalSet::new();
    local.run_until(actor.run()).await;

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