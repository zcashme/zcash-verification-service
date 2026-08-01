//! The ZFA authentication worker: a background process that watches the Zcash
//! mempool for shielded login payments and sends deterministic OTP responses.
//!
//! The worker is not an API server and does not own application login
//! sessions. A consumer application's server creates sessions, produces the
//! ZIP-321 request, and verifies the OTP locally. The worker watches the
//! mempool, decrypts incoming payments, and records only durable response
//! idempotence state.
//!
//! ## Architecture
//!
//! ```text
//! Consumer app server             response ledger       ZFA worker
//! ───────────────────             ───────────────       ──────────
//! creates app session                                      connects to lightwalletd or Zaino
//! renders ZIP-321 QR               incoming txid ──→      watches GetMempoolStream
//! verifies OTP locally             response txid          decrypts and sends OTP response
//! ```
//!
//! The worker owns one service wallet (a single shielded Zcash account) used
//! to decrypt incoming auth payments and send OTP response transactions. It
//! connects to a lightwalletd (or Zaino) gRPC endpoint — both serve the same
//! `CompactTxStream` proto, so the backend is selected by a config URL.
//!
//! ## Configuration
//!
//! A single `zfa.toml` containing a `[seed]` table (age-encrypted mnemonic +
//! birthday). All operational settings (network, LWD URL, sync intervals) are
//! hardcoded. The OTP HMAC key is derived from the seed:
//! `HMAC-SHA256(seed, "zvs-otp")`.
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
pub mod response_ledger;
pub mod sync;
pub mod wallet;

use tracing::info;

/// Initialize a new wallet: generate (or restore) a mnemonic, create an age
/// identity, derive the UFVK, write `zfa.toml`, and create the wallet account.
///
/// If `args.mnemonic` is `Some`, restores from that phrase (requires
/// `args.birthday`). If `None`, generates a fresh 24-word mnemonic.
pub async fn init_wallet(
    config: &config::AppConfig,
    args: &config::InitArgs,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use bip0039::{Count, English, Mnemonic};
    use secrecy::{ExposeSecret, Zeroize};
    use zcash_client_backend::data_api::{
        Account as _, AccountBirthday, WalletRead as _, WalletWrite as _,
    };
    use zcash_keys::keys::{UnifiedAddressRequest, UnifiedSpendingKey};

    if wallet::store::WalletStore::exists(&config.seed_path)? {
        anyhow::bail!(
            "wallet already initialized ({} has a [seed] table)",
            config.seed_path.display()
        );
    }

    std::fs::create_dir_all(&config.datadir)?;

    // Generate or restore mnemonic. The presence of --mnemonic determines mode.
    let (mnemonic, is_restore) = match &args.mnemonic {
        Some(phrase) => (<Mnemonic<English>>::from_phrase(phrase.trim())?, true),
        None => (Mnemonic::generate(Count::Words24), false),
    };

    // Create an age identity, or safely reuse one left by an interrupted
    // initialization. This mirrors zecd: a retry must not fail merely because
    // key generation completed before the network/bootstrap step did.
    let recipients = ensure_identity(&config.identity_path)?;

    // Derive the seed and UFVK.
    let seed_bytes = {
        let mut seed = mnemonic.to_seed("");
        let secret = secrecy::SecretVec::new(seed.to_vec());
        seed.zeroize();
        secret
    };

    let account_index = zip32::AccountId::try_from(config::ACCOUNT_INDEX).map_err(|_| {
        anyhow::anyhow!(
            "account {} is not a valid ZIP-32 account",
            config::ACCOUNT_INDEX
        )
    })?;
    let usk =
        UnifiedSpendingKey::from_seed(&config.network, seed_bytes.expose_secret(), account_index)
            .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
    let ufvk = usk.to_unified_full_viewing_key();
    let ufvk_encoded = ufvk.encode(&config.network);
    let (service_address, _) = ufvk
        .default_address(UnifiedAddressRequest::AllAvailableKeys)
        .map_err(|e| anyhow::anyhow!("deriving service unified address: {e}"))?;
    if !service_address.has_sapling() || !service_address.has_orchard() {
        anyhow::bail!(
            "service address must contain both Sapling and Orchard receivers for ZFA compatibility"
        );
    }
    let service_address = service_address.encode(&config.network);

    // A fresh wallet has no prior funds, so its birthday is the current tip.
    // A restored wallet must receive an explicit, conservative birthday so it
    // never silently skips pre-existing auth payments or funds.
    let mut bootstrap_client = lwd::LwdClient::connect(&config.lwd_url).await?;
    let birthday_height = match args.birthday {
        Some(0) => anyhow::bail!("wallet birthday must be at least height 1"),
        Some(height) => zcash_protocol::consensus::BlockHeight::from_u32(height),
        None if is_restore => {
            anyhow::bail!("--birthday is required when restoring from a mnemonic")
        }
        None => {
            let tip = bootstrap_client.get_latest_block().await?;
            let height = u32::try_from(tip.height).map_err(|_| {
                anyhow::anyhow!("lightwalletd returned an out-of-range chain height")
            })?;
            zcash_protocol::consensus::BlockHeight::from_u32(height.max(1))
        }
    };

    // Write zfa.toml with the [seed] table.
    wallet::store::WalletStore::init_with_mnemonic(
        &config.seed_path,
        recipients.iter().map(|recipient| recipient.as_ref() as _),
        &mnemonic,
        birthday_height,
    )?;

    // Create the wallet account.
    let mut db = wallet::open::init_dbs(config.network, &config.datadir)?;

    // Fetch birthday tree state from lightwalletd.
    let tree_state = bootstrap_client
        .get_tree_state(u64::from(birthday_height))
        .await?;
    let birthday = AccountBirthday::from_treestate(tree_state, None)
        .map_err(|_| anyhow::anyhow!("failed to derive birthday from tree state"))?;

    let (account_id, _) = db
        .create_account(config::ACCOUNT_NAME, &seed_bytes, &birthday, None)
        .context("creating wallet account")?;

    // Verify the account matches the seed.
    let created_ufvk = db
        .get_account(account_id)
        .map_err(|e| anyhow::anyhow!("get_account: {e}"))?
        .and_then(|a: zcash_client_sqlite::wallet::Account| {
            a.ufvk().map(|u| u.encode(&config.network))
        });
    if created_ufvk.as_deref() != Some(ufvk_encoded.as_str()) {
        anyhow::bail!("internal error: created account UFVK does not match the seed-derived UFVK");
    }

    eprintln!("Wallet initialized at {}", config.datadir.display());
    eprintln!("Config: {}", config.seed_path.display());
    eprintln!("age identity: {}", config.identity_path.display());
    eprintln!("service unified address: {service_address}");

    // Derive and print the OTP key (hex) for provisioning the consumer app server.
    let otp_key = config::derive_otp_key(seed_bytes.expose_secret());
    let otp_hex = hex::encode(otp_key.expose_secret());
    eprintln!("\nOTP HMAC key (provision the consumer app server with this):");
    println!("{otp_hex}");
    eprintln!();

    if !is_restore {
        eprintln!(
            "\n⚠  NEW WALLET — record this mnemonic and store it securely.\
             \n   This is the ONLY time it will be displayed.\n"
        );
        println!("{}", mnemonic.phrase());
        eprintln!();
    }

    // Initialize the worker-only response ledger. It contains no web sessions.
    response_ledger::init_db(&config.datadir.join("responses.sqlite"))?;

    Ok(())
}

/// Create an owner-only age identity, or return recipients derived from an
/// existing one after checking that it is still private.
///
/// An existing identity with no `zfa.toml` is an interrupted initialization,
/// not a reason to generate a second key that would make the first one
/// irrecoverable. This is adapted from zecd's `ensure_identity` flow.
fn ensure_identity(path: &std::path::Path) -> anyhow::Result<Vec<Box<dyn age::Recipient + Send>>> {
    use age::secrecy::ExposeSecret as _;

    if path.exists() {
        wallet::keys::check_identity_file_permissions(path)?;
        return Ok(
            age::IdentityFile::from_file(path.to_string_lossy().into_owned())?.to_recipients()?,
        );
    }

    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    use std::io::Write as _;
    writeln!(file, "# zfa-backend age identity (KEEP SECRET)")?;
    writeln!(file, "# public key: {recipient}")?;
    writeln!(file, "{}", identity.to_string().expose_secret())?;
    file.sync_all()?;

    Ok(vec![Box::new(recipient)])
}

/// Run the ZFA authentication worker until graceful shutdown.
///
/// This is the main entry point called by `main.rs`. It:
///
/// 1. Initializes `responses.sqlite` (outbound response idempotence only).
/// 2. Opens the service wallet (zcash_client_sqlite wallet DB).
/// 3. Connects to the lightwalletd gRPC endpoint.
/// 4. Spawns the single-writer actor (sync loop + mempool watcher).
/// 5. Waits for SIGINT/SIGTERM, then shuts down gracefully.
pub async fn run(config: config::AppConfig, init_args: config::InitArgs) -> anyhow::Result<()> {
    info!(
        network = config.network.name(),
        lwd_url = %config.lwd_url,
        datadir = %config.datadir.display(),
        "starting ZFA authentication worker"
    );

    // If the wallet hasn't been initialized yet, create it now.
    if !wallet::store::WalletStore::exists(&config.seed_path)? {
        info!("wallet not initialized — creating now");
        init_wallet(&config, &init_args).await?;
        info!("wallet initialized — starting worker");
    }

    let response_ledger_path = config.datadir.join("responses.sqlite");
    let _response_ledger = response_ledger::init_db(&response_ledger_path)?;
    info!(response_ledger = %response_ledger_path.display(), "response ledger initialized");

    // Shutdown signal.
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);

    // Spawn the wallet actor.
    let actor_cfg = wallet::actor::ActorConfig {
        network: config.network,
        wallet_dir: config.datadir.clone(),
        seed_path: config.seed_path.clone(),
        identity_path: config.identity_path.clone(),
        lwd_url: config.lwd_url.clone(),
        sync_interval: config.sync_interval(),
        connect_timeout: config.connect_timeout(),
        reconnect_base: config.reconnect_base(),
        reconnect_max: config.reconnect_max(),
        response_ledger_path,
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
