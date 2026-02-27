//! ZVS - Zcash Verification Service

use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use bip0039::{English, Mnemonic};
use tracing::info;
use tracing_subscriber::EnvFilter;
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;

mod memo_rules;
mod mempool;
mod otp_rules;
mod otp_send;
mod sync;
mod wallet;

use otp_send::ProcessedStore;
use wallet::Wallet;

// =============================================================================
// Constants
// =============================================================================

/// Interval (seconds) between background sync checks.
const SYNC_INTERVAL_SECS: u64 = 30;

// =============================================================================
// Seed Loading
// =============================================================================

/// Load wallet seed from MNEMONIC environment variable.
///
/// Returns the full 64-byte BIP39-derived seed for key derivation.
fn load_seed() -> Result<Vec<u8>> {
    let mnemonic_str = env::var("MNEMONIC")
        .map_err(|_| anyhow!("MNEMONIC environment variable required (24-word BIP39 phrase)"))?;

    let mnemonic: Mnemonic<English> = mnemonic_str
        .trim()
        .parse()
        .map_err(|e| anyhow!("Invalid mnemonic: {}", e))?;

    let passphrase = env::var("MNEMONIC_PASSPHRASE").unwrap_or_default();
    let seed = mnemonic.to_seed(&passphrase);

    info!(
        "Loaded seed from MNEMONIC ({} words)",
        mnemonic_str.split_whitespace().count()
    );

    Ok(seed.to_vec())
}

// =============================================================================
// Main
// =============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    dotenvy::dotenv().ok();

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let url = env::var("LIGHTWALLETD_URL").expect("LIGHTWALLETD_URL required");
    let birthday_height: u32 = env::var("BIRTHDAY_HEIGHT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let data_dir = env::var("ZVS_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./zvs_data"));
    let otp_secret = env::var("OTP_SECRET").expect("OTP_SECRET required");

    let seed = load_seed()?;
    let otp_secret_bytes = hex::decode(&otp_secret)?;

    println!("ZVS - Zcash Verification Service");
    println!("=================================");
    println!("Lightwalletd: {}", url);
    println!("Birthday height: {}", birthday_height);
    println!("Mode: Mempool streaming (real-time)");
    println!();

    // Single gRPC connection — cheap to clone for each task
    info!("Connecting to lightwalletd at {}", url);
    let mut client = CompactTxStreamerClient::connect(url.clone()).await?;

    // Fetch birthday for wallet initialization (only needed if wallet.db doesn't exist)
    let birthday = sync::fetch_birthday(&mut client, birthday_height).await?;

    // Create wallet
    let mut wallet = Wallet::new(&seed, Some(&birthday), &data_dir)?;

    match wallet.get_address() {
        Ok(address) => println!("Wallet address: {}", address),
        Err(e) => println!("Could not get address: {}", e),
    }
    println!();

    // Clone UFVK before wrapping wallet in Arc<Mutex>
    let ufvk = wallet.get_ufvk();

    // Initialize processed store
    let processed_store = Arc::new(std::sync::Mutex::new(ProcessedStore::load(
        data_dir.join("processed_otps.log"),
    )));

    // Initial blocking sync — processes OTPs for any enhanced transactions directly
    println!("=== INITIAL SYNC ===");
    println!("Syncing wallet to chain tip...");
    sync::sync_wallet(
        &mut client,
        &mut wallet,
        Some(&ufvk),
        Some(&otp_secret_bytes),
        Some(&processed_store),
    )
    .await?;

    let synced_height = wallet.get_synced_height().unwrap_or(0);
    println!("Synced to block: {}", synced_height);

    match wallet.get_balance() {
        Ok(balance) => {
            let total_zats = u64::from(balance.total);
            let spendable_zats = u64::from(balance.spendable);
            let sapling_zats = u64::from(balance.sapling_spendable);
            let orchard_zats = u64::from(balance.orchard_spendable);
            let spendable_zec = spendable_zats as f64 / 100_000_000.0;
            println!(
                "Balance: {:.8} ZEC ({} spendable, {} total)",
                spendable_zec, spendable_zats, total_zats
            );
            println!(
                "  Pools: Sapling={} zats, Orchard={} zats",
                sapling_zats, orchard_zats
            );
        }
        Err(e) => println!("Balance error: {}", e),
    }
    println!("====================");
    println!();
    println!("Background sync: every {}s", SYNC_INTERVAL_SECS);
    println!();

    println!("Starting ZVS service...");
    println!("Press Ctrl+C to stop");
    println!();

    // Wrap wallet for shared access between tasks
    let wallet = Arc::new(tokio::sync::Mutex::new(wallet));

    // Spawn two tasks: sync + mempool
    let sync_handle = tokio::spawn(sync::run_sync_loop(
        client.clone(),
        wallet.clone(),
        SYNC_INTERVAL_SECS,
        ufvk.clone(),
        otp_secret_bytes.clone(),
        processed_store.clone(),
    ));

    let mempool_handle = tokio::spawn(mempool::run_mempool_loop(
        client,
        wallet.clone(),
        ufvk,
        otp_secret_bytes,
        processed_store,
    ));

    // Wait for shutdown signal or task failure
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            println!("\nShutting down...");
        }
        result = sync_handle => {
            match result {
                Ok(_) => unreachable!("sync loop never returns"),
                Err(e) => eprintln!("Sync task panicked: {}", e),
            }
        }
        result = mempool_handle => {
            match result {
                Ok(_) => unreachable!("mempool loop never returns"),
                Err(e) => eprintln!("Mempool task panicked: {}", e),
            }
        }
    }

    Ok(())
}
