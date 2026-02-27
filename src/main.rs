//! ZVS - Zcash Verification Service

use std::path::{Path, PathBuf};
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
// Keys Loading
// =============================================================================

#[derive(serde::Deserialize)]
struct Keys {
    mnemonic: String,
    otp_secret: String,
    birthday_height: u32,
}

/// Load secrets and config from `keys.toml` in the data directory.
///
/// Returns (seed, otp_secret_bytes, birthday_height).
fn load_keys(data_dir: &Path) -> Result<(Vec<u8>, Vec<u8>, u32)> {
    let path = data_dir.join("keys.toml");
    let contents = std::fs::read_to_string(&path)
        .map_err(|_| anyhow!("keys.toml not found at {}", path.display()))?;
    let keys: Keys =
        toml::from_str(&contents).map_err(|e| anyhow!("Invalid keys.toml: {e}"))?;

    let mnemonic: Mnemonic<English> = keys
        .mnemonic
        .trim()
        .parse()
        .map_err(|e| anyhow!("Invalid mnemonic: {e}"))?;
    let seed = mnemonic.to_seed("").to_vec();
    let otp_secret =
        hex::decode(&keys.otp_secret).map_err(|e| anyhow!("Invalid otp_secret hex: {e}"))?;

    info!(
        "Loaded keys from {}",
        path.display()
    );

    Ok((seed, otp_secret, keys.birthday_height))
}

// =============================================================================
// Main
// =============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let url = "https://zec.rocks:443";
    let data_dir = PathBuf::from("./zvs_data");

    let (seed, otp_secret_bytes, birthday_height) = load_keys(&data_dir)?;

    println!("ZVS - Zcash Verification Service");
    println!("=================================");
    println!("Lightwalletd: {}", url);
    println!("Birthday height: {}", birthday_height);
    println!("Mode: Mempool streaming (real-time)");
    println!();

    // Single gRPC connection — cheap to clone for each task
    info!("Connecting to lightwalletd at {}", url);
    let mut client = CompactTxStreamerClient::connect(url).await?;

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
