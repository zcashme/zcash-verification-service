//! ZVS - Zcash Verification Service

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Result};
use bip0039::{English, Mnemonic};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, ChainSpec,
};
use zcash_primitives::transaction::TxId;

mod memo_rules;
mod mempool;
mod otp_rules;
mod sync;
mod wallet;

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

/// Returns (seed, otp_secret_bytes, birthday_height).
fn load_keys(data_dir: &Path) -> Result<(Vec<u8>, Vec<u8>, u32)> {
    let path = data_dir.join("keys.toml");
    let contents = std::fs::read_to_string(&path)
        .map_err(|_| anyhow!("keys.toml not found at {}", path.display()))?;
    let keys: Keys = toml::from_str(&contents).map_err(|e| anyhow!("Invalid keys.toml: {e}"))?;

    let mnemonic: Mnemonic<English> = keys
        .mnemonic
        .trim()
        .parse()
        .map_err(|e| anyhow!("Invalid mnemonic: {e}"))?;
    let seed = mnemonic.to_seed("").to_vec();
    let otp_secret =
        hex::decode(&keys.otp_secret).map_err(|e| anyhow!("Invalid otp_secret hex: {e}"))?;

    info!("Loaded keys from {}", path.display());

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

    let ufvk = wallet.get_ufvk();

    // Initial blocking sync
    println!("=== INITIAL SYNC ===");
    println!("Syncing wallet to chain tip...");
    let initial_requests =
        sync::sync_wallet(&mut client, &mut wallet, Some(&ufvk)).await?;

    // Process any OTP requests found during initial sync
    let mut responded: HashSet<TxId> = HashSet::new();
    for request in &initial_requests {
        if responded.insert(request.request_txid) {
            otp_rules::send_otp_response(request, &otp_secret_bytes, &mut wallet, &mut client)
                .await;
        }
    }

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

    // Channel: mempool detects requests, main loop processes them
    let (send_tx, mut recv_rx) = tokio::sync::mpsc::channel(64);

    // Spawn mempool (no wallet — just UFVK decryption + channel send)
    tokio::spawn(mempool::run_mempool_loop(
        client.clone(),
        ufvk.clone(),
        send_tx,
    ));

    // Main loop: owns the wallet exclusively, no Arc<Mutex>
    let mut last_synced_height = synced_height;
    let mut interval = tokio::time::interval(Duration::from_secs(SYNC_INTERVAL_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!("\nShutting down...");
                break;
            }
            _ = interval.tick() => {
                // Check chain height
                let chain_height = match client.get_latest_block(ChainSpec {}).await {
                    Ok(resp) => resp.into_inner().height as u32,
                    Err(e) => {
                        error!("Failed to get chain height: {}", e);
                        continue;
                    }
                };

                if chain_height <= last_synced_height {
                    continue;
                }

                info!(
                    "Chain at {}, last sync at {} (+{} blocks). Syncing...",
                    chain_height, last_synced_height, chain_height - last_synced_height
                );

                match sync::sync_wallet(&mut client, &mut wallet, Some(&ufvk)).await {
                    Ok(requests) => {
                        last_synced_height = chain_height;
                        for request in &requests {
                            if responded.insert(request.request_txid) {
                                otp_rules::send_otp_response(
                                    request, &otp_secret_bytes, &mut wallet, &mut client,
                                ).await;
                            }
                        }
                        match wallet.get_balance() {
                            Ok(b) => info!(
                                "Sync @ {}. Balance: {} spendable (S={}, O={})",
                                chain_height,
                                u64::from(b.spendable),
                                u64::from(b.sapling_spendable),
                                u64::from(b.orchard_spendable)
                            ),
                            Err(_) => info!("Sync @ {}", chain_height),
                        }
                    }
                    Err(e) => error!("Sync failed: {}", e),
                }
            }
            request = recv_rx.recv() => {
                match request {
                    Some(request) => {
                        if responded.insert(request.request_txid) {
                            otp_rules::send_otp_response(
                                &request, &otp_secret_bytes, &mut wallet, &mut client,
                            ).await;
                        }
                    }
                    None => {
                        error!("Mempool channel closed");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}
