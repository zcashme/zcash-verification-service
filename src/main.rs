//! ZVS - Zcash Verification Service
//!
//! Streams mempool transactions and responds to verification requests in real-time.
//!
//! # Seed Configuration
//!
//! Set `MNEMONIC` environment variable to a 24-word BIP39 mnemonic phrase.
//! Optional: `MNEMONIC_PASSPHRASE` for additional BIP39 passphrase protection.

use std::env;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Result};
use bip0039::{English, Mnemonic};
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, ChainSpec, Empty,
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, MainNetwork};

mod memo_rules;
mod otp_rules;
mod sync;
mod wallet;

use memo_rules::VerificationRequest;
use wallet::Wallet;

// =============================================================================
// Constants
// =============================================================================

/// Number of blocks between background syncs
const SYNC_BLOCK_INTERVAL: u32 = 1;

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

    // Return full 64-byte seed (compatible with zingolib and other Zcash wallets)
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

    // Connect to lightwalletd
    info!("Connecting to lightwalletd at {}", url);
    let mut client = CompactTxStreamerClient::connect(url.clone()).await?;

    // Fetch birthday for wallet initialization (only needed if wallet.db doesn't exist)
    let birthday = sync::fetch_birthday(&mut client, birthday_height).await?;

    // Create wallet and do initial sync
    let mut wallet = Wallet::new(&seed, Some(&birthday), &data_dir)?;

    match wallet.get_address() {
        Ok(address) => println!("Wallet address: {}", address),
        Err(e) => println!("Could not get address: {}", e),
    }
    println!();

    // Initial sync
    println!("=== INITIAL SYNC ===");
    println!("Syncing wallet to chain tip...");
    wallet.sync(&mut client).await?;

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
    println!("Background sync: every {} blocks", SYNC_BLOCK_INTERVAL);
    println!();

    println!("Starting ZVS service...");
    println!("Press Ctrl+C to stop");
    println!();

    // Run the service loop (wallet is borrowed, main retains ownership)
    tokio::select! {
        result = run_service_loop(&url, &mut wallet, &otp_secret_bytes) => {
            if let Err(e) = result {
                error!("Service loop failed: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            println!("\nShutting down...");
        }
    }

    Ok(())
}

// =============================================================================
// Service Loop
// =============================================================================

/// Main service loop - handles mempool events and background sync.
///
/// This is a single event-driven loop that:
/// - Streams mempool transactions and processes verification requests
/// - Periodically syncs the wallet to pick up confirmed transactions
/// - Sends OTP responses immediately when valid requests are detected
async fn run_service_loop(
    url: &str,
    wallet: &mut Wallet,
    otp_secret: &[u8],
) -> Result<()> {
    info!(
        "Starting service loop (sync every {} blocks)",
        SYNC_BLOCK_INTERVAL
    );

    let ufvk = wallet.get_ufvk();
    let mut last_synced_height = wallet.get_synced_height().unwrap_or(0);

    loop {
        // Fresh connection for each reconnect cycle
        let mut client = match CompactTxStreamerClient::connect(url.to_string()).await {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to connect to lightwalletd: {}", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        // Get mempool stream
        let stream_response = match client.get_mempool_stream(Empty {}).await {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to get mempool stream: {}", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        let mut stream = stream_response.into_inner();

        info!("Connected to mempool stream");

        // Sync check interval
        let mut sync_interval = tokio::time::interval(Duration::from_secs(30));
        sync_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        'stream: loop {
            tokio::select! {
                // Check for sync opportunity
                _ = sync_interval.tick() => {
                    if let Ok(chain_height) = get_chain_height(&mut client).await {
                        if chain_height >= last_synced_height + SYNC_BLOCK_INTERVAL {
                            info!(
                                "Chain at {}, last sync at {} (+{} blocks). Syncing...",
                                chain_height, last_synced_height, chain_height - last_synced_height
                            );
                            if let Err(e) = wallet.sync(&mut client).await {
                                error!("Background sync failed: {}", e);
                            } else {
                                last_synced_height = chain_height;
                                match wallet.get_balance() {
                                    Ok(b) => info!(
                                        "Sync complete @ {}. Balance: {} spendable (S={}, O={})",
                                        chain_height,
                                        u64::from(b.spendable),
                                        u64::from(b.sapling_spendable),
                                        u64::from(b.orchard_spendable)
                                    ),
                                    Err(_) => info!("Sync complete @ {}", chain_height),
                                }
                            }
                        }
                    }
                }

                // Handle mempool transaction
                msg = stream.message() => {
                    match msg {
                        Ok(Some(raw_tx)) => {
                            process_mempool_tx(
                                &raw_tx.data,
                                raw_tx.height as u32,
                                &ufvk,
                                otp_secret,
                                wallet,
                                &mut client,
                            ).await;
                        }
                        Ok(None) => {
                            // Stream closed (new block mined)
                            info!("Mempool stream closed (new block)");
                            break 'stream;
                        }
                        Err(e) => {
                            error!("Mempool stream error: {}", e);
                            tokio::time::sleep(Duration::from_secs(30)).await;
                            break 'stream;
                        }
                    }
                }
            }
        }

        // Brief delay before reconnect
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Process a single mempool transaction.
///
/// Parses the transaction, decrypts any memos for us, validates the
/// verification request, and sends an OTP response if valid.
async fn process_mempool_tx(
    tx_data: &[u8],
    height: u32,
    ufvk: &UnifiedFullViewingKey,
    otp_secret: &[u8],
    wallet: &mut Wallet,
    client: &mut CompactTxStreamerClient<tonic::transport::Channel>,
) {
    // Parse transaction
    let height = if height == 0 {
        BlockHeight::from_u32(2_600_000) // Mempool txs use recent height for branch ID
    } else {
        BlockHeight::from_u32(height)
    };
    let branch_id = BranchId::for_height(&MainNetwork, height);

    let tx = match Transaction::read(tx_data, branch_id) {
        Ok(t) => t,
        Err(e) => {
            warn!("Failed to parse mempool transaction: {}", e);
            return;
        }
    };

    let txid = tx.txid();
    debug!("Received mempool tx: {}", hex::encode(txid.as_ref()));

    // Decrypt memo using UFVK
    let decrypted = match wallet::decrypt_memo_with_ufvk(ufvk, &tx, height) {
        Some(d) => d,
        None => return, // Not for us
    };

    // Create verification request (validates memo format and payment)
    let request = match VerificationRequest::from_memo(&decrypted.memo, decrypted.txid, decrypted.value) {
        Some(r) => r,
        None => {
            // Check if it was a payment issue for logging
            let memo_text = memo_rules::extract_memo_text(&decrypted.memo);
            if memo_rules::validate_memo(&memo_text).is_some() {
                warn!(
                    "Payment too low: {} zats < {} minimum (tx={})",
                    u64::from(decrypted.value),
                    u64::from(memo_rules::MIN_PAYMENT),
                    hex::encode(decrypted.txid.as_ref())
                );
            }
            return;
        }
    };

    // Log the verification request
    let txid_hex = hex::encode(request.request_txid.as_ref());
    let otp = otp_rules::generate_otp(otp_secret, &request.session_id);

    info!("=== VERIFICATION REQUEST ===");
    info!("Session: {}", request.session_id);
    info!("Payment: {} zats", u64::from(request.value));
    info!("Request tx: {}", txid_hex);
    info!("Generated OTP: {}", otp);
    info!("Reply to: {}", request.user_address);
    info!("============================");

    // Send OTP response
    let params = otp_rules::OtpResponseParams {
        recipient_address: request.user_address.clone(),
        otp_code: otp,
        request_txid_hex: txid_hex.clone(),
    };

    let tx_request = match otp_rules::create_otp_transaction_request(&params) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to create transaction request: {}", e);
            return;
        }
    };

    match wallet.send_transaction(client, tx_request).await {
        Ok(response_txid) => {
            info!(
                "OTP response sent! tx={} (reply to {})",
                hex::encode(response_txid.as_ref()),
                txid_hex
            );
        }
        Err(e) => {
            error!("Failed to send OTP response: {}", e);
        }
    }
}

/// Get current chain height from lightwalletd
async fn get_chain_height(
    client: &mut CompactTxStreamerClient<tonic::transport::Channel>,
) -> Result<u32> {
    let response = client.get_latest_block(ChainSpec {}).await?;
    Ok(response.into_inner().height as u32)
}
