//! ZVS - Zcash Verification Service
//!
//! Streams mempool transactions and responds to verification requests in real-time.

use std::env;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::TxId;
use zcash_protocol::value::Zatoshis;

mod memo_rules;
mod otp_rules;
mod scan;
mod sync;
mod wallet;

use wallet::Wallet;

// =============================================================================
// Constants
// =============================================================================

/// Number of blocks between background syncs (matches confirmation policy)
const SYNC_BLOCK_INTERVAL: u32 = 1;

// =============================================================================
// Types
// =============================================================================

/// A verified request ready to be processed by the response sender.
#[derive(Debug, Clone)]
struct VerificationRequest {
    /// Session ID from the memo.
    session_id: String,
    /// User's address to send the OTP response to.
    user_address: String,
    /// Transaction ID of the request.
    request_txid: TxId,
    /// Payment value in zatoshis.
    value: Zatoshis,
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
    let seed_hex = env::var("SEED_HEX").expect("SEED_HEX required");
    let birthday_height: u32 = env::var("BIRTHDAY_HEIGHT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let data_dir = env::var("ZVS_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./zvs_data"));
    let otp_secret = env::var("OTP_SECRET").expect("OTP_SECRET required");

    let seed = hex::decode(&seed_hex)?;
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

    // Extract UFVK for mempool monitoring (doesn't need wallet ownership)
    let ufvk = wallet.get_ufvk();

    // Channel for passing verification requests from monitor to sender
    let (request_tx, request_rx) = mpsc::channel::<VerificationRequest>(32);

    println!("Starting ZVS mempool service...");
    println!("Press Ctrl+C to stop");
    println!();

    // Spawn mempool monitor task (uses UFVK only, no wallet ownership)
    let monitor_url = url.clone();
    let monitor_handle = tokio::spawn(async move {
        run_mempool_monitor(&monitor_url, &ufvk, &otp_secret_bytes, request_tx).await
    });

    // Spawn response sender task (owns wallet)
    let sender_url = url.clone();
    let sender_handle =
        tokio::spawn(async move { run_response_sender(&sender_url, wallet, request_rx).await });

    tokio::select! {
        result = monitor_handle => {
            if let Err(e) = result {
                error!("Mempool monitor task failed: {}", e);
            }
        }
        result = sender_handle => {
            if let Err(e) = result {
                error!("Response sender task failed: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            println!("\nShutting down...");
        }
    }

    Ok(())
}

// =============================================================================
// Mempool Monitor
// =============================================================================

/// Monitor mempool for verification requests.
///
/// This task only needs the UFVK for decryption - it doesn't own the wallet.
/// Valid requests are sent to the channel for the response sender to process.
async fn run_mempool_monitor(
    url: &str,
    ufvk: &UnifiedFullViewingKey,
    otp_secret: &[u8],
    request_tx: mpsc::Sender<VerificationRequest>,
) -> Result<()> {
    info!("Starting mempool monitor");

    loop {
        // Create fresh connection for each reconnect
        let mut client = match CompactTxStreamerClient::connect(url.to_string()).await {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to connect to lightwalletd: {}", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        info!("Connected to mempool stream");

        let request_tx = request_tx.clone();
        let result = scan::stream_mempool(&mut client, |tx, height| {
            // Decrypt memo using UFVK directly (no wallet borrow needed)
            if let Some(decrypted) = wallet::decrypt_memo_with_ufvk(ufvk, &tx, height) {
                let txid_hex = hex::encode(decrypted.txid.as_ref());
                let memo_text = memo_rules::extract_memo_text(&decrypted.memo);

                // Validate memo format
                if let Some(verification) = memo_rules::validate_memo(&memo_text) {
                    // Check payment amount
                    if memo_rules::is_valid_payment(decrypted.value) {
                        // Generate OTP for logging
                        let otp = otp_rules::generate_otp(otp_secret, &verification.session_id);

                        info!("=== VERIFICATION REQUEST ===");
                        info!("Session: {}", verification.session_id);
                        info!("Payment: {} zats ✓", u64::from(decrypted.value));
                        info!("Request tx: {}", txid_hex);
                        info!("Generated OTP: {}", otp);
                        info!("Reply to: {}", verification.user_address);
                        info!("============================");

                        // Send to response sender task
                        let request = VerificationRequest {
                            session_id: verification.session_id,
                            user_address: verification.user_address,
                            request_txid: decrypted.txid,
                            value: decrypted.value,
                        };

                        if let Err(e) = request_tx.try_send(request) {
                            error!("Failed to queue verification request: {}", e);
                        }
                    } else {
                        warn!(
                            "Payment too low: {} zats < {} minimum (tx={})",
                            u64::from(decrypted.value),
                            u64::from(memo_rules::MIN_PAYMENT),
                            txid_hex
                        );
                    }
                }
            }
            async { Ok(()) }
        })
        .await;

        match result {
            Ok(()) => {
                info!("Mempool stream closed, reconnecting in 500ms...");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => {
                error!("Mempool stream error: {}", e);
                warn!("Reconnecting in 30s...");
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        }
    }
}

// =============================================================================
// Response Sender
// =============================================================================

/// Send OTP responses to verification requests.
///
/// This task owns the wallet. Syncing happens when 10+ new blocks are mined,
/// not per-request, so sends are instant.
async fn run_response_sender(
    url: &str,
    mut wallet: Wallet,
    mut request_rx: mpsc::Receiver<VerificationRequest>,
) -> Result<()> {
    info!(
        "Starting response sender (sync every {} blocks)",
        SYNC_BLOCK_INTERVAL
    );

    // Create dedicated connection for sending
    let mut client = CompactTxStreamerClient::connect(url.to_string()).await?;

    // Read OTP secret from env (needed for generating OTP in response)
    let otp_secret_hex = env::var("OTP_SECRET").expect("OTP_SECRET required");
    let otp_secret = hex::decode(&otp_secret_hex)?;

    // Track last synced height
    let mut last_synced_height: u32 = wallet.get_synced_height().unwrap_or(0);

    // Check for new blocks every 30 seconds
    let mut block_check_interval = tokio::time::interval(Duration::from_secs(30));
    block_check_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            // Check chain tip and sync if 10+ new blocks
            _ = block_check_interval.tick() => {
                match get_chain_height(&mut client).await {
                    Ok(chain_height) if chain_height >= last_synced_height + SYNC_BLOCK_INTERVAL => {
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
                    Ok(_) => {} // Not enough new blocks yet
                    Err(e) => {
                        warn!("Failed to get chain height: {}", e);
                    }
                }
            }

            // Process verification requests instantly
            request = request_rx.recv() => {
                let Some(request) = request else { break };

                let txid_hex = hex::encode(request.request_txid.as_ref());
                info!(
                    "Processing verification request: {} ({} zats)",
                    txid_hex,
                    u64::from(request.value)
                );

                // Generate OTP
                let otp = otp_rules::generate_otp(&otp_secret, &request.session_id);

                // Create transaction request
                let params = otp_rules::OtpResponseParams {
                    recipient_address: request.user_address.clone(),
                    otp_code: otp.clone(),
                    request_txid_hex: txid_hex.clone(),
                };

                let tx_request = match otp_rules::create_otp_transaction_request(&params) {
                    Ok(r) => r,
                    Err(e) => {
                        error!("Failed to create transaction request: {}", e);
                        continue;
                    }
                };

                // Send the response transaction (no sync - use current state)
                match wallet.send_transaction(&mut client, tx_request).await {
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
        }
    }

    Ok(())
}

/// Get current chain height from lightwalletd
async fn get_chain_height(
    client: &mut CompactTxStreamerClient<tonic::transport::Channel>,
) -> Result<u32> {
    use zcash_client_backend::proto::service::ChainSpec;
    let response = client.get_latest_block(ChainSpec {}).await?;
    Ok(response.into_inner().height as u32)
}
