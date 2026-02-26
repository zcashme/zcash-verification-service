//! Mempool monitoring — the hot path.
//!
//! Streams mempool transactions, decrypts memos, validates verification
//! requests, deduplicates, creates OTP response transactions, and broadcasts.
//! The wallet lock is only held briefly for `create_transaction`.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tonic::transport::Channel;
use tracing::{debug, error, info, warn};

use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, Empty, RawTransaction,
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{BlockHeight, BranchId, MainNetwork};

use crate::memo_rules::{self, VerificationRequest};
use crate::otp_rules;
use crate::wallet::{self, Wallet};

// =============================================================================
// Deduplication
// =============================================================================

/// Tracks already-processed transaction IDs across stream reconnects.
struct ProcessedTxids(HashSet<TxId>);

impl ProcessedTxids {
    fn new() -> Self {
        Self(HashSet::new())
    }

    /// Returns `true` if this txid has not been seen before (and records it).
    fn is_new(&mut self, txid: TxId) -> bool {
        self.0.insert(txid)
    }
}

// =============================================================================
// Mempool Loop
// =============================================================================

/// Run the mempool monitoring loop. Never returns under normal operation.
pub async fn run_mempool_loop(
    mut client: CompactTxStreamerClient<Channel>,
    wallet: Arc<tokio::sync::Mutex<Wallet>>,
    ufvk: UnifiedFullViewingKey,
    otp_secret: Vec<u8>,
) -> ! {
    let mut processed = ProcessedTxids::new();

    loop {
        // Open mempool stream on existing channel (no full reconnect)
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

        loop {
            match stream.message().await {
                Ok(Some(raw_tx)) => {
                    process_mempool_tx(
                        &raw_tx.data,
                        raw_tx.height as u32,
                        &ufvk,
                        &otp_secret,
                        &mut processed,
                        &wallet,
                        &mut client,
                    )
                    .await;
                }
                Ok(None) => {
                    // Stream closed (new block mined)
                    info!("Mempool stream closed (new block)");
                    break;
                }
                Err(e) => {
                    error!("Mempool stream error: {}", e);
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    break;
                }
            }
        }

        // Brief delay before reopening stream
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Process a single mempool transaction.
///
/// All steps before `create_transaction` run without the wallet lock:
/// parsing, decryption, validation, dedup, OTP generation.
async fn process_mempool_tx(
    tx_data: &[u8],
    height: u32,
    ufvk: &UnifiedFullViewingKey,
    otp_secret: &[u8],
    processed: &mut ProcessedTxids,
    wallet: &Arc<tokio::sync::Mutex<Wallet>>,
    client: &mut CompactTxStreamerClient<Channel>,
) {
    // Parse transaction — no lock needed
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

    // Decrypt memo using UFVK — no lock needed
    let decrypted = match wallet::decrypt_memo_with_ufvk(ufvk, &tx, height) {
        Some(d) => d,
        None => return, // Not for us
    };

    // Check dedup — no lock needed
    if !processed.is_new(decrypted.txid) {
        info!(
            "Skipping duplicate tx: {}",
            hex::encode(decrypted.txid.as_ref())
        );
        return;
    }

    // Create verification request (validates memo format and payment) — no lock needed
    let request =
        match VerificationRequest::from_memo(&decrypted.memo, decrypted.txid, decrypted.value) {
            Some(r) => r,
            None => {
                let memo_text = memo_rules::extract_memo_text(&decrypted.memo);
                let txid_hex = hex::encode(decrypted.txid.as_ref());

                if let Some(data) = memo_rules::validate_memo(&memo_text) {
                    // Valid ZVS memo but payment too low
                    warn!(
                        "Payment too low: {} zats < {} minimum (tx={}, reply_to={})",
                        u64::from(decrypted.value),
                        u64::from(memo_rules::MIN_PAYMENT),
                        txid_hex,
                        data.user_address
                    );
                } else {
                    // Incoming transaction that isn't a verification request
                    info!(
                        "Incoming transaction: {} zats, memo=\"{}\" (tx={})",
                        u64::from(decrypted.value),
                        memo_text,
                        txid_hex
                    );
                }
                return;
            }
        };

    // Generate OTP — no lock needed
    let txid_hex = hex::encode(request.request_txid.as_ref());
    let otp = otp_rules::generate_otp(otp_secret, &request.session_id);

    info!("=== VERIFICATION REQUEST ===");
    info!("Session: {}", request.session_id);
    info!("Payment: {} zats", u64::from(request.value));
    info!("Request tx: {}", txid_hex);
    info!("Generated OTP: {}", otp);
    info!("Reply to: {}", request.user_address);
    info!("============================");

    // Build transaction request — no lock needed
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

    // Create transaction — lock wallet briefly for proving + signing
    let raw_tx_bytes = {
        let mut w = wallet.lock().await;
        match w.create_transaction(tx_request) {
            Ok((response_txid, bytes)) => {
                info!(
                    "Transaction created: {} (reply to {})",
                    hex::encode(response_txid.as_ref()),
                    txid_hex
                );
                bytes
            }
            Err(e) => {
                error!("Failed to create OTP response transaction: {}", e);
                return;
            }
        }
    }; // lock released

    // Broadcast — no lock needed
    match client
        .send_transaction(RawTransaction {
            data: raw_tx_bytes,
            height: 0,
        })
        .await
    {
        Ok(response) => {
            let send_response = response.into_inner();
            if send_response.error_code != 0 {
                error!(
                    "Broadcast rejected: {} (reply to {})",
                    send_response.error_message, txid_hex
                );
            } else {
                info!("OTP response broadcast (reply to {})", txid_hex);
            }
        }
        Err(e) => {
            error!("Broadcast failed: {} (reply to {})", e, txid_hex);
        }
    }
}
