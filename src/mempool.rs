//! Mempool monitoring — real-time OTP processing.
//!
//! Streams mempool transactions, decrypts memos, validates verification
//! requests, deduplicates, and sends OTP responses directly inline.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tonic::transport::Channel;
use tracing::{debug, error, info, warn};

use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, Empty,
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::{Transaction, TxId};
use zcash_protocol::consensus::{BlockHeight, BranchId, MainNetwork};

use crate::memo_rules::{self, VerificationRequest};
use crate::otp_rules::{self, RespondedSet};
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
    responded: RespondedSet,
) -> ! {
    let mut seen = ProcessedTxids::new();

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
                        &mut seen,
                        &wallet,
                        &mut client,
                        &responded,
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
/// Parses, decrypts, validates, and sends OTP response directly if valid.
async fn process_mempool_tx(
    tx_data: &[u8],
    height: u32,
    ufvk: &UnifiedFullViewingKey,
    otp_secret: &[u8],
    seen: &mut ProcessedTxids,
    wallet: &Arc<tokio::sync::Mutex<Wallet>>,
    client: &mut CompactTxStreamerClient<Channel>,
    responded: &RespondedSet,
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

    // Check in-memory dedup (across stream reconnects)
    if !seen.is_new(decrypted.txid) {
        info!(
            "Skipping duplicate tx: {}",
            hex::encode(decrypted.txid.as_ref())
        );
        return;
    }

    // Create verification request (validates memo format and payment)
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

    // Check responded set — skip if already sent
    if responded.lock().unwrap().contains(&request.request_txid) {
        return;
    }

    // Lock wallet, send OTP response, then mark responded
    // Note: we don't hold the std::sync::Mutex across the await
    let mut w = wallet.lock().await;
    otp_rules::send_otp_response(&request, otp_secret, &mut w, client, responded).await;
}
