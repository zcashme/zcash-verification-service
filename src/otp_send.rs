//! Shared OTP send logic and persistent processed store.
//!
//! Both mempool and sync call `send_otp_response()` directly inline.
//! ProcessedStore prevents duplicate OTPs across restarts.

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Arc;

use tonic::transport::Channel;
use tracing::{error, info};

use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, RawTransaction,
};
use zcash_primitives::transaction::TxId;

use crate::memo_rules::VerificationRequest;
use crate::otp_rules;
use crate::wallet::Wallet;

// =============================================================================
// Processed Store (persistent across restarts)
// =============================================================================

/// Tracks which verification request txids have been successfully processed.
/// Persists to disk so we don't re-send OTPs after restart.
pub struct ProcessedStore {
    path: PathBuf,
    txids: HashSet<TxId>,
}

impl ProcessedStore {
    /// Load from file. Creates empty store if file doesn't exist.
    pub fn load(path: PathBuf) -> Self {
        let mut txids = HashSet::new();

        if path.exists() {
            if let Ok(file) = fs::File::open(&path) {
                let reader = BufReader::new(file);
                for line in reader.lines() {
                    if let Ok(hex_str) = line {
                        let hex_str = hex_str.trim();
                        if hex_str.is_empty() {
                            continue;
                        }
                        if let Ok(bytes) = hex::decode(hex_str) {
                            if bytes.len() == 32 {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&bytes);
                                txids.insert(TxId::from_bytes(arr));
                            }
                        }
                    }
                }
                info!(
                    "Loaded {} processed OTP txids from {}",
                    txids.len(),
                    path.display()
                );
            }
        }

        Self { path, txids }
    }

    /// Mark a txid as processed and persist to disk.
    pub fn mark_processed(&mut self, txid: TxId) {
        if self.txids.insert(txid) {
            // Append to file
            if let Ok(mut file) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
            {
                let _ = writeln!(file, "{}", hex::encode(txid.as_ref()));
            }
        }
    }

    /// Check if a txid has already been processed.
    pub fn is_processed(&self, txid: &TxId) -> bool {
        self.txids.contains(txid)
    }
}

// =============================================================================
// Shared OTP Send
// =============================================================================

/// Generate OTP, create transaction, broadcast, and mark processed.
///
/// Called by both mempool and sync paths. Callers handle their own locking.
pub async fn send_otp_response(
    request: &VerificationRequest,
    otp_secret: &[u8],
    wallet: &mut Wallet,
    client: &mut CompactTxStreamerClient<Channel>,
    processed: &Arc<std::sync::Mutex<ProcessedStore>>,
) {
    let txid_hex = hex::encode(request.request_txid.as_ref());

    // Log the verification request block
    info!("=== VERIFICATION REQUEST ===");
    info!("Session: {}", request.session_id);
    info!("Payment: {} zats", u64::from(request.value));
    info!("Request tx: {}", txid_hex);

    // Generate OTP
    let otp = otp_rules::generate_otp(otp_secret, &request.session_id);
    info!("Generated OTP: {}", otp);
    info!("Reply to: {}", request.user_address);
    info!("============================");

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

    // Create transaction
    let raw_tx_bytes = match wallet.create_transaction(tx_request) {
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
    };

    // Broadcast
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

    // Mark processed regardless — tx was created, retrying would double-spend
    processed.lock().unwrap().mark_processed(request.request_txid);
}
