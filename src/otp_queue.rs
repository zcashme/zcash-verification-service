//! OTP Queue — producer-consumer architecture for verification requests.
//!
//! Both mempool and sync tasks enqueue verification requests here.
//! A single consumer task handles OTP generation, transaction creation,
//! and broadcasting with retry support.

use std::collections::HashMap;
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
// OTP Queue
// =============================================================================

/// Thread-safe queue for pending OTP verification requests.
pub struct OtpQueue {
    pending: std::sync::Mutex<HashMap<TxId, PendingOtp>>,
    notify: tokio::sync::Notify,
}

struct PendingOtp {
    request: VerificationRequest,
    cached_tx: Option<Vec<u8>>,
}

impl OtpQueue {
    pub fn new() -> Self {
        Self {
            pending: std::sync::Mutex::new(HashMap::new()),
            notify: tokio::sync::Notify::new(),
        }
    }

    /// Insert a verification request. Returns true if new (not duplicate).
    pub fn insert(&self, request: VerificationRequest) -> bool {
        let txid = request.request_txid;
        let mut pending = self.pending.lock().unwrap();
        if pending.contains_key(&txid) {
            return false;
        }
        pending.insert(
            txid,
            PendingOtp {
                request,
                cached_tx: None,
            },
        );
        self.notify.notify_one();
        true
    }

    /// Drain all pending items. Waits asynchronously if queue is empty.
    pub async fn take_pending(&self) -> Vec<(TxId, VerificationRequest, Option<Vec<u8>>)> {
        loop {
            // Register for notification BEFORE checking, to avoid missed wakeups
            let notified = self.notify.notified();

            {
                let mut pending = self.pending.lock().unwrap();
                if !pending.is_empty() {
                    return pending
                        .drain()
                        .map(|(txid, p)| (txid, p.request, p.cached_tx))
                        .collect();
                }
            }

            // Queue was empty — wait for notification
            notified.await;
        }
    }

    /// Re-insert a failed item with cached transaction bytes for retry.
    pub fn requeue(&self, txid: TxId, request: VerificationRequest, raw_tx: Option<Vec<u8>>) {
        let mut pending = self.pending.lock().unwrap();
        pending.insert(
            txid,
            PendingOtp {
                request,
                cached_tx: raw_tx,
            },
        );
        self.notify.notify_one();
    }

    /// Number of pending items.
    pub fn len(&self) -> usize {
        self.pending.lock().unwrap().len()
    }
}

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
// Consumer Task
// =============================================================================

/// Run the OTP consumer loop. Processes queued verification requests.
///
/// Never returns under normal operation.
pub async fn run_otp_consumer(
    queue: Arc<OtpQueue>,
    wallet: Arc<tokio::sync::Mutex<Wallet>>,
    mut client: CompactTxStreamerClient<Channel>,
    otp_secret: Vec<u8>,
    processed_store: Arc<std::sync::Mutex<ProcessedStore>>,
) -> ! {
    loop {
        let items = queue.take_pending().await;
        let mut had_failures = false;

        for (txid, request, cached_tx) in items {
            let txid_hex = hex::encode(request.request_txid.as_ref());

            // Log the verification request block
            info!("=== VERIFICATION REQUEST ===");
            info!("Session: {}", request.session_id);
            info!("Payment: {} zats", u64::from(request.value));
            info!("Request tx: {}", txid_hex);

            let raw_tx_bytes = if let Some(cached) = cached_tx {
                // Retry — reuse cached transaction bytes
                info!("Retrying broadcast for tx {}", txid_hex);
                cached
            } else {
                // First attempt — generate OTP, create tx
                let otp = otp_rules::generate_otp(&otp_secret, &request.session_id);
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
                        // Cannot retry without a tx request — requeue without cached bytes
                        queue.requeue(txid, request, None);
                        had_failures = true;
                        continue;
                    }
                };

                // Create transaction — lock wallet briefly
                let result = {
                    let mut w = wallet.lock().await;
                    w.create_transaction(tx_request)
                };

                match result {
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
                        queue.requeue(txid, request, None);
                        had_failures = true;
                        continue;
                    }
                }
            };

            // Broadcast
            match client
                .send_transaction(RawTransaction {
                    data: raw_tx_bytes.clone(),
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
                        // Don't requeue broadcast rejections — they won't succeed on retry
                        // (e.g., double-spend, invalid tx)
                    } else {
                        info!("OTP response broadcast (reply to {})", txid_hex);
                    }
                    // Mark processed regardless — tx was created, retrying would double-spend
                    processed_store.lock().unwrap().mark_processed(txid);
                }
                Err(e) => {
                    error!("Broadcast failed: {} (reply to {})", e, txid_hex);
                    // Network error — requeue with cached bytes for retry
                    queue.requeue(txid, request, Some(raw_tx_bytes));
                    had_failures = true;
                }
            }
        }

        if had_failures {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        }
    }
}
