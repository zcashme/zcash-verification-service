//! ZVS Verification Service
//!
//! Core service that monitors the blockchain for verification requests
//! and responds with HMAC-derived OTPs.

use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use tracing::{debug, error, info, warn};

use crate::memo_rules::{is_valid_payment, MIN_PAYMENT};
use crate::otp_rules::{create_otp_transaction_request, generate_otp, OtpResponseParams};
use crate::wallet::{ReceivedMemo, SyncResult, Wallet};

/// The ZVS verification service.
///
/// Wraps a Wallet with 2FA/OTP functionality - monitors for verification
/// requests and sends OTP responses.
pub struct VerificationService {
    wallet: Wallet,
    otp_secret: Vec<u8>,
}

impl VerificationService {
    /// Connect to lightwalletd and initialize the service.
    pub async fn connect(
        url: &str,
        seed: &[u8],
        birthday_height: u32,
        data_dir: &Path,
        otp_secret: Vec<u8>,
    ) -> Result<Self> {
        let wallet = Wallet::new(url, seed, birthday_height, data_dir).await?;

        if let Ok(address) = wallet.get_sapling_address() {
            info!("Sapling address: {}", address);
        }

        Ok(Self { wallet, otp_secret })
    }

    pub async fn get_latest_height(&mut self) -> Result<u32> {
        self.wallet.get_chain_height().await
    }

    pub async fn sync_incremental(&mut self) -> Result<SyncResult> {
        self.wallet.sync().await
    }

    pub fn get_balance(&self) -> Result<crate::wallet::AccountBalance> {
        self.wallet.get_balance()
    }

    pub fn get_address(&self) -> Result<String> {
        self.wallet.get_address()
    }

    pub async fn get_received_memos(&mut self) -> Result<Vec<ReceivedMemo>> {
        self.wallet.get_all_memos().await
    }

    // =========================================================================
    // Verification Logic
    // =========================================================================

    /// Generate HMAC-based OTP from session ID.
    fn generate_otp(&self, session_id: &str) -> String {
        generate_otp(&self.otp_secret, session_id)
    }

    /// Send OTP response to the user's address.
    async fn send_otp(
        &mut self,
        to_address: &str,
        otp: &str,
        request_txid_hex: &str,
    ) -> Result<zcash_primitives::transaction::TxId> {
        let params = OtpResponseParams {
            recipient_address: to_address.to_string(),
            otp_code: otp.to_string(),
            request_txid_hex: request_txid_hex.to_string(),
        };

        let request = create_otp_transaction_request(&params)?;
        self.wallet.send_transaction(request).await
    }

    /// Run the block monitoring loop.
    pub async fn run(&mut self, poll_interval: Duration) -> Result<()> {
        info!("Starting verification service with {:?} poll interval", poll_interval);

        // Initial sync
        let result = self.sync_incremental().await?;
        for memo in result.new_memos {
            self.handle_memo(memo).await;
        }

        let mut last_height = self.get_latest_height().await?;
        info!("Initial sync complete. Chain tip: {}", last_height);

        loop {
            tokio::time::sleep(poll_interval).await;

            match self.get_latest_height().await {
                Ok(current_height) => {
                    if current_height > last_height {
                        info!("New blocks detected: {} -> {}", last_height, current_height);

                        match self.sync_incremental().await {
                            Ok(result) => {
                                if result.blocks_scanned > 0 {
                                    info!(
                                        "Scanned {} blocks, {} new notes",
                                        result.blocks_scanned,
                                        result.sapling_notes_received + result.orchard_notes_received
                                    );
                                }

                                for memo in result.new_memos {
                                    self.handle_memo(memo).await;
                                }

                                last_height = current_height;
                            }
                            Err(e) => error!("Sync error: {}", e),
                        }
                    } else {
                        debug!("No new blocks (height: {})", current_height);
                    }
                }
                Err(e) => error!("Failed to get chain height: {}", e),
            }
        }
    }

    /// Handle a received memo - generate OTP and send response if valid.
    async fn handle_memo(&mut self, memo: ReceivedMemo) {
        if let Some(ref verification) = memo.verification {
            if !is_valid_payment(memo.value) {
                warn!(
                    "Ignoring underpaid request: {} < {} zats minimum (tx={})",
                    u64::from(memo.value), u64::from(MIN_PAYMENT), memo.txid_hex
                );
                return;
            }

            info!(
                "VERIFICATION REQUEST: session={}, reply_to={}, value={} zats, tx={}",
                verification.session_id, verification.user_address, u64::from(memo.value), memo.txid_hex
            );

            let otp = self.generate_otp(&verification.session_id);
            info!("Generated OTP: {} for session: {}", otp, verification.session_id);

            match self.send_otp(&verification.user_address, &otp, &memo.txid_hex).await {
                Ok(response_txid) => {
                    info!(
                        "OTP sent successfully! Response tx: {}",
                        hex::encode(response_txid.as_ref())
                    );
                }
                Err(e) => {
                    error!("Failed to send OTP: {}", e);
                }
            }
        } else if !memo.memo.is_empty() {
            info!(
                "Memo received (not a verification request): \"{}\" (value={} zats, tx={})",
                memo.memo.chars().take(50).collect::<String>(),
                u64::from(memo.value),
                memo.txid_hex
            );
        }
    }
}
