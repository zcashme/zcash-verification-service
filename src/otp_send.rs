//! Shared OTP send logic.
//!
//! Both mempool and sync call `send_otp_response()` directly inline.
//! `RespondedSet` prevents duplicate OTPs within a single run.

use std::collections::HashSet;
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

/// In-memory set of request txids we've already responded to.
pub type RespondedSet = Arc<std::sync::Mutex<HashSet<TxId>>>;

// =============================================================================
// Shared OTP Send
// =============================================================================

/// Generate OTP, create transaction, broadcast, and mark responded.
///
/// Called by both mempool and sync paths. Callers handle their own locking.
pub async fn send_otp_response(
    request: &VerificationRequest,
    otp_secret: &[u8],
    wallet: &mut Wallet,
    client: &mut CompactTxStreamerClient<Channel>,
    responded: &RespondedSet,
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

    // Mark responded regardless — tx was created, retrying would double-spend
    responded.lock().unwrap().insert(request.request_txid);
}
