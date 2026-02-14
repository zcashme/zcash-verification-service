//! ZVS Verification Logic
//!
//! Pure functions for verification request handling.
//! The wallet is owned by main.rs, not by this module.

use tracing::{error, info, warn};

use crate::memo_rules::{is_valid_payment, MIN_PAYMENT};
use crate::otp_rules::{create_otp_transaction_request, generate_otp, OtpResponseParams};
use crate::wallet::{ReceivedMemo, Wallet};

/// A pending verification request with its generated OTP.
#[derive(Debug, Clone)]
pub struct PendingRequest {
    pub session_id: String,
    pub otp: String,
    pub txid_hex: String,
}

/// Generate pending requests from memos.
pub fn get_pending_requests(memos: &[ReceivedMemo], otp_secret: &[u8]) -> Vec<PendingRequest> {
    memos
        .iter()
        .filter_map(|memo| {
            memo.verification.as_ref().map(|v| PendingRequest {
                session_id: v.session_id.clone(),
                otp: generate_otp(otp_secret, &v.session_id),
                txid_hex: memo.txid_hex.clone(),
            })
        })
        .collect()
}

/// Handle a received memo - generate OTP and send response if valid.
///
/// Returns `true` if an OTP was sent, `false` otherwise.
pub async fn handle_memo(
    wallet: &mut Wallet,
    memo: &ReceivedMemo,
    otp_secret: &[u8],
) -> bool {
    let Some(ref verification) = memo.verification else {
        // Not a verification request - just log if it has content
        if !memo.memo.is_empty() {
            info!(
                "Memo received (not a verification request): \"{}\" (value={} zats, tx={})",
                memo.memo.chars().take(50).collect::<String>(),
                u64::from(memo.value),
                memo.txid_hex
            );
        }
        return false;
    };

    if !is_valid_payment(memo.value) {
        warn!(
            "Ignoring underpaid request: {} < {} zats minimum (tx={})",
            u64::from(memo.value),
            u64::from(MIN_PAYMENT),
            memo.txid_hex
        );
        return false;
    }

    info!(
        "VERIFICATION REQUEST: session={}, reply_to={}, value={} zats, tx={}",
        verification.session_id,
        verification.user_address,
        u64::from(memo.value),
        memo.txid_hex
    );

    let otp = generate_otp(otp_secret, &verification.session_id);
    info!("Generated OTP: {} for session: {}", otp, verification.session_id);

    let params = OtpResponseParams {
        recipient_address: verification.user_address.clone(),
        otp_code: otp,
        request_txid_hex: memo.txid_hex.clone(),
    };

    let request = match create_otp_transaction_request(&params) {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to create OTP transaction request: {}", e);
            return false;
        }
    };

    match wallet.send_transaction(request).await {
        Ok(response_txid) => {
            info!(
                "OTP sent successfully! Response tx: {}",
                hex::encode(response_txid.as_ref())
            );
            true
        }
        Err(e) => {
            error!("Failed to send OTP: {}", e);
            false
        }
    }
}
