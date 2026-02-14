//! ZVS Verification Logic
//!
//! Handles verification requests by validating memos, generating OTPs,
//! and sending responses. The wallet is passed in for sending transactions.

use tracing::{error, info, warn};

use crate::memo_rules::{is_valid_payment, validate_memo, MIN_PAYMENT};
use crate::otp_rules::{create_otp_transaction_request, generate_otp, OtpResponseParams};
use crate::wallet::{DecryptedMemo, Wallet};

/// Handle a decrypted memo - validate, generate OTP, and send response if valid.
///
/// This is the main entry point called from main.rs for each decrypted memo.
///
/// Returns `Ok(())` on success (even if not a verification request),
/// returns `Err` only on critical failures.
pub async fn handle_memo(
    wallet: &mut Wallet,
    memo: &DecryptedMemo,
    otp_secret: &[u8],
) -> anyhow::Result<()> {
    let txid_hex = hex::encode(memo.txid.as_ref());

    // Check if this is a verification request
    let Some(verification) = validate_memo(&memo.memo_text) else {
        // Not a verification request - just log if it has content
        if !memo.memo_text.is_empty() {
            info!(
                "Memo received (not a verification request): \"{}\" (value={} zats, tx={})",
                memo.memo_text.chars().take(50).collect::<String>(),
                u64::from(memo.value),
                txid_hex
            );
        }
        return Ok(());
    };

    // Check minimum payment
    if !is_valid_payment(memo.value) {
        warn!(
            "Ignoring underpaid request: {} < {} zats minimum (tx={})",
            u64::from(memo.value),
            u64::from(MIN_PAYMENT),
            txid_hex
        );
        return Ok(());
    }

    info!(
        "VERIFICATION REQUEST: session={}, reply_to={}, value={} zats, tx={}",
        verification.session_id,
        verification.user_address,
        u64::from(memo.value),
        txid_hex
    );

    // Generate OTP
    let otp = generate_otp(otp_secret, &verification.session_id);
    info!("Generated OTP: {} for session: {}", otp, verification.session_id);

    // Build and send response
    let params = OtpResponseParams {
        recipient_address: verification.user_address.clone(),
        otp_code: otp,
        request_txid_hex: txid_hex.clone(),
    };

    let request = create_otp_transaction_request(&params)?;

    match wallet.send_transaction(request).await {
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

    Ok(())
}
