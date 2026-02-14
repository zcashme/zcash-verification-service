//! OTP generation and transaction proposal creation for ZVS responses.

use std::num::NonZeroUsize;
use std::str::FromStr;

use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::info;

use zcash_address::ZcashAddress;
use zcash_client_backend::{
    fees::{zip317::MultiOutputChangeStrategy, DustOutputPolicy, SplitPolicy, StandardFeeRule},
    zip321::{Payment, TransactionRequest},
};
use zcash_protocol::{
    memo::{Memo, MemoBytes},
    value::Zatoshis,
    ShieldedProtocol,
};

use crate::memo_rules::RESPONSE_AMOUNT_ZATS;

type HmacSha256 = Hmac<Sha256>;

/// OTP response memo format: `ZVS:otp:XXXXXX:req:TXID_PREFIX`
/// - XXXXXX: 6-digit OTP code
/// - TXID_PREFIX: First 16 chars of request txid for correlation
const TXID_PREFIX_LEN: usize = 16;

/// Generate HMAC-based OTP from session ID and secret.
pub fn generate_otp(secret: &[u8], session_id: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret)
        .expect("HMAC can take key of any size");
    mac.update(session_id.as_bytes());
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let code = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    format!("{:06}", code % 1_000_000)
}

/// Build the OTP response memo string.
///
/// Format: `ZVS:otp:XXXXXX:req:TXID_PREFIX`
pub fn build_otp_memo(otp: &str, request_txid_hex: &str) -> String {
    let txid_prefix = &request_txid_hex[..std::cmp::min(TXID_PREFIX_LEN, request_txid_hex.len())];
    format!("ZVS:otp:{}:req:{}", otp, txid_prefix)
}

/// Parameters for creating an OTP response transaction.
#[derive(Debug, Clone)]
pub struct OtpResponseParams {
    pub recipient_address: String,
    pub otp_code: String,
    pub request_txid_hex: String,
}

/// Create a ZIP-321 transaction request for the OTP response.
pub fn create_otp_transaction_request(params: &OtpResponseParams) -> Result<TransactionRequest> {
    let memo_text = build_otp_memo(&params.otp_code, &params.request_txid_hex);

    info!("=== OTP RESPONSE ===");
    info!("To: {}", params.recipient_address);
    info!("OTP: {}", params.otp_code);
    info!("Memo: {}", memo_text);
    info!("Request txid: {}", params.request_txid_hex);
    info!("====================");

    let recipient: ZcashAddress = params.recipient_address.parse()
        .map_err(|e| anyhow!("Invalid recipient address: {e}"))?;

    let memo = MemoBytes::from(
        Memo::from_str(&memo_text)
            .map_err(|e| anyhow!("Invalid memo: {e}"))?
    );

    let amount = Zatoshis::from_u64(RESPONSE_AMOUNT_ZATS)
        .map_err(|_| anyhow!("Invalid amount"))?;

    let payment = Payment::new(
        recipient.into(),
        amount,
        Some(memo),
        None, // label
        None, // message
        vec![], // other_params
    ).ok_or_else(|| anyhow!("Failed to create payment"))?;

    TransactionRequest::new(vec![payment])
        .map_err(|e| anyhow!("Failed to create transaction request: {e}"))
}

/// Create the change strategy for OTP response transactions.
///
/// Uses Sapling for change outputs (widely compatible) with ZIP-317 fees.
/// The `I` generic parameter should be the wallet database type (input source).
pub fn create_change_strategy<I>() -> MultiOutputChangeStrategy<StandardFeeRule, I> {
    zcash_client_backend::fees::zip317::MultiOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None, // no memo for change
        ShieldedProtocol::Sapling,
        DustOutputPolicy::default(),
        SplitPolicy::with_min_output_value(
            NonZeroUsize::new(1).unwrap(),
            Zatoshis::const_from_u64(5_000),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_otp_deterministic() {
        let secret = b"test_secret_key";
        let session_id = "session123";

        let otp1 = generate_otp(secret, session_id);
        let otp2 = generate_otp(secret, session_id);

        assert_eq!(otp1, otp2);
        assert_eq!(otp1.len(), 6);
        assert!(otp1.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_otp_different_sessions() {
        let secret = b"test_secret_key";

        let otp1 = generate_otp(secret, "session1");
        let otp2 = generate_otp(secret, "session2");

        assert_ne!(otp1, otp2);
    }

    #[test]
    fn test_build_otp_memo() {
        let otp = "123456";
        let txid = "abcdef1234567890abcdef1234567890";

        let memo = build_otp_memo(otp, txid);

        assert_eq!(memo, "ZVS:otp:123456:req:abcdef1234567890");
    }

    #[test]
    fn test_build_otp_memo_short_txid() {
        let otp = "654321";
        let txid = "abc123";

        let memo = build_otp_memo(otp, txid);

        assert_eq!(memo, "ZVS:otp:654321:req:abc123");
    }
}
