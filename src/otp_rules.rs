//! OTP generation and transaction proposal creation for ZVS responses.

use std::str::FromStr;

use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::info;

use zcash_address::ZcashAddress;
use zcash_client_backend::zip321::{Payment, TransactionRequest};
use zcash_protocol::memo::{Memo, MemoBytes};

use zcash_protocol::value::Zatoshis;

/// Amount sent back with OTP response.
pub const RESPONSE_AMOUNT: Zatoshis = Zatoshis::const_from_u64(10_000);

type HmacSha256 = Hmac<Sha256>;

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

/// Parameters for creating an OTP response transaction.
#[derive(Debug, Clone)]
pub struct OtpResponseParams {
    pub recipient_address: String,
    pub otp_code: String,
    pub request_txid_hex: String,
}

/// Create a ZIP-321 transaction request for the OTP response.
pub fn create_otp_transaction_request(params: &OtpResponseParams) -> Result<TransactionRequest> {
    info!("=== OTP RESPONSE ===");
    info!("To: {}", params.recipient_address);
    info!("OTP: {}", params.otp_code);
    info!("Request txid: {}", params.request_txid_hex);
    info!("====================");

    let recipient: ZcashAddress = params.recipient_address.parse()
        .map_err(|e| anyhow!("Invalid recipient address: {e}"))?;

    let memo = MemoBytes::from(
        Memo::from_str(&params.otp_code)
            .map_err(|e| anyhow!("Invalid memo: {e}"))?
    );

    let amount = RESPONSE_AMOUNT;

    let payment = Payment::new(
        recipient,
        amount,
        Some(memo),
        None, // label
        None, // message
        vec![], // other_params
    ).ok_or_else(|| anyhow!("Failed to create payment"))?;

    TransactionRequest::new(vec![payment])
        .map_err(|e| anyhow!("Failed to create transaction request: {e}"))
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
}
