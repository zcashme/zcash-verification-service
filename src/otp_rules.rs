//! OTP generation, transaction request creation, and OTP response sending.

use std::str::FromStr;

use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tonic::transport::Channel;
use tracing::{error, info};

use zcash_address::ZcashAddress;
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, RawTransaction,
};
use zcash_client_backend::zip321::{Payment, TransactionRequest};
use zcash_protocol::memo::{Memo, MemoBytes};
use zcash_protocol::value::Zatoshis;

use crate::memo_rules::VerificationRequest;
use crate::wallet::Wallet;

/// Amount sent back with OTP response.
pub const RESPONSE_AMOUNT: Zatoshis = Zatoshis::const_from_u64(50_000);

type HmacSha256 = Hmac<Sha256>;

/// Generate HMAC-based OTP from session ID and secret.
pub fn generate_otp(secret: &[u8], session_id: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(session_id.as_bytes());
    let result = mac.finalize();
    let bytes = result.into_bytes();
    let code = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    format!("{:06}", code % 1_000_000)
}

/// Parameters for creating an OTP response transaction.
#[derive(Debug)]
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

    let recipient: ZcashAddress = params
        .recipient_address
        .parse()
        .map_err(|e| anyhow!("Invalid recipient address: {e}"))?;

    let memo = MemoBytes::from(
        Memo::from_str(&params.otp_code).map_err(|e| anyhow!("Invalid memo: {e}"))?,
    );

    let amount = RESPONSE_AMOUNT;

    let payment = Payment::new(
        recipient,
        amount,
        Some(memo),
        None,   // label
        None,   // message
        vec![], // other_params
    )
    .ok_or_else(|| anyhow!("Failed to create payment"))?;

    TransactionRequest::new(vec![payment])
        .map_err(|e| anyhow!("Failed to create transaction request: {e}"))
}

// =============================================================================
// OTP Response Sending
// =============================================================================

/// Generate OTP, create transaction, and broadcast.
///
/// Called by the main loop which handles deduplication.
pub async fn send_otp_response(
    request: &VerificationRequest,
    otp_secret: &[u8],
    wallet: &mut Wallet,
    client: &mut CompactTxStreamerClient<Channel>,
) {
    let txid_hex = hex::encode(request.request_txid.as_ref());

    // Log the verification request block
    info!("=== VERIFICATION REQUEST ===");
    info!("Session: {}", request.session_id);
    info!("Payment: {} zats", u64::from(request.value));
    info!("Request tx: {}", txid_hex);

    // Generate OTP
    let otp = generate_otp(otp_secret, &request.session_id);
    info!("Generated OTP: {}", otp);
    info!("Reply to: {}", request.user_address);
    info!("============================");

    let params = OtpResponseParams {
        recipient_address: request.user_address.clone(),
        otp_code: otp,
        request_txid_hex: txid_hex.clone(),
    };

    let tx_request = match create_otp_transaction_request(&params) {
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

}
