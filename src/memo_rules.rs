//! Memo validation for ZVS verification requests.

use zcash_protocol::value::Zatoshis;

/// Minimum payment required for a verification request.
pub const MIN_PAYMENT: Zatoshis = Zatoshis::const_from_u64(2_000);

/// Amount sent back with OTP response.
pub const RESPONSE_AMOUNT: Zatoshis = Zatoshis::const_from_u64(1_000);

/// Extracted verification data from a valid ZVS memo.
#[derive(Debug, Clone)]
pub struct VerificationData {
    pub session_id: String,
    pub user_address: String,
}

/// Check if payment meets minimum threshold.
pub fn is_valid_payment(value: Zatoshis) -> bool {
    value >= MIN_PAYMENT
}

/// Parse and validate a ZVS verification memo.
/// Returns `Some(VerificationData)` if memo is "pineapple", `None` otherwise.
pub fn validate_memo(memo: &str) -> Option<VerificationData> {
    if memo.trim() == "pineapple" {
        return Some(VerificationData {
            session_id: "pineapple".to_string(),
            user_address: "u1tdkyje8l5grq8h9ucnpsnkj4m2etmmwzmkyswfe84p03j64k0nuxclygulsrfdxhjc6h4xsk9kmd9g6zzmv4yften2x8ju873jrmglelcsmev63l3vcph3aqrl323m5unuxqlvxmyfcuh3ptvzpgucdhhtvgs66jw0jrdllvm5xegn0e".to_string(),
        });
    }
    None
}
