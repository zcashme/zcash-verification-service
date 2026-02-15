//! Memo validation for ZVS verification requests.
//!
//! Memo format: `zvs/session_id,u-address`
//! - session_id: 16 digits (entropy for unique OTPs)
//! - u-address: valid Zcash unified address for OTP response

use zcash_address::ZcashAddress;
use zcash_protocol::{
    memo::{Memo, MemoBytes},
    value::Zatoshis,
};

/// Minimum payment required for a verification request.
pub const MIN_PAYMENT: Zatoshis = Zatoshis::const_from_u64(2_000);

/// Amount sent back with OTP response.
pub const RESPONSE_AMOUNT: Zatoshis = Zatoshis::const_from_u64(1_000);

/// Prefix identifying a ZVS verification request.
const ZVS_PREFIX: &str = "zvs/";

/// Required session_id length (digits).
const SESSION_ID_LEN: usize = 16;

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
///
/// Expected format: `zvs/session_id,u-address`
/// - session_id: exactly 16 digits
/// - u-address: valid Zcash unified address
///
/// Returns `Some(VerificationData)` if valid, `None` otherwise.
pub fn validate_memo(memo: &str) -> Option<VerificationData> {
    // Must start with "zvs/"
    let rest = memo.trim().strip_prefix(ZVS_PREFIX)?;

    // Split into session_id and u-address
    let (session_id, user_address) = rest.split_once(',')?;

    // Validate session_id: exactly 16 digits
    if session_id.len() != SESSION_ID_LEN {
        return None;
    }
    if !session_id.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    // Validate u-address is a real Zcash address
    if ZcashAddress::try_from_encoded(user_address).is_err() {
        return None;
    }

    Some(VerificationData {
        session_id: session_id.to_string(),
        user_address: user_address.to_string(),
    })
}

/// Extract UTF-8 text from MemoBytes.
///
/// Per ZIP-302:
/// - Empty memos return empty string
/// - Text memos are extracted as UTF-8
pub fn extract_memo_text(memo_bytes: &MemoBytes) -> String {
    match Memo::try_from(memo_bytes.clone()) {
        Ok(Memo::Text(text)) => text.to_string(),
        Ok(Memo::Empty) => String::new(),
        Ok(Memo::Future(_)) => String::new(),
        Ok(Memo::Arbitrary(_)) => String::new(),
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Valid mainnet unified address for testing
    const TEST_ADDRESS: &str = "u1tdkyje8l5grq8h9ucnpsnkj4m2etmmwzmkyswfe84p03j64k0nuxclygulsrfdxhjc6h4xsk9kmd9g6zzmv4yften2x8ju873jrmglelcsmev63l3vcph3aqrl323m5unuxqlvxmyfcuh3ptvzpgucdhhtvgs66jw0jrdllvm5xegn0e";

    #[test]
    fn test_valid_memo() {
        let memo = format!("zvs/1234567890123456,{}", TEST_ADDRESS);
        let result = validate_memo(&memo);
        assert!(result.is_some());
        let data = result.unwrap();
        assert_eq!(data.session_id, "1234567890123456");
        assert_eq!(data.user_address, TEST_ADDRESS);
    }

    #[test]
    fn test_valid_memo_with_whitespace() {
        let memo = format!("  zvs/1234567890123456,{}  ", TEST_ADDRESS);
        let result = validate_memo(&memo);
        assert!(result.is_some());
    }

    #[test]
    fn test_invalid_prefix() {
        let memo = format!("notzvs/1234567890123456,{}", TEST_ADDRESS);
        assert!(validate_memo(&memo).is_none());
    }

    #[test]
    fn test_uppercase_prefix_rejected() {
        let memo = format!("ZVS/1234567890123456,{}", TEST_ADDRESS);
        assert!(validate_memo(&memo).is_none());
    }

    #[test]
    fn test_missing_prefix() {
        let memo = format!("1234567890123456,{}", TEST_ADDRESS);
        assert!(validate_memo(&memo).is_none());
    }

    #[test]
    fn test_session_id_too_short() {
        let memo = format!("zvs/123456789012345,{}", TEST_ADDRESS); // 15 digits
        assert!(validate_memo(&memo).is_none());
    }

    #[test]
    fn test_session_id_too_long() {
        let memo = format!("zvs/12345678901234567,{}", TEST_ADDRESS); // 17 digits
        assert!(validate_memo(&memo).is_none());
    }

    #[test]
    fn test_session_id_non_digit() {
        let memo = format!("zvs/123456789012345a,{}", TEST_ADDRESS); // 'a' not digit
        assert!(validate_memo(&memo).is_none());
    }

    #[test]
    fn test_invalid_address() {
        let memo = "zvs/1234567890123456,u1notavalidaddress";
        assert!(validate_memo(memo).is_none());
    }

    #[test]
    fn test_missing_address() {
        let memo = "zvs/1234567890123456";
        assert!(validate_memo(memo).is_none());
    }

    #[test]
    fn test_empty_memo() {
        assert!(validate_memo("").is_none());
    }
}
