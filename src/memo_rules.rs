//! Memo validation for ZVS verification requests.
//!
//! Memo format: `(DO NOT MODIFY){zvs/session_id,u-address}`
//! - Content between first `{` and `}` is parsed
//! - session_id: 16 digits (entropy for unique OTPs)
//! - u-address: valid Zcash unified address for OTP response

use zcash_address::ZcashAddress;
use zcash_primitives::transaction::TxId;
use zcash_protocol::{
    memo::{Memo, MemoBytes},
    value::Zatoshis,
};

/// Minimum payment required for a verification request.
pub const MIN_PAYMENT: Zatoshis = Zatoshis::const_from_u64(200_000);

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

/// A verified request ready to be processed.
#[derive(Debug, Clone)]
pub struct VerificationRequest {
    pub session_id: String,
    pub user_address: String,
    pub request_txid: TxId,
    pub value: Zatoshis,
}

impl VerificationRequest {
    /// Create a verification request from memo bytes, txid, and payment value.
    ///
    /// Returns `Some(VerificationRequest)` if:
    /// - Memo is valid ZVS format: (DO NOT MODIFY){zvs/session_id,u-address}
    /// - Payment meets minimum threshold
    ///
    /// Returns `None` otherwise.
    pub fn from_memo(memo_bytes: &MemoBytes, txid: TxId, value: Zatoshis) -> Option<Self> {
        let memo_text = extract_memo_text(memo_bytes);
        let data = validate_memo(&memo_text)?;

        if !is_valid_payment(value) {
            return None;
        }

        Some(Self {
            session_id: data.session_id,
            user_address: data.user_address,
            request_txid: txid,
            value,
        })
    }
}

/// Check if payment meets minimum threshold.
pub fn is_valid_payment(value: Zatoshis) -> bool {
    value >= MIN_PAYMENT
}

/// Parse and validate a ZVS verification memo.
///
/// Expected format: `(DO NOT MODIFY){zvs/session_id,u-address}`
/// - Extracts content between first `{` and `}`
/// - session_id: exactly 16 digits
/// - u-address: valid Zcash unified address
///
/// Returns `Some(VerificationData)` if valid, `None` otherwise.
pub fn validate_memo(memo: &str) -> Option<VerificationData> {
    let trimmed = memo.trim();

    // Extract content between first { and }
    let start = trimmed.find('{')? + 1;
    let end = trimmed.find('}')?;
    if start >= end {
        return None;
    }
    let inner = &trimmed[start..end];

    // Must start with "zvs/"
    let rest = inner.strip_prefix(ZVS_PREFIX)?;

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
