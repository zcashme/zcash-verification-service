//! Strict 512-byte ZFA session memo parser.
//!
//! A ZFA authentication transaction carries a memo containing the exact session
//! ID. The parser extracts the 16-digit session ID from the memo bytes, removing
//! only trailing NUL padding (never whitespace), and rejecting anything malformed.
//!
//! ## Memo format
//!
//! The memo is the standard Zcash 512-byte memo field. The session ID is a
//! 16-digit decimal string placed at the start of the memo, padded with NUL
//! bytes to fill the 512 bytes. The parser:
//!
//! 1. Strips trailing NUL bytes (0x00) from the 512-byte memo.
//! 2. Rejects empty memos, interior NULs, and any content beyond the 16 digits.
//! 3. Validates that the remaining bytes are exactly 16 ASCII digits (0-9).

/// The length of a Zcash memo field in bytes.
pub const MEMO_LEN: usize = 512;

/// The length of a ZFA session ID (16 ASCII digits).
pub const SESSION_ID_LEN: usize = 16;

/// A parsed ZFA session memo — the 16-digit session ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMemo {
    pub session_id: String,
}

/// Parse a 512-byte memo, extracting the ZFA session ID.
///
/// Returns `None` if the memo is empty, contains interior NULs, has content
/// beyond the 16-digit session ID, or contains non-digit characters.
pub fn parse_memo(memo: &[u8]) -> Option<ParsedMemo> {
    if memo.len() != MEMO_LEN {
        return None;
    }

    // Strip trailing NUL padding only — never whitespace.
    let end = memo.iter().rposition(|&b| b != 0).map(|i| i + 1).unwrap_or(0);
    let trimmed = &memo[..end];

    // Reject empty memos.
    if trimmed.is_empty() {
        return None;
    }

    // Reject interior NULs — the session ID must be contiguous.
    if trimmed.contains(&0u8) {
        return None;
    }

    // Must be exactly 16 bytes (16 ASCII digits).
    if trimmed.len() != SESSION_ID_LEN {
        return None;
    }

    // All bytes must be ASCII digits.
    if !trimmed.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }

    let session_id = std::str::from_utf8(trimmed).ok()?.to_string();
    Some(ParsedMemo { session_id })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memo_with(s: &str) -> Vec<u8> {
        let mut m = vec![0u8; MEMO_LEN];
        let bytes = s.as_bytes();
        let len = bytes.len().min(MEMO_LEN);
        m[..len].copy_from_slice(&bytes[..len]);
        m
    }

    #[test]
    fn valid_16_digit_session_id() {
        let memo = memo_with("1234567890123456");
        let parsed = parse_memo(&memo).unwrap();
        assert_eq!(parsed.session_id, "1234567890123456");
    }

    #[test]
    fn rejects_empty_memo() {
        let memo = vec![0u8; MEMO_LEN];
        assert!(parse_memo(&memo).is_none());
    }

    #[test]
    fn rejects_too_short() {
        let memo = memo_with("123456789012345"); // 15 digits
        assert!(parse_memo(&memo).is_none());
    }

    #[test]
    fn rejects_too_long() {
        let memo = memo_with("12345678901234567"); // 17 digits
        assert!(parse_memo(&memo).is_none());
    }

    #[test]
    fn rejects_interior_nul() {
        let mut memo = memo_with("1234567890123456");
        memo[8] = 0; // interior NUL
        assert!(parse_memo(&memo).is_none());
    }

    #[test]
    fn rejects_non_digits() {
        let memo = memo_with("123456789012345A");
        assert!(parse_memo(&memo).is_none());
    }

    #[test]
    fn rejects_whitespace() {
        let memo = memo_with("123456789012345 ");
        assert!(parse_memo(&memo).is_none());
    }

    #[test]
    fn wrong_length_input_rejected() {
        assert!(parse_memo(b"too short").is_none());
    }
}