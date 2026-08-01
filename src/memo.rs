//! Strict 512-byte ZFA authentication memo parser.
//!
//! A ZFA authentication memo is UTF-8 text followed by NUL padding:
//!
//! ```text
//! DO NOT MODIFY:{zvs/1234567890123456,return-address}
//! ```
//!
//! This module deliberately validates only the wire-format boundary. The
//! worker validates the return address against its configured Zcash network
//! immediately before constructing an OTP response; keeping that operation
//! there preserves the exact encoded address for the HMAC message.

/// The length of a Zcash memo field in bytes.
pub const MEMO_LEN: usize = 512;

/// The length of a ZFA session ID (16 ASCII digits).
pub const SESSION_ID_LEN: usize = 16;

const PREFIX: &[u8] = b"DO NOT MODIFY:{zvs/";

/// A syntactically valid ZFA authentication memo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMemo {
    /// Exactly sixteen ASCII decimal digits.
    pub session_id: String,
    /// The exact encoded return address supplied by the payer.
    ///
    /// It is intentionally not normalized: this exact string is an input to
    /// the OTP HMAC and must match the consumer application's value byte for
    /// byte.
    pub return_address: String,
}

/// Parse a full Zcash memo as a ZFA authentication payload.
///
/// The parser accepts only full 512-byte memo fields, removes trailing NUL
/// padding, and rejects interior NULs, non-UTF-8 text, prefix/suffix changes,
/// non-decimal session IDs, empty return addresses, and additional separators.
pub fn parse_memo(memo: &[u8]) -> Option<ParsedMemo> {
    if memo.len() != MEMO_LEN {
        return None;
    }

    let end = memo.iter().rposition(|&byte| byte != 0).map(|i| i + 1)?;
    let payload = &memo[..end];
    if payload.contains(&0) {
        return None;
    }

    let content = payload.strip_prefix(PREFIX)?.strip_suffix(b"}")?;
    let (session_id, return_address) = match content.iter().position(|&byte| byte == b',') {
        Some(comma) => (&content[..comma], &content[comma + 1..]),
        None => return None, // return address is required
    };

    if session_id.len() != SESSION_ID_LEN || !session_id.iter().all(u8::is_ascii_digit) {
        return None;
    }

    if return_address.is_empty() || return_address.contains(&b',') {
        return None;
    }

    Some(ParsedMemo {
        session_id: std::str::from_utf8(session_id).ok()?.to_owned(),
        return_address: std::str::from_utf8(return_address).ok()?.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memo_with(text: &str) -> Vec<u8> {
        let mut memo = vec![0; MEMO_LEN];
        let bytes = text.as_bytes();
        memo[..bytes.len()].copy_from_slice(bytes);
        memo
    }

    #[test]
    fn rejects_missing_return_address() {
        let memo = memo_with("DO NOT MODIFY:{zvs/1234567890123456}");
        assert!(parse_memo(&memo).is_none());
    }

    #[test]
    fn preserves_the_exact_return_address() {
        let memo = memo_with("DO NOT MODIFY:{zvs/1234567890123456,u1example-return-address}");
        let parsed = parse_memo(&memo).expect("valid payload");
        assert_eq!(parsed.session_id, "1234567890123456");
        assert_eq!(parsed.return_address, "u1example-return-address");
    }

    #[test]
    fn rejects_any_wire_format_change() {
        for payload in [
            "1234567890123456",
            "DO NOT MODIFY:{zvs/123456789012345}",
            "DO NOT MODIFY:{zvs/12345678901234567}",
            "DO NOT MODIFY:{zvs/123456789012345a}",
            "DO NOT MODIFY:{zvs/1234567890123456,}",
            "DO NOT MODIFY:{zvs/1234567890123456,address,extra}",
            "DO NOT MODIFY:{zvs/1234567890123456} extra",
            "do not modify:{zvs/1234567890123456}",
        ] {
            assert!(parse_memo(&memo_with(payload)).is_none(), "{payload}");
        }
    }

    #[test]
    fn rejects_interior_nul_and_wrong_memo_length() {
        let mut memo = memo_with("DO NOT MODIFY:{zvs/1234567890123456,u1return}");
        memo[24] = 0;
        assert!(parse_memo(&memo).is_none());
        assert!(parse_memo(b"too short").is_none());
    }
}