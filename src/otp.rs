//! HMAC-SHA256 OTP challenge/response generation.
//!
//! ZFA's OTP flow: after a session is authenticated, the worker may issue an
//! OTP challenge. The challenge is an HMAC-SHA256 of the session ID and a
//! nonce, keyed by a per-session secret. The response is sent back to the
//! user via a shielded transaction memo.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// A 6-digit OTP code, zero-padded.
pub fn generate_otp(secret: &[u8], session_id: &str, nonce: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(session_id.as_bytes());
    mac.update(nonce);
    let result = mac.finalize().into_bytes();

    // Take the last 4 bytes, mod 1_000_000, zero-pad to 6 digits.
    let val = u32::from_be_bytes([
        result[28],
        result[29],
        result[30],
        result[31],
    ]) % 1_000_000;
    format!("{val:06}")
}

/// Verify a user-supplied OTP against the expected value (constant-time).
pub fn verify_otp(expected: &str, provided: &str) -> bool {
    use subtle::ConstantTimeEq;
    expected.as_bytes().ct_eq(provided.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn otp_is_deterministic() {
        let secret = b"test-secret-key-123";
        let otp1 = generate_otp(secret, "1234567890123456", &[1, 2, 3]);
        let otp2 = generate_otp(secret, "1234567890123456", &[1, 2, 3]);
        assert_eq!(otp1, otp2);
        assert_eq!(otp1.len(), 6);
        assert!(otp1.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn different_inputs_produce_different_otp() {
        let secret = b"test-secret-key-123";
        let otp1 = generate_otp(secret, "1111111111111111", &[0]);
        let otp2 = generate_otp(secret, "2222222222222222", &[0]);
        assert_ne!(otp1, otp2);
    }

    #[test]
    fn verify_matches() {
        let secret = b"key";
        let otp = generate_otp(secret, "1234567890123456", &[42]);
        assert!(verify_otp(&otp, &otp));
        assert!(!verify_otp(&otp, "000000"));
    }
}