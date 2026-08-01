//! Deterministic ZFA OTP generation.
//!
//! The worker and the consumer application's server compute exactly:
//!
//! ```text
//! HMAC-SHA256(secret, session_id + address)[0..4]
//! ```
//!
//! The first four bytes are interpreted as a big-endian `u32`, reduced modulo
//! one million, and formatted as six decimal digits. The address is the exact
//! encoded return address from the memo; it is not a transaction ID and is not
//! normalized before HMAC input construction.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Generate the six-digit OTP for one authenticated payment.
pub fn generate_otp(secret: &[u8], session_id: &str, address: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(session_id.as_bytes());
    mac.update(address.as_bytes());
    let digest = mac.finalize().into_bytes();

    let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % 1_000_000;
    format!("{value:06}")
}

/// Verify a user-supplied OTP against the expected value in constant time.
pub fn verify_otp(expected: &str, provided: &str) -> bool {
    use subtle::ConstantTimeEq;
    expected.as_bytes().ct_eq(provided.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specification_test_vector() {
        let secret: Vec<u8> = (0u8..=31).collect();
        assert_eq!(
            generate_otp(&secret, "1234567890123456", "u1example-return-address"),
            "880279"
        );
    }

    #[test]
    fn address_is_a_domain_separated_input() {
        let secret = b"test-secret-key-123";
        let first = generate_otp(secret, "1234567890123456", "u1first");
        let second = generate_otp(secret, "1234567890123456", "u1second");
        assert_ne!(first, second);
        assert_eq!(first.len(), 6);
        assert!(first.bytes().all(|byte| byte.is_ascii_digit()));
    }

    #[test]
    fn verify_matches() {
        let otp = generate_otp(b"key", "1234567890123456", "u1return");
        assert!(verify_otp(&otp, &otp));
        assert!(!verify_otp(&otp, "000000"));
    }
}
