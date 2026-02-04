//! CSRF protection for OAuth consent forms (F082-US6).
//!
//! Implements a double-submit cookie pattern using HMAC-SHA256:
//! - Generate a CSRF token with an embedded timestamp
//! - Sign it with HMAC-SHA256 using a server-side secret
//! - Validate the token signature and check 10-minute expiry
//!
//! The token format is: `{timestamp}:{random}` with a separate HMAC signature.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// CSRF token expiry in seconds (10 minutes).
const CSRF_EXPIRY_SECONDS: i64 = 600;

/// Generate a CSRF token and its HMAC signature.
///
/// Returns `(token, signature)` where:
/// - `token` = `{unix_timestamp}:{random_hex}`
/// - `signature` = hex-encoded HMAC-SHA256 of the token
///
/// SECURITY: Uses `OsRng` directly from the operating system's CSPRNG for the random component.
#[must_use] 
pub fn generate_csrf_token(secret: &[u8]) -> (String, String) {
    use rand::rngs::OsRng;
    use rand::RngCore;

    let timestamp = chrono::Utc::now().timestamp();
    let mut random_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut random_bytes);
    let random_hex = hex::encode(random_bytes);

    let token = format!("{timestamp}:{random_hex}");
    let signature = compute_hmac(secret, &token);

    (token, signature)
}

/// Validate a CSRF token against its HMAC signature.
///
/// Checks:
/// 1. HMAC signature matches (tamper protection)
/// 2. Token is not expired (10-minute window)
///
/// Returns `true` if valid.
#[must_use] 
pub fn validate_csrf_token(token: &str, signature: &str, secret: &[u8]) -> bool {
    // Verify HMAC signature
    let expected_sig = compute_hmac(secret, token);
    if !constant_time_eq(signature.as_bytes(), expected_sig.as_bytes()) {
        return false;
    }

    // Extract timestamp and check expiry
    let parts: Vec<&str> = token.splitn(2, ':').collect();
    if parts.len() != 2 {
        return false;
    }

    let timestamp: i64 = match parts[0].parse() {
        Ok(t) => t,
        Err(_) => return false,
    };

    let now = chrono::Utc::now().timestamp();
    let age = now - timestamp;

    // Token must not be expired and must not be from the future (clock skew tolerance: 5s)
    (-5..=CSRF_EXPIRY_SECONDS).contains(&age)
}

/// Compute HMAC-SHA256 of the given data, returning hex-encoded string.
fn compute_hmac(secret: &[u8], data: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(data.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Constant-time comparison to prevent timing attacks.
///
/// SECURITY: Uses the `subtle` crate for proper constant-time comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &[u8] = b"test-csrf-secret-32-bytes-long!!";

    #[test]
    fn test_generate_csrf_token() {
        let (token, signature) = generate_csrf_token(TEST_SECRET);
        assert!(!token.is_empty());
        assert!(!signature.is_empty());
        assert!(token.contains(':'));
        // Signature is hex-encoded HMAC-SHA256 = 64 hex chars
        assert_eq!(signature.len(), 64);
    }

    #[test]
    fn test_validate_valid_token() {
        let (token, signature) = generate_csrf_token(TEST_SECRET);
        assert!(validate_csrf_token(&token, &signature, TEST_SECRET));
    }

    #[test]
    fn test_validate_wrong_secret() {
        let (token, signature) = generate_csrf_token(TEST_SECRET);
        assert!(!validate_csrf_token(
            &token,
            &signature,
            b"wrong-secret-that-is-different!!"
        ));
    }

    #[test]
    fn test_validate_tampered_token() {
        let (_, signature) = generate_csrf_token(TEST_SECRET);
        assert!(!validate_csrf_token("0:tampered", &signature, TEST_SECRET));
    }

    #[test]
    fn test_validate_expired_token() {
        // Manually create an expired token (timestamp 20 min ago)
        let old_timestamp = chrono::Utc::now().timestamp() - 1200;
        let token = format!("{old_timestamp}:deadbeef");
        let signature = compute_hmac(TEST_SECRET, &token);
        assert!(!validate_csrf_token(&token, &signature, TEST_SECRET));
    }

    #[test]
    fn test_validate_malformed_token() {
        let signature = compute_hmac(TEST_SECRET, "no-colon");
        assert!(!validate_csrf_token("no-colon", &signature, TEST_SECRET));
    }

    #[test]
    fn test_validate_non_numeric_timestamp() {
        let token = "abc:random";
        let signature = compute_hmac(TEST_SECRET, token);
        assert!(!validate_csrf_token(token, &signature, TEST_SECRET));
    }
}
