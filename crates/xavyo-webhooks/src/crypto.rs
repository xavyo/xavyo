//! Cryptographic operations for webhook secrets and payload signing.
//!
//! - AES-256-GCM encryption/decryption for subscription secrets at rest
//! - HMAC-SHA256 computation for webhook payload signatures

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::WebhookError;

/// Nonce size for AES-GCM (96 bits / 12 bytes).
const NONCE_SIZE: usize = 12;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// AES-256-GCM encryption/decryption (for secrets at rest)
// ---------------------------------------------------------------------------

/// Encrypt a plaintext secret to a base64-encoded string for DB storage.
///
/// Format: base64(nonce || ciphertext || auth_tag)
pub fn encrypt_secret(plaintext: &str, key: &[u8]) -> Result<String, WebhookError> {
    if key.len() != 32 {
        return Err(WebhookError::EncryptionFailed(format!(
            "Invalid key length: expected 32 bytes, got {}",
            key.len()
        )));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| WebhookError::EncryptionFailed(e.to_string()))?;

    // SECURITY: Use OsRng directly from the operating system's CSPRNG for nonce generation
    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| WebhookError::EncryptionFailed(e.to_string()))?;

    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(BASE64.encode(&result))
}

/// Decrypt a base64-encoded secret from DB storage back to plaintext.
pub fn decrypt_secret(encoded: &str, key: &[u8]) -> Result<String, WebhookError> {
    if key.len() != 32 {
        return Err(WebhookError::EncryptionFailed(format!(
            "Invalid key length: expected 32 bytes, got {}",
            key.len()
        )));
    }

    let encrypted = BASE64
        .decode(encoded)
        .map_err(|e| WebhookError::EncryptionFailed(format!("Base64 decode failed: {e}")))?;

    if encrypted.len() < NONCE_SIZE + 1 {
        return Err(WebhookError::EncryptionFailed(
            "Invalid encrypted data format".to_string(),
        ));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| WebhookError::EncryptionFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(&encrypted[..NONCE_SIZE]);
    let ciphertext = &encrypted[NONCE_SIZE..];

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| WebhookError::EncryptionFailed(e.to_string()))?;

    String::from_utf8(plaintext).map_err(|e| WebhookError::EncryptionFailed(e.to_string()))
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 payload signing
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA256 signature for a webhook payload.
///
/// The signature covers `{timestamp}.{body}` to prevent replay attacks.
/// Returns hex-encoded signature string.
pub fn compute_hmac_signature(secret: &str, timestamp: &str, body: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");

    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);

    hex::encode(mac.finalize().into_bytes())
}

/// Verify an HMAC-SHA256 signature using constant-time comparison.
///
/// Returns true if the expected signature matches the computed one.
pub fn verify_hmac_signature(
    expected_hex: &str,
    secret: &str,
    timestamp: &str,
    body: &[u8],
) -> bool {
    let computed = compute_hmac_signature(secret, timestamp, body);
    constant_time_eq(expected_hex.as_bytes(), computed.as_bytes())
}

/// Constant-time byte comparison to prevent timing attacks.
///
/// SECURITY: Uses the `subtle` crate for proper constant-time comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    // --- AES-GCM tests ---

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = "my-webhook-secret-key-12345";

        let encrypted = encrypt_secret(plaintext, &key).expect("encryption failed");
        let decrypted = decrypt_secret(&encrypted, &key).expect("decryption failed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_encryptions_produce_different_ciphertext() {
        let key = test_key();
        let plaintext = "same-secret";

        let enc1 = encrypt_secret(plaintext, &key).expect("encryption failed");
        let enc2 = encrypt_secret(plaintext, &key).expect("encryption failed");

        // Random nonce makes ciphertexts differ
        assert_ne!(enc1, enc2);

        // But both decrypt to the same plaintext
        assert_eq!(
            decrypt_secret(&enc1, &key).unwrap(),
            decrypt_secret(&enc2, &key).unwrap()
        );
    }

    #[test]
    fn test_invalid_key_length() {
        let short_key = [0u8; 16];
        let result = encrypt_secret("test", &short_key);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid key length"));
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];

        let encrypted = encrypt_secret("secret", &key1).expect("encryption failed");
        let result = decrypt_secret(&encrypted, &key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_invalid_base64() {
        let key = test_key();
        let result = decrypt_secret("not-valid-base64!!!", &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_too_short() {
        let key = test_key();
        let short = BASE64.encode([0u8; 5]);
        let result = decrypt_secret(&short, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext_roundtrip() {
        let key = test_key();
        let encrypted = encrypt_secret("", &key).expect("encryption failed");
        let decrypted = decrypt_secret(&encrypted, &key).expect("decryption failed");
        assert_eq!(decrypted, "");
    }

    // --- HMAC-SHA256 tests ---

    #[test]
    fn test_hmac_signature_deterministic() {
        let sig1 = compute_hmac_signature("secret", "1706400000", b"payload");
        let sig2 = compute_hmac_signature("secret", "1706400000", b"payload");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_hmac_signature_changes_with_different_secret() {
        let sig1 = compute_hmac_signature("secret1", "1706400000", b"payload");
        let sig2 = compute_hmac_signature("secret2", "1706400000", b"payload");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_hmac_signature_changes_with_different_timestamp() {
        let sig1 = compute_hmac_signature("secret", "1706400000", b"payload");
        let sig2 = compute_hmac_signature("secret", "1706400001", b"payload");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_hmac_signature_changes_with_different_body() {
        let sig1 = compute_hmac_signature("secret", "1706400000", b"payload1");
        let sig2 = compute_hmac_signature("secret", "1706400000", b"payload2");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_hmac_signature_is_hex_encoded() {
        let sig = compute_hmac_signature("secret", "1706400000", b"payload");
        // SHA256 = 32 bytes = 64 hex chars
        assert_eq!(sig.len(), 64);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_verify_hmac_signature_valid() {
        let secret = "my-webhook-secret";
        let timestamp = "1706400000";
        let body = b"test-body";

        let sig = compute_hmac_signature(secret, timestamp, body);
        assert!(verify_hmac_signature(&sig, secret, timestamp, body));
    }

    #[test]
    fn test_verify_hmac_signature_invalid() {
        assert!(!verify_hmac_signature(
            "invalid-hex",
            "secret",
            "1706400000",
            b"payload"
        ));
    }

    #[test]
    fn test_constant_time_eq_equal() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn test_constant_time_eq_different_length() {
        assert!(!constant_time_eq(b"hello", b"hi"));
    }

    #[test]
    fn test_constant_time_eq_different_content() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }
}
