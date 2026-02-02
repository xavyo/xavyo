//! AES-GCM encryption/decryption for SIEM destination auth_config.
//!
//! Follows the existing pattern from xavyo-connector credential encryption.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::RngCore;
use thiserror::Error;

/// Nonce size for AES-GCM (96 bits / 12 bytes).
const NONCE_SIZE: usize = 12;

/// Errors from crypto operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid key length: expected 32 bytes, got {0}")]
    InvalidKeyLength(usize),

    #[error("Invalid encrypted data format")]
    InvalidFormat,

    #[error("Base64 decode error: {0}")]
    Base64Error(String),
}

/// Encrypt a plaintext string using AES-256-GCM.
///
/// Returns base64-encoded ciphertext with prepended nonce.
/// Format: base64(nonce || ciphertext)
pub fn encrypt_auth_config(plaintext: &str, key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(key.len()));
    }

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    // SECURITY: Use OsRng (CSPRNG) for cryptographic nonce generation
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt AES-256-GCM encrypted data back to plaintext.
///
/// Input: raw bytes with prepended nonce (nonce || ciphertext).
pub fn decrypt_auth_config(encrypted: &[u8], key: &[u8]) -> Result<String, CryptoError> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidKeyLength(key.len()));
    }

    if encrypted.len() < NONCE_SIZE + 1 {
        return Err(CryptoError::InvalidFormat);
    }

    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(&encrypted[..NONCE_SIZE]);
    let ciphertext = &encrypted[NONCE_SIZE..];

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    String::from_utf8(plaintext).map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

/// Encrypt plaintext to a base64-encoded string for DB storage.
pub fn encrypt_to_base64(plaintext: &str, key: &[u8]) -> Result<String, CryptoError> {
    let encrypted = encrypt_auth_config(plaintext, key)?;
    Ok(BASE64.encode(&encrypted))
}

/// Decrypt a base64-encoded string from DB storage.
pub fn decrypt_from_base64(encoded: &str, key: &[u8]) -> Result<String, CryptoError> {
    let encrypted = BASE64
        .decode(encoded)
        .map_err(|e| CryptoError::Base64Error(e.to_string()))?;
    decrypt_auth_config(&encrypted, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = r#"{"hec_token": "12345678-abcd-1234-abcd-1234567890ab"}"#;

        let encrypted = encrypt_auth_config(plaintext, &key).expect("encryption failed");
        let decrypted = decrypt_auth_config(&encrypted, &key).expect("decryption failed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_base64_roundtrip() {
        let key = test_key();
        let plaintext = r#"{"authorization": "Bearer my-secret-token"}"#;

        let encoded = encrypt_to_base64(plaintext, &key).expect("encryption failed");
        let decrypted = decrypt_from_base64(&encoded, &key).expect("decryption failed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_invalid_key_length() {
        let short_key = [0u8; 16];
        let result = encrypt_auth_config("test", &short_key);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CryptoError::InvalidKeyLength(16)
        ));
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];

        let encrypted = encrypt_auth_config("secret", &key1).expect("encryption failed");
        let result = decrypt_auth_config(&encrypted, &key2);

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_invalid_format() {
        let key = test_key();
        let result = decrypt_auth_config(&[0u8; 5], &key);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidFormat));
    }

    #[test]
    fn test_different_encryptions_produce_different_ciphertext() {
        let key = test_key();
        let plaintext = "same-input";

        let enc1 = encrypt_auth_config(plaintext, &key).expect("encryption failed");
        let enc2 = encrypt_auth_config(plaintext, &key).expect("encryption failed");

        // Due to random nonce, ciphertexts should differ
        assert_ne!(enc1, enc2);

        // But both decrypt to the same plaintext
        let dec1 = decrypt_auth_config(&enc1, &key).expect("decryption failed");
        let dec2 = decrypt_auth_config(&enc2, &key).expect("decryption failed");
        assert_eq!(dec1, plaintext);
        assert_eq!(dec2, plaintext);
    }

    #[test]
    fn test_empty_plaintext() {
        let key = test_key();
        let encrypted = encrypt_auth_config("", &key).expect("encryption failed");
        let decrypted = decrypt_auth_config(&encrypted, &key).expect("decryption failed");
        assert_eq!(decrypted, "");
    }

    #[test]
    fn test_unicode_plaintext() {
        let key = test_key();
        let plaintext = r#"{"token": "日本語テスト", "emoji": "🔐"}"#;
        let encrypted = encrypt_auth_config(plaintext, &key).expect("encryption failed");
        let decrypted = decrypt_auth_config(&encrypted, &key).expect("decryption failed");
        assert_eq!(decrypted, plaintext);
    }
}
