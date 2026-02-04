//! TOTP secret encryption using AES-256-GCM.
//!
//! Provides secure encryption and decryption of TOTP secrets at rest.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use thiserror::Error;

/// Size of the AES-256 key in bytes.
const KEY_SIZE: usize = 32;

/// Size of the GCM nonce (IV) in bytes.
const NONCE_SIZE: usize = 12;

/// Errors that can occur during TOTP encryption operations.
#[derive(Debug, Error)]
pub enum TotpEncryptionError {
    #[error("Encryption key not configured (MFA_ENCRYPTION_KEY environment variable)")]
    KeyNotConfigured,

    #[error("Invalid encryption key length: expected {KEY_SIZE} bytes, got {0}")]
    InvalidKeyLength(usize),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid IV length: expected {NONCE_SIZE} bytes, got {0}")]
    InvalidIvLength(usize),

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
}

/// Handles encryption and decryption of TOTP secrets.
///
/// Uses AES-256-GCM for authenticated encryption.
#[derive(Clone)]
pub struct TotpEncryption {
    cipher: Aes256Gcm,
}

impl TotpEncryption {
    /// Create a new instance from the `MFA_ENCRYPTION_KEY` environment variable.
    ///
    /// The key must be exactly 32 bytes (256 bits), provided as a hex-encoded string.
    pub fn from_env() -> Result<Self, TotpEncryptionError> {
        let key_hex = std::env::var("MFA_ENCRYPTION_KEY")
            .map_err(|_| TotpEncryptionError::KeyNotConfigured)?;

        Self::from_hex_key(&key_hex)
    }

    /// Create a new instance from a hex-encoded key string.
    pub fn from_hex_key(key_hex: &str) -> Result<Self, TotpEncryptionError> {
        let key_bytes = hex::decode(key_hex.trim())
            .map_err(|e| TotpEncryptionError::InvalidKeyFormat(e.to_string()))?;

        Self::from_key(&key_bytes)
    }

    /// Create a new instance from raw key bytes.
    pub fn from_key(key: &[u8]) -> Result<Self, TotpEncryptionError> {
        if key.len() != KEY_SIZE {
            return Err(TotpEncryptionError::InvalidKeyLength(key.len()));
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| TotpEncryptionError::InvalidKeyFormat(e.to_string()))?;

        Ok(Self { cipher })
    }

    /// Encrypt a TOTP secret.
    ///
    /// Returns (ciphertext, iv) tuple.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), TotpEncryptionError> {
        // Generate random IV
        let mut iv = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut iv);
        let nonce = Nonce::from_slice(&iv);

        // Encrypt
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| TotpEncryptionError::EncryptionFailed(e.to_string()))?;

        Ok((ciphertext, iv.to_vec()))
    }

    /// Decrypt a TOTP secret.
    pub fn decrypt(&self, ciphertext: &[u8], iv: &[u8]) -> Result<Vec<u8>, TotpEncryptionError> {
        if iv.len() != NONCE_SIZE {
            return Err(TotpEncryptionError::InvalidIvLength(iv.len()));
        }

        let nonce = Nonce::from_slice(iv);

        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| TotpEncryptionError::DecryptionFailed(e.to_string()))?;

        Ok(plaintext)
    }

    /// Generate a new random encryption key (for initial setup).
    #[must_use]
    pub fn generate_key() -> String {
        let mut key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        hex::encode(key)
    }
}

impl std::fmt::Debug for TotpEncryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpEncryption")
            .field("cipher", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Vec<u8> {
        // Use a fixed key for testing (32 bytes)
        vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let encryption = TotpEncryption::from_key(&test_key()).unwrap();
        let plaintext = b"JBSWY3DPEHPK3PXP"; // Example TOTP secret

        let (ciphertext, iv) = encryption.encrypt(plaintext).unwrap();
        let decrypted = encryption.decrypt(&ciphertext, &iv).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_different_ivs_produce_different_ciphertext() {
        let encryption = TotpEncryption::from_key(&test_key()).unwrap();
        let plaintext = b"JBSWY3DPEHPK3PXP";

        let (ciphertext1, iv1) = encryption.encrypt(plaintext).unwrap();
        let (ciphertext2, iv2) = encryption.encrypt(plaintext).unwrap();

        // IVs should be different (random)
        assert_ne!(iv1, iv2);
        // Ciphertexts should be different due to different IVs
        assert_ne!(ciphertext1, ciphertext2);

        // But both should decrypt to the same plaintext
        let decrypted1 = encryption.decrypt(&ciphertext1, &iv1).unwrap();
        let decrypted2 = encryption.decrypt(&ciphertext2, &iv2).unwrap();
        assert_eq!(decrypted1, decrypted2);
    }

    #[test]
    fn test_invalid_key_length() {
        let short_key = vec![0u8; 16]; // 16 bytes instead of 32
        let result = TotpEncryption::from_key(&short_key);
        assert!(matches!(
            result,
            Err(TotpEncryptionError::InvalidKeyLength(16))
        ));
    }

    #[test]
    fn test_invalid_iv_length() {
        let encryption = TotpEncryption::from_key(&test_key()).unwrap();
        let plaintext = b"JBSWY3DPEHPK3PXP";
        let (ciphertext, _) = encryption.encrypt(plaintext).unwrap();

        let invalid_iv = vec![0u8; 8]; // 8 bytes instead of 12
        let result = encryption.decrypt(&ciphertext, &invalid_iv);
        assert!(matches!(
            result,
            Err(TotpEncryptionError::InvalidIvLength(8))
        ));
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let encryption1 = TotpEncryption::from_key(&test_key()).unwrap();
        let mut wrong_key = test_key();
        wrong_key[0] = 0xFF; // Modify one byte
        let encryption2 = TotpEncryption::from_key(&wrong_key).unwrap();

        let plaintext = b"JBSWY3DPEHPK3PXP";
        let (ciphertext, iv) = encryption1.encrypt(plaintext).unwrap();

        // Decryption with wrong key should fail
        let result = encryption2.decrypt(&ciphertext, &iv);
        assert!(matches!(
            result,
            Err(TotpEncryptionError::DecryptionFailed(_))
        ));
    }

    #[test]
    fn test_from_hex_key() {
        let hex_key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let encryption = TotpEncryption::from_hex_key(hex_key).unwrap();

        let plaintext = b"test";
        let (ciphertext, iv) = encryption.encrypt(plaintext).unwrap();
        let decrypted = encryption.decrypt(&ciphertext, &iv).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_generate_key() {
        let key1 = TotpEncryption::generate_key();
        let key2 = TotpEncryption::generate_key();

        // Keys should be 64 hex characters (32 bytes)
        assert_eq!(key1.len(), 64);
        assert_eq!(key2.len(), 64);

        // Keys should be different (random)
        assert_ne!(key1, key2);

        // Keys should be valid
        assert!(TotpEncryption::from_hex_key(&key1).is_ok());
        assert!(TotpEncryption::from_hex_key(&key2).is_ok());
    }
}
