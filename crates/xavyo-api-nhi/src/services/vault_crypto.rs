//! AES-256-GCM encryption for vault secrets.
//!
//! Key hierarchy: Master Key (from env/KMS) → per-secret encryption.
//! For v1: single master key from `VAULT_MASTER_KEY` env var (32 bytes, base64).

use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes256Gcm, KeyInit,
};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Errors from vault crypto operations.
#[derive(Debug, Error)]
pub enum VaultCryptoError {
    #[error("VAULT_MASTER_KEY environment variable not set")]
    MissingKey,
    #[error("VAULT_MASTER_KEY must be exactly 32 bytes (base64-encoded)")]
    InvalidKeyLength,
    #[error("base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("unknown key_id: {0}")]
    UnknownKeyId(String),
}

/// AES-256-GCM encryption service for vault secrets.
///
/// Key material is zeroized on drop to prevent leaking secrets in freed memory.
/// Clone is intentionally NOT derived — there should be exactly one copy of the key.
pub struct VaultCrypto {
    key: ZeroizeKey,
    key_id: String,
}

/// Wrapper that ensures the key bytes are scrubbed from memory on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct ZeroizeKey([u8; 32]);

// Manual Clone for VaultCrypto — needed for NhiState but the key is still zeroized on drop.
impl Clone for VaultCrypto {
    fn clone(&self) -> Self {
        Self {
            key: ZeroizeKey(self.key.0),
            key_id: self.key_id.clone(),
        }
    }
}

impl VaultCrypto {
    /// Create from the `VAULT_MASTER_KEY` environment variable.
    /// The key must be 32 bytes, base64-encoded.
    pub fn from_env() -> Result<Self, VaultCryptoError> {
        let mut key_b64 =
            std::env::var("VAULT_MASTER_KEY").map_err(|_| VaultCryptoError::MissingKey)?;
        let result = Self::from_base64(&key_b64);
        // Scrub the env var copy from the stack
        key_b64.zeroize();
        result
    }

    /// Create from a base64-encoded key string.
    pub fn from_base64(key_b64: &str) -> Result<Self, VaultCryptoError> {
        use base64::Engine;
        let mut key_bytes = base64::engine::general_purpose::STANDARD.decode(key_b64)?;
        if key_bytes.len() != 32 {
            key_bytes.zeroize();
            return Err(VaultCryptoError::InvalidKeyLength);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        key_bytes.zeroize();
        Ok(Self {
            key: ZeroizeKey(key),
            key_id: "v1".to_string(),
        })
    }

    /// Returns the current key ID (for storage alongside ciphertext).
    pub fn current_key_id(&self) -> &str {
        &self.key_id
    }

    /// Encrypt plaintext, returning (ciphertext, nonce, key_id).
    #[allow(deprecated)] // aes-gcm 0.10 uses generic-array 0.x internally
    pub fn encrypt(
        &self,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>, String), VaultCryptoError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key.0)
            .map_err(|_| VaultCryptoError::InvalidKeyLength)?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| VaultCryptoError::EncryptionFailed)?;
        Ok((ciphertext, nonce.to_vec(), self.key_id.clone()))
    }

    /// Decrypt ciphertext using the stored nonce and key_id.
    ///
    /// Validates that the `key_id` matches the current key. If key rotation
    /// is implemented in the future, this is where old keys would be looked up.
    #[allow(deprecated)] // aes-gcm 0.10 uses generic-array 0.x internally
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &[u8],
        key_id: &str,
    ) -> Result<Vec<u8>, VaultCryptoError> {
        if key_id != self.key_id {
            return Err(VaultCryptoError::UnknownKeyId(key_id.to_string()));
        }
        let cipher = Aes256Gcm::new_from_slice(&self.key.0)
            .map_err(|_| VaultCryptoError::InvalidKeyLength)?;
        let nonce = aes_gcm::Nonce::from_slice(nonce);
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| VaultCryptoError::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn test_crypto() -> VaultCrypto {
        let key = [42u8; 32];
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(key);
        VaultCrypto::from_base64(&key_b64).unwrap()
    }

    #[test]
    fn test_roundtrip() {
        let crypto = test_crypto();
        let plaintext = b"super-secret-api-key-12345";

        let (ciphertext, nonce, key_id) = crypto.encrypt(plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);
        assert_eq!(nonce.len(), 12); // AES-GCM uses 96-bit nonce
        assert_eq!(key_id, "v1");

        let decrypted = crypto.decrypt(&ciphertext, &nonce, &key_id).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_nonces() {
        let crypto = test_crypto();
        let plaintext = b"same-plaintext";

        let (ct1, n1, _) = crypto.encrypt(plaintext).unwrap();
        let (ct2, n2, _) = crypto.encrypt(plaintext).unwrap();

        assert_ne!(n1, n2);
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_wrong_nonce_fails() {
        let crypto = test_crypto();
        let plaintext = b"test-data";
        let (ciphertext, _nonce, key_id) = crypto.encrypt(plaintext).unwrap();

        let wrong_nonce = vec![0u8; 12];
        assert!(crypto.decrypt(&ciphertext, &wrong_nonce, &key_id).is_err());
    }

    #[test]
    fn test_invalid_key_length() {
        let short_key = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
        assert!(VaultCrypto::from_base64(&short_key).is_err());
    }

    #[test]
    fn test_wrong_key_id_rejected() {
        let crypto = test_crypto();
        let plaintext = b"test-data";
        let (ciphertext, nonce, _key_id) = crypto.encrypt(plaintext).unwrap();

        let err = crypto.decrypt(&ciphertext, &nonce, "v2").unwrap_err();
        assert!(matches!(err, VaultCryptoError::UnknownKeyId(_)));
    }
}
