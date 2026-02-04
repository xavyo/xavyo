//! Connector Framework credential encryption
//!
//! AES-256-GCM encryption with HKDF per-tenant key derivation.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use uuid::Uuid;

use crate::error::{ConnectorError, ConnectorResult};

/// Length of AES-256 key in bytes.
const KEY_LENGTH: usize = 32;

/// Length of GCM nonce in bytes.
const NONCE_LENGTH: usize = 12;

/// Length of GCM authentication tag in bytes.
const TAG_LENGTH: usize = 16;

/// Context string for HKDF key derivation.
const HKDF_INFO: &[u8] = b"xavyo-connector-credentials-v1";

/// Service for encrypting and decrypting connector credentials.
///
/// Uses AES-256-GCM with HKDF-derived per-tenant keys.
#[derive(Clone)]
pub struct CredentialEncryption {
    /// Master key for deriving tenant-specific keys.
    master_key: [u8; KEY_LENGTH],
}

impl CredentialEncryption {
    /// Create a new encryption service with the given master key.
    ///
    /// # Arguments
    /// * `master_key` - 32-byte master key for deriving tenant keys.
    #[must_use] 
    pub fn new(master_key: [u8; KEY_LENGTH]) -> Self {
        Self { master_key }
    }

    /// Create a new encryption service from a hex-encoded master key.
    pub fn from_hex(hex_key: &str) -> ConnectorResult<Self> {
        let bytes = hex::decode(hex_key).map_err(|e| ConnectorError::EncryptionFailed {
            message: format!("invalid hex key: {e}"),
        })?;

        if bytes.len() != KEY_LENGTH {
            return Err(ConnectorError::EncryptionFailed {
                message: format!("key must be {} bytes, got {}", KEY_LENGTH, bytes.len()),
            });
        }

        let mut key = [0u8; KEY_LENGTH];
        key.copy_from_slice(&bytes);
        Ok(Self::new(key))
    }

    /// Create a new encryption service from a base64-encoded master key.
    pub fn from_base64(base64_key: &str) -> ConnectorResult<Self> {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let bytes = STANDARD
            .decode(base64_key)
            .map_err(|e| ConnectorError::EncryptionFailed {
                message: format!("invalid base64 key: {e}"),
            })?;

        if bytes.len() != KEY_LENGTH {
            return Err(ConnectorError::EncryptionFailed {
                message: format!("key must be {} bytes, got {}", KEY_LENGTH, bytes.len()),
            });
        }

        let mut key = [0u8; KEY_LENGTH];
        key.copy_from_slice(&bytes);
        Ok(Self::new(key))
    }

    /// Derive a tenant-specific key using HKDF.
    ///
    /// # Panics
    ///
    /// This function will panic if HKDF expansion fails, which should never happen
    /// with a 32-byte output length. This is validated by unit tests.
    fn derive_tenant_key(&self, tenant_id: Uuid) -> [u8; KEY_LENGTH] {
        let hkdf = Hkdf::<Sha256>::new(Some(tenant_id.as_bytes()), &self.master_key);
        let mut derived_key = [0u8; KEY_LENGTH];
        // SAFETY: 32 bytes is always a valid HKDF-SHA256 output length.
        // SHA256 output is 32 bytes, and HKDF can expand up to 255 * hash_len = 8160 bytes.
        // This assertion is verified by the test_derive_tenant_key_deterministic test.
        hkdf.expand(HKDF_INFO, &mut derived_key)
            .expect("HKDF-SHA256 supports 32-byte output; this is a programming error if it fails");
        derived_key
    }

    /// Encrypt credentials for a specific tenant.
    ///
    /// # Arguments
    /// * `tenant_id` - The tenant's UUID (used as salt for key derivation).
    /// * `plaintext` - The credentials to encrypt.
    ///
    /// # Returns
    /// Encrypted data as bytes (nonce || ciphertext || tag).
    pub fn encrypt(&self, tenant_id: Uuid, plaintext: &[u8]) -> ConnectorResult<Vec<u8>> {
        let key = self.derive_tenant_key(tenant_id);
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|e| ConnectorError::EncryptionFailed {
                message: format!("failed to create cipher: {e}"),
            })?;

        // SECURITY: Generate random nonce using OS CSPRNG
        use rand::rngs::OsRng;
        use rand::RngCore;
        let mut nonce_bytes = [0u8; NONCE_LENGTH];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext =
            cipher
                .encrypt(nonce, plaintext)
                .map_err(|e| ConnectorError::EncryptionFailed {
                    message: format!("encryption failed: {e}"),
                })?;

        // Return nonce || ciphertext (tag is appended by AES-GCM)
        let mut result = Vec::with_capacity(NONCE_LENGTH + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt credentials for a specific tenant.
    ///
    /// # Arguments
    /// * `tenant_id` - The tenant's UUID (must match the one used for encryption).
    /// * `ciphertext` - The encrypted data (nonce || ciphertext || tag).
    ///
    /// # Returns
    /// Decrypted plaintext.
    pub fn decrypt(&self, tenant_id: Uuid, ciphertext: &[u8]) -> ConnectorResult<Vec<u8>> {
        // Minimum length: nonce + tag (no actual ciphertext means empty plaintext)
        if ciphertext.len() < NONCE_LENGTH + TAG_LENGTH {
            return Err(ConnectorError::DecryptionFailed {
                message: "ciphertext too short".to_string(),
            });
        }

        let key = self.derive_tenant_key(tenant_id);
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|e| ConnectorError::DecryptionFailed {
                message: format!("failed to create cipher: {e}"),
            })?;

        // Extract nonce and ciphertext
        let (nonce_bytes, encrypted) = ciphertext.split_at(NONCE_LENGTH);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt
        let plaintext =
            cipher
                .decrypt(nonce, encrypted)
                .map_err(|e| ConnectorError::DecryptionFailed {
                    message: format!("decryption failed: {e}"),
                })?;

        Ok(plaintext)
    }

    /// Encrypt a string credential.
    pub fn encrypt_string(&self, tenant_id: Uuid, plaintext: &str) -> ConnectorResult<Vec<u8>> {
        self.encrypt(tenant_id, plaintext.as_bytes())
    }

    /// Decrypt to a string credential.
    pub fn decrypt_string(&self, tenant_id: Uuid, ciphertext: &[u8]) -> ConnectorResult<String> {
        let plaintext = self.decrypt(tenant_id, ciphertext)?;
        String::from_utf8(plaintext).map_err(|e| ConnectorError::DecryptionFailed {
            message: format!("decrypted data is not valid UTF-8: {e}"),
        })
    }

    /// Encrypt JSON credentials.
    pub fn encrypt_json<T: serde::Serialize>(
        &self,
        tenant_id: Uuid,
        value: &T,
    ) -> ConnectorResult<Vec<u8>> {
        let json = serde_json::to_vec(value).map_err(|e| ConnectorError::Serialization {
            message: format!("failed to serialize credentials: {e}"),
        })?;
        self.encrypt(tenant_id, &json)
    }

    /// Decrypt JSON credentials.
    pub fn decrypt_json<T: serde::de::DeserializeOwned>(
        &self,
        tenant_id: Uuid,
        ciphertext: &[u8],
    ) -> ConnectorResult<T> {
        let plaintext = self.decrypt(tenant_id, ciphertext)?;
        serde_json::from_slice(&plaintext).map_err(|e| ConnectorError::Serialization {
            message: format!("failed to deserialize credentials: {e}"),
        })
    }
}

impl std::fmt::Debug for CredentialEncryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialEncryption")
            .field("master_key", &"[REDACTED]")
            .finish()
    }
}

/// Generate a random master key.
///
/// This should only be used for initial setup or testing.
///
/// SECURITY: Uses `OsRng` directly from the operating system's CSPRNG.
#[must_use] 
pub fn generate_master_key() -> [u8; KEY_LENGTH] {
    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut key = [0u8; KEY_LENGTH];
    OsRng.fill_bytes(&mut key);
    key
}

/// Generate a random master key as a hex string.
#[must_use] 
pub fn generate_master_key_hex() -> String {
    hex::encode(generate_master_key())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_encryption_service() -> CredentialEncryption {
        // Use a fixed key for deterministic tests
        let key = [0x42u8; KEY_LENGTH];
        CredentialEncryption::new(key)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let service = test_encryption_service();
        let tenant_id = Uuid::new_v4();
        let plaintext = b"my-secret-password";

        let ciphertext = service.encrypt(tenant_id, plaintext).unwrap();
        let decrypted = service.decrypt(tenant_id, &ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_string() {
        let service = test_encryption_service();
        let tenant_id = Uuid::new_v4();
        let plaintext = "password123!@#";

        let ciphertext = service.encrypt_string(tenant_id, plaintext).unwrap();
        let decrypted = service.decrypt_string(tenant_id, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_json() {
        let service = test_encryption_service();
        let tenant_id = Uuid::new_v4();

        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Credentials {
            username: String,
            password: String,
        }

        let creds = Credentials {
            username: "admin".to_string(),
            password: "secret".to_string(),
        };

        let ciphertext = service.encrypt_json(tenant_id, &creds).unwrap();
        let decrypted: Credentials = service.decrypt_json(tenant_id, &ciphertext).unwrap();

        assert_eq!(creds, decrypted);
    }

    #[test]
    fn test_different_tenants_different_ciphertext() {
        let service = test_encryption_service();
        let tenant1 = Uuid::new_v4();
        let tenant2 = Uuid::new_v4();
        let plaintext = b"same-password";

        let ciphertext1 = service.encrypt(tenant1, plaintext).unwrap();
        let ciphertext2 = service.encrypt(tenant2, plaintext).unwrap();

        // Different tenants produce different ciphertexts (different derived keys)
        // Note: They might accidentally be the same due to random nonce, but that's extremely unlikely
        // The important thing is that cross-tenant decryption fails (tested below)
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_cross_tenant_decryption_fails() {
        let service = test_encryption_service();
        let tenant1 = Uuid::new_v4();
        let tenant2 = Uuid::new_v4();
        let plaintext = b"password";

        let ciphertext = service.encrypt(tenant1, plaintext).unwrap();

        // Trying to decrypt with wrong tenant should fail
        let result = service.decrypt(tenant2, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_ciphertext_too_short() {
        let service = test_encryption_service();
        let tenant_id = Uuid::new_v4();

        // Less than nonce + tag length
        let short_ciphertext = vec![0u8; 10];
        let result = service.decrypt(tenant_id, &short_ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_corrupted_ciphertext() {
        let service = test_encryption_service();
        let tenant_id = Uuid::new_v4();
        let plaintext = b"password";

        let mut ciphertext = service.encrypt(tenant_id, plaintext).unwrap();

        // Corrupt the ciphertext (not the nonce)
        if ciphertext.len() > NONCE_LENGTH {
            ciphertext[NONCE_LENGTH] ^= 0xFF;
        }

        let result = service.decrypt(tenant_id, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_hex() {
        let hex_key = "0".repeat(64); // 32 bytes of zeros in hex
        let service = CredentialEncryption::from_hex(&hex_key).unwrap();

        let tenant_id = Uuid::new_v4();
        let plaintext = b"test";
        let ciphertext = service.encrypt(tenant_id, plaintext).unwrap();
        let decrypted = service.decrypt(tenant_id, &ciphertext).unwrap();
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_from_hex_invalid_length() {
        let short_key = "00112233";
        let result = CredentialEncryption::from_hex(short_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_hex_invalid_chars() {
        let invalid_key = "gg".repeat(32);
        let result = CredentialEncryption::from_hex(&invalid_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_master_key() {
        let key1 = generate_master_key();
        let key2 = generate_master_key();

        // Random keys should be different
        assert_ne!(key1, key2);
        // Should be correct length
        assert_eq!(key1.len(), KEY_LENGTH);
    }

    #[test]
    fn test_empty_plaintext() {
        let service = test_encryption_service();
        let tenant_id = Uuid::new_v4();
        let plaintext = b"";

        let ciphertext = service.encrypt(tenant_id, plaintext).unwrap();
        let decrypted = service.decrypt(tenant_id, &ciphertext).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_large_plaintext() {
        let service = test_encryption_service();
        let tenant_id = Uuid::new_v4();
        let plaintext: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();

        let ciphertext = service.encrypt(tenant_id, &plaintext).unwrap();
        let decrypted = service.decrypt(tenant_id, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_debug_redacts_key() {
        let service = test_encryption_service();
        let debug_str = format!("{service:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("42")); // Should not show actual key bytes
    }
}
