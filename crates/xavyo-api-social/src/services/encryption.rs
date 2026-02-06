//! Encryption service for social tokens using AES-256-GCM.
//!
//! Provides per-tenant encryption keys derived via HKDF from a master key.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use uuid::Uuid;

use crate::error::{SocialError, SocialResult};

/// Nonce size for AES-GCM (96 bits = 12 bytes).
const NONCE_SIZE: usize = 12;

/// Key size for AES-256 (256 bits = 32 bytes).
const KEY_SIZE: usize = 32;

/// Encryption service for social authentication tokens.
#[derive(Clone)]
pub struct EncryptionService {
    master_key: [u8; KEY_SIZE],
}

impl EncryptionService {
    /// Create a new encryption service from a base64-encoded master key.
    pub fn new(master_key_base64: &str) -> SocialResult<Self> {
        let master_key_bytes =
            BASE64
                .decode(master_key_base64)
                .map_err(|e| SocialError::EncryptionError {
                    operation: format!("decode master key: {e}"),
                })?;

        if master_key_bytes.len() != KEY_SIZE {
            return Err(SocialError::EncryptionError {
                operation: format!(
                    "master key must be {} bytes, got {}",
                    KEY_SIZE,
                    master_key_bytes.len()
                ),
            });
        }

        let mut master_key = [0u8; KEY_SIZE];
        master_key.copy_from_slice(&master_key_bytes);

        Ok(Self { master_key })
    }

    /// Derive a per-tenant encryption key using HKDF.
    fn derive_tenant_key(&self, tenant_id: Uuid) -> [u8; KEY_SIZE] {
        let hkdf = Hkdf::<Sha256>::new(None, &self.master_key);
        let info = format!("xavyo-social-{tenant_id}");

        let mut tenant_key = [0u8; KEY_SIZE];
        hkdf.expand(info.as_bytes(), &mut tenant_key)
            .expect("HKDF expand should never fail with valid parameters");

        tenant_key
    }

    /// Encrypt data for a specific tenant.
    ///
    /// Returns the ciphertext with the nonce prepended.
    pub fn encrypt(&self, tenant_id: Uuid, plaintext: &[u8]) -> SocialResult<Vec<u8>> {
        let tenant_key = self.derive_tenant_key(tenant_id);
        let cipher =
            Aes256Gcm::new_from_slice(&tenant_key).map_err(|e| SocialError::EncryptionError {
                operation: format!("create cipher: {e}"),
            })?;

        // Generate a random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        // Encrypt the plaintext
        let ciphertext =
            cipher
                .encrypt(&nonce, plaintext)
                .map_err(|e| SocialError::EncryptionError {
                    operation: format!("encrypt: {e}"),
                })?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt data for a specific tenant.
    ///
    /// Expects the ciphertext with the nonce prepended.
    pub fn decrypt(&self, tenant_id: Uuid, ciphertext: &[u8]) -> SocialResult<Vec<u8>> {
        if ciphertext.len() < NONCE_SIZE {
            return Err(SocialError::EncryptionError {
                operation: "ciphertext too short".to_string(),
            });
        }

        let tenant_key = self.derive_tenant_key(tenant_id);
        let cipher =
            Aes256Gcm::new_from_slice(&tenant_key).map_err(|e| SocialError::EncryptionError {
                operation: format!("create cipher: {e}"),
            })?;

        // Extract nonce and ciphertext
        let nonce_array: [u8; NONCE_SIZE] =
            ciphertext[..NONCE_SIZE]
                .try_into()
                .map_err(|_| SocialError::EncryptionError {
                    operation: "invalid nonce length".to_string(),
                })?;
        let nonce = Nonce::from(nonce_array);
        let encrypted_data = &ciphertext[NONCE_SIZE..];

        // Decrypt
        cipher
            .decrypt(&nonce, encrypted_data)
            .map_err(|e| SocialError::EncryptionError {
                operation: format!("decrypt: {e}"),
            })
    }

    /// Encrypt a string value for a tenant.
    pub fn encrypt_string(&self, tenant_id: Uuid, plaintext: &str) -> SocialResult<Vec<u8>> {
        self.encrypt(tenant_id, plaintext.as_bytes())
    }

    /// Decrypt a string value for a tenant.
    pub fn decrypt_string(&self, tenant_id: Uuid, ciphertext: &[u8]) -> SocialResult<String> {
        let plaintext = self.decrypt(tenant_id, ciphertext)?;
        String::from_utf8(plaintext).map_err(|e| SocialError::EncryptionError {
            operation: format!("invalid UTF-8: {e}"),
        })
    }
}

/// Generate a new random master key and return it base64-encoded.
#[must_use]
pub fn generate_master_key() -> String {
    let mut key = [0u8; KEY_SIZE];
    OsRng.fill_bytes(&mut key);
    BASE64.encode(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_service() -> EncryptionService {
        let key = generate_master_key();
        EncryptionService::new(&key).unwrap()
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let service = test_service();
        let tenant_id = Uuid::new_v4();
        let plaintext = b"my secret access token";

        let ciphertext = service.encrypt(tenant_id, plaintext).unwrap();
        let decrypted = service.decrypt(tenant_id, &ciphertext).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_different_tenants_produce_different_ciphertext() {
        let service = test_service();
        let tenant1 = Uuid::new_v4();
        let tenant2 = Uuid::new_v4();
        let plaintext = b"same plaintext";

        let ciphertext1 = service.encrypt(tenant1, plaintext).unwrap();
        let ciphertext2 = service.encrypt(tenant2, plaintext).unwrap();

        // Different tenants should produce different ciphertexts
        // (even ignoring the random nonce, the key is different)
        assert_ne!(ciphertext1, ciphertext2);

        // Each should only decrypt with the correct tenant
        let decrypted1 = service.decrypt(tenant1, &ciphertext1).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted1);

        // Decrypting with wrong tenant should fail
        assert!(service.decrypt(tenant2, &ciphertext1).is_err());
    }

    #[test]
    fn test_encrypt_string() {
        let service = test_service();
        let tenant_id = Uuid::new_v4();
        let plaintext = "my secret string";

        let ciphertext = service.encrypt_string(tenant_id, plaintext).unwrap();
        let decrypted = service.decrypt_string(tenant_id, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_invalid_key_length() {
        let short_key = BASE64.encode([0u8; 16]); // 16 bytes instead of 32
        let result = EncryptionService::new(&short_key);

        assert!(result.is_err());
        if let Err(SocialError::EncryptionError { operation }) = result {
            assert!(operation.contains("must be 32 bytes"));
        }
    }

    #[test]
    fn test_invalid_base64() {
        let result = EncryptionService::new("not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_ciphertext_too_short() {
        let service = test_service();
        let tenant_id = Uuid::new_v4();

        // Less than nonce size
        let result = service.decrypt(tenant_id, &[0u8; 5]);
        assert!(result.is_err());
    }
}
