//! Encryption utilities for client secrets.

use crate::error::{FederationError, FederationResult};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use uuid::Uuid;

/// AES-256-GCM nonce size in bytes.
const NONCE_SIZE: usize = 12;

/// Encryption service for client secrets.
#[derive(Debug, Clone)]
pub struct EncryptionService {
    /// Master encryption key (32 bytes for AES-256).
    master_key: [u8; 32],
}

impl EncryptionService {
    /// Create a new encryption service with a master key.
    ///
    /// The master key should be loaded from environment or a secrets manager.
    #[must_use]
    pub fn new(master_key: [u8; 32]) -> Self {
        Self { master_key }
    }

    /// Create from a base64-encoded master key.
    pub fn from_base64(master_key_base64: &str) -> FederationResult<Self> {
        let key_bytes = BASE64
            .decode(master_key_base64)
            .map_err(|e| FederationError::EncryptionFailed(format!("Invalid base64 key: {e}")))?;

        if key_bytes.len() != 32 {
            return Err(FederationError::EncryptionFailed(format!(
                "Master key must be 32 bytes, got {}",
                key_bytes.len()
            )));
        }

        let mut master_key = [0u8; 32];
        master_key.copy_from_slice(&key_bytes);
        Ok(Self::new(master_key))
    }

    /// Derive a tenant-specific encryption key using HKDF.
    ///
    /// This provides per-tenant key isolation - compromising one tenant's
    /// encrypted data doesn't expose other tenants.
    ///
    /// Uses HKDF-SHA256 (RFC 5869) for cryptographically secure key derivation:
    /// - IKM (Input Key Material): master key
    /// - Salt: static domain separator for this application
    /// - Info: `tenant_id` for per-tenant key isolation
    fn derive_tenant_key(&self, tenant_id: Uuid) -> [u8; 32] {
        // SECURITY: Use HKDF-SHA256 for proper cryptographic key derivation.
        // The salt provides domain separation between different usages.
        // The info field contains the tenant_id for per-tenant key isolation.
        const SALT: &[u8] = b"xavyo-oidc-federation-v1";

        let hkdf = Hkdf::<Sha256>::new(Some(SALT), &self.master_key);

        let mut derived = [0u8; 32];
        // HKDF expand with tenant_id as context info
        hkdf.expand(tenant_id.as_bytes(), &mut derived)
            .expect("HKDF expand should never fail for 32-byte output");

        derived
    }

    /// Encrypt a secret for a specific tenant.
    ///
    /// Returns: nonce (12 bytes) || ciphertext
    pub fn encrypt(&self, tenant_id: Uuid, plaintext: &str) -> FederationResult<Vec<u8>> {
        let key = self.derive_tenant_key(tenant_id);
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| FederationError::EncryptionFailed(e.to_string()))?;

        // Generate random nonce
        // SECURITY: Use OsRng (CSPRNG) for cryptographic nonce generation
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| FederationError::EncryptionFailed(e.to_string()))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt a secret for a specific tenant.
    ///
    /// Expects: nonce (12 bytes) || ciphertext
    pub fn decrypt(&self, tenant_id: Uuid, encrypted: &[u8]) -> FederationResult<String> {
        if encrypted.len() < NONCE_SIZE {
            return Err(FederationError::DecryptionFailed(
                "Encrypted data too short".to_string(),
            ));
        }

        let key = self.derive_tenant_key(tenant_id);
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| FederationError::DecryptionFailed(e.to_string()))?;

        // Split nonce and ciphertext
        let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| FederationError::DecryptionFailed(e.to_string()))?;

        String::from_utf8(plaintext).map_err(|e| FederationError::DecryptionFailed(e.to_string()))
    }
}

/// Generate a random master key for testing/initialization.
///
/// SECURITY: Uses `OsRng` (CSPRNG) for cryptographic key generation.
#[must_use]
pub fn generate_master_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

/// Generate a random master key as base64 string.
#[must_use]
pub fn generate_master_key_base64() -> String {
    BASE64.encode(generate_master_key())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_service() -> EncryptionService {
        EncryptionService::new(generate_master_key())
    }

    #[test]
    fn test_encrypt_decrypt() {
        let service = test_service();
        let tenant_id = Uuid::new_v4();
        let secret = "my-super-secret-client-secret";

        let encrypted = service.encrypt(tenant_id, secret).unwrap();
        let decrypted = service.decrypt(tenant_id, &encrypted).unwrap();

        assert_eq!(decrypted, secret);
    }

    #[test]
    fn test_different_tenants_different_ciphertext() {
        let service = test_service();
        let tenant1 = Uuid::new_v4();
        let tenant2 = Uuid::new_v4();
        let secret = "shared-secret";

        let encrypted1 = service.encrypt(tenant1, secret).unwrap();
        let encrypted2 = service.encrypt(tenant2, secret).unwrap();

        // Different ciphertexts (due to different nonces and keys)
        assert_ne!(encrypted1, encrypted2);

        // Each can only decrypt their own
        assert!(service.decrypt(tenant2, &encrypted1).is_err());
        assert!(service.decrypt(tenant1, &encrypted2).is_err());
    }

    #[test]
    fn test_from_base64() {
        let key = generate_master_key_base64();
        let service = EncryptionService::from_base64(&key).unwrap();

        let tenant_id = Uuid::new_v4();
        let secret = "test";

        let encrypted = service.encrypt(tenant_id, secret).unwrap();
        let decrypted = service.decrypt(tenant_id, &encrypted).unwrap();

        assert_eq!(decrypted, secret);
    }
}
