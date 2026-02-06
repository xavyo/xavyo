//! Credential encryption for dynamic secrets (F120).
//!
//! Provides AES-256-GCM encryption for storing sensitive credential values.
//! Based on the ticketing encryption pattern (F064).

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::RngCore;
use thiserror::Error;

/// Length of the AES-256 key in bytes.
const KEY_LENGTH: usize = 32;
/// Length of the GCM nonce in bytes.
const NONCE_LENGTH: usize = 12;

/// Encryption errors for credential management.
#[derive(Debug, Error)]
pub enum EncryptionError {
    /// Encryption key not configured.
    #[error("Encryption key not configured: {0}")]
    KeyNotConfigured(String),

    /// Invalid encryption key format.
    #[error("Invalid encryption key: {0}")]
    InvalidKey(String),

    /// Encryption operation failed.
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption operation failed.
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Get the encryption key from environment.
///
/// SECURITY: This function requires the `XAVYO_SECRETS_ENCRYPTION_KEY` environment
/// variable to be set. There is no fallback to a hardcoded key to prevent
/// accidental use of weak encryption in production.
///
/// To generate a key: `openssl rand -base64 32`
fn get_encryption_key() -> Result<[u8; KEY_LENGTH], EncryptionError> {
    let key_b64 = std::env::var("XAVYO_SECRETS_ENCRYPTION_KEY").map_err(|_| {
        EncryptionError::KeyNotConfigured(
            "XAVYO_SECRETS_ENCRYPTION_KEY environment variable not set. \
             Generate a key with: openssl rand -base64 32"
                .to_string(),
        )
    })?;

    let key_bytes = BASE64
        .decode(&key_b64)
        .map_err(|e| EncryptionError::InvalidKey(format!("Invalid base64 key: {e}")))?;

    if key_bytes.len() != KEY_LENGTH {
        return Err(EncryptionError::InvalidKey(format!(
            "Key must be {} bytes, got {}",
            KEY_LENGTH,
            key_bytes.len()
        )));
    }

    let mut key = [0u8; KEY_LENGTH];
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

/// Encrypt a credential value using AES-256-GCM.
///
/// Returns a base64-encoded string containing the nonce and ciphertext.
/// Use this for encrypting credential values before storing in the database.
pub fn encrypt_credential_value(plaintext: &str) -> Result<String, EncryptionError> {
    let key = get_encryption_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| EncryptionError::EncryptionFailed(format!("Failed to create cipher: {e}")))?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| EncryptionError::EncryptionFailed(format!("Encryption failed: {e}")))?;

    // Combine nonce + ciphertext and encode as base64
    let mut combined = Vec::with_capacity(NONCE_LENGTH + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(BASE64.encode(&combined))
}

/// Decrypt a credential value using AES-256-GCM.
///
/// Expects a base64-encoded string containing the nonce and ciphertext.
/// Use this for decrypting credential values retrieved from the database.
pub fn decrypt_credential_value(encrypted: &str) -> Result<String, EncryptionError> {
    let key = get_encryption_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| EncryptionError::DecryptionFailed(format!("Failed to create cipher: {e}")))?;

    // Decode from base64
    let combined = BASE64
        .decode(encrypted)
        .map_err(|e| EncryptionError::DecryptionFailed(format!("Invalid base64: {e}")))?;

    if combined.len() < NONCE_LENGTH {
        return Err(EncryptionError::DecryptionFailed(
            "Encrypted data too short".to_string(),
        ));
    }

    // Split nonce and ciphertext
    let (nonce_bytes, ciphertext) = combined.split_at(NONCE_LENGTH);
    let nonce_array: [u8; NONCE_LENGTH] = nonce_bytes
        .try_into()
        .map_err(|_| EncryptionError::DecryptionFailed("invalid nonce length".to_string()))?;
    let nonce = Nonce::from(nonce_array);

    // Decrypt
    let plaintext_bytes = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| EncryptionError::DecryptionFailed(format!("Decryption failed: {e}")))?;

    String::from_utf8(plaintext_bytes)
        .map_err(|e| EncryptionError::DecryptionFailed(format!("Invalid UTF-8: {e}")))
}

/// Encrypt a JSON credential object using AES-256-GCM.
///
/// Returns a base64-encoded string containing the nonce and ciphertext.
/// Use this for encrypting structured credential objects.
pub fn encrypt_credentials_json(plaintext: &serde_json::Value) -> Result<String, EncryptionError> {
    let json_str = serde_json::to_string(plaintext).map_err(|e| {
        EncryptionError::SerializationError(format!("JSON serialization failed: {e}"))
    })?;
    encrypt_credential_value(&json_str)
}

/// Decrypt a JSON credential object using AES-256-GCM.
///
/// Expects a base64-encoded string containing the nonce and ciphertext.
/// Use this for decrypting structured credential objects.
pub fn decrypt_credentials_json(encrypted: &str) -> Result<serde_json::Value, EncryptionError> {
    let json_str = decrypt_credential_value(encrypted)?;
    serde_json::from_str(&json_str).map_err(|e| {
        EncryptionError::SerializationError(format!("JSON deserialization failed: {e}"))
    })
}

/// Service wrapper for encryption operations.
///
/// Provides methods for encrypting and decrypting credential values
/// with automatic key management.
pub struct EncryptionService {
    key: [u8; KEY_LENGTH],
}

impl EncryptionService {
    /// Create an `EncryptionService` from environment or generate a key.
    ///
    /// In production, expects `XAVYO_SECRETS_ENCRYPTION_KEY` to be set.
    /// In development, generates a temporary key if not set.
    pub fn from_env_or_generate() -> Result<Self, crate::error::ApiAgentsError> {
        let key = match get_encryption_key() {
            Ok(key) => key,
            Err(EncryptionError::KeyNotConfigured(_)) => {
                // Generate a temporary key for development
                tracing::warn!(
                    "XAVYO_SECRETS_ENCRYPTION_KEY not set. Using generated key. \
                     Set this in production!"
                );
                let mut key = [0u8; KEY_LENGTH];
                OsRng.fill_bytes(&mut key);
                key
            }
            Err(e) => return Err(crate::error::ApiAgentsError::EncryptionError(e.to_string())),
        };
        Ok(Self { key })
    }

    /// Encrypt a credential value.
    pub fn encrypt(&self, plaintext: &str) -> Result<String, crate::error::ApiAgentsError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|e| {
            crate::error::ApiAgentsError::EncryptionError(format!("Failed to create cipher: {e}"))
        })?;

        let mut nonce_bytes = [0u8; NONCE_LENGTH];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).map_err(|e| {
            crate::error::ApiAgentsError::EncryptionError(format!("Encryption failed: {e}"))
        })?;

        let mut combined = Vec::with_capacity(NONCE_LENGTH + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);

        Ok(BASE64.encode(&combined))
    }

    /// Decrypt a credential value.
    pub fn decrypt(&self, encrypted: &str) -> Result<String, crate::error::ApiAgentsError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|e| {
            crate::error::ApiAgentsError::EncryptionError(format!("Failed to create cipher: {e}"))
        })?;

        let combined = BASE64.decode(encrypted).map_err(|e| {
            crate::error::ApiAgentsError::EncryptionError(format!("Invalid base64: {e}"))
        })?;

        if combined.len() < NONCE_LENGTH {
            return Err(crate::error::ApiAgentsError::EncryptionError(
                "Encrypted data too short".to_string(),
            ));
        }

        let (nonce_bytes, ciphertext) = combined.split_at(NONCE_LENGTH);
        let nonce_array: [u8; NONCE_LENGTH] = nonce_bytes.try_into().map_err(|_| {
            crate::error::ApiAgentsError::EncryptionError("invalid nonce length".to_string())
        })?;
        let nonce = Nonce::from(nonce_array);

        let plaintext_bytes = cipher.decrypt(&nonce, ciphertext).map_err(|e| {
            crate::error::ApiAgentsError::EncryptionError(format!("Decryption failed: {e}"))
        })?;

        String::from_utf8(plaintext_bytes).map_err(|e| {
            crate::error::ApiAgentsError::EncryptionError(format!("Invalid UTF-8: {e}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    // Mutex to serialize environment variable tests
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    const TEST_KEY: &str = "dGVzdC1lbmNyeXB0LWtleS0zMi1ieXRlcy1sb25nISE=";

    /// Set up the test encryption key.
    fn setup_test_key() {
        // Test key: 32 bytes encoded as base64
        // "test-encrypt-key-32-bytes-long!!" = 32 bytes
        std::env::set_var("XAVYO_SECRETS_ENCRYPTION_KEY", TEST_KEY);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let _lock = ENV_MUTEX.lock().unwrap();
        setup_test_key();

        let plaintext = "my-secret-password-123";
        let encrypted = encrypt_credential_value(plaintext).unwrap();

        // Encrypted should be base64
        assert!(BASE64.decode(&encrypted).is_ok());

        // Decrypt should return original
        let decrypted = decrypt_credential_value(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_different_each_time() {
        let _lock = ENV_MUTEX.lock().unwrap();
        setup_test_key();

        let plaintext = "same-value";

        let encrypted1 = encrypt_credential_value(plaintext).unwrap();
        let encrypted2 = encrypt_credential_value(plaintext).unwrap();

        // Each encryption should produce different output (due to random nonce)
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same value
        assert_eq!(
            decrypt_credential_value(&encrypted1).unwrap(),
            decrypt_credential_value(&encrypted2).unwrap()
        );
    }

    #[test]
    fn test_json_encrypt_decrypt_roundtrip() {
        let _lock = ENV_MUTEX.lock().unwrap();
        setup_test_key();

        let credentials = json!({
            "username": "admin",
            "password": "secret123",
            "host": "db.example.com",
            "port": 5432
        });

        let encrypted = encrypt_credentials_json(&credentials).unwrap();
        let decrypted = decrypt_credentials_json(&encrypted).unwrap();

        assert_eq!(decrypted, credentials);
    }

    #[test]
    fn test_decrypt_invalid_base64() {
        let _lock = ENV_MUTEX.lock().unwrap();
        setup_test_key();

        let result = decrypt_credential_value("not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_too_short() {
        let _lock = ENV_MUTEX.lock().unwrap();
        setup_test_key();

        let result = decrypt_credential_value(&BASE64.encode([0u8; 5]));
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_key_returns_error() {
        let _lock = ENV_MUTEX.lock().unwrap();

        // Save original value
        let key_backup = std::env::var("XAVYO_SECRETS_ENCRYPTION_KEY").ok();

        // Remove the key to test error handling
        std::env::remove_var("XAVYO_SECRETS_ENCRYPTION_KEY");

        let result = get_encryption_key();
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("not set"));

        // Restore key
        match key_backup {
            Some(key) => std::env::set_var("XAVYO_SECRETS_ENCRYPTION_KEY", key),
            None => std::env::set_var("XAVYO_SECRETS_ENCRYPTION_KEY", TEST_KEY),
        }
    }
}
