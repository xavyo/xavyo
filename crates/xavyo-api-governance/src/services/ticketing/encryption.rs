//! Credential encryption for ticketing configurations (F064).
//!
//! Provides AES-GCM encryption for storing sensitive credentials.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::RngCore;

use super::TicketingError;

/// Length of the AES-256 key in bytes.
const KEY_LENGTH: usize = 32;
/// Length of the GCM nonce in bytes.
const NONCE_LENGTH: usize = 12;

/// Get the encryption key from environment.
///
/// SECURITY: This function requires the XAVYO_TICKETING_ENCRYPTION_KEY environment
/// variable to be set. There is no fallback to a hardcoded key to prevent
/// accidental use of weak encryption in production.
///
/// To generate a key: `openssl rand -base64 32`
fn get_encryption_key() -> Result<[u8; KEY_LENGTH], TicketingError> {
    let key_b64 = std::env::var("XAVYO_TICKETING_ENCRYPTION_KEY").map_err(|_| {
        TicketingError::EncryptionError(
            "XAVYO_TICKETING_ENCRYPTION_KEY environment variable not set. \
             Generate a key with: openssl rand -base64 32"
                .to_string(),
        )
    })?;

    let key_bytes = BASE64
        .decode(&key_b64)
        .map_err(|e| TicketingError::EncryptionError(format!("Invalid base64 key: {}", e)))?;

    if key_bytes.len() != KEY_LENGTH {
        return Err(TicketingError::EncryptionError(format!(
            "Key must be {} bytes, got {}",
            KEY_LENGTH,
            key_bytes.len()
        )));
    }

    let mut key = [0u8; KEY_LENGTH];
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

/// Encrypt credentials using AES-256-GCM.
///
/// Returns a base64-encoded string containing the nonce and ciphertext.
pub fn encrypt_credentials(plaintext: &serde_json::Value) -> Result<String, TicketingError> {
    let key = get_encryption_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| TicketingError::EncryptionError(format!("Failed to create cipher: {}", e)))?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Serialize and encrypt
    let plaintext_bytes = serde_json::to_vec(plaintext).map_err(|e| {
        TicketingError::EncryptionError(format!("JSON serialization failed: {}", e))
    })?;

    let ciphertext = cipher
        .encrypt(nonce, plaintext_bytes.as_slice())
        .map_err(|e| TicketingError::EncryptionError(format!("Encryption failed: {}", e)))?;

    // Combine nonce + ciphertext and encode as base64
    let mut combined = Vec::with_capacity(NONCE_LENGTH + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(BASE64.encode(&combined))
}

/// Decrypt credentials using AES-256-GCM.
///
/// Expects a base64-encoded string containing the nonce and ciphertext.
pub fn decrypt_credentials(encrypted: &str) -> Result<serde_json::Value, TicketingError> {
    let key = get_encryption_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| TicketingError::EncryptionError(format!("Failed to create cipher: {}", e)))?;

    // Decode from base64
    let combined = BASE64
        .decode(encrypted)
        .map_err(|e| TicketingError::EncryptionError(format!("Invalid base64: {}", e)))?;

    if combined.len() < NONCE_LENGTH {
        return Err(TicketingError::EncryptionError(
            "Encrypted data too short".to_string(),
        ));
    }

    // Split nonce and ciphertext
    let (nonce_bytes, ciphertext) = combined.split_at(NONCE_LENGTH);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt
    let plaintext_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| TicketingError::EncryptionError(format!("Decryption failed: {}", e)))?;

    // Deserialize
    serde_json::from_slice(&plaintext_bytes)
        .map_err(|e| TicketingError::EncryptionError(format!("JSON deserialization failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    // Mutex to serialize environment variable tests
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    const TEST_KEY: &str = "dGVzdC1lbmNyeXB0LWtleS0zMi1ieXRlcy1sb25nISE=";

    /// Set up the test encryption key. Uses a fixed key for deterministic tests.
    fn setup_test_key() {
        // Test key: 32 bytes encoded as base64
        // "test-encrypt-key-32-bytes-long!!" = 32 bytes
        std::env::set_var("XAVYO_TICKETING_ENCRYPTION_KEY", TEST_KEY);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let _lock = ENV_MUTEX.lock().unwrap();
        setup_test_key();

        let credentials = json!({
            "username": "admin",
            "password": "secret123",
            "api_key": "abc-123-xyz"
        });

        let encrypted = encrypt_credentials(&credentials).unwrap();

        // Encrypted should be base64
        assert!(BASE64.decode(&encrypted).is_ok());

        // Decrypt should return original
        let decrypted = decrypt_credentials(&encrypted).unwrap();
        assert_eq!(decrypted, credentials);
    }

    #[test]
    fn test_encrypt_different_each_time() {
        let _lock = ENV_MUTEX.lock().unwrap();
        setup_test_key();

        let credentials = json!({"key": "value"});

        let encrypted1 = encrypt_credentials(&credentials).unwrap();
        let encrypted2 = encrypt_credentials(&credentials).unwrap();

        // Each encryption should produce different output (due to random nonce)
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same value
        assert_eq!(
            decrypt_credentials(&encrypted1).unwrap(),
            decrypt_credentials(&encrypted2).unwrap()
        );
    }

    #[test]
    fn test_decrypt_invalid_base64() {
        let _lock = ENV_MUTEX.lock().unwrap();
        setup_test_key();

        let result = decrypt_credentials("not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_too_short() {
        let _lock = ENV_MUTEX.lock().unwrap();
        setup_test_key();

        let result = decrypt_credentials(&BASE64.encode(&[0u8; 5]));
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_key_returns_error() {
        let _lock = ENV_MUTEX.lock().unwrap();

        // Save original value
        let key_backup = std::env::var("XAVYO_TICKETING_ENCRYPTION_KEY").ok();

        // Remove the key to test error handling
        std::env::remove_var("XAVYO_TICKETING_ENCRYPTION_KEY");

        let result = get_encryption_key();
        assert!(result.is_err());
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(err_msg.contains("not set"));

        // Restore key
        match key_backup {
            Some(key) => std::env::set_var("XAVYO_TICKETING_ENCRYPTION_KEY", key),
            None => std::env::set_var("XAVYO_TICKETING_ENCRYPTION_KEY", TEST_KEY),
        }
    }
}
