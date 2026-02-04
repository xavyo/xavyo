//! Encrypted file credential storage backend

use crate::credentials::store::CredentialStore;
use crate::error::{CliError, CliResult};
use crate::models::Credentials;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::RngCore;
use std::path::PathBuf;

/// Credential store using encrypted file storage
///
/// Uses AES-256-GCM for encryption with a key derived from machine-specific data.
/// This is a fallback for when keyring is unavailable.
pub struct FileCredentialStore {
    path: PathBuf,
}

impl FileCredentialStore {
    /// Create a new file credential store
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Get an encryption key derived from machine-specific data
    fn get_encryption_key() -> [u8; 32] {
        // Use a combination of machine-specific values
        // This is not perfect security but provides reasonable protection
        // for credentials at rest when keyring is unavailable

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        use std::hash::{Hash, Hasher};

        // Hash hostname
        if let Ok(hostname) = std::env::var("HOSTNAME").or_else(|_| std::env::var("COMPUTERNAME")) {
            hostname.hash(&mut hasher);
        }

        // Hash username
        if let Ok(user) = std::env::var("USER").or_else(|_| std::env::var("USERNAME")) {
            user.hash(&mut hasher);
        }

        // Hash home directory
        if let Some(home) = dirs::home_dir() {
            home.to_string_lossy().hash(&mut hasher);
        }

        // Add a static salt
        "xavyo-cli-credential-encryption-v1".hash(&mut hasher);

        let hash = hasher.finish();

        // Expand to 32 bytes using simple derivation
        let mut key = [0u8; 32];
        let hash_bytes = hash.to_le_bytes();
        for i in 0..4 {
            key[i * 8..(i + 1) * 8].copy_from_slice(&hash_bytes);
            // Mix each segment slightly
            for j in 0..8 {
                key[i * 8 + j] = key[i * 8 + j].wrapping_add((i * 8 + j) as u8);
            }
        }

        key
    }

    fn encrypt(&self, data: &[u8]) -> CliResult<Vec<u8>> {
        let key = Self::get_encryption_key();
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| CliError::CredentialStorage(format!("Encryption init failed: {e}")))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| CliError::CredentialStorage(format!("Encryption failed: {e}")))?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend(ciphertext);

        Ok(result)
    }

    fn decrypt(&self, data: &[u8]) -> CliResult<Vec<u8>> {
        if data.len() < 12 {
            return Err(CliError::CredentialStorage(
                "Invalid encrypted data".to_string(),
            ));
        }

        let key = Self::get_encryption_key();
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| CliError::CredentialStorage(format!("Decryption init failed: {e}")))?;

        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| CliError::CredentialStorage(format!("Decryption failed: {e}")))
    }
}

impl CredentialStore for FileCredentialStore {
    fn store(&self, credentials: &Credentials) -> CliResult<()> {
        let json = serde_json::to_string(credentials)?;
        let encrypted = self.encrypt(json.as_bytes())?;
        let encoded = BASE64.encode(&encrypted);

        // Ensure parent directory exists
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Write with restricted permissions
        std::fs::write(&self.path, encoded)?;

        // Set file permissions to owner-only (Unix)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&self.path, perms)?;
        }

        Ok(())
    }

    fn load(&self) -> CliResult<Option<Credentials>> {
        if !self.path.exists() {
            return Ok(None);
        }

        let encoded = std::fs::read_to_string(&self.path)?;
        let encrypted = BASE64
            .decode(encoded.trim())
            .map_err(|e| CliError::CredentialStorage(format!("Invalid credential file: {e}")))?;
        let decrypted = self.decrypt(&encrypted)?;
        let json = String::from_utf8(decrypted)
            .map_err(|e| CliError::CredentialStorage(format!("Invalid credential data: {e}")))?;
        let credentials: Credentials = serde_json::from_str(&json)?;

        Ok(Some(credentials))
    }

    fn delete(&self) -> CliResult<()> {
        if self.path.exists() {
            std::fs::remove_file(&self.path)?;
        }
        Ok(())
    }

    fn exists(&self) -> bool {
        self.path.exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use tempfile::TempDir;

    fn create_test_credentials() -> Credentials {
        Credentials {
            access_token: "test_access_token".to_string(),
            refresh_token: "test_refresh_token".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            token_type: "Bearer".to_string(),
        }
    }

    #[test]
    fn test_file_store_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("credentials.enc");
        let store = FileCredentialStore::new(path);

        let credentials = create_test_credentials();

        // Store
        store.store(&credentials).unwrap();
        assert!(store.exists());

        // Load
        let loaded = store.load().unwrap().unwrap();
        assert_eq!(loaded.access_token, credentials.access_token);
        assert_eq!(loaded.refresh_token, credentials.refresh_token);

        // Delete
        store.delete().unwrap();
        assert!(!store.exists());
    }

    #[test]
    fn test_file_store_not_exists() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("nonexistent.enc");
        let store = FileCredentialStore::new(path);

        assert!(!store.exists());
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn test_encryption_key_consistency() {
        let key1 = FileCredentialStore::get_encryption_key();
        let key2 = FileCredentialStore::get_encryption_key();
        assert_eq!(key1, key2);
    }
}
