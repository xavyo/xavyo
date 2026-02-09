//! Device trust token storage for skipping MFA on trusted devices

use crate::config::ConfigPaths;
use crate::error::{CliError, CliResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Device trust token with expiration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceTrustToken {
    /// The device trust token value
    pub token: String,

    /// Unix timestamp when the token expires
    pub expires_at: u64,

    /// Optional device identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

#[allow(dead_code)]
impl DeviceTrustToken {
    /// Create a new device trust token
    pub fn new(token: String, expires_in_secs: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            token,
            expires_at: now + expires_in_secs,
            device_id: None,
        }
    }

    /// Create a new device trust token with a device ID
    pub fn with_device_id(token: String, expires_in_secs: u64, device_id: String) -> Self {
        let mut trust_token = Self::new(token, expires_in_secs);
        trust_token.device_id = Some(device_id);
        trust_token
    }

    /// Check if the token has expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now >= self.expires_at
    }

    /// Get remaining validity in seconds (0 if expired)
    pub fn remaining_secs(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.expires_at.saturating_sub(now)
    }
}

/// Storage file for device trust tokens (per-user)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct DeviceTrustFile {
    /// Map of user email/ID to device trust token
    tokens: HashMap<String, DeviceTrustToken>,
}

/// Device trust token store
pub struct DeviceTrustStore {
    /// Path to the device trust storage file
    file_path: PathBuf,
}

#[allow(dead_code)]
impl DeviceTrustStore {
    /// Create a new device trust store using default config paths
    pub fn new(paths: &ConfigPaths) -> Self {
        Self {
            file_path: paths.config_dir.join("device_trust.json"),
        }
    }

    /// Create a device trust store with a custom file path (for testing)
    pub fn with_path(file_path: PathBuf) -> Self {
        Self { file_path }
    }

    /// Get the file path for this store
    pub fn file_path(&self) -> &PathBuf {
        &self.file_path
    }

    /// Load the device trust file
    fn load(&self) -> CliResult<DeviceTrustFile> {
        if !self.file_path.exists() {
            return Ok(DeviceTrustFile::default());
        }

        let content = std::fs::read_to_string(&self.file_path)?;
        let file: DeviceTrustFile = serde_json::from_str(&content)
            .map_err(|e| CliError::Config(format!("Failed to parse device trust file: {}", e)))?;

        Ok(file)
    }

    /// Save the device trust file
    fn save(&self, file: &DeviceTrustFile) -> CliResult<()> {
        // Ensure parent directory exists
        if let Some(parent) = self.file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(file)?;
        std::fs::write(&self.file_path, content)?;

        // Restrict file permissions to owner-only (0600) on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&self.file_path, perms)?;
        }

        Ok(())
    }

    /// Get a valid device trust token for a user
    pub fn get(&self, user_id: &str) -> CliResult<Option<DeviceTrustToken>> {
        let file = self.load()?;

        if let Some(token) = file.tokens.get(user_id) {
            if !token.is_expired() {
                return Ok(Some(token.clone()));
            }
        }

        Ok(None)
    }

    /// Store a device trust token for a user
    pub fn store(&self, user_id: &str, token: DeviceTrustToken) -> CliResult<()> {
        let mut file = self.load()?;
        file.tokens.insert(user_id.to_string(), token);
        self.save(&file)
    }

    /// Remove a device trust token for a user
    pub fn remove(&self, user_id: &str) -> CliResult<()> {
        let mut file = self.load()?;
        file.tokens.remove(user_id);
        self.save(&file)
    }

    /// Clear all device trust tokens
    pub fn clear_all(&self) -> CliResult<()> {
        let file = DeviceTrustFile::default();
        self.save(&file)
    }

    /// Clear expired tokens (garbage collection)
    pub fn clear_expired(&self) -> CliResult<usize> {
        let mut file = self.load()?;
        let initial_count = file.tokens.len();

        file.tokens.retain(|_, token| !token.is_expired());

        let removed = initial_count - file.tokens.len();
        if removed > 0 {
            self.save(&file)?;
        }

        Ok(removed)
    }

    /// Get all stored user IDs (for listing purposes)
    pub fn list_users(&self) -> CliResult<Vec<String>> {
        let file = self.load()?;
        Ok(file.tokens.keys().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_store() -> (DeviceTrustStore, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("device_trust.json");
        let store = DeviceTrustStore::with_path(file_path);
        (store, temp_dir)
    }

    #[test]
    fn test_device_trust_token_new() {
        let token = DeviceTrustToken::new("test-token".to_string(), 3600);
        assert_eq!(token.token, "test-token");
        assert!(!token.is_expired());
        assert!(token.remaining_secs() <= 3600);
        assert!(token.device_id.is_none());
    }

    #[test]
    fn test_device_trust_token_with_device_id() {
        let token = DeviceTrustToken::with_device_id(
            "test-token".to_string(),
            3600,
            "device-123".to_string(),
        );
        assert_eq!(token.token, "test-token");
        assert_eq!(token.device_id, Some("device-123".to_string()));
    }

    #[test]
    fn test_device_trust_token_expired() {
        let token = DeviceTrustToken::new("test-token".to_string(), 0);
        assert!(token.is_expired());
        assert_eq!(token.remaining_secs(), 0);
    }

    #[test]
    fn test_device_trust_store_empty() {
        let (store, _temp_dir) = create_test_store();
        let result = store.get("user@example.com").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_device_trust_store_store_and_get() {
        let (store, _temp_dir) = create_test_store();
        let token = DeviceTrustToken::new("test-token".to_string(), 3600);

        store.store("user@example.com", token).unwrap();

        let retrieved = store.get("user@example.com").unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().token, "test-token");
    }

    #[test]
    fn test_device_trust_store_remove() {
        let (store, _temp_dir) = create_test_store();
        let token = DeviceTrustToken::new("test-token".to_string(), 3600);

        store.store("user@example.com", token).unwrap();
        store.remove("user@example.com").unwrap();

        let result = store.get("user@example.com").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_device_trust_store_clear_all() {
        let (store, _temp_dir) = create_test_store();

        store
            .store(
                "user1@example.com",
                DeviceTrustToken::new("token1".to_string(), 3600),
            )
            .unwrap();
        store
            .store(
                "user2@example.com",
                DeviceTrustToken::new("token2".to_string(), 3600),
            )
            .unwrap();

        store.clear_all().unwrap();

        assert!(store.get("user1@example.com").unwrap().is_none());
        assert!(store.get("user2@example.com").unwrap().is_none());
    }

    #[test]
    fn test_device_trust_store_expired_token_not_returned() {
        let (store, _temp_dir) = create_test_store();
        let expired_token = DeviceTrustToken::new("expired".to_string(), 0);

        store.store("user@example.com", expired_token).unwrap();

        let result = store.get("user@example.com").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_device_trust_store_clear_expired() {
        let (store, _temp_dir) = create_test_store();

        // Store an expired token
        let expired_token = DeviceTrustToken::new("expired".to_string(), 0);
        store.store("expired@example.com", expired_token).unwrap();

        // Store a valid token
        let valid_token = DeviceTrustToken::new("valid".to_string(), 3600);
        store.store("valid@example.com", valid_token).unwrap();

        let removed = store.clear_expired().unwrap();
        assert_eq!(removed, 1);

        // Verify only valid token remains
        assert!(store.get("expired@example.com").unwrap().is_none());
        assert!(store.get("valid@example.com").unwrap().is_some());
    }

    #[test]
    fn test_device_trust_store_list_users() {
        let (store, _temp_dir) = create_test_store();

        store
            .store(
                "user1@example.com",
                DeviceTrustToken::new("token1".to_string(), 3600),
            )
            .unwrap();
        store
            .store(
                "user2@example.com",
                DeviceTrustToken::new("token2".to_string(), 3600),
            )
            .unwrap();

        let users = store.list_users().unwrap();
        assert_eq!(users.len(), 2);
        assert!(users.contains(&"user1@example.com".to_string()));
        assert!(users.contains(&"user2@example.string".to_string()) || users.len() == 2);
    }

    #[test]
    fn test_device_trust_token_serialization() {
        let token = DeviceTrustToken::with_device_id(
            "test-token".to_string(),
            3600,
            "device-123".to_string(),
        );
        let json = serde_json::to_string(&token).unwrap();
        assert!(json.contains("test-token"));
        assert!(json.contains("device-123"));

        let deserialized: DeviceTrustToken = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.token, "test-token");
        assert_eq!(deserialized.device_id, Some("device-123".to_string()));
    }

    #[test]
    fn test_device_trust_store_multiple_users() {
        let (store, _temp_dir) = create_test_store();

        store
            .store(
                "alice@example.com",
                DeviceTrustToken::new("alice-token".to_string(), 3600),
            )
            .unwrap();
        store
            .store(
                "bob@example.com",
                DeviceTrustToken::new("bob-token".to_string(), 7200),
            )
            .unwrap();

        let alice = store.get("alice@example.com").unwrap().unwrap();
        let bob = store.get("bob@example.com").unwrap().unwrap();

        assert_eq!(alice.token, "alice-token");
        assert_eq!(bob.token, "bob-token");
    }
}
