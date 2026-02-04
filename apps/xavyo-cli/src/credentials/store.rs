//! Credential storage abstraction

use crate::config::ConfigPaths;
use crate::credentials::{FileCredentialStore, KeyringCredentialStore};
use crate::error::CliResult;
use crate::models::Credentials;

/// Trait for credential storage backends
pub trait CredentialStore: Send + Sync {
    /// Store credentials
    fn store(&self, credentials: &Credentials) -> CliResult<()>;

    /// Load credentials
    fn load(&self) -> CliResult<Option<Credentials>>;

    /// Delete stored credentials
    fn delete(&self) -> CliResult<()>;

    /// Check if credentials exist
    fn exists(&self) -> bool;
}

/// Get the appropriate credential store for the current platform
///
/// Tries keyring first, falls back to encrypted file if unavailable
pub fn get_credential_store(paths: &ConfigPaths) -> Box<dyn CredentialStore> {
    // Try keyring first
    match KeyringCredentialStore::new() {
        Ok(store) if store.is_available() => {
            return Box::new(store);
        }
        _ => {
            // Keyring unavailable, use file fallback
            eprintln!("Warning: System keyring unavailable. Using encrypted file storage.");
        }
    }

    // Fall back to encrypted file
    Box::new(FileCredentialStore::new(paths.credentials_file.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_get_credential_store() {
        let temp_dir = TempDir::new().unwrap();
        let paths = ConfigPaths {
            config_dir: temp_dir.path().to_path_buf(),
            config_file: temp_dir.path().join("config.json"),
            session_file: temp_dir.path().join("session.json"),
            credentials_file: temp_dir.path().join("credentials.enc"),
            cache_dir: temp_dir.path().join("cache"),
            history_file: temp_dir.path().join("shell_history"),
            version_history_dir: temp_dir.path().join("history"),
        };

        // Should return some store (either keyring or file)
        let _store = get_credential_store(&paths);
    }
}
