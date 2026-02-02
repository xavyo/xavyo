//! OS keyring credential storage backend

use crate::credentials::store::CredentialStore;
use crate::error::{CliError, CliResult};
use crate::models::Credentials;
use keyring::Entry;

const SERVICE_NAME: &str = "xavyo-cli";
const USERNAME: &str = "credentials";

/// Credential store using the OS keyring
///
/// - macOS: Keychain
/// - Linux: Secret Service (GNOME Keyring, KWallet)
/// - Windows: Credential Manager
pub struct KeyringCredentialStore {
    entry: Entry,
}

impl KeyringCredentialStore {
    /// Create a new keyring credential store
    pub fn new() -> CliResult<Self> {
        let entry = Entry::new(SERVICE_NAME, USERNAME)
            .map_err(|e| CliError::CredentialStorage(format!("Failed to access keyring: {}", e)))?;
        Ok(Self { entry })
    }

    /// Check if keyring is available on this system
    pub fn is_available(&self) -> bool {
        // Try a get operation - if it fails with NoEntry, keyring is available
        // If it fails with other errors, keyring may not be available
        match self.entry.get_password() {
            Ok(_) => true,
            Err(keyring::Error::NoEntry) => true,
            Err(_) => false,
        }
    }
}

impl CredentialStore for KeyringCredentialStore {
    fn store(&self, credentials: &Credentials) -> CliResult<()> {
        let json = serde_json::to_string(credentials)?;
        self.entry
            .set_password(&json)
            .map_err(|e| CliError::CredentialStorage(format!("Failed to store credentials: {}", e)))
    }

    fn load(&self) -> CliResult<Option<Credentials>> {
        match self.entry.get_password() {
            Ok(json) => {
                let credentials: Credentials = serde_json::from_str(&json)?;
                Ok(Some(credentials))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(CliError::CredentialStorage(format!(
                "Failed to load credentials: {}",
                e
            ))),
        }
    }

    fn delete(&self) -> CliResult<()> {
        match self.entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()), // Already deleted
            Err(e) => Err(CliError::CredentialStorage(format!(
                "Failed to delete credentials: {}",
                e
            ))),
        }
    }

    fn exists(&self) -> bool {
        self.entry.get_password().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyring_store_creation() {
        // This test may fail on systems without a keyring
        let result = KeyringCredentialStore::new();
        // Just check it doesn't panic
        let _ = result;
    }
}
