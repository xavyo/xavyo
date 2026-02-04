//! API key generation and hashing service.

use sha2::{Digest, Sha256};

/// Prefix for production API keys.
pub const API_KEY_PREFIX: &str = "xavyo_sk_live_";

/// Length of the random hex portion of the API key.
pub const API_KEY_HEX_LENGTH: usize = 32;

/// Service for generating and hashing API keys.
#[derive(Clone)]
pub struct ApiKeyService;

impl ApiKeyService {
    /// Create a new API key service.
    #[must_use] 
    pub fn new() -> Self {
        Self
    }

    /// Generate a new API key.
    ///
    /// Format: `xavyo_sk_live_` + 32 hex characters (16 random bytes)
    ///
    /// Returns the plaintext API key. This should be shown to the user once
    /// and then only the hash should be stored.
    ///
    /// SECURITY: Uses `OsRng` directly from the operating system's CSPRNG.
    #[must_use] 
    pub fn generate_api_key(&self) -> String {
        use rand::rngs::OsRng;
        use rand::RngCore;
        let mut random_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut random_bytes);
        let hex_string = hex::encode(random_bytes);

        format!("{API_KEY_PREFIX}{hex_string}")
    }

    /// Hash an API key using SHA-256.
    ///
    /// The hash is returned as a hex string and should be stored in the database.
    /// The plaintext key cannot be recovered from the hash.
    #[must_use] 
    pub fn hash_api_key(&self, api_key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(api_key.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Generate the key prefix for storage (first part of the key for identification).
    ///
    /// This returns the `xavyo_sk_live_` prefix which can be used to identify
    /// keys in logs without exposing the full key.
    #[must_use] 
    pub fn get_key_prefix(&self) -> &'static str {
        API_KEY_PREFIX
    }

    /// Create an API key for a user and return both the plaintext key and hash.
    ///
    /// Returns (`plaintext_key`, `key_hash`, `key_prefix`)
    #[must_use] 
    pub fn create_key_pair(&self) -> (String, String, String) {
        let plaintext_key = self.generate_api_key();
        let key_hash = self.hash_api_key(&plaintext_key);
        let key_prefix = API_KEY_PREFIX.to_string();

        (plaintext_key, key_hash, key_prefix)
    }
}

impl Default for ApiKeyService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_api_key_format() {
        let service = ApiKeyService::new();
        let key = service.generate_api_key();

        assert!(key.starts_with(API_KEY_PREFIX));
        assert_eq!(key.len(), API_KEY_PREFIX.len() + API_KEY_HEX_LENGTH);
    }

    #[test]
    fn test_generate_api_key_unique() {
        let service = ApiKeyService::new();
        let key1 = service.generate_api_key();
        let key2 = service.generate_api_key();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_hash_api_key() {
        let service = ApiKeyService::new();
        let key = "xavyo_sk_live_test123";
        let hash = service.hash_api_key(key);

        // SHA-256 produces 64 hex characters
        assert_eq!(hash.len(), 64);

        // Same input should produce same hash
        let hash2 = service.hash_api_key(key);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_hash_different_keys() {
        let service = ApiKeyService::new();
        let hash1 = service.hash_api_key("key1");
        let hash2 = service.hash_api_key("key2");

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_create_key_pair() {
        let service = ApiKeyService::new();
        let (plaintext, hash, prefix) = service.create_key_pair();

        assert!(plaintext.starts_with(API_KEY_PREFIX));
        assert_eq!(hash.len(), 64);
        assert_eq!(prefix, API_KEY_PREFIX);

        // Verify the hash matches the plaintext
        let computed_hash = service.hash_api_key(&plaintext);
        assert_eq!(hash, computed_hash);
    }
}
