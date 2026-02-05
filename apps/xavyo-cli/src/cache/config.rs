//! Cache configuration for offline mode

use serde::{Deserialize, Serialize};

/// Default TTL in seconds (1 hour)
pub const DEFAULT_TTL_SECONDS: u64 = 3600;

/// Default maximum cache size in bytes (10MB)
pub const DEFAULT_MAX_SIZE_BYTES: u64 = 10 * 1024 * 1024;

/// User-configurable cache settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Default TTL in seconds (default: 3600 = 1 hour)
    pub default_ttl_seconds: u64,
    /// Maximum cache size in bytes (default: 10MB)
    pub max_size_bytes: u64,
    /// Whether offline mode/caching is enabled
    pub enabled: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            default_ttl_seconds: DEFAULT_TTL_SECONDS,
            max_size_bytes: DEFAULT_MAX_SIZE_BYTES,
            enabled: true,
        }
    }
}

impl CacheConfig {
    /// Create a new cache config with custom TTL
    #[allow(dead_code)]
    pub fn with_ttl(ttl_seconds: u64) -> Self {
        Self {
            default_ttl_seconds: ttl_seconds,
            ..Default::default()
        }
    }

    /// Check if caching is enabled
    #[allow(dead_code)]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_cache_config() {
        let config = CacheConfig::default();
        assert_eq!(config.default_ttl_seconds, DEFAULT_TTL_SECONDS);
        assert_eq!(config.max_size_bytes, DEFAULT_MAX_SIZE_BYTES);
        assert!(config.enabled);
    }

    #[test]
    fn test_cache_config_with_ttl() {
        let config = CacheConfig::with_ttl(7200);
        assert_eq!(config.default_ttl_seconds, 7200);
        assert!(config.enabled);
    }

    #[test]
    fn test_cache_config_is_enabled() {
        let mut config = CacheConfig::default();
        assert!(config.is_enabled());

        config.enabled = false;
        assert!(!config.is_enabled());
    }
}
