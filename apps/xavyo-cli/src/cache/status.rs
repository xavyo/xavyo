//! Cache status information for the `xavyo cache status` command

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Status information about the cache
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct CacheStatus {
    /// Total size of all cache files in bytes
    pub total_size_bytes: u64,
    /// Number of cached entries
    pub entry_count: usize,
    /// List of cached resource types
    pub cached_resources: Vec<CachedResource>,
    /// Path to cache directory
    pub cache_dir: PathBuf,
    /// Default TTL in seconds
    pub default_ttl_seconds: u64,
}

#[allow(dead_code)]
impl CacheStatus {
    /// Get the total size as a human-readable string
    pub fn size_human(&self) -> String {
        let bytes = self.total_size_bytes;
        if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.1} KB", bytes as f64 / 1024.0)
        } else {
            format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
        }
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.entry_count == 0
    }
}

/// Information about a single cached resource
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedResource {
    /// Resource type (e.g., "agents", "tools")
    pub resource_type: String,
    /// When this resource was last cached
    pub cached_at: DateTime<Utc>,
    /// Whether this entry is expired
    pub is_expired: bool,
    /// File size in bytes
    pub size_bytes: u64,
}

impl CachedResource {
    /// Get the status as a string ("Fresh" or "Expired")
    pub fn status_str(&self) -> &'static str {
        if self.is_expired {
            "Expired"
        } else {
            "Fresh"
        }
    }

    /// Get the size as a human-readable string
    pub fn size_human(&self) -> String {
        let bytes = self.size_bytes;
        if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.1} KB", bytes as f64 / 1024.0)
        } else {
            format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_status_size_human() {
        let status = CacheStatus {
            total_size_bytes: 500,
            entry_count: 0,
            cached_resources: vec![],
            cache_dir: PathBuf::from("/tmp"),
            default_ttl_seconds: 3600,
        };
        assert_eq!(status.size_human(), "500 B");

        let status = CacheStatus {
            total_size_bytes: 2048,
            ..status
        };
        assert_eq!(status.size_human(), "2.0 KB");

        let status = CacheStatus {
            total_size_bytes: 5 * 1024 * 1024,
            ..status
        };
        assert_eq!(status.size_human(), "5.0 MB");
    }

    #[test]
    fn test_cache_status_is_empty() {
        let status = CacheStatus {
            total_size_bytes: 0,
            entry_count: 0,
            cached_resources: vec![],
            cache_dir: PathBuf::from("/tmp"),
            default_ttl_seconds: 3600,
        };
        assert!(status.is_empty());

        let status = CacheStatus {
            entry_count: 1,
            ..status
        };
        assert!(!status.is_empty());
    }

    #[test]
    fn test_cached_resource_status_str() {
        let resource = CachedResource {
            resource_type: "agents".to_string(),
            cached_at: Utc::now(),
            is_expired: false,
            size_bytes: 1000,
        };
        assert_eq!(resource.status_str(), "Fresh");

        let resource = CachedResource {
            is_expired: true,
            ..resource
        };
        assert_eq!(resource.status_str(), "Expired");
    }
}
