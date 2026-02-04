//! Cache entry model for storing cached API responses

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Current cache format version
pub const CACHE_VERSION: u32 = 1;

/// A cached API response with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry<T> {
    /// The cached data
    pub data: T,
    /// When this entry was cached (RFC 3339 timestamp)
    pub cached_at: DateTime<Utc>,
    /// TTL in seconds (how long this entry is valid)
    pub ttl_seconds: u64,
    /// Cache format version for migration handling
    pub version: u32,
}

impl<T> CacheEntry<T> {
    /// Create a new cache entry with the given data and TTL
    pub fn new(data: T, ttl_seconds: u64) -> Self {
        Self {
            data,
            cached_at: Utc::now(),
            ttl_seconds,
            version: CACHE_VERSION,
        }
    }

    /// Check if this cache entry has expired
    pub fn is_expired(&self) -> bool {
        let expiry = self.cached_at + chrono::Duration::seconds(self.ttl_seconds as i64);
        Utc::now() > expiry
    }

    /// Check if this cache entry is stale (alias for is_expired)
    #[allow(dead_code)]
    pub fn is_stale(&self) -> bool {
        self.is_expired()
    }

    /// Get the age of this cache entry in seconds
    #[allow(dead_code)]
    pub fn age_seconds(&self) -> i64 {
        (Utc::now() - self.cached_at).num_seconds()
    }

    /// Get a human-readable age string (e.g., "5 minutes ago", "2 hours ago")
    #[allow(dead_code)]
    pub fn age_human(&self) -> String {
        let seconds = self.age_seconds();
        if seconds < 60 {
            format!("{} seconds ago", seconds)
        } else if seconds < 3600 {
            format!("{} minutes ago", seconds / 60)
        } else if seconds < 86400 {
            format!("{} hours ago", seconds / 3600)
        } else {
            format!("{} days ago", seconds / 86400)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_entry_new() {
        let entry = CacheEntry::new("test data".to_string(), 3600);
        assert_eq!(entry.data, "test data");
        assert_eq!(entry.ttl_seconds, 3600);
        assert_eq!(entry.version, CACHE_VERSION);
    }

    #[test]
    fn test_cache_entry_not_expired() {
        let entry = CacheEntry::new("test".to_string(), 3600);
        assert!(!entry.is_expired());
        assert!(!entry.is_stale());
    }

    #[test]
    fn test_cache_entry_expired() {
        let mut entry = CacheEntry::new("test".to_string(), 1);
        // Manually set cached_at to the past
        entry.cached_at = Utc::now() - chrono::Duration::seconds(10);
        assert!(entry.is_expired());
        assert!(entry.is_stale());
    }

    #[test]
    fn test_cache_entry_age() {
        let entry = CacheEntry::new("test".to_string(), 3600);
        // Age should be very small (just created)
        assert!(entry.age_seconds() < 2);
    }

    #[test]
    fn test_cache_entry_age_human() {
        let mut entry = CacheEntry::new("test".to_string(), 3600);

        // Just created
        assert!(entry.age_human().contains("seconds ago"));

        // Set to 5 minutes ago
        entry.cached_at = Utc::now() - chrono::Duration::minutes(5);
        assert!(entry.age_human().contains("minutes ago"));

        // Set to 2 hours ago
        entry.cached_at = Utc::now() - chrono::Duration::hours(2);
        assert!(entry.age_human().contains("hours ago"));

        // Set to 3 days ago
        entry.cached_at = Utc::now() - chrono::Duration::days(3);
        assert!(entry.age_human().contains("days ago"));
    }
}
