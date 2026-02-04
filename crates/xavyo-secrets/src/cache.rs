//! In-memory secret cache with per-entry TTL.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::sync::RwLock;

use crate::{SecretError, SecretProvider, SecretValue};

/// Internal cache entry wrapping a `SecretValue` with TTL metadata.
#[derive(Debug, Clone)]
pub struct CachedSecret {
    /// The cached secret value.
    pub secret: SecretValue,
    /// When this cache entry expires.
    pub expires_at: DateTime<Utc>,
    /// Last refresh attempt time (for retry backoff).
    pub refresh_attempted_at: Option<DateTime<Utc>>,
}

/// Cache statistics for health reporting.
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Total number of cached entries.
    pub total_count: usize,
    /// Number of expired entries still in cache.
    pub expired_count: usize,
}

/// In-memory TTL cache for secrets.
#[derive(Debug)]
pub struct SecretCache {
    entries: RwLock<HashMap<String, CachedSecret>>,
    ttl_seconds: u64,
}

impl SecretCache {
    /// Create a new cache with the given TTL in seconds.
    #[must_use] 
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl_seconds,
        }
    }

    /// Get a cached secret by name, if it exists and is not expired.
    pub async fn get(&self, name: &str) -> Option<SecretValue> {
        let entries = self.entries.read().await;
        entries.get(name).and_then(|cached| {
            if Utc::now() < cached.expires_at {
                Some(cached.secret.clone())
            } else {
                None
            }
        })
    }

    /// Get a cached secret even if expired (for degraded mode).
    pub async fn get_even_expired(&self, name: &str) -> Option<SecretValue> {
        let entries = self.entries.read().await;
        entries.get(name).map(|cached| cached.secret.clone())
    }

    /// Store a secret in the cache.
    pub async fn set(&self, secret: SecretValue) {
        let expires_at = Utc::now() + chrono::Duration::seconds(self.ttl_seconds as i64);
        let name = secret.name.clone();
        let cached = CachedSecret {
            secret,
            expires_at,
            refresh_attempted_at: None,
        };
        let mut entries = self.entries.write().await;
        entries.insert(name, cached);
    }

    /// Invalidate a cache entry by name.
    pub async fn invalidate(&self, name: &str) {
        let mut entries = self.entries.write().await;
        entries.remove(name);
    }

    /// Remove all expired entries from the cache.
    pub async fn clear_expired(&self) {
        let now = Utc::now();
        let mut entries = self.entries.write().await;
        entries.retain(|_, cached| cached.expires_at > now);
    }

    /// Get cache statistics.
    pub async fn stats(&self) -> CacheStats {
        let now = Utc::now();
        let entries = self.entries.read().await;
        let total_count = entries.len();
        let expired_count = entries.values().filter(|c| c.expires_at <= now).count();
        CacheStats {
            total_count,
            expired_count,
        }
    }
}

/// A `SecretProvider` wrapper that adds TTL-based caching to any inner provider.
pub struct CachedSecretProvider {
    inner: Arc<dyn SecretProvider>,
    cache: SecretCache,
}

impl CachedSecretProvider {
    /// Create a new cached provider wrapping the given inner provider.
    pub fn new(inner: Arc<dyn SecretProvider>, cache_ttl_seconds: u64) -> Self {
        Self {
            inner,
            cache: SecretCache::new(cache_ttl_seconds),
        }
    }

    /// Get cache statistics for health checking.
    pub async fn cache_stats(&self) -> CacheStats {
        self.cache.stats().await
    }

    /// Get a reference to the inner provider.
    pub fn inner(&self) -> &Arc<dyn SecretProvider> {
        &self.inner
    }

    /// Invalidate a cached entry, forcing the next get to go to the provider.
    pub async fn invalidate(&self, name: &str) {
        self.cache.invalidate(name).await;
    }
}

impl std::fmt::Debug for CachedSecretProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedSecretProvider")
            .field("provider_type", &self.inner.provider_type())
            .finish()
    }
}

#[async_trait]
impl SecretProvider for CachedSecretProvider {
    async fn get_secret(&self, name: &str) -> Result<SecretValue, SecretError> {
        // Check cache first
        if let Some(cached) = self.cache.get(name).await {
            tracing::debug!(secret_name = name, "Secret cache hit");
            return Ok(cached);
        }

        tracing::debug!(
            secret_name = name,
            "Secret cache miss, fetching from provider"
        );

        // Try to fetch from inner provider
        match self.inner.get_secret(name).await {
            Ok(secret) => {
                tracing::info!(
                    secret_name = name,
                    provider = self.inner.provider_type(),
                    "Secret loaded from provider"
                );
                self.cache.set(secret.clone()).await;
                Ok(secret)
            }
            Err(e) => {
                // On provider failure, try to return expired cached value (degraded mode)
                if let Some(stale) = self.cache.get_even_expired(name).await {
                    tracing::warn!(
                        secret_name = name,
                        provider = self.inner.provider_type(),
                        error = %e,
                        "Provider unavailable, using stale cached secret"
                    );
                    return Ok(stale);
                }
                Err(e)
            }
        }
    }

    async fn health_check(&self) -> Result<bool, SecretError> {
        self.inner.health_check().await
    }

    fn provider_type(&self) -> &'static str {
        self.inner.provider_type()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_set_and_get() {
        let cache = SecretCache::new(300);
        let secret = SecretValue::new("test_key", b"test_value".to_vec());
        cache.set(secret).await;

        let result = cache.get("test_key").await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().as_str().unwrap(), "test_value");
    }

    #[tokio::test]
    async fn test_cache_miss() {
        let cache = SecretCache::new(300);
        let result = cache.get("nonexistent").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_cache_expired() {
        // TTL of 0 seconds means immediate expiry
        let cache = SecretCache::new(0);
        let secret = SecretValue::new("test_key", b"test_value".to_vec());
        cache.set(secret).await;

        // Sleep briefly to ensure expiry
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // Regular get should return None (expired)
        let result = cache.get("test_key").await;
        assert!(result.is_none());

        // get_even_expired should still return the value
        let result = cache.get_even_expired("test_key").await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_cache_invalidate() {
        let cache = SecretCache::new(300);
        let secret = SecretValue::new("test_key", b"test_value".to_vec());
        cache.set(secret).await;

        assert!(cache.get("test_key").await.is_some());
        cache.invalidate("test_key").await;
        assert!(cache.get("test_key").await.is_none());
    }

    #[tokio::test]
    async fn test_cache_clear_expired() {
        let cache = SecretCache::new(0);
        cache.set(SecretValue::new("key1", b"v1".to_vec())).await;
        cache.set(SecretValue::new("key2", b"v2".to_vec())).await;

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let stats = cache.stats().await;
        assert_eq!(stats.total_count, 2);
        assert_eq!(stats.expired_count, 2);

        cache.clear_expired().await;

        let stats = cache.stats().await;
        assert_eq!(stats.total_count, 0);
        assert_eq!(stats.expired_count, 0);
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let cache = SecretCache::new(300);
        cache.set(SecretValue::new("key1", b"v1".to_vec())).await;
        cache.set(SecretValue::new("key2", b"v2".to_vec())).await;

        let stats = cache.stats().await;
        assert_eq!(stats.total_count, 2);
        assert_eq!(stats.expired_count, 0);
    }
}
