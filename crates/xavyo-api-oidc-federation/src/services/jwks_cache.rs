//! JWKS caching service for fetching and caching IdP signing keys.
//!
//! This service fetches JWKS (JSON Web Key Sets) from federated Identity Providers
//! and caches them to reduce network latency and improve token verification performance.

use crate::error::{FederationError, FederationResult};
use crate::models::{Jwk, JwkSet};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

/// Default TTL for cached JWKS (10 minutes).
pub const DEFAULT_JWKS_CACHE_TTL: Duration = Duration::from_secs(600);

/// Cached JWKS entry with TTL tracking.
#[derive(Debug, Clone)]
struct CachedJwks {
    keys: JwkSet,
    fetched_at: Instant,
    ttl: Duration,
}

impl CachedJwks {
    /// Check if this cache entry has expired.
    fn is_expired(&self) -> bool {
        self.fetched_at.elapsed() > self.ttl
    }
}

/// JWKS caching service.
///
/// Fetches and caches JWKS from IdP endpoints with configurable TTL.
#[derive(Clone)]
pub struct JwksCache {
    /// Cached JWKS keyed by JWKS URI.
    cache: Arc<RwLock<HashMap<String, CachedJwks>>>,
    /// Default TTL for cache entries.
    default_ttl: Duration,
    /// HTTP client for fetching JWKS.
    http_client: reqwest::Client,
}

/// Cache statistics for monitoring.
#[derive(Debug, Clone, Default)]
pub struct JwksCacheStats {
    /// Number of cache hits.
    pub cache_hits: u64,
    /// Number of cache misses.
    pub cache_misses: u64,
    /// Number of force refreshes.
    pub force_refreshes: u64,
    /// Number of entries currently cached.
    pub cached_entries: usize,
}

impl JwksCache {
    /// Create a new JWKS cache with default TTL.
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            default_ttl,
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("Failed to create HTTP client"),
        }
    }

    /// Create a new JWKS cache with custom HTTP client.
    pub fn with_client(default_ttl: Duration, http_client: reqwest::Client) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            default_ttl,
            http_client,
        }
    }

    /// Get keys from cache or fetch from the JWKS URI.
    ///
    /// Returns cached keys if available and not expired, otherwise fetches fresh keys.
    #[instrument(skip(self))]
    pub async fn get_keys(&self, jwks_uri: &str) -> FederationResult<JwkSet> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(jwks_uri) {
                if !cached.is_expired() {
                    debug!(jwks_uri = %jwks_uri, "JWKS cache hit");
                    return Ok(cached.keys.clone());
                }
            }
        }

        // Cache miss or expired - fetch fresh keys
        debug!(jwks_uri = %jwks_uri, "JWKS cache miss, fetching");
        self.fetch_and_cache(jwks_uri).await
    }

    /// Force refresh keys from the JWKS URI, bypassing cache.
    ///
    /// Use this when you suspect keys have rotated and need the latest version.
    #[instrument(skip(self))]
    pub async fn get_keys_force_refresh(&self, jwks_uri: &str) -> FederationResult<JwkSet> {
        info!(jwks_uri = %jwks_uri, "Force refreshing JWKS");
        self.fetch_and_cache(jwks_uri).await
    }

    /// Find a specific key by key ID (kid).
    ///
    /// Returns None if the key is not found in the cached JWKS.
    #[instrument(skip(self))]
    pub async fn find_key(&self, jwks_uri: &str, kid: &str) -> FederationResult<Option<Jwk>> {
        let jwks = self.get_keys(jwks_uri).await?;
        Ok(jwks.find_key(kid).cloned())
    }

    /// Find a signing key, optionally by kid.
    ///
    /// If kid is provided, finds that specific key. Otherwise, returns the first
    /// suitable RSA signing key.
    #[instrument(skip(self))]
    pub async fn find_signing_key(
        &self,
        jwks_uri: &str,
        kid: Option<&str>,
    ) -> FederationResult<Option<Jwk>> {
        let jwks = self.get_keys(jwks_uri).await?;
        Ok(jwks.find_signing_key(kid).cloned())
    }

    /// Clear all cached entries.
    pub async fn clear(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
        info!("JWKS cache cleared");
    }

    /// Remove a specific entry from the cache.
    pub async fn invalidate(&self, jwks_uri: &str) {
        let mut cache = self.cache.write().await;
        if cache.remove(jwks_uri).is_some() {
            debug!(jwks_uri = %jwks_uri, "JWKS cache entry invalidated");
        }
    }

    /// Get cache statistics.
    pub async fn stats(&self) -> JwksCacheStats {
        let cache = self.cache.read().await;
        JwksCacheStats {
            cached_entries: cache.len(),
            ..Default::default()
        }
    }

    /// Fetch JWKS from URI and update cache.
    async fn fetch_and_cache(&self, jwks_uri: &str) -> FederationResult<JwkSet> {
        let jwks = self.fetch_jwks(jwks_uri).await?;

        // Update cache
        let cached = CachedJwks {
            keys: jwks.clone(),
            fetched_at: Instant::now(),
            ttl: self.default_ttl,
        };

        let mut cache = self.cache.write().await;
        cache.insert(jwks_uri.to_string(), cached);

        info!(
            jwks_uri = %jwks_uri,
            key_count = jwks.keys.len(),
            "JWKS cached"
        );

        Ok(jwks)
    }

    /// Fetch JWKS from the given URI.
    async fn fetch_jwks(&self, jwks_uri: &str) -> FederationResult<JwkSet> {
        let response = self
            .http_client
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| FederationError::JwksFetchFailed(format!("HTTP error: {}", e)))?;

        if !response.status().is_success() {
            return Err(FederationError::JwksFetchFailed(format!(
                "HTTP status {}",
                response.status()
            )));
        }

        let jwks: JwkSet = response
            .json()
            .await
            .map_err(|e| FederationError::JwksFetchFailed(format!("JSON parse error: {}", e)))?;

        if jwks.keys.is_empty() {
            warn!(jwks_uri = %jwks_uri, "JWKS returned empty key set");
        }

        Ok(jwks)
    }
}

impl Default for JwksCache {
    fn default() -> Self {
        Self::new(DEFAULT_JWKS_CACHE_TTL)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_jwks_json() -> String {
        r#"{
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "key-1",
                    "alg": "RS256",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                    "e": "AQAB"
                }
            ]
        }"#
        .to_string()
    }

    #[tokio::test]
    async fn test_fetch_jwks() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(sample_jwks_json()))
            .mount(&mock_server)
            .await;

        let cache = JwksCache::new(Duration::from_secs(60));
        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());

        let result = cache.get_keys(&jwks_uri).await;
        assert!(result.is_ok());

        let jwks = result.unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kid, Some("key-1".to_string()));
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(sample_jwks_json()))
            .expect(1) // Should only be called once
            .mount(&mock_server)
            .await;

        let cache = JwksCache::new(Duration::from_secs(60));
        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());

        // First call - should fetch
        let result1 = cache.get_keys(&jwks_uri).await;
        assert!(result1.is_ok());

        // Second call - should hit cache
        let result2 = cache.get_keys(&jwks_uri).await;
        assert!(result2.is_ok());

        // Both should return the same keys
        assert_eq!(result1.unwrap().keys.len(), result2.unwrap().keys.len());
    }

    #[tokio::test]
    async fn test_force_refresh() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(sample_jwks_json()))
            .expect(2) // Should be called twice
            .mount(&mock_server)
            .await;

        let cache = JwksCache::new(Duration::from_secs(60));
        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());

        // First call
        let _ = cache.get_keys(&jwks_uri).await;

        // Force refresh
        let result = cache.get_keys_force_refresh(&jwks_uri).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_find_key() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(sample_jwks_json()))
            .mount(&mock_server)
            .await;

        let cache = JwksCache::new(Duration::from_secs(60));
        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());

        let key = cache.find_key(&jwks_uri, "key-1").await.unwrap();
        assert!(key.is_some());
        assert_eq!(key.unwrap().kid, Some("key-1".to_string()));

        let missing = cache.find_key(&jwks_uri, "key-999").await.unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_fetch_error() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let cache = JwksCache::new(Duration::from_secs(60));
        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());

        let result = cache.get_keys(&jwks_uri).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            FederationError::JwksFetchFailed(_)
        ));
    }

    #[tokio::test]
    async fn test_invalidate() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/.well-known/jwks.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(sample_jwks_json()))
            .expect(2) // Should be called twice after invalidation
            .mount(&mock_server)
            .await;

        let cache = JwksCache::new(Duration::from_secs(60));
        let jwks_uri = format!("{}/.well-known/jwks.json", mock_server.uri());

        // Fetch and cache
        let _ = cache.get_keys(&jwks_uri).await;

        // Invalidate
        cache.invalidate(&jwks_uri).await;

        // Should fetch again
        let result = cache.get_keys(&jwks_uri).await;
        assert!(result.is_ok());
    }
}
