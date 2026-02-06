//! In-memory LRU cache for token revocation lookups (F082).
//!
//! Uses `moka` async cache to avoid per-request database queries for
//! revocation checks. Cache miss falls through to DB.
//!
//! - Max entries: 10,000
//! - TTL: 30 seconds
//! - On new revocation: invalidate the cache entry

use moka::future::Cache;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use xavyo_db::models::RevokedToken;

/// Maximum number of entries in the revocation cache.
const MAX_CACHE_ENTRIES: u64 = 10_000;

/// Time-to-live for cache entries (seconds).
const CACHE_TTL_SECONDS: u64 = 30;

/// In-memory LRU cache for revoked token JTIs.
///
/// Wraps a `moka::future::Cache<String, bool>` where:
/// - Key: JTI string
/// - Value: true = revoked, false = not revoked
#[derive(Clone)]
pub struct RevocationCache {
    cache: Cache<String, bool>,
    pool: Arc<PgPool>,
}

impl RevocationCache {
    /// Create a new revocation cache.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        let cache = Cache::builder()
            .max_capacity(MAX_CACHE_ENTRIES)
            .time_to_live(Duration::from_secs(CACHE_TTL_SECONDS))
            .build();

        Self {
            cache,
            pool: Arc::new(pool),
        }
    }

    /// Check if a JTI has been revoked.
    ///
    /// Checks cache first; on miss, falls through to DB and caches the result.
    /// Returns `Ok(true)` if the token is revoked.
    pub async fn is_revoked(&self, jti: &str) -> Result<bool, sqlx::Error> {
        // Check cache first
        if let Some(revoked) = self.cache.get(jti).await {
            return Ok(revoked);
        }

        // Cache miss — query DB
        let revoked = RevokedToken::is_revoked(&*self.pool, jti).await?;

        // Cache the result
        self.cache.insert(jti.to_string(), revoked).await;

        Ok(revoked)
    }

    /// Invalidate a cache entry (call after new revocation).
    ///
    /// This ensures the next `is_revoked()` call will hit the DB
    /// and see the freshly revoked token.
    pub async fn invalidate(&self, jti: &str) {
        // Insert as revoked immediately so next check doesn't need DB
        self.cache.insert(jti.to_string(), true).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_constants() {
        assert_eq!(MAX_CACHE_ENTRIES, 10_000);
        assert_eq!(CACHE_TTL_SECONDS, 30);
    }
}
