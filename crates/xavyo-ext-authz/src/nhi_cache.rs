use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use sqlx::PgPool;
use uuid::Uuid;
use xavyo_core::TenantId;

use xavyo_db::models::{GovNhiRiskScore, NhiAgent, NhiAgentWithIdentity, NhiIdentity};
use xavyo_nhi::NhiType;

/// Cache key for NHI lookups: (tenant_id, nhi_id).
type CacheKey = (TenantId, Uuid);

/// Cached NHI identity with related data.
#[derive(Debug, Clone)]
pub struct CachedNhi {
    pub identity: NhiIdentity,
    pub agent: Option<NhiAgentWithIdentity>,
    pub risk_score: Option<GovNhiRiskScore>,
}

/// In-memory cache for NHI identity lookups.
pub struct NhiCache {
    cache: Cache<CacheKey, Arc<CachedNhi>>,
}

impl NhiCache {
    /// Create a new NHI cache with the given TTL.
    pub fn new(ttl_secs: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(ttl_secs))
            .build();
        Self { cache }
    }

    /// Get or load an NHI identity with its related data.
    pub async fn get_or_load(
        &self,
        pool: &PgPool,
        tenant_id: TenantId,
        nhi_id: Uuid,
    ) -> Result<Option<Arc<CachedNhi>>, sqlx::Error> {
        let key = (tenant_id, nhi_id);

        if let Some(cached) = self.cache.get(&key).await {
            return Ok(Some(cached));
        }

        let tenant_uuid = *tenant_id.as_uuid();

        // Cache miss: load from database
        let identity = match NhiIdentity::find_by_id(pool, tenant_uuid, nhi_id).await? {
            Some(id) => id,
            None => return Ok(None),
        };

        // Load agent details if this is an agent
        let agent = if identity.nhi_type == NhiType::Agent {
            NhiAgent::find_by_nhi_id(pool, tenant_uuid, nhi_id).await?
        } else {
            None
        };

        // Load risk score
        let risk_score = GovNhiRiskScore::find_by_nhi(pool, tenant_uuid, nhi_id).await?;

        let cached = Arc::new(CachedNhi {
            identity,
            agent,
            risk_score,
        });

        self.cache.insert(key, Arc::clone(&cached)).await;

        Ok(Some(cached))
    }

    /// Invalidate a specific entry.
    pub async fn invalidate(&self, tenant_id: TenantId, nhi_id: Uuid) {
        self.cache.invalidate(&(tenant_id, nhi_id)).await;
    }

    /// Invalidate all entries.
    pub fn invalidate_all(&self) {
        self.cache.invalidate_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nhi_cache_creation() {
        let cache = NhiCache::new(60);
        // Just verify it doesn't panic
        cache.invalidate_all();
    }

    #[tokio::test]
    async fn test_nhi_cache_invalidation() {
        let cache = NhiCache::new(60);
        let tenant_id = TenantId::new();
        let nhi_id = Uuid::new_v4();

        // Invalidating a non-existent entry should not panic
        cache.invalidate(tenant_id, nhi_id).await;
        cache.invalidate_all();
    }
}
