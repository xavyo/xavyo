//! In-memory caches for authorization policies and entitlement action mappings.
//!
//! Uses moka for TTL-based caching to avoid hitting the database on every
//! authorization check. Caches are keyed by `tenant_id` and automatically
//! expire after 60 seconds.

use std::sync::Arc;

use moka::future::Cache;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::Result;
use crate::types::{ConditionData, PolicyWithConditions};
use xavyo_db::models::authorization_policy::AuthorizationPolicy;
use xavyo_db::models::entitlement_action_mapping::EntitlementActionMapping;
use xavyo_db::models::policy_condition::PolicyConditionRecord;

// ---------------------------------------------------------------------------
// PolicyCache
// ---------------------------------------------------------------------------

/// Cache of active policies (with conditions) per tenant.
///
/// Key: `tenant_id` (Uuid)
/// Value: Vec<PolicyWithConditions> (sorted: deny-first, then by priority)
/// TTL: 60 seconds
/// Max entries: 1000
pub struct PolicyCache {
    cache: Cache<Uuid, Arc<Vec<PolicyWithConditions>>>,
}

impl PolicyCache {
    /// Create a new policy cache.
    #[must_use] 
    pub fn new() -> Self {
        let cache = Cache::builder()
            .max_capacity(1000)
            .time_to_live(std::time::Duration::from_secs(60))
            .build();
        Self { cache }
    }

    /// Get active policies for a tenant, loading from DB on cache miss.
    pub async fn get_policies(
        &self,
        pool: &PgPool,
        tenant_id: Uuid,
    ) -> Result<Arc<Vec<PolicyWithConditions>>> {
        // Check cache first
        if let Some(cached) = self.cache.get(&tenant_id).await {
            return Ok(cached);
        }

        // Cache miss: load from database
        let policies = self.load_policies(pool, tenant_id).await?;
        let arc = Arc::new(policies);
        self.cache.insert(tenant_id, Arc::clone(&arc)).await;
        Ok(arc)
    }

    /// Invalidate the cache for a specific tenant.
    /// Call this when policies or conditions are modified.
    pub async fn invalidate(&self, tenant_id: Uuid) {
        self.cache.invalidate(&tenant_id).await;
    }

    /// Invalidate all cached entries.
    pub fn invalidate_all(&self) {
        self.cache.invalidate_all();
    }

    /// Load policies and their conditions from the database.
    async fn load_policies(
        &self,
        pool: &PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<PolicyWithConditions>> {
        // Load all active policies for the tenant (sorted: deny-first, then by priority)
        let policies = AuthorizationPolicy::find_active_by_tenant(pool, tenant_id).await?;

        let mut result = Vec::with_capacity(policies.len());
        for policy in policies {
            // Load conditions for each policy
            let condition_records =
                PolicyConditionRecord::find_by_policy_id(pool, tenant_id, policy.id).await?;

            let conditions = condition_records
                .into_iter()
                .map(|c| ConditionData {
                    id: c.id,
                    condition_type: c.condition_type,
                    attribute_path: c.attribute_path,
                    operator: c.operator,
                    value: c.value,
                })
                .collect();

            result.push(PolicyWithConditions {
                id: policy.id,
                tenant_id: policy.tenant_id,
                name: policy.name,
                effect: policy.effect,
                priority: policy.priority,
                status: policy.status,
                resource_type: policy.resource_type,
                action: policy.action,
                conditions,
            });
        }

        Ok(result)
    }
}

impl Default for PolicyCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MappingCache
// ---------------------------------------------------------------------------

/// Cache of entitlement-to-action mappings per tenant.
///
/// Key: `tenant_id` (Uuid)
/// Value: Vec<EntitlementActionMapping>
/// TTL: 60 seconds
/// Max entries: 1000
pub struct MappingCache {
    cache: Cache<Uuid, Arc<Vec<EntitlementActionMapping>>>,
}

impl MappingCache {
    /// Create a new mapping cache.
    #[must_use] 
    pub fn new() -> Self {
        let cache = Cache::builder()
            .max_capacity(1000)
            .time_to_live(std::time::Duration::from_secs(60))
            .build();
        Self { cache }
    }

    /// Get mappings for a tenant, loading from DB on cache miss.
    pub async fn get_mappings(
        &self,
        pool: &PgPool,
        tenant_id: Uuid,
    ) -> Result<Arc<Vec<EntitlementActionMapping>>> {
        // Check cache first
        if let Some(cached) = self.cache.get(&tenant_id).await {
            return Ok(cached);
        }

        // Cache miss: load from database
        let mappings = EntitlementActionMapping::find_by_tenant(pool, tenant_id).await?;
        let arc = Arc::new(mappings);
        self.cache.insert(tenant_id, Arc::clone(&arc)).await;
        Ok(arc)
    }

    /// Invalidate the cache for a specific tenant.
    /// Call this when mappings are modified.
    pub async fn invalidate(&self, tenant_id: Uuid) {
        self.cache.invalidate(&tenant_id).await;
    }

    /// Invalidate all cached entries.
    pub fn invalidate_all(&self) {
        self.cache.invalidate_all();
    }
}

impl Default for MappingCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_policy_cache_creation() {
        let cache = PolicyCache::new();
        // Invalidation on a non-existent key should not panic
        cache.invalidate(Uuid::new_v4()).await;
    }

    #[tokio::test]
    async fn test_mapping_cache_creation() {
        let cache = MappingCache::new();
        // Invalidation on a non-existent key should not panic
        cache.invalidate(Uuid::new_v4()).await;
    }

    #[test]
    fn test_policy_cache_default() {
        let _cache = PolicyCache::default();
    }

    #[test]
    fn test_mapping_cache_default() {
        let _cache = MappingCache::default();
    }

    #[test]
    fn test_invalidate_all() {
        let policy_cache = PolicyCache::new();
        policy_cache.invalidate_all();

        let mapping_cache = MappingCache::new();
        mapping_cache.invalidate_all();
    }
}
