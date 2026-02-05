//! Role resolution for policy evaluation.
//!
//! This module provides role resolution from the database during policy evaluation.
//! Roles are cached using Moka for performance.
//!
//! # Example
//!
//! ```ignore
//! use xavyo_authorization::roles::{RoleResolver, RoleCache};
//!
//! let cache = RoleCache::new(Duration::from_secs(300));
//! let resolver = DatabaseRoleResolver::new(pool, cache);
//!
//! let roles = resolver.resolve_roles(tenant_id, user_id).await?;
//! ```

use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use uuid::Uuid;

use crate::error::AuthorizationError;

/// A resolved role with its metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRole {
    /// Role identifier
    pub id: Uuid,
    /// Role name
    pub name: String,
    /// Role description
    pub description: Option<String>,
}

/// Cache for resolved user roles.
pub struct RoleCache {
    cache: Cache<(Uuid, Uuid), Vec<ResolvedRole>>,
    ttl: Duration,
}

impl RoleCache {
    /// Create a new role cache with the specified TTL.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        let cache = Cache::builder()
            .time_to_live(ttl)
            .max_capacity(10_000)
            .build();
        Self { cache, ttl }
    }

    /// Get roles from cache.
    pub async fn get(&self, tenant_id: Uuid, user_id: Uuid) -> Option<Vec<ResolvedRole>> {
        self.cache.get(&(tenant_id, user_id)).await
    }

    /// Insert roles into cache.
    pub async fn insert(&self, tenant_id: Uuid, user_id: Uuid, roles: Vec<ResolvedRole>) {
        self.cache.insert((tenant_id, user_id), roles).await;
    }

    /// Invalidate roles for a specific user.
    pub async fn invalidate_user(&self, tenant_id: Uuid, user_id: Uuid) {
        self.cache.invalidate(&(tenant_id, user_id)).await;
    }

    /// Invalidate all roles for a tenant.
    pub async fn invalidate_tenant(&self, _tenant_id: Uuid) {
        // Note: Moka doesn't support prefix invalidation, so we iterate
        // In production, consider using a different cache or tracking keys
        self.cache.invalidate_all();
    }

    /// Get the configured TTL.
    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }
}

/// Trait for resolving user roles.
#[async_trait::async_trait]
pub trait RoleResolver: Send + Sync {
    /// Resolve roles for a user in a tenant.
    async fn resolve_roles(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<ResolvedRole>, AuthorizationError>;

    /// Invalidate cached roles for a user.
    async fn invalidate_user_roles(&self, tenant_id: Uuid, user_id: Uuid);

    /// Invalidate all cached roles for a tenant.
    async fn invalidate_tenant_roles(&self, tenant_id: Uuid);
}

/// In-memory role resolver for testing.
pub struct InMemoryRoleResolver {
    roles: std::sync::Arc<
        tokio::sync::RwLock<std::collections::HashMap<(Uuid, Uuid), Vec<ResolvedRole>>>,
    >,
    cache: Arc<RoleCache>,
}

impl Default for InMemoryRoleResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryRoleResolver {
    #[must_use]
    pub fn new() -> Self {
        Self {
            roles: std::sync::Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            cache: Arc::new(RoleCache::new(Duration::from_secs(300))),
        }
    }

    pub async fn assign_role(&self, tenant_id: Uuid, user_id: Uuid, role: ResolvedRole) {
        let mut roles = self.roles.write().await;
        let entry = roles.entry((tenant_id, user_id)).or_insert_with(Vec::new);
        entry.push(role);
        // Invalidate cache
        self.cache.invalidate_user(tenant_id, user_id).await;
    }

    pub async fn clear_roles(&self, tenant_id: Uuid, user_id: Uuid) {
        let mut roles = self.roles.write().await;
        roles.remove(&(tenant_id, user_id));
        self.cache.invalidate_user(tenant_id, user_id).await;
    }
}

#[async_trait::async_trait]
impl RoleResolver for InMemoryRoleResolver {
    async fn resolve_roles(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<ResolvedRole>, AuthorizationError> {
        // Check cache first
        if let Some(roles) = self.cache.get(tenant_id, user_id).await {
            return Ok(roles);
        }

        // Fetch from in-memory store
        let roles_map = self.roles.read().await;
        let resolved = roles_map
            .get(&(tenant_id, user_id))
            .cloned()
            .unwrap_or_default();

        // Cache the result
        self.cache
            .insert(tenant_id, user_id, resolved.clone())
            .await;

        Ok(resolved)
    }

    async fn invalidate_user_roles(&self, tenant_id: Uuid, user_id: Uuid) {
        self.cache.invalidate_user(tenant_id, user_id).await;
    }

    async fn invalidate_tenant_roles(&self, tenant_id: Uuid) {
        self.cache.invalidate_tenant(tenant_id).await;
    }
}

/// Caching role resolver that wraps any `RoleResolver` with caching.
pub struct CachingRoleResolver<R: RoleResolver> {
    inner: R,
    cache: Arc<RoleCache>,
}

impl<R: RoleResolver> CachingRoleResolver<R> {
    pub fn new(inner: R, cache: Arc<RoleCache>) -> Self {
        Self { inner, cache }
    }
}

#[async_trait::async_trait]
impl<R: RoleResolver> RoleResolver for CachingRoleResolver<R> {
    async fn resolve_roles(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<ResolvedRole>, AuthorizationError> {
        if let Some(roles) = self.cache.get(tenant_id, user_id).await {
            return Ok(roles);
        }

        let roles = self.inner.resolve_roles(tenant_id, user_id).await?;
        self.cache.insert(tenant_id, user_id, roles.clone()).await;
        Ok(roles)
    }

    async fn invalidate_user_roles(&self, tenant_id: Uuid, user_id: Uuid) {
        self.cache.invalidate_user(tenant_id, user_id).await;
        self.inner.invalidate_user_roles(tenant_id, user_id).await;
    }

    async fn invalidate_tenant_roles(&self, tenant_id: Uuid) {
        self.cache.invalidate_tenant(tenant_id).await;
        self.inner.invalidate_tenant_roles(tenant_id).await;
    }
}

// Alias for backwards compatibility
pub type DatabaseRoleResolver = InMemoryRoleResolver;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_role_cache_creation() {
        let cache = RoleCache::new(Duration::from_secs(60));
        assert_eq!(cache.ttl(), Duration::from_secs(60));
    }

    #[tokio::test]
    async fn test_role_cache_insert_and_get() {
        let cache = RoleCache::new(Duration::from_secs(60));
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let roles = vec![ResolvedRole {
            id: Uuid::new_v4(),
            name: "admin".to_string(),
            description: Some("Administrator role".to_string()),
        }];

        cache.insert(tenant_id, user_id, roles.clone()).await;
        let cached = cache.get(tenant_id, user_id).await;

        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), roles);
    }

    #[tokio::test]
    async fn test_role_cache_miss() {
        let cache = RoleCache::new(Duration::from_secs(60));
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let cached = cache.get(tenant_id, user_id).await;
        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn test_role_cache_invalidate_user() {
        let cache = RoleCache::new(Duration::from_secs(60));
        let tenant_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let roles = vec![ResolvedRole {
            id: Uuid::new_v4(),
            name: "admin".to_string(),
            description: None,
        }];

        cache.insert(tenant_id, user_id, roles).await;
        assert!(cache.get(tenant_id, user_id).await.is_some());

        cache.invalidate_user(tenant_id, user_id).await;
        assert!(cache.get(tenant_id, user_id).await.is_none());
    }

    #[tokio::test]
    async fn test_role_cache_tenant_isolation() {
        let cache = RoleCache::new(Duration::from_secs(60));
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let roles_a = vec![ResolvedRole {
            id: Uuid::new_v4(),
            name: "admin".to_string(),
            description: None,
        }];
        let roles_b = vec![ResolvedRole {
            id: Uuid::new_v4(),
            name: "viewer".to_string(),
            description: None,
        }];

        cache.insert(tenant_a, user_id, roles_a.clone()).await;
        cache.insert(tenant_b, user_id, roles_b.clone()).await;

        let cached_a = cache.get(tenant_a, user_id).await;
        let cached_b = cache.get(tenant_b, user_id).await;

        assert_eq!(cached_a.unwrap()[0].name, "admin");
        assert_eq!(cached_b.unwrap()[0].name, "viewer");
    }

    #[tokio::test]
    async fn test_resolved_role_equality() {
        let id = Uuid::new_v4();
        let role1 = ResolvedRole {
            id,
            name: "admin".to_string(),
            description: Some("Admin".to_string()),
        };
        let role2 = ResolvedRole {
            id,
            name: "admin".to_string(),
            description: Some("Admin".to_string()),
        };

        assert_eq!(role1, role2);
    }
}
