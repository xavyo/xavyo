//! Home Realm Discovery (HRD) service.
//!
//! Determines which identity provider to use based on the user's email domain.

use crate::error::{FederationError, FederationResult};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::instrument;
use uuid::Uuid;
use xavyo_db::models::{IdentityProviderDomain, TenantIdentityProvider};

/// Cache entry for domain-to-IdP mapping.
#[derive(Debug, Clone)]
pub struct HrdCacheEntry {
    pub idp_id: Uuid,
    pub idp_name: String,
    pub issuer_url: String,
    pub cached_at: chrono::DateTime<chrono::Utc>,
}

/// Home Realm Discovery service.
#[derive(Clone)]
pub struct HrdService {
    pool: PgPool,
    /// Cache: `tenant_id` -> (domain -> `cache_entry`)
    cache: Arc<RwLock<HashMap<Uuid, HashMap<String, HrdCacheEntry>>>>,
    /// Cache TTL in seconds.
    cache_ttl_secs: i64,
}

impl HrdService {
    /// Create a new HRD service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl_secs: 300, // 5 minutes default
        }
    }

    /// Create a new HRD service with custom cache TTL.
    #[must_use] 
    pub fn with_cache_ttl(pool: PgPool, cache_ttl_secs: i64) -> Self {
        Self {
            pool,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl_secs,
        }
    }

    /// Discover the identity provider for an email address.
    #[instrument(skip(self))]
    pub async fn discover(
        &self,
        tenant_id: Uuid,
        email: &str,
    ) -> FederationResult<Option<HrdResult>> {
        let domain = Self::extract_domain(email)?;

        // Check cache first
        if let Some(cached) = self.get_from_cache(tenant_id, &domain).await {
            tracing::debug!(tenant_id = %tenant_id, domain = %domain, "HRD cache hit");
            return Ok(Some(HrdResult {
                idp_id: cached.idp_id,
                idp_name: cached.idp_name,
                issuer_url: cached.issuer_url,
                domain: domain.clone(),
            }));
        }

        tracing::debug!(tenant_id = %tenant_id, domain = %domain, "HRD cache miss, querying database");

        // Query database for domain mapping
        let result = self.lookup_domain(tenant_id, &domain).await?;

        // Cache the result if found
        if let Some(ref hrd_result) = result {
            self.add_to_cache(tenant_id, &domain, hrd_result).await;
        }

        Ok(result)
    }

    /// Extract domain from email address.
    fn extract_domain(email: &str) -> FederationResult<String> {
        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 {
            return Err(FederationError::InvalidEmail(email.to_string()));
        }
        let domain = parts[1].to_lowercase();
        if domain.is_empty() {
            return Err(FederationError::InvalidEmail(email.to_string()));
        }
        Ok(domain)
    }

    /// Lookup domain in database with priority ordering.
    async fn lookup_domain(
        &self,
        tenant_id: Uuid,
        domain: &str,
    ) -> FederationResult<Option<HrdResult>> {
        // Find domain mapping with highest priority for this tenant
        let domain_entry =
            IdentityProviderDomain::find_by_domain(&self.pool, tenant_id, domain).await?;

        let Some(domain_entry) = domain_entry else {
            return Ok(None);
        };

        // Get the identity provider
        let idp = TenantIdentityProvider::find_by_id_and_tenant(
            &self.pool,
            domain_entry.identity_provider_id,
            tenant_id,
        )
        .await?;

        let Some(idp) = idp else {
            tracing::warn!(
                tenant_id = %tenant_id,
                domain = %domain,
                idp_id = %domain_entry.identity_provider_id,
                "Domain maps to non-existent IdP"
            );
            return Ok(None);
        };

        // Check if IdP is enabled
        if !idp.is_enabled {
            tracing::debug!(
                tenant_id = %tenant_id,
                domain = %domain,
                idp_id = %idp.id,
                "IdP is disabled"
            );
            return Ok(None);
        }

        Ok(Some(HrdResult {
            idp_id: idp.id,
            idp_name: idp.name,
            issuer_url: idp.issuer_url,
            domain: domain.to_string(),
        }))
    }

    /// Get domain-to-IdP mapping from cache.
    async fn get_from_cache(&self, tenant_id: Uuid, domain: &str) -> Option<HrdCacheEntry> {
        let cache = self.cache.read().await;
        let tenant_cache = cache.get(&tenant_id)?;
        let entry = tenant_cache.get(domain)?;

        // Check if cache entry is still valid
        let now = chrono::Utc::now();
        let age = now.signed_duration_since(entry.cached_at);
        if age.num_seconds() > self.cache_ttl_secs {
            return None;
        }

        Some(entry.clone())
    }

    /// Add domain-to-IdP mapping to cache.
    async fn add_to_cache(&self, tenant_id: Uuid, domain: &str, result: &HrdResult) {
        let entry = HrdCacheEntry {
            idp_id: result.idp_id,
            idp_name: result.idp_name.clone(),
            issuer_url: result.issuer_url.clone(),
            cached_at: chrono::Utc::now(),
        };

        let mut cache = self.cache.write().await;
        let tenant_cache = cache.entry(tenant_id).or_default();
        tenant_cache.insert(domain.to_string(), entry);
    }

    /// Clear cache for a specific tenant.
    pub async fn clear_tenant_cache(&self, tenant_id: Uuid) {
        let mut cache = self.cache.write().await;
        cache.remove(&tenant_id);
        tracing::info!(tenant_id = %tenant_id, "Cleared HRD cache for tenant");
    }

    /// Clear all caches.
    pub async fn clear_all_caches(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
        tracing::info!("Cleared all HRD caches");
    }

    /// Invalidate cache for a specific domain in a tenant.
    pub async fn invalidate_domain(&self, tenant_id: Uuid, domain: &str) {
        let mut cache = self.cache.write().await;
        if let Some(tenant_cache) = cache.get_mut(&tenant_id) {
            tenant_cache.remove(domain);
            tracing::debug!(tenant_id = %tenant_id, domain = %domain, "Invalidated HRD cache entry");
        }
    }
}

/// Result of Home Realm Discovery.
#[derive(Debug, Clone)]
pub struct HrdResult {
    /// Identity provider ID.
    pub idp_id: Uuid,
    /// Identity provider name.
    pub idp_name: String,
    /// Issuer URL for the `IdP`.
    pub issuer_url: String,
    /// Domain that matched.
    pub domain: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            HrdService::extract_domain("user@example.com").unwrap(),
            "example.com"
        );
        assert_eq!(
            HrdService::extract_domain("USER@EXAMPLE.COM").unwrap(),
            "example.com"
        );
        assert_eq!(
            HrdService::extract_domain("test@sub.domain.co.uk").unwrap(),
            "sub.domain.co.uk"
        );
    }

    #[test]
    fn test_extract_domain_invalid() {
        assert!(HrdService::extract_domain("invalid").is_err());
        assert!(HrdService::extract_domain("no@").is_err());
        assert!(HrdService::extract_domain("@nodomain").is_ok()); // Domain part is "nodomain"
        assert!(HrdService::extract_domain("multiple@at@signs").is_err());
    }
}
