//! Branding management service (F030).
//!
//! Handles tenant branding operations: view, update, and public access.

use crate::error::ApiAuthError;
use crate::models::{BrandingResponse, PublicBrandingResponse, UpdateBrandingRequest};
use crate::services::{css_sanitizer, validators};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;
use xavyo_core::TenantId;
use xavyo_db::models::{PublicBranding, TenantBranding, UpdateBranding};
use xavyo_db::set_tenant_context;

/// Cache entry with timestamp for TTL-based expiration.
#[derive(Clone)]
struct CacheEntry {
    data: PublicBrandingResponse,
    inserted_at: Instant,
}

/// Branding management service.
#[derive(Clone)]
pub struct BrandingService {
    pool: PgPool,
    /// Cache for public branding by tenant slug, with 5-minute TTL.
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    /// Cache TTL duration.
    cache_ttl: Duration,
}

impl BrandingService {
    /// Create a new branding service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Create a new branding service with custom cache TTL.
    #[must_use] 
    pub fn with_cache_ttl(pool: PgPool, ttl_secs: u64) -> Self {
        Self {
            pool,
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_ttl: Duration::from_secs(ttl_secs),
        }
    }

    // ========================================================================
    // User Story 1: Configure Visual Branding
    // ========================================================================

    /// Get branding configuration for a tenant.
    pub async fn get_branding(&self, tenant_id: Uuid) -> Result<BrandingResponse, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let branding = TenantBranding::find_by_tenant(&self.pool, tenant_id)
            .await
            .map_err(ApiAuthError::Database)?;

        // Return existing branding or default values
        match branding {
            Some(b) => Ok(BrandingResponse::from(b)),
            None => Ok(BrandingResponse::default_for_tenant(tenant_id)),
        }
    }

    /// Update branding configuration for a tenant.
    pub async fn update_branding(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        request: UpdateBrandingRequest,
    ) -> Result<BrandingResponse, ApiAuthError> {
        // Validate all color fields
        let color_fields = [
            ("primary_color", &request.primary_color),
            ("secondary_color", &request.secondary_color),
            ("accent_color", &request.accent_color),
            ("background_color", &request.background_color),
            ("text_color", &request.text_color),
        ];
        for (field_name, color_opt) in color_fields {
            if let Some(ref color) = color_opt {
                if !validators::validate_hex_color(color) {
                    return Err(ApiAuthError::Validation(format!(
                        "Invalid {field_name} format: {color}. Use #RGB or #RRGGBB"
                    )));
                }
            }
        }

        // Validate all URL fields
        let url_fields = [
            ("logo_url", &request.logo_url),
            ("logo_dark_url", &request.logo_dark_url),
            ("favicon_url", &request.favicon_url),
            ("email_logo_url", &request.email_logo_url),
            (
                "login_page_background_url",
                &request.login_page_background_url,
            ),
            ("privacy_policy_url", &request.privacy_policy_url),
            ("terms_of_service_url", &request.terms_of_service_url),
            ("support_url", &request.support_url),
        ];
        for (field_name, url_opt) in url_fields {
            if let Some(ref url) = url_opt {
                if !validators::validate_url(url) {
                    return Err(ApiAuthError::Validation(format!(
                        "Invalid {field_name} format. Use absolute URL or /relative/path"
                    )));
                }
            }
        }

        // Validate font family if provided
        if let Some(ref font) = request.font_family {
            if !validators::validate_font_family(font) {
                return Err(ApiAuthError::Validation(
                    "Invalid font_family format".to_string(),
                ));
            }
        }

        // Sanitize custom CSS if provided
        let sanitized_css = if let Some(ref css) = request.custom_css {
            Some(css_sanitizer::sanitize_css(css)?)
        } else {
            None
        };

        // Set tenant context
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Normalize hex colors to uppercase #RRGGBB format
        let update_data = UpdateBranding {
            logo_url: request.logo_url,
            logo_dark_url: request.logo_dark_url,
            favicon_url: request.favicon_url,
            email_logo_url: request.email_logo_url,
            primary_color: request
                .primary_color
                .and_then(|c| validators::normalize_hex_color(&c)),
            secondary_color: request
                .secondary_color
                .and_then(|c| validators::normalize_hex_color(&c)),
            accent_color: request
                .accent_color
                .and_then(|c| validators::normalize_hex_color(&c)),
            background_color: request
                .background_color
                .and_then(|c| validators::normalize_hex_color(&c)),
            text_color: request
                .text_color
                .and_then(|c| validators::normalize_hex_color(&c)),
            font_family: request.font_family,
            custom_css: sanitized_css,
            login_page_title: request.login_page_title,
            login_page_subtitle: request.login_page_subtitle,
            login_page_background_url: request.login_page_background_url,
            footer_text: request.footer_text,
            privacy_policy_url: request.privacy_policy_url,
            terms_of_service_url: request.terms_of_service_url,
            support_url: request.support_url,
        };

        let branding = TenantBranding::upsert(&self.pool, tenant_id, update_data, Some(user_id))
            .await
            .map_err(ApiAuthError::Database)?;

        // Invalidate cache for this tenant
        self.invalidate_cache_for_tenant(tenant_id).await;

        info!(
            tenant_id = %tenant_id,
            user_id = %user_id,
            "Branding updated"
        );

        Ok(BrandingResponse::from(branding))
    }

    // ========================================================================
    // Public Branding Endpoint
    // ========================================================================

    /// Get public branding by tenant slug (for login pages).
    /// Uses caching with 5-minute TTL.
    pub async fn get_public_branding(
        &self,
        tenant_slug: &str,
    ) -> Result<PublicBrandingResponse, ApiAuthError> {
        // Check cache first
        if let Some(cached) = self.get_from_cache(tenant_slug).await {
            return Ok(cached);
        }

        // Fetch from database
        let branding = TenantBranding::find_by_slug(&self.pool, tenant_slug)
            .await
            .map_err(ApiAuthError::Database)?;

        let response = if let Some(b) = branding {
            let public: PublicBranding = b.into();
            PublicBrandingResponse::from(public)
        } else {
            // Check if tenant exists
            let tenant_exists = self.check_tenant_exists_by_slug(tenant_slug).await?;
            if !tenant_exists {
                return Err(ApiAuthError::TenantSlugNotFound);
            }
            // Tenant exists but no branding - return defaults
            PublicBrandingResponse::default()
        };

        // Store in cache
        self.store_in_cache(tenant_slug, response.clone()).await;

        Ok(response)
    }

    // ========================================================================
    // Cache Management
    // ========================================================================

    /// Get cached branding if not expired.
    async fn get_from_cache(&self, slug: &str) -> Option<PublicBrandingResponse> {
        let cache = self.cache.read().await;
        if let Some(entry) = cache.get(slug) {
            if entry.inserted_at.elapsed() < self.cache_ttl {
                return Some(entry.data.clone());
            }
        }
        None
    }

    /// Store branding in cache.
    async fn store_in_cache(&self, slug: &str, data: PublicBrandingResponse) {
        let mut cache = self.cache.write().await;
        cache.insert(
            slug.to_string(),
            CacheEntry {
                data,
                inserted_at: Instant::now(),
            },
        );
    }

    /// Invalidate cache entries for a tenant.
    async fn invalidate_cache_for_tenant(&self, tenant_id: Uuid) {
        // Get tenant slug to invalidate the right cache entry
        match self.get_tenant_slug(tenant_id).await {
            Ok(Some(slug)) => {
                let mut cache = self.cache.write().await;
                cache.remove(&slug);
                info!(tenant_id = %tenant_id, slug = %slug, "Cache invalidated");
            }
            Ok(None) => {
                warn!(tenant_id = %tenant_id, "Could not find tenant slug for cache invalidation");
            }
            Err(e) => {
                warn!(tenant_id = %tenant_id, error = %e, "Error finding tenant slug for cache invalidation");
            }
        }
    }

    /// Clear all cached branding data.
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
        info!("Branding cache cleared");
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Check if a tenant exists by slug.
    async fn check_tenant_exists_by_slug(&self, slug: &str) -> Result<bool, ApiAuthError> {
        let result: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM tenants WHERE slug = $1")
            .bind(slug)
            .fetch_optional(&self.pool)
            .await
            .map_err(ApiAuthError::Database)?;
        Ok(result.is_some())
    }

    /// Get tenant slug by ID.
    async fn get_tenant_slug(&self, tenant_id: Uuid) -> Result<Option<String>, ApiAuthError> {
        let result: Option<(String,)> = sqlx::query_as("SELECT slug FROM tenants WHERE id = $1")
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(ApiAuthError::Database)?;
        Ok(result.map(|(slug,)| slug))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_color_validation() {
        assert!(validators::validate_hex_color("#abc"));
        assert!(validators::validate_hex_color("#AABBCC"));
        assert!(!validators::validate_hex_color("abc"));
        assert!(!validators::validate_hex_color("#abcde"));
    }

    #[test]
    fn test_url_validation() {
        assert!(validators::validate_url("/assets/logo.png"));
        assert!(validators::validate_url("https://example.com/logo.png"));
        assert!(!validators::validate_url("not-a-url"));
    }

    #[tokio::test]
    async fn test_cache_entry_creation() {
        let entry = CacheEntry {
            data: PublicBrandingResponse::default(),
            inserted_at: Instant::now(),
        };
        assert!(entry.inserted_at.elapsed() < Duration::from_secs(1));
    }
}
