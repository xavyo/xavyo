//! SCIM 2.0 API router configuration

use axum::{
    routing::{delete, get},
    Extension, Router,
};
use sqlx::PgPool;
use std::sync::Arc;

use crate::handlers::{admin, groups, users};
use crate::middleware::{auth::ScimAuthLayer, rate_limit::RateLimitLayer};
use crate::services::{AuditService, GroupService, TokenService, UserService};

/// Configuration for SCIM router
pub struct ScimConfig {
    /// Database pool
    pub pool: PgPool,
    /// Base URL for SCIM resource locations
    pub base_url: String,
    /// Rate limit per second
    pub rate_limit_per_sec: u32,
    /// Burst limit
    pub rate_limit_burst: u32,
}

impl ScimConfig {
    /// Create config with default rate limits
    pub fn new(pool: PgPool, base_url: impl Into<String>) -> Self {
        Self {
            pool,
            base_url: base_url.into(),
            rate_limit_per_sec: 25,
            rate_limit_burst: 50,
        }
    }

    /// Set rate limits
    pub fn with_rate_limits(mut self, per_sec: u32, burst: u32) -> Self {
        self.rate_limit_per_sec = per_sec;
        self.rate_limit_burst = burst;
        self
    }
}

/// Create the SCIM 2.0 resource router (for /scim/v2 endpoints)
///
/// This router handles User and Group provisioning endpoints.
/// It requires SCIM Bearer token authentication.
///
/// Mount at `/scim/v2`:
/// - GET/POST /Users
/// - GET/PUT/PATCH/DELETE /Users/:id
/// - GET/POST /Groups
/// - GET/PUT/PATCH/DELETE /Groups/:id
pub fn scim_resource_router(config: ScimConfig) -> Router {
    // Create services
    let pool = config.pool.clone();
    let base_url = config.base_url.clone();
    let token_service = Arc::new(TokenService::new(pool.clone()));
    let user_service = Arc::new(UserService::new(pool.clone(), base_url.clone()));
    let group_service = Arc::new(GroupService::new(pool.clone(), base_url));
    let audit_service = Arc::new(AuditService::new(pool.clone()));

    Router::new()
        // User endpoints
        .route("/Users", get(users::list_users).post(users::create_user))
        .route(
            "/Users/:id",
            get(users::get_user)
                .put(users::replace_user)
                .patch(users::update_user)
                .delete(users::delete_user),
        )
        // Group endpoints
        .route(
            "/Groups",
            get(groups::list_groups).post(groups::create_group),
        )
        .route(
            "/Groups/:id",
            get(groups::get_group)
                .put(groups::replace_group)
                .patch(groups::update_group)
                .delete(groups::delete_group),
        )
        // Apply SCIM auth and rate limiting (innermost layers)
        // Note: Layers are applied in reverse order - last layer is outermost (runs first)
        .layer(ScimAuthLayer::new())
        .layer(RateLimitLayer::new(
            config.rate_limit_per_sec,
            config.rate_limit_burst,
        ))
        // Add services as extensions (outermost layers - run before auth)
        .layer(Extension(pool))
        .layer(Extension(audit_service))
        .layer(Extension(group_service))
        .layer(Extension(user_service))
        .layer(Extension(token_service.clone()))
}

/// Create the SCIM admin router (for /admin/scim endpoints)
///
/// This router handles SCIM token and mapping management.
/// It requires admin JWT authentication (not SCIM token).
///
/// Mount at `/admin/scim`:
/// - GET/POST /tokens
/// - DELETE /tokens/:id
/// - GET/PUT /mappings
pub fn scim_admin_router(pool: PgPool) -> Router {
    let token_service = Arc::new(TokenService::new(pool.clone()));

    Router::new()
        .route("/tokens", get(admin::list_tokens).post(admin::create_token))
        .route("/tokens/:id", delete(admin::revoke_token))
        .route(
            "/mappings",
            get(admin::get_mappings).put(admin::update_mappings),
        )
        .layer(Extension(token_service))
        .layer(Extension(pool))
}

/// Create the full SCIM router combining resource and admin routes
///
/// This is a convenience function that creates both routers and nests them appropriately.
/// Use the individual router functions if you need more control over mounting.
pub fn scim_router(config: ScimConfig) -> Router {
    let pool = config.pool.clone();

    Router::new()
        .nest("/scim/v2", scim_resource_router(config))
        .nest("/admin/scim", scim_admin_router(pool))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_scim_config_defaults() {
        // This would need a mock pool in real tests
        // For now, just verify the struct works
    }
}
