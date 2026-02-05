//! Router configuration for tenant provisioning API.

use axum::{
    middleware,
    routing::{delete, get, patch, post},
    Extension, Router,
};
use sqlx::PgPool;
use std::sync::Arc;
use xavyo_api_auth::middleware::RateLimiter;

use crate::handlers::{
    accept_invitation_handler, cancel_downgrade_handler, cancel_invitation_handler,
    create_api_key_handler, create_invitation_handler, deactivate_api_key_handler,
    deactivate_oauth_client_handler, delete_tenant_handler, downgrade_plan_handler,
    get_api_key_usage_handler, get_plan_history_handler, get_settings_handler,
    get_tenant_status_handler, get_tenant_usage_handler, get_tenant_usage_history_handler,
    get_tenant_user_settings_handler, introspect_api_key_handler, list_api_keys_handler,
    list_deleted_tenants_handler, list_invitations_handler, list_oauth_clients_handler,
    list_plans_handler, provision_handler, reactivate_tenant_handler, restore_tenant_handler,
    rotate_api_key_handler, rotate_oauth_secret_handler, suspend_tenant_handler,
    update_settings_handler, update_tenant_user_settings_handler, upgrade_plan_handler,
};
use crate::middleware::{provision_rate_limit_middleware, provision_rate_limiter};
use crate::services::{ApiKeyService, PlanService, ProvisioningService, SlugService};

/// Application state for tenant provisioning.
#[derive(Clone)]
pub struct TenantAppState {
    /// Database connection pool.
    pub pool: PgPool,
    /// Service for provisioning new tenants.
    pub provisioning_service: Arc<ProvisioningService>,
    /// Service for plan management (F-PLAN-MGMT).
    pub plan_service: Arc<PlanService>,
    /// Rate limiter for the provisioning endpoint.
    pub rate_limiter: Arc<RateLimiter>,
}

/// Create the tenant provisioning router.
///
/// Provides:
/// - POST /tenants/provision - Create a new tenant (rate limited: 10 req/IP/hour)
///
/// ## Rate Limiting
///
/// The provisioning endpoint is protected by rate limiting to prevent abuse.
/// Each IP address is limited to 10 provisioning requests per hour.
pub fn tenant_router(pool: PgPool) -> Router {
    let slug_service = Arc::new(SlugService::new(pool.clone()));
    let api_key_service = Arc::new(ApiKeyService::new());
    let provisioning_service = Arc::new(ProvisioningService::new(
        pool.clone(),
        slug_service,
        api_key_service,
    ));
    let plan_service = Arc::new(PlanService::new(pool.clone()));

    // Create rate limiter for provisioning endpoint
    let rate_limiter = Arc::new(provision_rate_limiter());

    let state = TenantAppState {
        pool,
        provisioning_service,
        plan_service,
        rate_limiter: rate_limiter.clone(),
    };

    Router::new()
        .route("/provision", post(provision_handler))
        .layer(middleware::from_fn(provision_rate_limit_middleware))
        .layer(Extension(rate_limiter))
        .with_state(state)
}

/// Create the system administration router.
///
/// Provides:
/// - GET /system/tenants/{id} - Get tenant status
/// - POST /system/tenants/{id}/suspend - Suspend a tenant
/// - POST /system/tenants/{id}/reactivate - Reactivate a suspended tenant
/// - POST /system/tenants/{id}/delete - Soft delete a tenant
/// - POST /system/tenants/{id}/restore - Restore a soft-deleted tenant
/// - GET /system/tenants/deleted - List all soft-deleted tenants
/// - GET /system/tenants/{id}/usage - Get current usage metrics
/// - GET /system/tenants/{id}/usage/history - Get historical usage metrics
/// - GET /system/tenants/{id}/settings - Get tenant settings
/// - PATCH /system/tenants/{id}/settings - Update tenant settings
///
/// ## Authorization
///
/// All endpoints require authentication as a system tenant administrator.
/// Only users with JWT claims containing `tid == SYSTEM_TENANT_ID` can access.
pub fn system_admin_router(pool: PgPool) -> Router {
    let slug_service = Arc::new(SlugService::new(pool.clone()));
    let api_key_service = Arc::new(ApiKeyService::new());
    let provisioning_service = Arc::new(ProvisioningService::new(
        pool.clone(),
        slug_service,
        api_key_service,
    ));
    let plan_service = Arc::new(PlanService::new(pool.clone()));

    // Rate limiter not applied to system admin routes (already protected by auth)
    let rate_limiter = Arc::new(provision_rate_limiter());

    let state = TenantAppState {
        pool,
        provisioning_service,
        plan_service,
        rate_limiter,
    };

    Router::new()
        .route("/tenants/:id", get(get_tenant_status_handler))
        .route("/tenants/:id/suspend", post(suspend_tenant_handler))
        .route("/tenants/:id/reactivate", post(reactivate_tenant_handler))
        .route("/tenants/:id/delete", post(delete_tenant_handler))
        .route("/tenants/:id/restore", post(restore_tenant_handler))
        .route("/tenants/:id/usage", get(get_tenant_usage_handler))
        .route(
            "/tenants/:id/usage/history",
            get(get_tenant_usage_history_handler),
        )
        .route("/tenants/:id/settings", get(get_settings_handler))
        .route("/tenants/:id/settings", patch(update_settings_handler))
        .route("/tenants/deleted", get(list_deleted_tenants_handler))
        // Plan management routes (F-PLAN-MGMT)
        .route("/tenants/:id/plan/upgrade", post(upgrade_plan_handler))
        .route("/tenants/:id/plan/downgrade", post(downgrade_plan_handler))
        .route(
            "/tenants/:id/plan/pending",
            delete(cancel_downgrade_handler),
        )
        .route("/tenants/:id/plan/history", get(get_plan_history_handler))
        .route("/plans", get(list_plans_handler))
        .with_state(state)
}

/// Create the tenant API keys router.
///
/// Provides:
/// - GET /tenants/{tenant_id}/api-keys - List all API keys
/// - POST /tenants/{tenant_id}/api-keys - Create a new API key (F-049)
/// - POST /tenants/{tenant_id}/api-keys/{key_id}/rotate - Rotate an API key
/// - DELETE /tenants/{tenant_id}/api-keys/{key_id} - Deactivate an API key
/// - GET /tenants/{tenant_id}/api-keys/{key_id}/usage - Get API key usage statistics (F-054)
/// - GET /api-keys/introspect - Introspect the current API key (F-055)
/// - GET /tenants/{tenant_id}/settings - Get tenant settings (F-056)
/// - PATCH /tenants/{tenant_id}/settings - Update tenant settings (F-056)
///
/// ## Authorization
///
/// Endpoints are accessible by:
/// - System tenant administrators (can access any tenant)
/// - Tenant's own users (can only access their tenant's keys/settings)
/// - /api-keys/introspect requires a valid API key (introspects itself)
pub fn api_keys_router(pool: PgPool) -> Router {
    let slug_service = Arc::new(SlugService::new(pool.clone()));
    let api_key_service = Arc::new(ApiKeyService::new());
    let provisioning_service = Arc::new(ProvisioningService::new(
        pool.clone(),
        slug_service,
        api_key_service,
    ));
    let plan_service = Arc::new(PlanService::new(pool.clone()));

    let rate_limiter = Arc::new(provision_rate_limiter());

    let state = TenantAppState {
        pool,
        provisioning_service,
        plan_service,
        rate_limiter,
    };

    Router::new()
        .route(
            "/tenants/:tenant_id/api-keys",
            get(list_api_keys_handler).post(create_api_key_handler),
        )
        .route(
            "/tenants/:tenant_id/api-keys/:key_id/rotate",
            post(rotate_api_key_handler),
        )
        .route(
            "/tenants/:tenant_id/api-keys/:key_id",
            delete(deactivate_api_key_handler),
        )
        // F-054: API Key Usage Statistics
        .route(
            "/tenants/:tenant_id/api-keys/:key_id/usage",
            get(get_api_key_usage_handler),
        )
        // F-055: API Key Introspection
        .route("/api-keys/introspect", get(introspect_api_key_handler))
        // F-056: Tenant User Settings
        .route(
            "/tenants/:tenant_id/settings",
            get(get_tenant_user_settings_handler).patch(update_tenant_user_settings_handler),
        )
        // F-057: Tenant Invitations
        .route(
            "/tenants/:tenant_id/invitations",
            get(list_invitations_handler).post(create_invitation_handler),
        )
        .route(
            "/tenants/:tenant_id/invitations/:invitation_id",
            delete(cancel_invitation_handler),
        )
        // F-057: Accept invitation (public endpoint)
        .route("/invitations/accept", post(accept_invitation_handler))
        .with_state(state)
}

/// Create the tenant OAuth clients router.
///
/// Provides:
/// - GET /tenants/{tenant_id}/oauth-clients - List all OAuth clients
/// - POST /tenants/{tenant_id}/oauth-clients/{client_id}/rotate-secret - Rotate client secret
/// - DELETE /tenants/{tenant_id}/oauth-clients/{client_id} - Deactivate an OAuth client
///
/// ## Authorization
///
/// Endpoints are accessible by:
/// - System tenant administrators (can access any tenant)
/// - Tenant's own users (can only access their tenant's clients)
pub fn oauth_clients_router(pool: PgPool) -> Router {
    let slug_service = Arc::new(SlugService::new(pool.clone()));
    let api_key_service = Arc::new(ApiKeyService::new());
    let provisioning_service = Arc::new(ProvisioningService::new(
        pool.clone(),
        slug_service,
        api_key_service,
    ));
    let plan_service = Arc::new(PlanService::new(pool.clone()));

    let rate_limiter = Arc::new(provision_rate_limiter());

    let state = TenantAppState {
        pool,
        provisioning_service,
        plan_service,
        rate_limiter,
    };

    Router::new()
        .route(
            "/tenants/:tenant_id/oauth-clients",
            get(list_oauth_clients_handler),
        )
        .route(
            "/tenants/:tenant_id/oauth-clients/:client_id/rotate-secret",
            post(rotate_oauth_secret_handler),
        )
        .route(
            "/tenants/:tenant_id/oauth-clients/:client_id",
            delete(deactivate_oauth_client_handler),
        )
        .with_state(state)
}
