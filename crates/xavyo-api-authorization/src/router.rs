//! Router configuration for the authorization API (F083).

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use sqlx::PgPool;
use xavyo_authorization::{MappingCache, PolicyCache, PolicyDecisionPoint};

use crate::handlers;
use crate::services::{MappingService, PolicyService};

/// Shared state for all authorization API handlers.
#[derive(Clone)]
pub struct AuthorizationState {
    /// Database connection pool.
    pub pool: PgPool,

    /// The Policy Decision Point (PDP) engine.
    pub pdp: Arc<PolicyDecisionPoint>,

    /// Policy cache (shared with PDP).
    pub policy_cache: Arc<PolicyCache>,

    /// Mapping cache (shared with PDP).
    pub mapping_cache: Arc<MappingCache>,

    /// Service for managing entitlement-action mappings.
    pub mapping_service: Arc<MappingService>,

    /// Service for managing authorization policies.
    pub policy_service: Arc<PolicyService>,

    /// Audit verbosity: "all" or "`deny_only`".
    pub audit_verbosity: String,

    /// Risk score threshold above which NHI requests are denied.
    pub risk_score_deny_threshold: i32,
}

/// Create the authorization router with all endpoints.
///
/// # Routes
///
/// ## Mappings (admin)
/// - `GET    /admin/authorization/mappings`      - List mappings
/// - `POST   /admin/authorization/mappings`      - Create mapping
/// - `GET    /admin/authorization/mappings/:id`   - Get mapping
/// - `DELETE /admin/authorization/mappings/:id`   - Delete mapping
///
/// ## Policies (admin)
/// - `GET    /admin/authorization/policies`      - List policies
/// - `POST   /admin/authorization/policies`      - Create policy
/// - `GET    /admin/authorization/policies/:id`   - Get policy
/// - `PUT    /admin/authorization/policies/:id`   - Update policy
/// - `DELETE /admin/authorization/policies/:id`   - Deactivate policy
///
/// ## Query API
/// - `GET    /authorization/can-i`               - Check current user's authorization
/// - `GET    /admin/authorization/check`         - Check another user's authorization (admin)
/// - `POST   /admin/authorization/bulk-check`    - Bulk authorization check (admin)
///
/// ## Explain API (admin)
/// - `GET    /admin/authorization/explain-nhi`   - Dry-run NHI authorization pipeline
pub fn authorization_router(
    pool: PgPool,
    audit_verbosity: String,
    risk_score_deny_threshold: i32,
) -> Router {
    let policy_cache = Arc::new(PolicyCache::new());
    let mapping_cache = Arc::new(MappingCache::new());
    let pdp = Arc::new(PolicyDecisionPoint::new(
        policy_cache.clone(),
        mapping_cache.clone(),
    ));

    let mapping_service = Arc::new(MappingService::new(pool.clone(), mapping_cache.clone()));
    let policy_service = Arc::new(PolicyService::new(pool.clone(), policy_cache.clone()));

    let state = AuthorizationState {
        pool,
        pdp,
        policy_cache,
        mapping_cache,
        mapping_service,
        policy_service,
        audit_verbosity,
        risk_score_deny_threshold,
    };

    Router::new()
        // Mappings (admin)
        .route(
            "/admin/authorization/mappings",
            get(handlers::mappings::list_mappings).post(handlers::mappings::create_mapping),
        )
        .route(
            "/admin/authorization/mappings/:id",
            get(handlers::mappings::get_mapping).delete(handlers::mappings::delete_mapping),
        )
        // Policies (admin)
        .route(
            "/admin/authorization/policies",
            get(handlers::policies::list_policies).post(handlers::policies::create_policy),
        )
        .route(
            "/admin/authorization/policies/:id",
            get(handlers::policies::get_policy)
                .put(handlers::policies::update_policy)
                .delete(handlers::policies::deactivate_policy),
        )
        // Query API
        .route("/authorization/can-i", get(handlers::query::can_i_handler))
        .route(
            "/admin/authorization/check",
            get(handlers::query::admin_check_handler),
        )
        .route(
            "/admin/authorization/bulk-check",
            post(handlers::query::bulk_check_handler),
        )
        // Explain API (admin)
        .route(
            "/admin/authorization/explain-nhi",
            get(handlers::explain::explain_nhi_handler),
        )
        .with_state(state)
}
