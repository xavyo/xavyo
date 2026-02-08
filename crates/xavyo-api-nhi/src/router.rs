//! Router configuration for unified NHI API.
//!
//! Provides the consolidated router for all NHI endpoints under `/nhi`:
//! - Unified list/get (Phase 3)
//! - Type-specific CRUD: tools, agents, service accounts (Phase 3)
//! - Lifecycle transitions (Phase 4)
//! - Credentials management (Phase 5)
//! - Permissions and SoD (Phase 7)
//! - Risk scoring and inactivity (Phase 8)
//! - Certification campaigns (Phase 8)

use crate::handlers::agents::agent_routes;
use crate::handlers::certification::certification_routes;
use crate::handlers::credentials::credential_routes;
use crate::handlers::inactivity::inactivity_routes;
use crate::handlers::lifecycle::lifecycle_routes;
use crate::handlers::permissions::permission_routes;
use crate::handlers::risk::risk_routes;
use crate::handlers::service_accounts::service_account_routes;
use crate::handlers::sod::sod_routes;
use crate::handlers::tools::tool_routes;
use crate::handlers::unified::unified_routes;
use crate::state::NhiState;
use axum::Router;

/// Creates the unified NHI API router.
///
/// Route groups are added incrementally as phases are implemented.
///
/// # Arguments
///
/// * `state` - Application state containing the database pool and services.
pub fn nhi_router(state: NhiState) -> Router {
    Router::new()
        // Phase 3: Unified endpoints
        .merge(unified_routes(state.clone()))
        // Phase 3: Type-specific CRUD
        .merge(tool_routes(state.clone()))
        .merge(agent_routes(state.clone()))
        .merge(service_account_routes(state.clone()))
        // Phase 4: Lifecycle transitions
        .merge(lifecycle_routes(state.clone()))
        // Phase 5: Credential management
        .merge(credential_routes(state.clone()))
        // Phase 7: Permissions
        .merge(permission_routes(state.clone()))
        // Phase 8: Risk scoring
        .merge(risk_routes(state.clone()))
        // Phase 9: Certification campaigns
        .merge(certification_routes(state.clone()))
        // Phase 10: SoD validation
        .merge(sod_routes(state.clone()))
        // Phase 11: Inactivity detection and orphan management
        .merge(inactivity_routes(state))
}
