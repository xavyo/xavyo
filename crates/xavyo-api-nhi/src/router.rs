//! Router configuration for unified NHI API.
//!
//! Provides the consolidated router for all NHI endpoints under `/nhi`:
//! - Unified list/get (Phase 3)
//! - Type-specific CRUD: tools, agents, service accounts (Phase 3)
//! - Lifecycle transitions (Phase 4)
//! - Permissions and SoD (Phase 7)
//! - Risk scoring and inactivity (Phase 8)
//! - Certification campaigns (Phase 8)
//!
//! Also provides protocol routers (Feature 205 — Protocol Migration):
//! - MCP router: `/mcp/tools`, `/mcp/tools/:name/call`
//! - A2A router: `/a2a/tasks`, `/a2a/tasks/:id`, `/a2a/tasks/:id/cancel`
//! - Discovery router: `/.well-known/agents/:id`

use crate::handlers::agents::agent_routes;
use crate::handlers::blueprints::blueprint_routes;
use crate::handlers::certification::certification_routes;
use crate::handlers::inactivity::inactivity_routes;
use crate::handlers::lifecycle::lifecycle_routes;
use crate::handlers::mcp_discovery;
use crate::handlers::nhi_delegation::nhi_delegation_routes;
use crate::handlers::nhi_permissions::nhi_nhi_permission_routes;
use crate::handlers::permissions::permission_routes;
use crate::handlers::provision;
use crate::handlers::risk::risk_routes;
use crate::handlers::service_accounts::service_account_routes;
use crate::handlers::sod::sod_routes;
use crate::handlers::tools::tool_routes;
use crate::handlers::unified::unified_routes;
use crate::handlers::user_permissions::user_permission_routes;
use crate::handlers::vault;
use crate::state::NhiState;
use axum::routing::{delete, get, post};
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
        // Composite provisioning endpoint
        .merge(
            Router::new()
                .route("/provision-agent", post(provision::provision_agent))
                .with_state(state.clone()),
        )
        // Phase 3: Unified endpoints
        .merge(unified_routes(state.clone()))
        // Phase 3: Type-specific CRUD
        .merge(tool_routes(state.clone()))
        .merge(agent_routes(state.clone()))
        .merge(service_account_routes(state.clone()))
        // Agent Blueprints: reusable agent configuration templates
        .merge(blueprint_routes(state.clone()))
        // Phase 4: Lifecycle transitions
        .merge(lifecycle_routes(state.clone()))
        // Phase 7: Permissions
        .merge(permission_routes(state.clone()))
        // Feature 204: User-to-NHI permissions
        .merge(user_permission_routes(state.clone()))
        // Feature 204: NHI-to-NHI permissions
        .merge(nhi_nhi_permission_routes(state.clone()))
        // Phase 8: Risk scoring
        .merge(risk_routes(state.clone()))
        // Phase 9: Certification campaigns
        .merge(certification_routes(state.clone()))
        // Phase 10: SoD validation
        .merge(sod_routes(state.clone()))
        // NHI Delegation management
        .merge(nhi_delegation_routes(state.clone()))
        // Phase 11: Inactivity detection and orphan management
        .merge(inactivity_routes(state.clone()))
        // Activity summary
        .merge(
            Router::new()
                .route(
                    "/:nhi_id/activity-summary",
                    get(crate::handlers::activity::activity_summary_handler),
                )
                .with_state(state.clone()),
        )
        // MCP tool discovery from AgentGateway
        .merge(
            Router::new()
                .route(
                    "/mcp-discovery/gateways",
                    get(mcp_discovery::list_gateways_handler),
                )
                .route(
                    "/mcp-discovery/tools",
                    get(mcp_discovery::discover_tools_handler),
                )
                .route(
                    "/mcp-discovery/import",
                    post(mcp_discovery::import_tools_handler),
                )
                .route(
                    "/mcp-discovery/sync-check",
                    get(mcp_discovery::sync_check_handler),
                )
                .with_state(state.clone()),
        )
        // Vault: encrypted secret and lease management
        .merge(
            Router::new()
                .route("/:nhi_id/vault/secrets", post(vault::store_secret_handler))
                .route("/:nhi_id/vault/secrets", get(vault::list_secrets_handler))
                .route(
                    "/:nhi_id/vault/secrets/:secret_id",
                    delete(vault::delete_secret_handler),
                )
                .route(
                    "/:nhi_id/vault/secrets/:secret_id/rotate",
                    post(vault::rotate_secret_handler),
                )
                .route("/:nhi_id/vault/leases", post(vault::create_lease_handler))
                .route("/:nhi_id/vault/leases", get(vault::list_leases_handler))
                .route(
                    "/:nhi_id/vault/leases/:lease_id/renew",
                    post(vault::renew_lease_handler),
                )
                .route(
                    "/:nhi_id/vault/leases/:lease_id",
                    delete(vault::revoke_lease_handler),
                )
                .with_state(state.clone()),
        )
        // Token Vault: external OAuth provider token management
        .merge(
            Router::new()
                .route(
                    "/:nhi_id/vault/external-tokens",
                    post(crate::handlers::token_vault::store_external_token_handler)
                        .get(crate::handlers::token_vault::list_external_tokens_handler),
                )
                .route(
                    "/:nhi_id/vault/external-tokens/:token_id",
                    delete(crate::handlers::token_vault::delete_external_token_handler),
                )
                .route(
                    "/:nhi_id/vault/token-exchange",
                    post(crate::handlers::token_vault::token_exchange_handler),
                )
                .with_state(state),
        )
}

/// Creates the MCP (Model Context Protocol) router.
///
/// Endpoints:
/// - `GET /tools` — List available tools for the authenticated agent
/// - `POST /tools/:name/call` — Invoke a tool by name
///
/// Mount at `/mcp` in `main.rs`.
pub fn mcp_router(state: NhiState) -> Router {
    Router::new()
        .route("/tools", get(crate::handlers::mcp::list_tools))
        .route("/tools/:name/call", post(crate::handlers::mcp::call_tool))
        .with_state(state)
}

/// Creates the A2A (Agent-to-Agent) Protocol router.
///
/// Endpoints:
/// - `POST /tasks` — Create a new asynchronous task
/// - `GET /tasks` — List tasks for the authenticated agent
/// - `GET /tasks/:id` — Get task status
/// - `POST /tasks/:id/cancel` — Cancel a task
///
/// Mount at `/a2a` in `main.rs`.
pub fn a2a_router(state: NhiState) -> Router {
    Router::new()
        .route("/tasks", post(crate::handlers::a2a::create_task))
        .route("/tasks", get(crate::handlers::a2a::list_tasks))
        .route("/tasks/:id", get(crate::handlers::a2a::get_task))
        .route("/tasks/:id/cancel", post(crate::handlers::a2a::cancel_task))
        .with_state(state)
}

/// Creates the A2A AgentCard discovery router.
///
/// Endpoints:
/// - `GET /.well-known/agents/:id` — Get AgentCard for an agent (public, no auth)
///
/// Mount directly (merged) at root level in `main.rs`.
pub fn discovery_router(state: NhiState) -> Router {
    Router::new()
        .route(
            "/.well-known/agents/:id",
            get(crate::handlers::discovery::get_agent_card),
        )
        .with_state(state)
}
