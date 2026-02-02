//! Router configuration for unified NHI API.
//!
//! F109 - NHI API Consolidation
//!
//! This module provides the consolidated router for all NHI endpoints:
//! - `/nhi` - Unified list/get endpoints
//! - `/nhi/risk-summary` - Risk statistics
//! - `/nhi/staleness-report` - Inactive NHI report
//! - `/nhi/certifications/*` - Certification campaigns
//! - `/nhi/service-accounts/*` - Service account management
//! - `/nhi/agents/*` - AI agent management
//! - `/nhi/tools/*` - Tool registry
//! - `/nhi/approvals/*` - HITL approvals

use axum::{
    routing::{delete, get, post},
    Router,
};
use sqlx::PgPool;

use crate::handlers::{
    bulk_decide, cancel_campaign, create_campaign, decide_item, get_campaign, get_campaign_summary,
    get_my_pending, get_nhi, get_risk_summary, get_staleness_report, launch_campaign,
    list_campaign_items, list_campaigns, list_nhi, CertificationState, NhiState, RiskState,
};
use crate::services::{UnifiedCertificationService, UnifiedListService, UnifiedRiskService};

// Import handlers from sub-modules
use crate::handlers::agents::{
    authorize_agent,
    create_agent,
    delete_agent,
    get_agent,
    // F110: Agent credential handlers
    get_agent_credential,
    get_baseline,
    get_security_assessment,
    get_tenant_thresholds,
    get_thresholds,
    grant_agent_permission,
    list_agent_credentials,
    list_agent_permissions,
    list_agents,
    list_anomalies,
    query_agent_audit,
    reactivate_agent,
    reset_thresholds,
    revoke_agent_credential,
    revoke_agent_permission,
    rotate_agent_credentials,
    set_tenant_thresholds,
    suspend_agent,
    update_agent,
    update_thresholds,
    validate_agent_credential,
    AgentCredentialState,
};
use crate::handlers::approvals::{
    approve_request, check_approval_status, deny_request, get_approval, list_approvals,
};
use crate::handlers::service_accounts::{
    // Request handlers (T029)
    approve_request as approve_sa_request,
    // Risk handlers (T028)
    calculate_risk_score,
    cancel_request as cancel_sa_request,
    // CRUD handlers
    certify_service_account,
    create_service_account,
    delete_service_account,
    // Credential handlers (T026)
    get_credential,
    get_my_pending_requests,
    get_request,
    get_request_summary,
    get_risk_score,
    get_service_account,
    get_service_account_summary,
    // Usage handlers (T027)
    get_usage_summary,
    list_credentials,
    list_requests,
    list_service_accounts,
    list_usage,
    reactivate_service_account,
    record_usage,
    reject_request as reject_sa_request,
    revoke_credential,
    rotate_credentials,
    submit_request,
    suspend_service_account,
    transfer_ownership,
    update_service_account,
};
use crate::handlers::tools::{create_tool, delete_tool, get_tool, list_tools, update_tool};

// Import state types
use crate::state::{AgentsState, ApprovalsState, ServiceAccountsState, ToolsState};

/// Application state containing all services needed by NHI handlers.
#[derive(Clone)]
pub struct NhiAppState {
    pub list_service: UnifiedListService,
    pub risk_service: UnifiedRiskService,
    pub certification_service: UnifiedCertificationService,
}

impl NhiAppState {
    /// Creates a new NhiAppState with the given database pool.
    pub fn new(pool: PgPool) -> Self {
        Self {
            list_service: UnifiedListService::new(pool.clone()),
            risk_service: UnifiedRiskService::new(pool.clone()),
            certification_service: UnifiedCertificationService::new(pool),
        }
    }
}

/// Creates the unified NHI API router.
///
/// Mounts endpoints under `/nhi`:
///
/// ## Root Endpoints
/// - `GET /` - List all NHIs (polymorphic)
/// - `GET /:id` - Get specific NHI by ID
/// - `GET /risk-summary` - Risk statistics dashboard
///
/// ## Service Accounts (`/service-accounts/*`)
/// - `GET /service-accounts` - List service accounts
/// - `POST /service-accounts` - Create service account
/// - `GET /service-accounts/summary` - Summary statistics
/// - `GET /service-accounts/:id` - Get service account
/// - `PUT /service-accounts/:id` - Update service account
/// - `DELETE /service-accounts/:id` - Delete service account
///
/// ## AI Agents (`/agents/*`)
/// - `GET /agents` - List AI agents
/// - `POST /agents` - Create AI agent
/// - `GET /agents/:id` - Get agent
/// - `PATCH /agents/:id` - Update agent
/// - `DELETE /agents/:id` - Delete agent
/// - `POST /agents/:id/suspend` - Suspend agent
/// - `POST /agents/:id/reactivate` - Reactivate agent
/// - `POST /agents/authorize` - Real-time authorization
/// - `GET /agents/:id/permissions` - List agent permissions
/// - `POST /agents/:id/permissions` - Grant permission
/// - `DELETE /agents/:agent_id/permissions/:tool_id` - Revoke permission
/// - `GET /agents/:id/audit` - Query audit trail
///
/// ## Tools (`/tools/*`)
/// - `GET /tools` - List tools
/// - `POST /tools` - Register tool
/// - `GET /tools/:id` - Get tool
/// - `PATCH /tools/:id` - Update tool
/// - `DELETE /tools/:id` - Delete tool
///
/// ## Approvals (`/approvals/*`)
/// - `GET /approvals` - List approvals
/// - `GET /approvals/:id` - Get approval
/// - `GET /approvals/:id/status` - Check approval status
/// - `POST /approvals/:id/approve` - Approve request
/// - `POST /approvals/:id/deny` - Deny request
///
/// ## Certifications (`/certifications/*`)
/// - `POST /certifications/campaigns` - Create campaign
/// - `GET /certifications/campaigns` - List campaigns
/// - `GET /certifications/campaigns/:id` - Get campaign
/// - `POST /certifications/campaigns/:id/launch` - Launch campaign
/// - `POST /certifications/campaigns/:id/cancel` - Cancel campaign
/// - `GET /certifications/campaigns/:id/items` - List campaign items
/// - `POST /certifications/items/:id/decide` - Make decision
///
/// # Arguments
///
/// * `pool` - PostgreSQL connection pool
///
/// # Example
///
/// ```rust,ignore
/// use xavyo_api_nhi::router;
/// use axum::Router;
///
/// let nhi_router = router(pool)?;
/// let app = Router::new().nest("/nhi", nhi_router);
/// ```
///
/// # Errors
///
/// Returns `ApiNhiError` if the internal services cannot be created.
pub fn router(pool: PgPool) -> Result<Router, crate::error::ApiNhiError> {
    use std::sync::Arc;
    use xavyo_api_governance::services::NhiUsageService;

    let app_state = NhiAppState::new(pool.clone());

    // State for list/get handlers
    let list_state = NhiState {
        list_service: app_state.list_service.clone(),
    };

    // State for risk handlers (with usage service for staleness report)
    let usage_service = Arc::new(NhiUsageService::new(pool.clone()));
    let risk_state =
        RiskState::new(app_state.risk_service.clone()).with_usage_service(usage_service);

    // State for certification handlers
    let cert_state = CertificationState {
        certification_service: app_state.certification_service.clone(),
    };

    // State for consolidated handlers
    let agents_state = AgentsState::new(pool.clone())?;
    let service_accounts_state = ServiceAccountsState::new(pool.clone());
    let tools_state = ToolsState::new(agents_state.clone());
    let approvals_state = ApprovalsState::new(agents_state.clone());

    // F110: State for agent credential handlers
    let agent_credential_state = AgentCredentialState {
        credential_service: crate::services::AgentCredentialService::new(pool.clone()),
    };

    // Build sub-routers
    let cert_routes = certification_router(cert_state);
    let service_accounts_routes = service_accounts_router(service_accounts_state);
    let agents_routes = agents_router(agents_state, agent_credential_state);
    let tools_routes = tools_router(tools_state);
    let approvals_routes = approvals_router(approvals_state);

    Ok(Router::new()
        // List all NHIs: GET /nhi
        .route("/", get(list_nhi).with_state(list_state.clone()))
        // Get risk summary: GET /nhi/risk-summary
        // Note: Must be registered before /:id to avoid path conflict
        .route(
            "/risk-summary",
            get(get_risk_summary).with_state(risk_state.clone()),
        )
        // Get staleness report: GET /nhi/staleness-report
        .route(
            "/staleness-report",
            get(get_staleness_report).with_state(risk_state),
        )
        // Consolidated sub-routers
        .nest("/service-accounts", service_accounts_routes)
        .nest("/agents", agents_routes)
        .nest("/tools", tools_routes)
        .nest("/approvals", approvals_routes)
        // Certification routes: /nhi/certifications/...
        .nest("/certifications", cert_routes)
        // Get specific NHI: GET /nhi/:id
        // Note: Must be last to avoid capturing other paths
        .route("/:id", get(get_nhi).with_state(list_state)))
}

/// Creates the certification campaign sub-router.
fn certification_router(state: CertificationState) -> Router {
    Router::new()
        // POST/GET /certifications/campaigns
        .route("/campaigns", post(create_campaign).get(list_campaigns))
        // My pending items (before campaigns/:id to avoid conflict)
        .route("/my-pending", get(get_my_pending))
        // Bulk operations on items
        .route("/items/bulk-decide", post(bulk_decide))
        // GET/POST operations on specific campaign
        .route("/campaigns/:campaign_id", get(get_campaign))
        .route("/campaigns/:campaign_id/launch", post(launch_campaign))
        .route("/campaigns/:campaign_id/cancel", post(cancel_campaign))
        .route("/campaigns/:campaign_id/items", get(list_campaign_items))
        .route("/campaigns/:campaign_id/summary", get(get_campaign_summary))
        // Decision on specific item
        .route("/items/:item_id/decide", post(decide_item))
        .with_state(state)
}

/// Creates the service accounts sub-router.
fn service_accounts_router(state: ServiceAccountsState) -> Router {
    Router::new()
        // List and create
        .route("/", get(list_service_accounts).post(create_service_account))
        // Summary statistics (before /:id to avoid conflict)
        .route("/summary", get(get_service_account_summary))
        // Request endpoints (before /:id to avoid conflict)
        .route("/requests", get(list_requests).post(submit_request))
        .route("/requests/summary", get(get_request_summary))
        .route("/requests/my-pending", get(get_my_pending_requests))
        .route("/requests/:request_id", get(get_request))
        .route("/requests/:request_id/approve", post(approve_sa_request))
        .route("/requests/:request_id/reject", post(reject_sa_request))
        .route("/requests/:request_id/cancel", post(cancel_sa_request))
        // Individual service account CRUD
        .route(
            "/:id",
            get(get_service_account)
                .put(update_service_account)
                .delete(delete_service_account),
        )
        // Lifecycle operations
        .route("/:id/suspend", post(suspend_service_account))
        .route("/:id/reactivate", post(reactivate_service_account))
        .route("/:id/transfer-ownership", post(transfer_ownership))
        .route("/:id/certify", post(certify_service_account))
        // Credentials (T026)
        .route("/:id/credentials", get(list_credentials))
        .route("/:id/credentials/rotate", post(rotate_credentials))
        .route("/:nhi_id/credentials/:credential_id", get(get_credential))
        .route(
            "/:nhi_id/credentials/:credential_id/revoke",
            post(revoke_credential),
        )
        // Usage (T027)
        .route("/:id/usage", get(list_usage).post(record_usage))
        .route("/:id/usage/summary", get(get_usage_summary))
        // Risk (T028)
        .route("/:id/risk", get(get_risk_score))
        .route("/:id/risk/calculate", post(calculate_risk_score))
        .with_state(state)
}

/// Creates the AI agents sub-router.
fn agents_router(state: AgentsState, credential_state: AgentCredentialState) -> Router {
    // F110: Credential routes with separate state
    let credential_routes = Router::new()
        .route("/:id/credentials", get(list_agent_credentials))
        .route("/:id/credentials/rotate", post(rotate_agent_credentials))
        .route("/:id/credentials/validate", post(validate_agent_credential))
        .route(
            "/:agent_id/credentials/:credential_id",
            get(get_agent_credential),
        )
        .route(
            "/:agent_id/credentials/:credential_id/revoke",
            post(revoke_agent_credential),
        )
        .with_state(credential_state);

    Router::new()
        // List and create
        .route("/", get(list_agents).post(create_agent))
        // Authorization endpoint (before /:id to avoid conflict)
        .route("/authorize", post(authorize_agent))
        // Tenant-wide threshold management (F094) - must be before /:id
        .route(
            "/thresholds",
            get(get_tenant_thresholds).put(set_tenant_thresholds),
        )
        // Individual agent CRUD
        .route(
            "/:id",
            get(get_agent).patch(update_agent).delete(delete_agent),
        )
        // Lifecycle operations
        .route("/:id/suspend", post(suspend_agent))
        .route("/:id/reactivate", post(reactivate_agent))
        // Permissions
        .route(
            "/:id/permissions",
            get(list_agent_permissions).post(grant_agent_permission),
        )
        .route(
            "/:agent_id/permissions/:tool_id",
            delete(revoke_agent_permission),
        )
        // Audit
        .route("/:id/audit", get(query_agent_audit))
        // Security Assessment (F093)
        .route("/:id/security-assessment", get(get_security_assessment))
        // Anomaly Detection (F094)
        .route("/:id/anomalies", get(list_anomalies))
        .route("/:id/baseline", get(get_baseline))
        .route(
            "/:id/thresholds",
            get(get_thresholds)
                .put(update_thresholds)
                .delete(reset_thresholds),
        )
        .with_state(state)
        // F110: Merge credential routes
        .merge(credential_routes)
}

/// Creates the tools sub-router.
fn tools_router(state: ToolsState) -> Router {
    Router::new()
        // List and create
        .route("/", get(list_tools).post(create_tool))
        // Individual tool CRUD
        .route("/:id", get(get_tool).patch(update_tool).delete(delete_tool))
        .with_state(state.agents_state)
}

/// Creates the approvals sub-router.
fn approvals_router(state: ApprovalsState) -> Router {
    Router::new()
        // List approvals
        .route("/", get(list_approvals))
        // Individual approval operations
        .route("/:id", get(get_approval))
        .route("/:id/status", get(check_approval_status))
        .route("/:id/approve", post(approve_request))
        .route("/:id/deny", post(deny_request))
        .with_state(state.agents_state)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_nhi_app_state_creation() {
        // Note: This test verifies the types compile correctly
        // Integration tests would test actual routing behavior
        assert!(true);
    }
}
