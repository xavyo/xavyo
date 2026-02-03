//! Router configuration for the AI Agent Security API.
//!
//! Sets up all routes for agent management, tools, permissions,
//! authorization, audit, A2A discovery, MCP tools, and A2A tasks.

use axum::{
    routing::{delete, get, patch, post},
    Router,
};
use sqlx::PgPool;
use std::sync::Arc;

use crate::handlers;
use crate::handlers::anomaly::AnomalyState;
use crate::services::encryption::EncryptionService;
use crate::services::{
    A2aService, AgentService, AnomalyService, ApprovalService, AssessmentService, AuditService,
    AuthorizationService, BaselineService, CaService, CertificateService, DynamicCredentialService,
    IdentityAuditService, IdentityFederationService, IdentityProviderService, McpService,
    PermissionService, RevocationService, RoleMappingService, SecretPermissionService,
    SecretProviderService, SecretTypeService, ToolService, WebhookService,
};

/// Shared state for the agents API.
#[derive(Clone)]
pub struct AgentsState {
    /// Database connection pool.
    pub pool: PgPool,
    /// Agent service.
    pub agent_service: Arc<AgentService>,
    /// Tool service.
    pub tool_service: Arc<ToolService>,
    /// Permission service.
    pub permission_service: Arc<PermissionService>,
    /// Authorization service.
    pub authorization_service: Arc<AuthorizationService>,
    /// Audit service.
    pub audit_service: Arc<AuditService>,
    /// MCP service (F091).
    pub mcp_service: Arc<McpService>,
    /// A2A service (F091).
    pub a2a_service: Arc<A2aService>,
    /// Webhook service (F091).
    pub webhook_service: Arc<WebhookService>,
    /// Approval service (F092).
    pub approval_service: Arc<ApprovalService>,
    /// Assessment service (F093).
    pub assessment_service: Arc<AssessmentService>,
    /// Anomaly service (F094).
    pub anomaly_service: Arc<AnomalyService>,
    /// Baseline service (F094).
    pub baseline_service: Arc<BaselineService>,
    /// Dynamic Credential service (F120).
    pub credential_service: Arc<DynamicCredentialService>,
    /// Secret Permission service (F120).
    pub secret_permission_service: Arc<SecretPermissionService>,
    /// Secret Type service (F120).
    pub secret_type_service: Arc<SecretTypeService>,
    /// Secret Provider service (F120).
    pub secret_provider_service: Arc<SecretProviderService>,
    /// Identity Audit service (F121).
    pub identity_audit_service: Arc<IdentityAuditService>,
    /// Identity Provider service (F121).
    pub identity_provider_service: Arc<IdentityProviderService>,
    /// Role Mapping service (F121).
    pub role_mapping_service: Arc<RoleMappingService>,
    /// Identity Federation service (F121).
    pub identity_federation_service: Arc<IdentityFederationService>,
    /// CA service (F127).
    pub ca_service: Arc<CaService>,
    /// Certificate service (F127).
    pub certificate_service: Arc<CertificateService>,
    /// Revocation service for CRL and OCSP (F127).
    pub revocation_service: Arc<RevocationService>,
}

impl AgentsState {
    /// Create a new AgentsState with the given database pool.
    ///
    /// # Errors
    ///
    /// Returns `ApiAgentsError::Internal` if the webhook HTTP client cannot be built.
    pub fn new(pool: PgPool) -> Result<Self, crate::error::ApiAgentsError> {
        let agent_service = Arc::new(AgentService::new(pool.clone()));
        let tool_service = Arc::new(ToolService::new(pool.clone()));
        let permission_service = Arc::new(PermissionService::new(pool.clone()));
        let audit_service = Arc::new(AuditService::new(pool.clone()));

        // F091: MCP & A2A services (webhook needed for approval service)
        let webhook_service = Arc::new(WebhookService::new(pool.clone())?);

        // F092: Human-in-the-Loop Approval service (needed for authorization)
        let approval_service = Arc::new(ApprovalService::new(
            pool.clone(),
            Arc::clone(&audit_service),
            Arc::clone(&webhook_service),
        ));

        // Authorization service with HITL integration
        let authorization_service = Arc::new(AuthorizationService::new(
            pool.clone(),
            Arc::clone(&permission_service),
            Arc::clone(&audit_service),
            Arc::clone(&approval_service),
        ));

        // F091: MCP & A2A services
        let mcp_service = Arc::new(McpService::new(
            pool.clone(),
            Arc::clone(&permission_service),
            Arc::clone(&audit_service),
        ));
        let a2a_service = Arc::new(A2aService::new(pool.clone(), Arc::clone(&webhook_service)));

        // F093: Security Assessment service
        let assessment_service = Arc::new(AssessmentService::new(pool.clone()));

        // F094: Behavioral Anomaly Detection services
        let anomaly_service = Arc::new(AnomalyService::new(pool.clone()));
        let baseline_service = Arc::new(BaselineService::new(pool.clone()));

        // F120: Encryption service (must be created first)
        let encryption_service = Arc::new(EncryptionService::from_env_or_generate()?);

        // F120: Dynamic Credential service
        let credential_service = Arc::new(DynamicCredentialService::new(
            pool.clone(),
            Arc::clone(&encryption_service),
        ));
        let secret_permission_service = Arc::new(SecretPermissionService::new(pool.clone()));
        let secret_type_service = Arc::new(SecretTypeService::new(pool.clone()));
        let secret_provider_service = Arc::new(SecretProviderService::new(
            pool.clone(),
            Arc::clone(&encryption_service),
        ));

        // F121: Workload Identity Federation services
        let identity_audit_service = Arc::new(IdentityAuditService::new(pool.clone()));
        let identity_provider_service = Arc::new(IdentityProviderService::new(
            pool.clone(),
            (*identity_audit_service).clone(),
        ));
        let role_mapping_service = Arc::new(RoleMappingService::new(
            pool.clone(),
            (*identity_audit_service).clone(),
        ));
        let identity_federation_service = Arc::new(IdentityFederationService::new(
            pool.clone(),
            (*identity_provider_service).clone(),
            (*role_mapping_service).clone(),
            (*identity_audit_service).clone(),
        ));

        // F127: Agent PKI & Certificate Issuance services
        let ca_service = Arc::new(CaService::new(
            pool.clone(),
            Arc::clone(&encryption_service),
        ));
        let certificate_service = Arc::new(CertificateService::new(
            pool.clone(),
            Arc::clone(&ca_service),
            Arc::clone(&audit_service),
        ));
        // Use with_ca_service to enable actual X.509 CRL PEM generation
        let revocation_service = Arc::new(RevocationService::with_ca_service(
            pool.clone(),
            Arc::clone(&certificate_service),
            Arc::clone(&ca_service),
        ));

        Ok(Self {
            pool,
            agent_service,
            tool_service,
            permission_service,
            authorization_service,
            audit_service,
            mcp_service,
            a2a_service,
            webhook_service,
            approval_service,
            assessment_service,
            anomaly_service,
            baseline_service,
            credential_service,
            secret_permission_service,
            secret_type_service,
            secret_provider_service,
            identity_audit_service,
            identity_provider_service,
            role_mapping_service,
            identity_federation_service,
            ca_service,
            certificate_service,
            revocation_service,
        })
    }

    /// Get the anomaly state for F094 handlers.
    pub fn anomaly_state(&self) -> AnomalyState {
        AnomalyState {
            anomaly_service: AnomalyService::new(self.pool.clone()),
            baseline_service: BaselineService::new(self.pool.clone()),
        }
    }

    /// Get optional reference to credential service for error logging.
    pub fn credential_service_opt(&self) -> Option<&DynamicCredentialService> {
        Some(&self.credential_service)
    }
}

/// Create the main agents API router.
///
/// Mounts all agent-related routes:
/// - /agents - Agent CRUD and management
/// - /tools - Tool registry CRUD
/// - /agents/{id}/permissions - Permission management
/// - /agents/authorize - Real-time authorization
/// - /agents/{id}/audit - Audit trail queries
/// - /approvals - Human-in-the-Loop approval management (F092)
pub fn agents_router(state: AgentsState) -> Router {
    Router::new()
        // Agent management
        .route("/agents", post(handlers::create_agent))
        .route("/agents", get(handlers::list_agents))
        .route("/agents/authorize", post(handlers::authorize))
        .route("/agents/:id", get(handlers::get_agent))
        .route("/agents/:id", patch(handlers::update_agent))
        .route("/agents/:id", delete(handlers::delete_agent))
        .route("/agents/:id/suspend", post(handlers::suspend_agent))
        .route("/agents/:id/reactivate", post(handlers::reactivate_agent))
        // F123: Three-layer authorization - user-agent check
        .route("/agents/:id/can-operate", post(handlers::can_operate_agent))
        // Agent permissions
        .route("/agents/:id/permissions", post(handlers::grant_permission))
        .route("/agents/:id/permissions", get(handlers::list_permissions))
        .route(
            "/agents/:id/permissions/:tool_id",
            delete(handlers::revoke_permission),
        )
        // Agent audit
        .route("/agents/:id/audit", get(handlers::query_audit))
        // Dynamic Credentials (F120)
        .route(
            "/agents/:id/credentials/request",
            post(handlers::request_credentials),
        )
        // Secret Permissions (F120)
        .route(
            "/agents/:id/secret-permissions",
            post(handlers::grant_permission),
        )
        .route(
            "/agents/:id/secret-permissions",
            get(handlers::list_agent_secret_permissions),
        )
        .route(
            "/agents/:id/secret-permissions",
            delete(handlers::revoke_permission),
        )
        .route(
            "/agents/:id/secret-permissions/all",
            delete(handlers::revoke_all_permissions),
        )
        .route(
            "/agents/:id/secret-permissions/:permission_id",
            get(handlers::get_secret_permission),
        )
        .route(
            "/agents/:id/secret-permissions/:permission_id",
            patch(handlers::update_secret_permission),
        )
        .route(
            "/agents/:id/secret-permissions/check/:secret_type",
            get(handlers::check_secret_permission),
        )
        // Security Assessment (F093)
        .route(
            "/agents/:id/security-assessment",
            get(handlers::get_agent_security_assessment),
        )
        // Behavioral Anomaly Detection (F094)
        .route("/agents/:id/anomalies", get(handlers::list_agent_anomalies))
        .route("/agents/:id/baseline", get(handlers::get_agent_baseline))
        .route(
            "/agents/:id/thresholds",
            get(handlers::get_agent_thresholds),
        )
        .route(
            "/agents/:id/thresholds",
            axum::routing::put(handlers::set_agent_thresholds),
        )
        .route(
            "/agents/:id/thresholds",
            delete(handlers::reset_agent_thresholds),
        )
        // Tenant-wide threshold management (F094)
        .route("/agents/thresholds", get(handlers::get_tenant_thresholds))
        .route(
            "/agents/thresholds",
            axum::routing::put(handlers::set_tenant_thresholds),
        )
        // Tool management
        .route("/tools", post(handlers::create_tool))
        .route("/tools", get(handlers::list_tools))
        .route("/tools/:id", get(handlers::get_tool))
        .route("/tools/:id", patch(handlers::update_tool))
        .route("/tools/:id", delete(handlers::delete_tool))
        // Secret Type Configuration (F120)
        .route("/secret-types", post(handlers::create_secret_type))
        .route("/secret-types", get(handlers::list_secret_types))
        .route("/secret-types/:id", get(handlers::get_secret_type))
        .route("/secret-types/:id", patch(handlers::update_secret_type))
        .route("/secret-types/:id", delete(handlers::delete_secret_type))
        .route(
            "/secret-types/by-name/:type_name",
            get(handlers::get_secret_type_by_name),
        )
        .route(
            "/secret-types/:id/enable",
            post(handlers::enable_secret_type),
        )
        .route(
            "/secret-types/:id/disable",
            post(handlers::disable_secret_type),
        )
        // Secret Provider Configuration (F120)
        .route("/providers", post(handlers::create_provider))
        .route("/providers", get(handlers::list_providers))
        .route("/providers/:id", get(handlers::get_provider))
        .route("/providers/:id", patch(handlers::update_provider))
        .route("/providers/:id", delete(handlers::delete_provider))
        .route("/providers/:id/activate", post(handlers::activate_provider))
        .route(
            "/providers/:id/deactivate",
            post(handlers::deactivate_provider),
        )
        .route(
            "/providers/:id/health",
            post(handlers::check_provider_health),
        )
        // Human-in-the-Loop Approvals (F092)
        .route("/approvals", get(handlers::list_approvals))
        .route("/approvals/:id", get(handlers::get_approval))
        .route(
            "/approvals/:id/status",
            get(handlers::check_approval_status),
        )
        .route("/approvals/:id/approve", post(handlers::approve_request))
        .route("/approvals/:id/deny", post(handlers::deny_request))
        // Workload Identity Federation - Identity Providers (F121)
        .route(
            "/identity-providers",
            post(handlers::create_identity_provider),
        )
        .route(
            "/identity-providers",
            get(handlers::list_identity_providers),
        )
        .route(
            "/identity-providers/:id",
            get(handlers::get_identity_provider),
        )
        .route(
            "/identity-providers/:id",
            patch(handlers::update_identity_provider),
        )
        .route(
            "/identity-providers/:id",
            delete(handlers::delete_identity_provider),
        )
        .route(
            "/identity-providers/:id/health",
            post(handlers::check_identity_provider_health),
        )
        // Workload Identity Federation - Role Mappings (F121)
        .route("/role-mappings", post(handlers::create_role_mapping))
        .route("/role-mappings", get(handlers::list_role_mappings))
        .route("/role-mappings/:id", get(handlers::get_role_mapping))
        .route("/role-mappings/:id", patch(handlers::update_role_mapping))
        .route("/role-mappings/:id", delete(handlers::delete_role_mapping))
        // Workload Identity Federation - Cloud Credentials (F121)
        .route(
            "/agents/:id/cloud-credentials",
            post(handlers::request_cloud_credentials),
        )
        // Workload Identity Federation - Token Verification (F121)
        .route(
            "/identity/verify-token",
            post(handlers::verify_identity_token),
        )
        // Workload Identity Federation - Audit (F121)
        .route("/identity/audit", get(handlers::query_identity_audit))
        // Agent PKI & Certificate Issuance (F127)
        .route(
            "/agents/:id/certificates",
            post(handlers::issue_certificate),
        )
        .route(
            "/agents/:id/certificates",
            get(handlers::list_agent_certificates),
        )
        .route(
            "/agents/:id/certificates/:cert_id",
            get(handlers::get_agent_certificate),
        )
        .route(
            "/agents/:id/certificates/:cert_id/renew",
            post(handlers::renew_certificate),
        )
        .route(
            "/agents/:id/certificates/:cert_id/revoke",
            post(handlers::revoke_certificate),
        )
        .route("/certificates", get(handlers::list_certificates))
        .route(
            "/certificates/expiring",
            get(handlers::list_expiring_certificates),
        )
        .route("/certificates/:cert_id", get(handlers::get_certificate))
        // PKI endpoints (F127)
        .route("/pki/crl/:ca_id", get(handlers::get_crl))
        .route("/pki/ocsp/:ca_id", post(handlers::ocsp_responder))
        .route("/pki/ca-chain/:ca_id", get(handlers::get_ca_chain))
        // Certificate Authority endpoints (F127)
        .route("/certificate-authorities", get(handlers::list_cas))
        .route(
            "/certificate-authorities/internal",
            post(handlers::create_internal_ca),
        )
        .route(
            "/certificate-authorities/external",
            post(handlers::create_external_ca),
        )
        .route("/certificate-authorities/:ca_id", get(handlers::get_ca))
        .route(
            "/certificate-authorities/:ca_id",
            patch(handlers::update_ca),
        )
        .route(
            "/certificate-authorities/:ca_id",
            delete(handlers::delete_ca),
        )
        .route(
            "/certificate-authorities/:ca_id/default",
            post(handlers::set_default_ca),
        )
        .with_state(state)
}

/// Create the A2A discovery router.
///
/// Mounts the AgentCard discovery endpoint:
/// - /.well-known/agents/{id}.json - A2A AgentCard endpoint
pub fn discovery_router(state: AgentsState) -> Router {
    Router::new()
        // Support both patterns for A2A AgentCard discovery
        .route("/.well-known/agents/:id", get(handlers::get_agent_card))
        .with_state(state)
}

/// Create the MCP (Model Context Protocol) router.
///
/// Mounts MCP endpoints:
/// - GET /mcp/tools - List available tools
/// - POST /mcp/tools/{name}/call - Invoke a tool
pub fn mcp_router(state: AgentsState) -> Router {
    Router::new()
        .route("/tools", get(handlers::list_mcp_tools))
        .route("/tools/:name/call", post(handlers::call_tool))
        .with_state(state)
}

/// Create the A2A (Agent-to-Agent) task router.
///
/// Mounts A2A task management endpoints:
/// - POST /a2a/tasks - Create a new task
/// - GET /a2a/tasks - List tasks
/// - GET /a2a/tasks/{id} - Get task status
/// - POST /a2a/tasks/{id}/cancel - Cancel a task
pub fn a2a_router(state: AgentsState) -> Router {
    Router::new()
        .route("/tasks", post(handlers::create_task))
        .route("/tasks", get(handlers::list_tasks))
        .route("/tasks/:id", get(handlers::get_task))
        .route("/tasks/:id/cancel", post(handlers::cancel_task))
        .with_state(state)
}

/// Create an mTLS-protected router for agent-to-agent communication (F127).
///
/// This router requires mTLS authentication and extracts agent identity
/// from the client certificate. The `MtlsIdentity` extension is available
/// to all handlers in this router.
///
/// Routes:
/// - POST /a2a/secure/tasks - Create task (requires mTLS)
/// - GET /a2a/secure/tasks - List tasks (requires mTLS)
/// - POST /a2a/secure/call - Direct A2A RPC call (requires mTLS)
///
/// # Arguments
/// * `state` - The agents state containing service references
/// * `mtls_config` - Configuration for mTLS validation (required vs optional)
pub fn mtls_a2a_router(state: AgentsState, mtls_config: crate::middleware::MtlsConfig) -> Router {
    use crate::middleware::MtlsLayer;

    let mtls_layer = MtlsLayer::new(
        mtls_config,
        state.pool.clone(),
        Arc::clone(&state.certificate_service),
    );

    Router::new()
        .route("/tasks", post(handlers::create_task))
        .route("/tasks", get(handlers::list_tasks))
        .route("/tasks/:id", get(handlers::get_task))
        .route("/tasks/:id/cancel", post(handlers::cancel_task))
        .layer(mtls_layer)
        .with_state(state)
}

/// Create an mTLS-optional router for agent-to-agent communication (F127).
///
/// This router accepts both mTLS-authenticated requests and regular requests.
/// If mTLS is used, the `MtlsIdentity` extension is available to handlers.
/// If not, handlers can use JWT authentication as fallback.
///
/// This is useful for gradual mTLS rollout where clients may not all
/// have certificates yet.
///
/// # Arguments
/// * `state` - The agents state containing service references
pub fn mtls_optional_a2a_router(state: AgentsState) -> Router {
    mtls_a2a_router(state, crate::middleware::MtlsConfig::optional())
}

/// Create an mTLS-required router for agent-to-agent communication (F127).
///
/// This router requires mTLS authentication. Requests without valid
/// client certificates will be rejected with 401 Unauthorized.
///
/// # Arguments
/// * `state` - The agents state containing service references
pub fn mtls_required_a2a_router(state: AgentsState) -> Router {
    mtls_a2a_router(state, crate::middleware::MtlsConfig::required())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_creation() {
        // This test verifies the state struct can be created
        // Actual pool creation requires database
    }

    #[test]
    fn test_mtls_config_variants() {
        use crate::middleware::MtlsConfig;

        let required = MtlsConfig::required();
        assert!(required.required);

        let optional = MtlsConfig::optional();
        assert!(!optional.required);
    }
}
