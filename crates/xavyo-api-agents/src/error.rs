//! Error types for the AI Agent Security API.
//!
//! Uses RFC 7807 Problem Details for HTTP APIs for structured error responses.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Base URL for error type URIs.
const ERROR_BASE_URL: &str = "https://xavyo.net/errors/agents";

/// RFC 7807 Problem Details structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProblemDetails {
    /// URI identifying the problem type.
    #[serde(rename = "type")]
    pub error_type: String,

    /// Short human-readable summary.
    pub title: String,

    /// HTTP status code.
    pub status: u16,

    /// Human-readable explanation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,

    /// URI of the specific occurrence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
}

impl ProblemDetails {
    /// Create a new `ProblemDetails` instance.
    #[must_use]
    pub fn new(error_type: &str, title: &str, status: StatusCode) -> Self {
        Self {
            error_type: format!("{ERROR_BASE_URL}/{error_type}"),
            title: title.to_string(),
            status: status.as_u16(),
            detail: None,
            instance: None,
        }
    }

    /// Add detail message.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Add instance URI.
    #[must_use]
    pub fn with_instance(mut self, instance: impl Into<String>) -> Self {
        self.instance = Some(instance.into());
        self
    }
}

/// AI Agent Security API errors.
#[derive(Debug, Error)]
pub enum ApiAgentsError {
    // Agent errors
    /// Agent not found.
    #[error("Agent not found")]
    AgentNotFound,

    /// Agent name already exists for this tenant.
    #[error("Agent name already exists")]
    AgentNameExists,

    /// Agent is not active.
    #[error("Agent is not active")]
    AgentNotActive,

    /// Agent is already suspended.
    #[error("Agent is already suspended")]
    AgentAlreadySuspended,

    /// Agent is expired and cannot be reactivated.
    #[error("Agent has expired")]
    AgentExpired,

    /// Agent cannot be reactivated (not suspended).
    #[error("Agent cannot be reactivated")]
    AgentCannotReactivate,

    /// Agent has no backup owner to promote.
    #[error("Agent has no backup owner")]
    NoBackupOwner,

    /// Backup owner not found (user no longer exists).
    #[error("Backup owner not found")]
    BackupOwnerNotFound,

    // Tool errors
    /// Tool not found.
    #[error("Tool not found")]
    ToolNotFound,

    /// Tool name already exists for this tenant.
    #[error("Tool name already exists")]
    ToolNameExists,

    /// Tool is not active.
    #[error("Tool is not active")]
    ToolNotActive,

    /// Invalid JSON Schema for tool input.
    #[error("Invalid input schema: {0}")]
    InvalidInputSchema(String),

    // Permission errors
    /// Permission not found.
    #[error("Permission not found")]
    PermissionNotFound,

    /// Permission already exists for this agent/tool combination.
    #[error("Permission already exists")]
    PermissionExists,

    /// Permission has expired.
    #[error("Permission has expired")]
    PermissionExpired,

    // Authorization errors
    /// Agent does not have permission for the requested tool.
    #[error("Agent does not have permission for tool '{0}'")]
    NoPermission(String),

    /// Rate limit exceeded for agent/tool combination.
    #[error("Rate limit exceeded: {0}/{1} calls in current hour")]
    RateLimitExceeded(i32, i32),

    /// Authorization requires human approval.
    #[error("Human approval required for this action")]
    ApprovalRequired,

    // General errors
    /// Invalid request parameters.
    #[error("Validation error: {0}")]
    Validation(String),

    /// Missing tenant context.
    #[error("Missing tenant context")]
    MissingTenant,

    /// Missing user context.
    #[error("Missing user context")]
    MissingUser,

    /// Unauthorized access.
    #[error("Unauthorized")]
    Unauthorized,

    /// Internal server error.
    #[error("Internal server error: {0}")]
    Internal(String),

    /// Database error.
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Invalid risk level.
    #[error("Invalid risk level: {0}")]
    InvalidRiskLevel(String),

    /// Invalid agent type.
    #[error("Invalid agent type: {0}")]
    InvalidAgentType(String),

    /// Invalid status.
    #[error("Invalid status: {0}")]
    InvalidStatus(String),

    // F092: Human-in-the-Loop Approval errors
    /// Approval request not found.
    #[error("Approval request not found")]
    ApprovalNotFound,

    /// Approval request has already been decided.
    #[error("Approval request has already been decided")]
    ApprovalAlreadyDecided,

    /// Approval request has expired.
    #[error("Approval request has expired")]
    ApprovalExpired,

    /// User is not authorized to approve/deny this request.
    #[error("Not authorized to approve/deny this request")]
    NotAuthorizedApprover,

    /// Denial reason is required.
    #[error("Denial reason is required")]
    DenialReasonRequired,

    // F091: MCP & A2A errors
    /// Missing tenant ID in claims.
    #[error("Missing tenant ID in JWT claims")]
    MissingTenantId,

    /// Missing agent ID in claims.
    #[error("Missing agent ID in JWT claims")]
    MissingAgentId,

    /// Not found (generic).
    #[error("Not found: {0}")]
    NotFound(String),

    /// Bad request (generic).
    #[error("Bad request: {0}")]
    BadRequest(String),

    /// Invalid state transition.
    #[error("Invalid state transition: {0}")]
    InvalidStateTransition(String),

    // F120: Dynamic Secrets Provisioning errors
    /// Secret type not found.
    #[error("Secret type not found: {0}")]
    SecretTypeNotFound(String),

    /// Secret type already exists.
    #[error("Secret type already exists: {0}")]
    SecretTypeExists(String),

    /// Secret type is not enabled.
    #[error("Secret type is not enabled: {0}")]
    SecretTypeDisabled(String),

    /// Agent does not have permission for the requested secret type.
    #[error("Agent does not have permission for secret type '{0}'")]
    SecretPermissionDenied(String),

    /// Agent secret permission not found.
    #[error("Agent secret permission not found")]
    SecretPermissionNotFound,

    /// Agent secret permission has expired.
    #[error("Agent secret permission has expired")]
    SecretPermissionExpired,

    /// Secret provider not found.
    #[error("Secret provider not found: {0}")]
    SecretProviderNotFound(String),

    /// Secret provider is not available.
    #[error("Secret provider unavailable: {0}")]
    SecretProviderUnavailable(String),

    /// Secret provider health check failed.
    #[error("Secret provider unhealthy: {0}")]
    SecretProviderUnhealthy(String),

    /// Credential request rate limit exceeded.
    #[error("Credential rate limit exceeded: {0}/{1} requests in current hour")]
    CredentialRateLimitExceeded(i32, i32),

    /// Invalid TTL requested.
    #[error("Invalid TTL: {0}")]
    InvalidTtl(String),

    /// Invalid rate limit requested.
    #[error("Invalid rate limit: {0}")]
    InvalidRateLimit(String),

    /// Dynamic credential not found.
    #[error("Credential not found")]
    CredentialNotFound,

    /// Dynamic credential has expired.
    #[error("Credential has expired")]
    CredentialExpired,

    /// Dynamic credential has been revoked.
    #[error("Credential has been revoked")]
    CredentialRevoked,

    /// Encryption error.
    #[error("Encryption error: {0}")]
    EncryptionError(String),

    /// Provider authentication failed.
    #[error("Provider authentication failed: {0}")]
    ProviderAuthFailed(String),

    /// Provider operation timed out.
    #[error("Provider operation timed out: {0}")]
    ProviderTimeout(String),

    // F121: Workload Identity Federation errors
    /// Identity provider not found.
    #[error("Identity provider not found")]
    IdentityProviderNotFound,

    /// Identity provider already exists with this name.
    #[error("Identity provider name already exists")]
    IdentityProviderExists,

    /// Duplicate identity provider name for this tenant (T042).
    #[error("Identity provider name '{0}' already exists for this tenant")]
    DuplicateProviderName(String),

    /// Identity provider is not active.
    #[error("Identity provider is not active")]
    IdentityProviderNotActive,

    /// Identity provider is unhealthy.
    #[error("Identity provider is unhealthy: {0}")]
    IdentityProviderUnhealthy(String),

    /// Invalid identity provider configuration.
    #[error("Invalid identity provider configuration: {0}")]
    InvalidProviderConfig(String),

    /// Role mapping not found.
    #[error("Role mapping not found")]
    RoleMappingNotFound,

    /// Role mapping already exists for this agent type.
    #[error("Role mapping already exists for this agent type")]
    RoleMappingExists,

    /// No role mapping found for agent type.
    #[error("No role mapping found for agent type '{0}'")]
    NoRoleMappingForAgent(String),

    /// Cloud credential request denied.
    #[error("Cloud credential request denied: {0}")]
    CloudCredentialDenied(String),

    /// Cloud credential rate limit exceeded.
    #[error("Cloud credential rate limit exceeded: {0}/{1} requests in current hour")]
    CloudCredentialRateLimited(i32, i32),

    /// Cloud provider error.
    #[error("Cloud provider error: {0}")]
    CloudProviderError(String),

    /// Invalid cloud provider type.
    #[error("Invalid cloud provider type: {0}")]
    InvalidCloudProviderType(String),

    /// Identity provider has active role mappings.
    #[error("Identity provider has active role mappings: {0}")]
    IdentityProviderHasRoleMappings(uuid::Uuid),

    /// Missing bearer token.
    #[error("Missing bearer token")]
    MissingToken,

    // F127: PKI & Certificate errors
    /// Certificate Authority not found.
    #[error("Certificate Authority not found")]
    CaNotFound,

    /// Certificate Authority already exists with this name.
    #[error("Certificate Authority name already exists")]
    CaNameExists,

    /// Certificate Authority is not active.
    #[error("Certificate Authority is not active")]
    CaNotActive,

    /// No default Certificate Authority configured for tenant.
    #[error("No default Certificate Authority configured")]
    NoDefaultCa,

    /// Certificate not found.
    #[error("Certificate not found")]
    CertificateNotFound,

    /// Certificate has already been revoked.
    #[error("Certificate has already been revoked")]
    CertificateAlreadyRevoked,

    /// Certificate has expired.
    #[error("Certificate has expired")]
    CertificateExpired,

    /// Certificate is not valid yet (`not_before` is in the future).
    #[error("Certificate is not valid yet")]
    CertificateNotYetValid,

    /// Cannot renew a revoked certificate.
    #[error("Cannot renew a revoked certificate")]
    CannotRenewRevokedCertificate,

    /// Requested validity period exceeds CA maximum.
    #[error("Validity period exceeds maximum: {requested} days requested, max {max} days")]
    ValidityExceedsMax { requested: i32, max: i32 },

    /// Invalid certificate format.
    #[error("Invalid certificate format: {0}")]
    InvalidCertificateFormat(String),

    /// Invalid key algorithm.
    #[error("Invalid key algorithm: {0}")]
    InvalidKeyAlgorithm(String),

    /// Invalid revocation reason.
    #[error("Invalid revocation reason: {0}")]
    InvalidRevocationReason(String),

    /// CA private key is not available.
    #[error("CA private key unavailable")]
    CaPrivateKeyUnavailable,

    /// Certificate signing failed.
    #[error("Certificate signing failed: {0}")]
    CertificateSigningFailed(String),

    /// mTLS certificate required but not provided.
    #[error("Client certificate required for mTLS")]
    MtlsCertificateRequired,

    /// mTLS certificate validation failed.
    #[error("mTLS certificate validation failed: {0}")]
    MtlsValidationFailed(String),

    /// External CA provider error.
    #[error("External CA error: {0}")]
    ExternalCaError(String),

    /// CRL generation failed.
    #[error("CRL generation failed: {0}")]
    CrlGenerationFailed(String),

    /// OCSP response error.
    #[error("OCSP error: {0}")]
    OcspError(String),

    /// CA already exists with the given name.
    #[error("Certificate Authority '{0}' already exists")]
    CaAlreadyExists(String),

    /// Invalid CA type.
    #[error("Invalid CA type: {0}")]
    InvalidCaType(String),

    /// CA creation failed.
    #[error("CA creation failed: {0}")]
    CaCreationFailed(String),

    /// CA is disabled.
    #[error("Certificate Authority is disabled")]
    CaDisabled(uuid::Uuid),

    /// Cannot delete the default CA.
    #[error("Cannot delete the default Certificate Authority")]
    CannotDeleteDefaultCa,

    /// CA has active certificates and cannot be deleted.
    #[error("Certificate Authority {ca_id} has {count} active certificates and cannot be deleted")]
    CaHasActiveCertificates { ca_id: uuid::Uuid, count: i64 },

    /// CA provider not implemented.
    #[error("CA provider not implemented: {0}")]
    CaProviderNotImplemented(String),

    /// CA not found (by UUID).
    #[error("Certificate Authority not found: {0}")]
    CaNotFoundId(uuid::Uuid),

    /// Certificate not found (by UUID).
    #[error("Certificate not found: {0}")]
    CertificateNotFoundId(uuid::Uuid),

    /// Certificate issuance failed.
    #[error("Certificate issuance failed: {0}")]
    CertificateIssueFailed(String),

    /// Agent not found (by UUID).
    #[error("Agent not found: {0}")]
    AgentNotFoundId(uuid::Uuid),

    /// Agent not active (by UUID).
    #[error("Agent is not active: {0}")]
    AgentNotActiveId(uuid::Uuid),
}

impl ApiAgentsError {
    /// Convert to `ProblemDetails`.
    #[must_use]
    pub fn to_problem_details(&self) -> ProblemDetails {
        match self {
            // Agent errors
            ApiAgentsError::AgentNotFound => {
                ProblemDetails::new("agent-not-found", "Agent Not Found", StatusCode::NOT_FOUND)
                    .with_detail("The requested agent was not found.")
            }
            ApiAgentsError::AgentNameExists => {
                ProblemDetails::new("agent-name-exists", "Agent Name Exists", StatusCode::CONFLICT)
                    .with_detail("An agent with this name already exists for this tenant.")
            }
            ApiAgentsError::AgentNotActive => ProblemDetails::new(
                "agent-not-active",
                "Agent Not Active",
                StatusCode::FORBIDDEN,
            )
            .with_detail("The agent is not active and cannot perform this operation."),
            ApiAgentsError::AgentAlreadySuspended => ProblemDetails::new(
                "agent-already-suspended",
                "Agent Already Suspended",
                StatusCode::CONFLICT,
            )
            .with_detail("The agent is already suspended."),
            ApiAgentsError::AgentExpired => ProblemDetails::new(
                "agent-expired",
                "Agent Expired",
                StatusCode::FORBIDDEN,
            )
            .with_detail("The agent has expired and cannot be used."),
            ApiAgentsError::AgentCannotReactivate => ProblemDetails::new(
                "agent-cannot-reactivate",
                "Cannot Reactivate Agent",
                StatusCode::BAD_REQUEST,
            )
            .with_detail("The agent cannot be reactivated. Only suspended agents can be reactivated."),
            ApiAgentsError::NoBackupOwner => ProblemDetails::new(
                "no-backup-owner",
                "No Backup Owner",
                StatusCode::BAD_REQUEST,
            )
            .with_detail("The agent has no backup owner to promote."),
            ApiAgentsError::BackupOwnerNotFound => ProblemDetails::new(
                "backup-owner-not-found",
                "Backup Owner Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail("The backup owner no longer exists in the tenant."),

            // Tool errors
            ApiAgentsError::ToolNotFound => {
                ProblemDetails::new("tool-not-found", "Tool Not Found", StatusCode::NOT_FOUND)
                    .with_detail("The requested tool was not found.")
            }
            ApiAgentsError::ToolNameExists => {
                ProblemDetails::new("tool-name-exists", "Tool Name Exists", StatusCode::CONFLICT)
                    .with_detail("A tool with this name already exists for this tenant.")
            }
            ApiAgentsError::ToolNotActive => {
                ProblemDetails::new("tool-not-active", "Tool Not Active", StatusCode::FORBIDDEN)
                    .with_detail("The tool is not active and cannot be used.")
            }
            ApiAgentsError::InvalidInputSchema(msg) => ProblemDetails::new(
                "invalid-input-schema",
                "Invalid Input Schema",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(msg.clone()),

            // Permission errors
            ApiAgentsError::PermissionNotFound => ProblemDetails::new(
                "permission-not-found",
                "Permission Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail("The requested permission was not found."),
            ApiAgentsError::PermissionExists => ProblemDetails::new(
                "permission-exists",
                "Permission Exists",
                StatusCode::CONFLICT,
            )
            .with_detail("A permission for this agent/tool combination already exists."),
            ApiAgentsError::PermissionExpired => ProblemDetails::new(
                "permission-expired",
                "Permission Expired",
                StatusCode::FORBIDDEN,
            )
            .with_detail("The permission has expired."),

            // Authorization errors
            ApiAgentsError::NoPermission(tool_name) => ProblemDetails::new(
                "no-permission",
                "No Permission",
                StatusCode::FORBIDDEN,
            )
            .with_detail(format!("Agent does not have permission for tool '{tool_name}'.")),
            ApiAgentsError::RateLimitExceeded(current, max) => ProblemDetails::new(
                "rate-limit-exceeded",
                "Rate Limit Exceeded",
                StatusCode::TOO_MANY_REQUESTS,
            )
            .with_detail(format!(
                "Rate limit exceeded: {current}/{max} calls in current hour."
            )),
            ApiAgentsError::ApprovalRequired => ProblemDetails::new(
                "approval-required",
                "Approval Required",
                StatusCode::FORBIDDEN,
            )
            .with_detail("This action requires human approval."),

            // General errors
            ApiAgentsError::Validation(msg) => ProblemDetails::new(
                "validation-error",
                "Validation Error",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(msg.clone()),
            ApiAgentsError::MissingTenant => ProblemDetails::new(
                "missing-tenant",
                "Missing Tenant",
                StatusCode::BAD_REQUEST,
            )
            .with_detail("Tenant context is required."),
            ApiAgentsError::MissingUser => ProblemDetails::new(
                "missing-user",
                "Missing User",
                StatusCode::BAD_REQUEST,
            )
            .with_detail("User context is required."),
            ApiAgentsError::Unauthorized => {
                ProblemDetails::new("unauthorized", "Unauthorized", StatusCode::UNAUTHORIZED)
                    .with_detail("Authentication required.")
            }
            ApiAgentsError::Internal(msg) => ProblemDetails::new(
                "internal-error",
                "Internal Server Error",
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .with_detail(msg.clone()),
            ApiAgentsError::Database(err) => ProblemDetails::new(
                "database-error",
                "Database Error",
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .with_detail(err.to_string()),
            ApiAgentsError::InvalidRiskLevel(level) => ProblemDetails::new(
                "invalid-risk-level",
                "Invalid Risk Level",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(format!("Invalid risk level: {level}. Must be one of: low, medium, high, critical.")),
            ApiAgentsError::InvalidAgentType(agent_type) => ProblemDetails::new(
                "invalid-agent-type",
                "Invalid Agent Type",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(format!("Invalid agent type: {agent_type}. Must be one of: autonomous, copilot, workflow, orchestrator.")),
            ApiAgentsError::InvalidStatus(status) => ProblemDetails::new(
                "invalid-status",
                "Invalid Status",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(format!("Invalid status: {status}.")),

            // F092: Human-in-the-Loop Approval errors
            ApiAgentsError::ApprovalNotFound => ProblemDetails::new(
                "approval-not-found",
                "Approval Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail("The requested approval was not found."),
            ApiAgentsError::ApprovalAlreadyDecided => ProblemDetails::new(
                "approval-already-decided",
                "Approval Already Decided",
                StatusCode::CONFLICT,
            )
            .with_detail("This approval request has already been decided."),
            ApiAgentsError::ApprovalExpired => ProblemDetails::new(
                "approval-expired",
                "Approval Expired",
                StatusCode::CONFLICT,
            )
            .with_detail("This approval request has expired."),
            ApiAgentsError::NotAuthorizedApprover => ProblemDetails::new(
                "not-authorized-approver",
                "Not Authorized",
                StatusCode::FORBIDDEN,
            )
            .with_detail("You are not authorized to approve/deny requests for this agent."),
            ApiAgentsError::DenialReasonRequired => ProblemDetails::new(
                "denial-reason-required",
                "Denial Reason Required",
                StatusCode::BAD_REQUEST,
            )
            .with_detail("A reason must be provided when denying an approval request."),

            // F091: MCP & A2A errors
            ApiAgentsError::MissingTenantId => ProblemDetails::new(
                "missing-tenant-id",
                "Missing Tenant ID",
                StatusCode::UNAUTHORIZED,
            )
            .with_detail("JWT token must contain a tenant_id claim."),
            ApiAgentsError::MissingAgentId => ProblemDetails::new(
                "missing-agent-id",
                "Missing Agent ID",
                StatusCode::UNAUTHORIZED,
            )
            .with_detail("JWT token must contain an agent_id (sub) claim."),
            ApiAgentsError::NotFound(msg) => ProblemDetails::new(
                "not-found",
                "Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail(msg.clone()),
            ApiAgentsError::BadRequest(msg) => ProblemDetails::new(
                "bad-request",
                "Bad Request",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(msg.clone()),
            ApiAgentsError::InvalidStateTransition(msg) => ProblemDetails::new(
                "invalid-state-transition",
                "Invalid State Transition",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(msg.clone()),

            // F120: Dynamic Secrets Provisioning errors
            ApiAgentsError::SecretTypeNotFound(type_name) => ProblemDetails::new(
                "secret-type-not-found",
                "Secret Type Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail(format!("Secret type '{type_name}' not found.")),
            ApiAgentsError::SecretTypeExists(type_name) => ProblemDetails::new(
                "secret-type-exists",
                "Secret Type Exists",
                StatusCode::CONFLICT,
            )
            .with_detail(format!("Secret type '{type_name}' already exists for this tenant.")),
            ApiAgentsError::SecretTypeDisabled(type_name) => ProblemDetails::new(
                "secret-type-disabled",
                "Secret Type Disabled",
                StatusCode::FORBIDDEN,
            )
            .with_detail(format!("Secret type '{type_name}' is not enabled.")),
            ApiAgentsError::SecretPermissionDenied(type_name) => ProblemDetails::new(
                "secret-permission-denied",
                "Secret Permission Denied",
                StatusCode::FORBIDDEN,
            )
            .with_detail(format!("Agent does not have permission for secret type '{type_name}'.")),
            ApiAgentsError::SecretPermissionNotFound => ProblemDetails::new(
                "secret-permission-not-found",
                "Secret Permission Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail("The requested agent secret permission was not found."),
            ApiAgentsError::SecretPermissionExpired => ProblemDetails::new(
                "secret-permission-expired",
                "Secret Permission Expired",
                StatusCode::FORBIDDEN,
            )
            .with_detail("The agent's secret permission has expired."),
            ApiAgentsError::SecretProviderNotFound(provider) => ProblemDetails::new(
                "secret-provider-not-found",
                "Secret Provider Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail(format!("Secret provider '{provider}' not found.")),
            ApiAgentsError::SecretProviderUnavailable(msg) => ProblemDetails::new(
                "secret-provider-unavailable",
                "Secret Provider Unavailable",
                StatusCode::SERVICE_UNAVAILABLE,
            )
            .with_detail(msg.clone()),
            ApiAgentsError::SecretProviderUnhealthy(msg) => ProblemDetails::new(
                "secret-provider-unhealthy",
                "Secret Provider Unhealthy",
                StatusCode::SERVICE_UNAVAILABLE,
            )
            .with_detail(msg.clone()),
            ApiAgentsError::CredentialRateLimitExceeded(current, max) => ProblemDetails::new(
                "credential-rate-limit-exceeded",
                "Credential Rate Limit Exceeded",
                StatusCode::TOO_MANY_REQUESTS,
            )
            .with_detail(format!(
                "Credential request rate limit exceeded: {current}/{max} requests in current hour."
            )),
            ApiAgentsError::InvalidTtl(msg) => ProblemDetails::new(
                "invalid-ttl",
                "Invalid TTL",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(msg.clone()),
            ApiAgentsError::InvalidRateLimit(msg) => ProblemDetails::new(
                "invalid-rate-limit",
                "Invalid Rate Limit",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(msg.clone()),
            ApiAgentsError::CredentialNotFound => ProblemDetails::new(
                "credential-not-found",
                "Credential Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail("The requested credential was not found."),
            ApiAgentsError::CredentialExpired => ProblemDetails::new(
                "credential-expired",
                "Credential Expired",
                StatusCode::GONE,
            )
            .with_detail("The credential has expired and is no longer valid."),
            ApiAgentsError::CredentialRevoked => ProblemDetails::new(
                "credential-revoked",
                "Credential Revoked",
                StatusCode::GONE,
            )
            .with_detail("The credential has been revoked and is no longer valid."),
            ApiAgentsError::EncryptionError(msg) => ProblemDetails::new(
                "encryption-error",
                "Encryption Error",
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .with_detail(msg.clone()),
            ApiAgentsError::ProviderAuthFailed(msg) => ProblemDetails::new(
                "provider-auth-failed",
                "Provider Authentication Failed",
                StatusCode::BAD_GATEWAY,
            )
            .with_detail(msg.clone()),
            ApiAgentsError::ProviderTimeout(msg) => ProblemDetails::new(
                "provider-timeout",
                "Provider Timeout",
                StatusCode::GATEWAY_TIMEOUT,
            )
            .with_detail(msg.clone()),

            // F121: Workload Identity Federation errors
            ApiAgentsError::IdentityProviderNotFound => ProblemDetails::new(
                "identity-provider-not-found",
                "Identity Provider Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail("The requested identity provider configuration was not found."),
            ApiAgentsError::IdentityProviderExists => ProblemDetails::new(
                "identity-provider-exists",
                "Identity Provider Exists",
                StatusCode::CONFLICT,
            )
            .with_detail("An identity provider with this name already exists for this tenant."),
            ApiAgentsError::DuplicateProviderName(name) => ProblemDetails::new(
                "duplicate-provider-name",
                "Duplicate Provider Name",
                StatusCode::CONFLICT,
            )
            .with_detail(format!("An identity provider named '{name}' already exists for this tenant.")),
            ApiAgentsError::IdentityProviderNotActive => ProblemDetails::new(
                "identity-provider-not-active",
                "Identity Provider Not Active",
                StatusCode::FORBIDDEN,
            )
            .with_detail("The identity provider is not active and cannot be used."),
            ApiAgentsError::IdentityProviderUnhealthy(msg) => ProblemDetails::new(
                "identity-provider-unhealthy",
                "Identity Provider Unhealthy",
                StatusCode::SERVICE_UNAVAILABLE,
            )
            .with_detail(msg.clone()),
            ApiAgentsError::InvalidProviderConfig(msg) => ProblemDetails::new(
                "invalid-provider-config",
                "Invalid Provider Configuration",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(msg.clone()),
            ApiAgentsError::RoleMappingNotFound => ProblemDetails::new(
                "role-mapping-not-found",
                "Role Mapping Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail("The requested role mapping was not found."),
            ApiAgentsError::RoleMappingExists => ProblemDetails::new(
                "role-mapping-exists",
                "Role Mapping Exists",
                StatusCode::CONFLICT,
            )
            .with_detail("A role mapping for this agent type already exists for this provider."),
            ApiAgentsError::NoRoleMappingForAgent(agent_type) => ProblemDetails::new(
                "no-role-mapping",
                "No Role Mapping",
                StatusCode::FORBIDDEN,
            )
            .with_detail(format!("No role mapping found for agent type '{agent_type}'.")),
            ApiAgentsError::CloudCredentialDenied(reason) => ProblemDetails::new(
                "cloud-credential-denied",
                "Cloud Credential Denied",
                StatusCode::FORBIDDEN,
            )
            .with_detail(reason.clone()),
            ApiAgentsError::CloudCredentialRateLimited(current, max) => ProblemDetails::new(
                "cloud-credential-rate-limited",
                "Cloud Credential Rate Limited",
                StatusCode::TOO_MANY_REQUESTS,
            )
            .with_detail(format!(
                "Cloud credential request rate limit exceeded: {current}/{max} requests in current hour."
            )),
            ApiAgentsError::CloudProviderError(msg) => ProblemDetails::new(
                "cloud-provider-error",
                "Cloud Provider Error",
                StatusCode::BAD_GATEWAY,
            )
            .with_detail(msg.clone()),
            ApiAgentsError::InvalidCloudProviderType(provider_type) => ProblemDetails::new(
                "invalid-cloud-provider-type",
                "Invalid Cloud Provider Type",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(format!("Invalid cloud provider type: '{provider_type}'.")),
            ApiAgentsError::IdentityProviderHasRoleMappings(id) => ProblemDetails::new(
                "identity-provider-has-mappings",
                "Identity Provider Has Role Mappings",
                StatusCode::CONFLICT,
            )
            .with_detail(format!(
                "Cannot delete identity provider '{id}': it has active role mappings."
            )),
            ApiAgentsError::MissingToken => ProblemDetails::new(
                "missing-token",
                "Missing Bearer Token",
                StatusCode::UNAUTHORIZED,
            )
            .with_detail("Authorization header with Bearer token is required."),

            // F127: PKI & Certificate errors
            ApiAgentsError::CaNotFound => ProblemDetails::new(
                "ca-not-found",
                "Certificate Authority Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail("The requested Certificate Authority was not found."),
            ApiAgentsError::CaNameExists => ProblemDetails::new(
                "ca-name-exists",
                "CA Name Exists",
                StatusCode::CONFLICT,
            )
            .with_detail("A Certificate Authority with this name already exists for this tenant."),
            ApiAgentsError::CaNotActive => ProblemDetails::new(
                "ca-not-active",
                "CA Not Active",
                StatusCode::FORBIDDEN,
            )
            .with_detail("The Certificate Authority is not active and cannot issue certificates."),
            ApiAgentsError::NoDefaultCa => ProblemDetails::new(
                "no-default-ca",
                "No Default CA",
                StatusCode::NOT_FOUND,
            )
            .with_detail("No default Certificate Authority is configured for this tenant."),
            ApiAgentsError::CertificateNotFound => ProblemDetails::new(
                "certificate-not-found",
                "Certificate Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail("The requested certificate was not found."),
            ApiAgentsError::CertificateAlreadyRevoked => ProblemDetails::new(
                "certificate-already-revoked",
                "Certificate Already Revoked",
                StatusCode::CONFLICT,
            )
            .with_detail("The certificate has already been revoked."),
            ApiAgentsError::CertificateExpired => ProblemDetails::new(
                "certificate-expired",
                "Certificate Expired",
                StatusCode::GONE,
            )
            .with_detail("The certificate has expired."),
            ApiAgentsError::CertificateNotYetValid => ProblemDetails::new(
                "certificate-not-yet-valid",
                "Certificate Not Yet Valid",
                StatusCode::FORBIDDEN,
            )
            .with_detail("The certificate is not valid yet."),
            ApiAgentsError::CannotRenewRevokedCertificate => ProblemDetails::new(
                "cannot-renew-revoked",
                "Cannot Renew Revoked Certificate",
                StatusCode::CONFLICT,
            )
            .with_detail("A revoked certificate cannot be renewed."),
            ApiAgentsError::ValidityExceedsMax { requested, max } => ProblemDetails::new(
                "validity-exceeds-max",
                "Validity Exceeds Maximum",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(format!(
                "Requested validity of {requested} days exceeds maximum of {max} days."
            )),
            ApiAgentsError::InvalidCertificateFormat(msg) => ProblemDetails::new(
                "invalid-certificate-format",
                "Invalid Certificate Format",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(msg.clone()),
            ApiAgentsError::InvalidKeyAlgorithm(alg) => ProblemDetails::new(
                "invalid-key-algorithm",
                "Invalid Key Algorithm",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(format!("Invalid key algorithm: {alg}. Use rsa2048, rsa4096, ecdsa_p256, or ecdsa_p384.")),
            ApiAgentsError::InvalidRevocationReason(reason) => ProblemDetails::new(
                "invalid-revocation-reason",
                "Invalid Revocation Reason",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(format!("Invalid revocation reason: {reason}.")),
            ApiAgentsError::CaPrivateKeyUnavailable => ProblemDetails::new(
                "ca-private-key-unavailable",
                "CA Private Key Unavailable",
                StatusCode::SERVICE_UNAVAILABLE,
            )
            .with_detail("The CA private key is not available for signing."),
            ApiAgentsError::CertificateSigningFailed(msg) => ProblemDetails::new(
                "certificate-signing-failed",
                "Certificate Signing Failed",
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .with_detail(msg.clone()),
            ApiAgentsError::MtlsCertificateRequired => ProblemDetails::new(
                "mtls-certificate-required",
                "mTLS Certificate Required",
                StatusCode::UNAUTHORIZED,
            )
            .with_detail("Client certificate is required for mTLS authentication."),
            ApiAgentsError::MtlsValidationFailed(msg) => ProblemDetails::new(
                "mtls-validation-failed",
                "mTLS Validation Failed",
                StatusCode::UNAUTHORIZED,
            )
            .with_detail(msg.clone()),
            ApiAgentsError::ExternalCaError(msg) => ProblemDetails::new(
                "external-ca-error",
                "External CA Error",
                StatusCode::BAD_GATEWAY,
            )
            .with_detail(msg.clone()),
            ApiAgentsError::CrlGenerationFailed(msg) => ProblemDetails::new(
                "crl-generation-failed",
                "CRL Generation Failed",
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .with_detail(msg.clone()),
            ApiAgentsError::OcspError(msg) => ProblemDetails::new(
                "ocsp-error",
                "OCSP Error",
                StatusCode::BAD_GATEWAY,
            )
            .with_detail(msg.clone()),
            ApiAgentsError::CaAlreadyExists(name) => ProblemDetails::new(
                "ca-already-exists",
                "CA Already Exists",
                StatusCode::CONFLICT,
            )
            .with_detail(format!("A Certificate Authority named '{name}' already exists.")),
            ApiAgentsError::InvalidCaType(ca_type) => ProblemDetails::new(
                "invalid-ca-type",
                "Invalid CA Type",
                StatusCode::BAD_REQUEST,
            )
            .with_detail(format!("Invalid CA type: '{ca_type}'. Use 'internal', 'step_ca', or 'vault_pki'.")),
            ApiAgentsError::CaCreationFailed(msg) => ProblemDetails::new(
                "ca-creation-failed",
                "CA Creation Failed",
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .with_detail(msg.clone()),
            ApiAgentsError::CaDisabled(id) => ProblemDetails::new(
                "ca-disabled",
                "CA Disabled",
                StatusCode::FORBIDDEN,
            )
            .with_detail(format!("Certificate Authority '{id}' is disabled.")),
            ApiAgentsError::CannotDeleteDefaultCa => ProblemDetails::new(
                "cannot-delete-default-ca",
                "Cannot Delete Default CA",
                StatusCode::CONFLICT,
            )
            .with_detail("Cannot delete the default Certificate Authority. Set another CA as default first."),
            ApiAgentsError::CaHasActiveCertificates { ca_id, count } => ProblemDetails::new(
                "ca-has-active-certificates",
                "CA Has Active Certificates",
                StatusCode::CONFLICT,
            )
            .with_detail(format!(
                "Certificate Authority '{ca_id}' has {count} active certificate(s). Revoke or let them expire before deleting the CA."
            )),
            ApiAgentsError::CaProviderNotImplemented(provider) => ProblemDetails::new(
                "ca-provider-not-implemented",
                "CA Provider Not Implemented",
                StatusCode::NOT_IMPLEMENTED,
            )
            .with_detail(format!("CA provider '{provider}' is not yet implemented.")),
            ApiAgentsError::CaNotFoundId(id) => ProblemDetails::new(
                "ca-not-found",
                "Certificate Authority Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail(format!("Certificate Authority '{id}' was not found.")),
            ApiAgentsError::CertificateNotFoundId(id) => ProblemDetails::new(
                "certificate-not-found",
                "Certificate Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail(format!("Certificate '{id}' was not found.")),
            ApiAgentsError::CertificateIssueFailed(msg) => ProblemDetails::new(
                "certificate-issue-failed",
                "Certificate Issuance Failed",
                StatusCode::INTERNAL_SERVER_ERROR,
            )
            .with_detail(format!("Certificate issuance failed: {msg}")),
            ApiAgentsError::AgentNotFoundId(id) => ProblemDetails::new(
                "agent-not-found",
                "Agent Not Found",
                StatusCode::NOT_FOUND,
            )
            .with_detail(format!("Agent '{id}' was not found.")),
            ApiAgentsError::AgentNotActiveId(id) => ProblemDetails::new(
                "agent-not-active",
                "Agent Not Active",
                StatusCode::FORBIDDEN,
            )
            .with_detail(format!("Agent '{id}' is not active.")),
        }
    }

    /// Get the HTTP status code for this error.
    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        match self {
            // Not Found
            ApiAgentsError::AgentNotFound
            | ApiAgentsError::ToolNotFound
            | ApiAgentsError::PermissionNotFound
            | ApiAgentsError::ApprovalNotFound
            | ApiAgentsError::BackupOwnerNotFound
            | ApiAgentsError::SecretPermissionNotFound
            | ApiAgentsError::CredentialNotFound
            | ApiAgentsError::IdentityProviderNotFound
            | ApiAgentsError::RoleMappingNotFound => StatusCode::NOT_FOUND,

            // Conflict
            ApiAgentsError::AgentNameExists
            | ApiAgentsError::ToolNameExists
            | ApiAgentsError::PermissionExists
            | ApiAgentsError::AgentAlreadySuspended
            | ApiAgentsError::ApprovalAlreadyDecided
            | ApiAgentsError::ApprovalExpired
            | ApiAgentsError::SecretTypeExists(_)
            | ApiAgentsError::IdentityProviderExists
            | ApiAgentsError::DuplicateProviderName(_)
            | ApiAgentsError::IdentityProviderHasRoleMappings(_)
            | ApiAgentsError::RoleMappingExists => StatusCode::CONFLICT,

            // Forbidden
            ApiAgentsError::AgentNotActive
            | ApiAgentsError::AgentExpired
            | ApiAgentsError::ToolNotActive
            | ApiAgentsError::PermissionExpired
            | ApiAgentsError::NoPermission(_)
            | ApiAgentsError::ApprovalRequired
            | ApiAgentsError::NotAuthorizedApprover
            | ApiAgentsError::SecretTypeDisabled(_)
            | ApiAgentsError::SecretPermissionDenied(_)
            | ApiAgentsError::SecretPermissionExpired
            | ApiAgentsError::IdentityProviderNotActive
            | ApiAgentsError::NoRoleMappingForAgent(_)
            | ApiAgentsError::CloudCredentialDenied(_) => StatusCode::FORBIDDEN,

            // Too Many Requests
            ApiAgentsError::RateLimitExceeded(_, _)
            | ApiAgentsError::CredentialRateLimitExceeded(_, _)
            | ApiAgentsError::CloudCredentialRateLimited(_, _) => StatusCode::TOO_MANY_REQUESTS,

            // Bad Request
            ApiAgentsError::Validation(_)
            | ApiAgentsError::MissingTenant
            | ApiAgentsError::MissingUser
            | ApiAgentsError::InvalidInputSchema(_)
            | ApiAgentsError::InvalidRiskLevel(_)
            | ApiAgentsError::InvalidAgentType(_)
            | ApiAgentsError::InvalidStatus(_)
            | ApiAgentsError::AgentCannotReactivate
            | ApiAgentsError::BadRequest(_)
            | ApiAgentsError::InvalidStateTransition(_)
            | ApiAgentsError::DenialReasonRequired
            | ApiAgentsError::NoBackupOwner
            | ApiAgentsError::InvalidTtl(_)
            | ApiAgentsError::InvalidRateLimit(_)
            | ApiAgentsError::InvalidProviderConfig(_)
            | ApiAgentsError::InvalidCloudProviderType(_) => StatusCode::BAD_REQUEST,

            // Not Found (F091, F120)
            ApiAgentsError::NotFound(_)
            | ApiAgentsError::SecretTypeNotFound(_)
            | ApiAgentsError::SecretProviderNotFound(_) => StatusCode::NOT_FOUND,

            // Unauthorized
            ApiAgentsError::Unauthorized
            | ApiAgentsError::MissingTenantId
            | ApiAgentsError::MissingAgentId
            | ApiAgentsError::MissingToken => StatusCode::UNAUTHORIZED,

            // Service Unavailable (F120, F121)
            ApiAgentsError::SecretProviderUnavailable(_)
            | ApiAgentsError::SecretProviderUnhealthy(_)
            | ApiAgentsError::IdentityProviderUnhealthy(_) => StatusCode::SERVICE_UNAVAILABLE,

            // Gone (F120 - expired/revoked credentials)
            ApiAgentsError::CredentialExpired | ApiAgentsError::CredentialRevoked => {
                StatusCode::GONE
            }

            // Internal Server Error
            ApiAgentsError::Internal(_)
            | ApiAgentsError::Database(_)
            | ApiAgentsError::EncryptionError(_) => StatusCode::INTERNAL_SERVER_ERROR,

            // Gateway errors (provider issues)
            ApiAgentsError::ProviderAuthFailed(_) | ApiAgentsError::CloudProviderError(_) => {
                StatusCode::BAD_GATEWAY
            }
            ApiAgentsError::ProviderTimeout(_) => StatusCode::GATEWAY_TIMEOUT,

            // F127: PKI errors - Not Found
            ApiAgentsError::CaNotFound
            | ApiAgentsError::CertificateNotFound
            | ApiAgentsError::NoDefaultCa => StatusCode::NOT_FOUND,

            // F127: PKI errors - Conflict
            ApiAgentsError::CaNameExists
            | ApiAgentsError::CertificateAlreadyRevoked
            | ApiAgentsError::CannotRenewRevokedCertificate => StatusCode::CONFLICT,

            // F127: PKI errors - Forbidden
            ApiAgentsError::CaNotActive | ApiAgentsError::CertificateNotYetValid => {
                StatusCode::FORBIDDEN
            }

            // F127: PKI errors - Bad Request
            ApiAgentsError::ValidityExceedsMax { .. }
            | ApiAgentsError::InvalidCertificateFormat(_)
            | ApiAgentsError::InvalidKeyAlgorithm(_)
            | ApiAgentsError::InvalidRevocationReason(_) => StatusCode::BAD_REQUEST,

            // F127: PKI errors - Unauthorized
            ApiAgentsError::MtlsCertificateRequired | ApiAgentsError::MtlsValidationFailed(_) => {
                StatusCode::UNAUTHORIZED
            }

            // F127: PKI errors - Service Unavailable
            ApiAgentsError::CaPrivateKeyUnavailable => StatusCode::SERVICE_UNAVAILABLE,

            // F127: PKI errors - Internal Server Error
            ApiAgentsError::CertificateSigningFailed(_)
            | ApiAgentsError::CrlGenerationFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,

            // F127: PKI errors - Bad Gateway
            ApiAgentsError::ExternalCaError(_) | ApiAgentsError::OcspError(_) => {
                StatusCode::BAD_GATEWAY
            }

            // F127: PKI errors - Gone (expired certificate)
            ApiAgentsError::CertificateExpired => StatusCode::GONE,

            // F127: Additional CA errors
            ApiAgentsError::CaAlreadyExists(_)
            | ApiAgentsError::CannotDeleteDefaultCa
            | ApiAgentsError::CaHasActiveCertificates { .. } => StatusCode::CONFLICT,
            ApiAgentsError::InvalidCaType(_) => StatusCode::BAD_REQUEST,
            ApiAgentsError::CaCreationFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiAgentsError::CaDisabled(_) => StatusCode::FORBIDDEN,
            ApiAgentsError::CaProviderNotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
            ApiAgentsError::CaNotFoundId(_) => StatusCode::NOT_FOUND,
            ApiAgentsError::CertificateNotFoundId(_) => StatusCode::NOT_FOUND,
            ApiAgentsError::CertificateIssueFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiAgentsError::AgentNotFoundId(_) => StatusCode::NOT_FOUND,
            ApiAgentsError::AgentNotActiveId(_) => StatusCode::FORBIDDEN,
        }
    }
}

impl IntoResponse for ApiAgentsError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let problem = self.to_problem_details();

        let mut response = (status, Json(problem)).into_response();
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/problem+json"),
        );

        // Add Retry-After header for rate limiting
        if matches!(
            self,
            ApiAgentsError::RateLimitExceeded(_, _)
                | ApiAgentsError::CredentialRateLimitExceeded(_, _)
                | ApiAgentsError::CloudCredentialRateLimited(_, _)
        ) {
            response.headers_mut().insert(
                http::header::RETRY_AFTER,
                http::HeaderValue::from_static("60"),
            );
        }

        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_problem_details_serialization() {
        let problem = ProblemDetails::new("test-error", "Test Error", StatusCode::BAD_REQUEST)
            .with_detail("This is a test error")
            .with_instance("/test/path");

        let json = serde_json::to_string(&problem).unwrap();
        assert!(json.contains("\"type\":\"https://xavyo.net/errors/agents/test-error\""));
        assert!(json.contains("\"title\":\"Test Error\""));
        assert!(json.contains("\"status\":400"));
        assert!(json.contains("\"detail\":\"This is a test error\""));
        assert!(json.contains("\"instance\":\"/test/path\""));
    }

    #[test]
    fn test_error_status_codes() {
        assert_eq!(
            ApiAgentsError::AgentNotFound.status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            ApiAgentsError::AgentNameExists.status_code(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            ApiAgentsError::AgentNotActive.status_code(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            ApiAgentsError::RateLimitExceeded(50, 50).status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            ApiAgentsError::Validation("test".to_string()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ApiAgentsError::Unauthorized.status_code(),
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn test_problem_details_types() {
        let error = ApiAgentsError::AgentNotFound;
        let problem = error.to_problem_details();
        assert_eq!(
            problem.error_type,
            "https://xavyo.net/errors/agents/agent-not-found"
        );
        assert_eq!(problem.title, "Agent Not Found");
    }

    #[test]
    fn test_no_permission_error() {
        let error = ApiAgentsError::NoPermission("send_email".to_string());
        let problem = error.to_problem_details();
        assert!(problem.detail.unwrap().contains("send_email"));
    }

    #[test]
    fn test_rate_limit_error() {
        let error = ApiAgentsError::RateLimitExceeded(50, 50);
        let problem = error.to_problem_details();
        assert!(problem.detail.unwrap().contains("50/50"));
    }
}
