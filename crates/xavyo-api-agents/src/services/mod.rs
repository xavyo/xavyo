//! Business logic services for the AI Agent Security API.

pub mod agent_service;
pub mod audit_service;
pub mod authorization_service;
pub mod permission_service;
pub mod tool_service;

// Credential encryption (F120)
pub mod encryption;

// Dynamic Credential Service (F120)
pub mod credential_service;
#[cfg(test)]
mod credential_service_test;

// Secret Permission Service (F120)
pub mod secret_permission_service;

// Secret Type Service (F120)
pub mod secret_type_service;

// Secret Provider Service (F120)
pub mod secret_provider_service;

// Provider Registry for real secret provider integration (F120)
pub mod provider_registry;

// MCP & A2A Protocol services (F091)
pub mod a2a_service;
pub mod mcp_service;
pub mod webhook_service;

// Human-in-the-Loop Approval service (F092)
pub mod approval_service;

// Security Assessment service (F093)
pub mod assessment_service;

// Behavioral Anomaly Detection services (F094)
pub mod anomaly_service;
pub mod baseline_service;

pub use agent_service::AgentService;
pub use audit_service::AuditService;
pub use authorization_service::AuthorizationService;
pub use permission_service::PermissionService;
pub use tool_service::ToolService;

// F091 exports
pub use a2a_service::A2aService;
pub use mcp_service::McpService;
pub use webhook_service::WebhookService;

// F092 exports
pub use approval_service::ApprovalService;

// F093 exports
pub use assessment_service::AssessmentService;

// F094 exports
pub use anomaly_service::AnomalyService;
pub use baseline_service::BaselineService;

// F120 exports
pub use credential_service::DynamicCredentialService;
pub use provider_registry::ProviderRegistry;
pub use secret_permission_service::SecretPermissionService;
pub use secret_provider_service::SecretProviderService;
pub use secret_type_service::SecretTypeService;

// Workload Identity Federation services (F121)
pub mod identity_audit_service;
pub mod identity_federation_service;
pub mod identity_provider_service;
pub mod role_mapping_service;

// F121 exports
pub use identity_audit_service::{IdentityAuditService, MappingOperation, ProviderOperation};
pub use identity_federation_service::{CloudCredentialResponse, IdentityFederationService};
pub use identity_provider_service::IdentityProviderService;
pub use role_mapping_service::RoleMappingService;

// Agent PKI & Certificate Issuance services (F127)
pub mod ca_service;
pub mod certificate_service;
pub mod mtls_service;
pub mod revocation_service;

// F127 exports
pub use ca_service::{
    CaListResponse, CaResponse, CaService, CreateExternalCaRequest, CreateInternalCaRequest,
    UpdateCaRequest,
};
pub use certificate_service::{CertificateListResponse, CertificateService};
pub use mtls_service::{MtlsService, MtlsValidationResult};
pub use revocation_service::{CrlResponse, OcspRequest, OcspResponse, RevocationService};
