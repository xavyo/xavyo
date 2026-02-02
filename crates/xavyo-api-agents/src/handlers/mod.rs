//! HTTP handlers for the AI Agent Security API.

pub mod agents;
pub mod audit;
pub mod authorize;
pub mod discovery;
pub mod permissions;
pub mod tools;

// MCP & A2A Protocol handlers (F091)
pub mod a2a;
pub mod mcp;

// Human-in-the-Loop Approval handlers (F092)
pub mod approvals;

// Security Assessment handlers (F093)
pub mod assessment;

// Behavioral Anomaly Detection handlers (F094)
pub mod anomaly;

// Dynamic Secrets Provisioning handlers (F120)
pub mod credentials;
pub mod providers;
pub mod secret_permissions;
pub mod secret_types;

// Workload Identity Federation handlers (F121)
pub mod identity_federation;
pub mod identity_providers;
pub mod role_mappings;

// Agent PKI & Certificate Issuance handlers (F127)
pub mod ca;
pub mod certificates;
pub mod revocation;

pub use agents::*;
pub use audit::*;
pub use authorize::*;
pub use discovery::*;
pub use permissions::*;
pub use tools::*;

// F091 handler exports
pub use a2a::{cancel_task, create_task, get_task, list_tasks};
pub use mcp::{call_tool, list_tools as list_mcp_tools};

// F092 handler exports
pub use approvals::{
    approve_request, check_approval_status, deny_request, get_approval, list_approvals,
};

// F093 handler exports
pub use assessment::get_agent_security_assessment;

// F094 handler exports
pub use anomaly::{
    get_agent_baseline, get_agent_thresholds, get_tenant_thresholds, list_agent_anomalies,
    reset_agent_thresholds, set_agent_thresholds, set_tenant_thresholds,
};

// F120 handler exports
pub use credentials::request_credentials;
pub use providers::{
    activate_provider, check_provider_health, create_provider, deactivate_provider,
    delete_provider, get_provider, list_providers, update_provider,
};
pub use secret_permissions::{
    check_permission as check_secret_permission, get_permission as get_secret_permission,
    grant_permission, list_agent_permissions as list_agent_secret_permissions,
    revoke_all_permissions, revoke_permission, update_permission as update_secret_permission,
};
pub use secret_types::{
    create_secret_type, delete_secret_type, disable_secret_type, enable_secret_type,
    get_secret_type, get_secret_type_by_name, list_secret_types, update_secret_type,
};

// F121 handler exports
pub use identity_federation::{
    query_identity_audit, request_cloud_credentials, verify_identity_token,
};
pub use identity_providers::{
    check_identity_provider_health, create_identity_provider, delete_identity_provider,
    get_identity_provider, list_identity_providers, update_identity_provider,
};
pub use role_mappings::{
    create_role_mapping, delete_role_mapping, get_role_mapping, list_role_mappings,
    update_role_mapping,
};

// F127 handler exports
pub use ca::{
    create_external_ca, create_internal_ca, delete_ca, get_ca, get_ca_chain, list_cas, set_default_ca,
    update_ca,
};
pub use certificates::{
    get_agent_certificate, get_certificate, issue_certificate, list_agent_certificates,
    list_certificates, list_expiring_certificates, renew_certificate, revoke_certificate,
};
pub use revocation::{get_crl, ocsp_responder};
