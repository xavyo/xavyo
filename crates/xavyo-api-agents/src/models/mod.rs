//! Request and response models for the AI Agent Security API.

pub mod requests;
pub mod responses;

// MCP Protocol models (F091)
pub mod mcp_requests;

// A2A Protocol models (F091)
pub mod a2a_requests;

// Human-in-the-Loop Approval models (F092)
pub mod approval_models;

// Security Assessment models (F093)
pub mod assessment_models;

// Behavioral Anomaly Detection models (F094)
pub mod anomaly_models;

// Dynamic Secrets Provisioning models (F120)
pub mod credential_models;

pub use requests::*;
pub use responses::*;

// MCP exports
pub use mcp_requests::{
    McpCallRequest, McpCallResponse, McpContext, McpErrorCode, McpErrorResponse, McpTool,
    McpToolsResponse,
};

// A2A exports
pub use a2a_requests::{
    A2aErrorResponse, A2aTaskListResponse, A2aTaskResponse, A2aTaskWebhookPayload,
    CancelA2aTaskResponse, CreateA2aTaskRequest, CreateA2aTaskResponse, ListA2aTasksQuery,
};

// Approval exports (F092)
pub use approval_models::{
    ApprovalListResponse, ApprovalResponse, ApprovalStatusResponse, ApprovalSummary,
    ApprovalWebhookPayload, ApproveRequest, DenyRequest, ListApprovalsQuery,
};

// Assessment exports (F093)
pub use assessment_models::{
    Category, CheckName, ComplianceStatus, OwaspAgenticCompliance, Priority, Recommendation,
    RiskLevel, SecurityAssessment, Severity, Status, VulnerabilityCheck,
};

// Anomaly exports (F094)
pub use anomaly_models::{
    AnomalyListResponse, AnomalyThresholdInput, AnomalyType, Baseline, BaselineResponse,
    BaselineStatus, BaselineType, DetectedAnomaly, ListAnomaliesQuery, SetThresholdsRequest,
    Severity as AnomalySeverity, Threshold, ThresholdSource, ThresholdsResponse,
};

// Credential exports (F120)
pub use credential_models::{
    CredentialListResponse, CredentialRequest, CredentialRequestContext, CredentialResponse,
    CredentialSummary, ListCredentialsQuery, RateLimitInfo, RevokeCredentialRequest,
};
