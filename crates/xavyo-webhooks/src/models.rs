//! Request/response types, enums, and webhook payload structures.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

// ---------------------------------------------------------------------------
// WebhookEventType enum — 35 variants
// ---------------------------------------------------------------------------

/// All supported webhook event types.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub enum WebhookEventType {
    // User lifecycle
    #[serde(rename = "user.created")]
    UserCreated,
    #[serde(rename = "user.updated")]
    UserUpdated,
    #[serde(rename = "user.deleted")]
    UserDeleted,
    #[serde(rename = "user.disabled")]
    UserDisabled,
    #[serde(rename = "user.enabled")]
    UserEnabled,
    // Authentication
    #[serde(rename = "auth.login.success")]
    AuthLoginSuccess,
    #[serde(rename = "auth.login.failed")]
    AuthLoginFailed,
    #[serde(rename = "auth.mfa.enrolled")]
    AuthMfaEnrolled,
    #[serde(rename = "auth.mfa.verified")]
    AuthMfaVerified,
    #[serde(rename = "auth.token.revoked")]
    AuthTokenRevoked,
    // Group
    #[serde(rename = "group.member.added")]
    GroupMemberAdded,
    #[serde(rename = "group.member.removed")]
    GroupMemberRemoved,
    #[serde(rename = "group.created")]
    GroupCreated,
    #[serde(rename = "group.deleted")]
    GroupDeleted,
    // Role / Entitlement
    #[serde(rename = "role.assigned")]
    RoleAssigned,
    #[serde(rename = "role.unassigned")]
    RoleUnassigned,
    #[serde(rename = "entitlement.granted")]
    EntitlementGranted,
    #[serde(rename = "entitlement.revoked")]
    EntitlementRevoked,
    // Governance
    #[serde(rename = "access_request.created")]
    AccessRequestCreated,
    #[serde(rename = "access_request.approved")]
    AccessRequestApproved,
    #[serde(rename = "access_request.denied")]
    AccessRequestDenied,
    #[serde(rename = "certification.completed")]
    CertificationCompleted,
    // Provisioning
    #[serde(rename = "provisioning.completed")]
    ProvisioningCompleted,
    #[serde(rename = "provisioning.failed")]
    ProvisioningFailed,
    #[serde(rename = "reconciliation.completed")]
    ReconciliationCompleted,
    // Admin
    #[serde(rename = "tenant.settings.updated")]
    TenantSettingsUpdated,
    #[serde(rename = "connector.status.changed")]
    ConnectorStatusChanged,
    #[serde(rename = "webhook.subscription.disabled")]
    WebhookSubscriptionDisabled,
    // Import (F086)
    #[serde(rename = "import.started")]
    ImportStarted,
    #[serde(rename = "import.completed")]
    ImportCompleted,
    #[serde(rename = "import.failed")]
    ImportFailed,
    // SCIM Outbound Provisioning (F087)
    #[serde(rename = "scim.sync.started")]
    ScimSyncStarted,
    #[serde(rename = "scim.sync.completed")]
    ScimSyncCompleted,
    #[serde(rename = "scim.sync.failed")]
    ScimSyncFailed,
    #[serde(rename = "scim.operation.failed")]
    ScimOperationFailed,
    // AI Agent Security (F094)
    #[serde(rename = "agent.anomaly.detected")]
    AgentAnomalyDetected,
}

impl WebhookEventType {
    /// Returns all supported event types.
    #[must_use]
    pub fn all() -> Vec<Self> {
        vec![
            Self::UserCreated,
            Self::UserUpdated,
            Self::UserDeleted,
            Self::UserDisabled,
            Self::UserEnabled,
            Self::AuthLoginSuccess,
            Self::AuthLoginFailed,
            Self::AuthMfaEnrolled,
            Self::AuthMfaVerified,
            Self::AuthTokenRevoked,
            Self::GroupMemberAdded,
            Self::GroupMemberRemoved,
            Self::GroupCreated,
            Self::GroupDeleted,
            Self::RoleAssigned,
            Self::RoleUnassigned,
            Self::EntitlementGranted,
            Self::EntitlementRevoked,
            Self::AccessRequestCreated,
            Self::AccessRequestApproved,
            Self::AccessRequestDenied,
            Self::CertificationCompleted,
            Self::ProvisioningCompleted,
            Self::ProvisioningFailed,
            Self::ReconciliationCompleted,
            Self::TenantSettingsUpdated,
            Self::ConnectorStatusChanged,
            Self::WebhookSubscriptionDisabled,
            Self::ImportStarted,
            Self::ImportCompleted,
            Self::ImportFailed,
            Self::ScimSyncStarted,
            Self::ScimSyncCompleted,
            Self::ScimSyncFailed,
            Self::ScimOperationFailed,
            Self::AgentAnomalyDetected,
        ]
    }

    /// Returns the string representation used in API payloads.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UserCreated => "user.created",
            Self::UserUpdated => "user.updated",
            Self::UserDeleted => "user.deleted",
            Self::UserDisabled => "user.disabled",
            Self::UserEnabled => "user.enabled",
            Self::AuthLoginSuccess => "auth.login.success",
            Self::AuthLoginFailed => "auth.login.failed",
            Self::AuthMfaEnrolled => "auth.mfa.enrolled",
            Self::AuthMfaVerified => "auth.mfa.verified",
            Self::AuthTokenRevoked => "auth.token.revoked",
            Self::GroupMemberAdded => "group.member.added",
            Self::GroupMemberRemoved => "group.member.removed",
            Self::GroupCreated => "group.created",
            Self::GroupDeleted => "group.deleted",
            Self::RoleAssigned => "role.assigned",
            Self::RoleUnassigned => "role.unassigned",
            Self::EntitlementGranted => "entitlement.granted",
            Self::EntitlementRevoked => "entitlement.revoked",
            Self::AccessRequestCreated => "access_request.created",
            Self::AccessRequestApproved => "access_request.approved",
            Self::AccessRequestDenied => "access_request.denied",
            Self::CertificationCompleted => "certification.completed",
            Self::ProvisioningCompleted => "provisioning.completed",
            Self::ProvisioningFailed => "provisioning.failed",
            Self::ReconciliationCompleted => "reconciliation.completed",
            Self::TenantSettingsUpdated => "tenant.settings.updated",
            Self::ConnectorStatusChanged => "connector.status.changed",
            Self::WebhookSubscriptionDisabled => "webhook.subscription.disabled",
            Self::ImportStarted => "import.started",
            Self::ImportCompleted => "import.completed",
            Self::ImportFailed => "import.failed",
            Self::ScimSyncStarted => "scim.sync.started",
            Self::ScimSyncCompleted => "scim.sync.completed",
            Self::ScimSyncFailed => "scim.sync.failed",
            Self::ScimOperationFailed => "scim.operation.failed",
            Self::AgentAnomalyDetected => "agent.anomaly.detected",
        }
    }

    /// Returns the category for this event type.
    #[must_use]
    pub fn category(&self) -> &'static str {
        match self {
            Self::UserCreated
            | Self::UserUpdated
            | Self::UserDeleted
            | Self::UserDisabled
            | Self::UserEnabled => "user",
            Self::AuthLoginSuccess
            | Self::AuthLoginFailed
            | Self::AuthMfaEnrolled
            | Self::AuthMfaVerified
            | Self::AuthTokenRevoked => "authentication",
            Self::GroupMemberAdded
            | Self::GroupMemberRemoved
            | Self::GroupCreated
            | Self::GroupDeleted => "group",
            Self::RoleAssigned
            | Self::RoleUnassigned
            | Self::EntitlementGranted
            | Self::EntitlementRevoked => "role_entitlement",
            Self::AccessRequestCreated
            | Self::AccessRequestApproved
            | Self::AccessRequestDenied
            | Self::CertificationCompleted => "governance",
            Self::ProvisioningCompleted
            | Self::ProvisioningFailed
            | Self::ReconciliationCompleted => "provisioning",
            Self::TenantSettingsUpdated
            | Self::ConnectorStatusChanged
            | Self::WebhookSubscriptionDisabled => "admin",
            Self::ImportStarted | Self::ImportCompleted | Self::ImportFailed => "import",
            Self::ScimSyncStarted
            | Self::ScimSyncCompleted
            | Self::ScimSyncFailed
            | Self::ScimOperationFailed => "scim_provisioning",
            Self::AgentAnomalyDetected => "agent_security",
        }
    }

    /// Returns a human-readable description.
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::UserCreated => "A new user was created",
            Self::UserUpdated => "A user profile was updated",
            Self::UserDeleted => "A user was deleted",
            Self::UserDisabled => "A user account was disabled",
            Self::UserEnabled => "A user account was enabled",
            Self::AuthLoginSuccess => "A user logged in successfully",
            Self::AuthLoginFailed => "A login attempt failed",
            Self::AuthMfaEnrolled => "An MFA factor was enrolled",
            Self::AuthMfaVerified => "An MFA factor was verified",
            Self::AuthTokenRevoked => "A token was revoked",
            Self::GroupMemberAdded => "A member was added to a group",
            Self::GroupMemberRemoved => "A member was removed from a group",
            Self::GroupCreated => "A group was created",
            Self::GroupDeleted => "A group was deleted",
            Self::RoleAssigned => "A role was assigned to a user",
            Self::RoleUnassigned => "A role was unassigned from a user",
            Self::EntitlementGranted => "An entitlement was granted",
            Self::EntitlementRevoked => "An entitlement was revoked",
            Self::AccessRequestCreated => "An access request was created",
            Self::AccessRequestApproved => "An access request was approved",
            Self::AccessRequestDenied => "An access request was denied",
            Self::CertificationCompleted => "A certification campaign was completed",
            Self::ProvisioningCompleted => "A provisioning task completed successfully",
            Self::ProvisioningFailed => "A provisioning task failed",
            Self::ReconciliationCompleted => "A reconciliation run completed",
            Self::TenantSettingsUpdated => "Tenant settings were updated",
            Self::ConnectorStatusChanged => "A connector status changed",
            Self::WebhookSubscriptionDisabled => {
                "A webhook subscription was auto-disabled due to consecutive failures"
            }
            Self::ImportStarted => "A bulk user import job started processing",
            Self::ImportCompleted => "A bulk user import job completed",
            Self::ImportFailed => "A bulk user import job failed",
            Self::ScimSyncStarted => "A SCIM outbound sync or reconciliation run started",
            Self::ScimSyncCompleted => {
                "A SCIM outbound sync or reconciliation run completed successfully"
            }
            Self::ScimSyncFailed => "A SCIM outbound sync or reconciliation run failed",
            Self::ScimOperationFailed => {
                "An individual SCIM provisioning operation permanently failed"
            }
            Self::AgentAnomalyDetected => "An AI agent behavioral anomaly was detected",
        }
    }

    /// Parse a string into a `WebhookEventType`. Returns None for unknown types.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        serde_json::from_value(serde_json::Value::String(s.to_string())).ok()
    }
}

// ---------------------------------------------------------------------------
// DeliveryStatus enum
// ---------------------------------------------------------------------------

/// Status of a webhook delivery attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum DeliveryStatus {
    Pending,
    Success,
    Failed,
    Timeout,
    Abandoned,
}

impl DeliveryStatus {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Success => "success",
            Self::Failed => "failed",
            Self::Timeout => "timeout",
            Self::Abandoned => "abandoned",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "success" => Some(Self::Success),
            "failed" => Some(Self::Failed),
            "timeout" => Some(Self::Timeout),
            "abandoned" => Some(Self::Abandoned),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

/// Request body for creating a webhook subscription.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateWebhookSubscriptionRequest {
    /// Display name for this subscription.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name: String,

    /// Optional description.
    #[validate(length(max = 1000, message = "Description cannot exceed 1000 characters"))]
    pub description: Option<String>,

    /// Target URL for webhook delivery (HTTPS required in production).
    #[validate(length(
        min = 10,
        max = 2000,
        message = "URL must be between 10 and 2000 characters"
    ))]
    pub url: String,

    /// Shared secret for HMAC-SHA256 signature verification.
    #[validate(length(max = 255, message = "Secret cannot exceed 255 characters"))]
    pub secret: Option<String>,

    /// Event types this subscription receives.
    #[validate(length(
        min = 1,
        max = 50,
        message = "Must subscribe to between 1 and 50 event types"
    ))]
    pub event_types: Vec<String>,
}

/// Request body for updating a webhook subscription.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateWebhookSubscriptionRequest {
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name: Option<String>,

    #[validate(length(max = 1000, message = "Description cannot exceed 1000 characters"))]
    pub description: Option<String>,

    #[validate(length(
        min = 10,
        max = 2000,
        message = "URL must be between 10 and 2000 characters"
    ))]
    pub url: Option<String>,

    #[validate(length(max = 255, message = "Secret cannot exceed 255 characters"))]
    pub secret: Option<String>,

    #[validate(length(
        min = 1,
        max = 50,
        message = "Must subscribe to between 1 and 50 event types"
    ))]
    pub event_types: Option<Vec<String>>,

    pub enabled: Option<bool>,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// A webhook subscription response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WebhookSubscriptionResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub url: String,
    pub event_types: Vec<String>,
    pub enabled: bool,
    pub consecutive_failures: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Paginated list of webhook subscriptions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WebhookSubscriptionListResponse {
    pub items: Vec<WebhookSubscriptionResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// A webhook delivery summary (for list endpoint).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WebhookDeliveryResponse {
    pub id: Uuid,
    pub subscription_id: Uuid,
    pub event_id: Uuid,
    pub event_type: String,
    pub status: String,
    pub attempt_number: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_code: Option<i16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
}

/// Full webhook delivery detail (for single delivery endpoint).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WebhookDeliveryDetailResponse {
    pub id: Uuid,
    pub subscription_id: Uuid,
    pub event_id: Uuid,
    pub event_type: String,
    pub status: String,
    pub attempt_number: i32,
    pub max_attempts: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<DateTime<Utc>>,
    pub request_payload: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_headers: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_code: Option<i16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<i32>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
}

/// Paginated list of webhook deliveries.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WebhookDeliveryListResponse {
    pub items: Vec<WebhookDeliveryResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Information about a supported event type.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EventTypeInfo {
    pub event_type: String,
    pub category: String,
    pub description: String,
}

/// List of all available event types.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EventTypeListResponse {
    pub event_types: Vec<EventTypeInfo>,
}

// ---------------------------------------------------------------------------
// Query parameters
// ---------------------------------------------------------------------------

/// Query parameters for listing subscriptions.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListSubscriptionsQuery {
    /// Maximum results to return (default: 20, max: 100).
    #[serde(default = "default_limit")]
    pub limit: i64,

    /// Number of results to skip (default: 0).
    #[serde(default)]
    pub offset: i64,

    /// Filter by enabled/disabled status.
    pub enabled: Option<bool>,
}

/// Query parameters for listing deliveries.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListDeliveriesQuery {
    /// Maximum results to return (default: 20, max: 100).
    #[serde(default = "default_limit")]
    pub limit: i64,

    /// Number of results to skip (default: 0).
    #[serde(default)]
    pub offset: i64,

    /// Filter by delivery status.
    pub status: Option<String>,
}

fn default_limit() -> i64 {
    20
}

// ---------------------------------------------------------------------------
// Webhook payload (sent to subscriber endpoints)
// ---------------------------------------------------------------------------

/// JSON payload delivered to webhook endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WebhookPayload {
    pub event_id: Uuid,
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub tenant_id: Uuid,
    pub data: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_serialization() {
        let event = WebhookEventType::UserCreated;
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(json, "\"user.created\"");
    }

    #[test]
    fn test_event_type_deserialization() {
        let event: WebhookEventType = serde_json::from_str("\"user.created\"").unwrap();
        assert_eq!(event, WebhookEventType::UserCreated);
    }

    #[test]
    fn test_event_type_all_returns_36() {
        assert_eq!(WebhookEventType::all().len(), 36);
    }

    #[test]
    fn test_event_type_from_str() {
        assert_eq!(
            WebhookEventType::parse("user.created"),
            Some(WebhookEventType::UserCreated)
        );
        assert_eq!(
            WebhookEventType::parse("auth.login.success"),
            Some(WebhookEventType::AuthLoginSuccess)
        );
        assert_eq!(WebhookEventType::parse("invalid.type"), None);
    }

    #[test]
    fn test_event_type_as_str_roundtrip() {
        for et in WebhookEventType::all() {
            let s = et.as_str();
            let parsed = WebhookEventType::parse(s);
            assert_eq!(parsed, Some(et), "Failed roundtrip for {s}");
        }
    }

    #[test]
    fn test_delivery_status_serialization() {
        let status = DeliveryStatus::Pending;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"pending\"");
    }

    #[test]
    fn test_delivery_status_from_str() {
        assert_eq!(
            DeliveryStatus::parse("pending"),
            Some(DeliveryStatus::Pending)
        );
        assert_eq!(
            DeliveryStatus::parse("success"),
            Some(DeliveryStatus::Success)
        );
        assert_eq!(DeliveryStatus::parse("unknown"), None);
    }

    #[test]
    fn test_webhook_payload_serialization() {
        let payload = WebhookPayload {
            event_id: Uuid::nil(),
            event_type: "user.created".to_string(),
            timestamp: DateTime::parse_from_rfc3339("2026-01-28T12:00:00Z")
                .unwrap()
                .into(),
            tenant_id: Uuid::nil(),
            data: serde_json::json!({"user_id": "abc"}),
        };
        let json = serde_json::to_value(&payload).unwrap();
        assert_eq!(json["event_type"], "user.created");
        assert_eq!(json["data"]["user_id"], "abc");
    }
}
