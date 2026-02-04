//! Request and response models for delegation endpoints.
//!
//! Enhanced in F053 to support scoped delegations and lifecycle management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{DelegationStatus, GovApprovalDelegation};

/// Request to create a new delegation.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateDelegationRequest {
    /// User receiving approval authority.
    pub delegate_id: Uuid,

    /// When the delegation becomes active.
    pub starts_at: DateTime<Utc>,

    /// When the delegation ends.
    pub ends_at: DateTime<Utc>,

    /// Optional scope restrictions. If None, full delegation authority.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<CreateDelegationScopeRequest>,
}

/// Scope restrictions for a delegation (F053).
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateDelegationScopeRequest {
    /// Applications in scope. Empty = no application restriction.
    #[serde(default)]
    pub application_ids: Vec<Uuid>,

    /// Entitlements in scope. Empty = no entitlement restriction.
    #[serde(default)]
    pub entitlement_ids: Vec<Uuid>,

    /// Roles in scope. Empty = no role restriction.
    #[serde(default)]
    pub role_ids: Vec<Uuid>,

    /// Workflow types in scope. Empty = no type restriction.
    /// Valid values: "`access_request`", "certification", "`state_transition`"
    #[serde(default)]
    pub workflow_types: Vec<String>,
}

/// Request to extend a delegation's end date.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ExtendDelegationRequest {
    /// New end date (must be after current end date).
    pub new_ends_at: DateTime<Utc>,
}

/// Query parameters for listing delegations.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListDelegationsQuery {
    /// Filter by active status.
    pub is_active: Option<bool>,

    /// Filter to only currently active delegations.
    pub active_now: Option<bool>,

    /// Filter by status (F053): pending, active, expired, revoked.
    pub status: Option<String>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListDelegationsQuery {
    fn default() -> Self {
        Self {
            is_active: None,
            active_now: None,
            status: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Delegation response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DelegationResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// User who delegated authority.
    pub delegator_id: Uuid,

    /// User receiving authority.
    pub delegate_id: Uuid,

    /// When the delegation becomes active.
    pub starts_at: DateTime<Utc>,

    /// When the delegation ends.
    pub ends_at: DateTime<Utc>,

    /// Whether the delegation is active (not revoked). Legacy field.
    pub is_active: bool,

    /// Whether the delegation is currently in effect.
    pub is_currently_active: bool,

    /// Lifecycle status (F053).
    pub status: DelegationStatus,

    /// Scope ID if scoped delegation (F053).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_id: Option<Uuid>,

    /// Whether expiration warning was sent (F053).
    pub expiry_warning_sent: bool,

    /// When the delegation was created.
    pub created_at: DateTime<Utc>,

    /// When the delegation was revoked (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

impl From<GovApprovalDelegation> for DelegationResponse {
    fn from(delegation: GovApprovalDelegation) -> Self {
        let now = Utc::now();
        Self {
            id: delegation.id,
            delegator_id: delegation.delegator_id,
            delegate_id: delegation.delegate_id,
            starts_at: delegation.starts_at,
            ends_at: delegation.ends_at,
            is_active: delegation.is_active,
            is_currently_active: delegation.is_currently_active(now),
            status: delegation.status,
            scope_id: delegation.scope_id,
            expiry_warning_sent: delegation.expiry_warning_sent,
            created_at: delegation.created_at,
            revoked_at: delegation.revoked_at,
        }
    }
}

/// Scope details response (F053).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DelegationScopeResponse {
    /// Scope ID.
    pub id: Uuid,

    /// Applications in scope.
    pub application_ids: Vec<Uuid>,

    /// Entitlements in scope.
    pub entitlement_ids: Vec<Uuid>,

    /// Roles in scope.
    pub role_ids: Vec<Uuid>,

    /// Workflow types in scope.
    pub workflow_types: Vec<String>,

    /// When the scope was created.
    pub created_at: DateTime<Utc>,
}

/// Paginated list of delegations.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DelegationListResponse {
    /// List of delegations.
    pub items: Vec<DelegationResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

/// A work item that a deputy can act on (F053).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DelegatedWorkItem {
    /// Unique identifier of the work item.
    pub id: Uuid,

    /// Type of work item.
    pub work_item_type: String,

    /// ID of the delegation granting authority.
    pub delegation_id: Uuid,

    /// ID of the original authority (delegator).
    pub delegator_id: Uuid,

    /// Display name/email of the delegator.
    pub delegator_display: Option<String>,

    /// ID of the access request (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_request_id: Option<Uuid>,

    /// ID of the certification item (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certification_item_id: Option<Uuid>,

    /// ID of the related application.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_id: Option<Uuid>,

    /// Application name for display.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_name: Option<String>,

    /// ID of the related entitlement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitlement_id: Option<Uuid>,

    /// Entitlement name for display.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitlement_name: Option<String>,

    /// ID of the related role.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_id: Option<Uuid>,

    /// Role name for display.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role_name: Option<String>,

    /// Summary/description of the work item.
    pub summary: String,

    /// Priority level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,

    /// Due date for the work item.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub due_at: Option<DateTime<Utc>>,

    /// When the work item was created.
    pub created_at: DateTime<Utc>,
}

/// Paginated list of delegated work items (F053).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DelegatedWorkItemListResponse {
    /// List of delegated work items.
    pub items: Vec<DelegatedWorkItem>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

/// Query parameters for listing delegated work items.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListDelegatedWorkItemsQuery {
    /// Filter by delegator ID.
    pub delegator_id: Option<Uuid>,

    /// Filter by work item type (`access_request`, certification, `state_transition`).
    pub work_item_type: Option<String>,

    /// Filter by application ID.
    pub application_id: Option<Uuid>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

/// Response for delegation lifecycle processing (F053).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DelegationLifecycleResponse {
    /// Number of delegations activated (pending -> active).
    pub activated_count: usize,

    /// Number of delegations expired (active -> expired).
    pub expired_count: usize,

    /// Number of expiration warnings sent.
    pub warnings_sent: usize,

    /// IDs of activated delegations.
    pub activated_ids: Vec<Uuid>,

    /// IDs of expired delegations.
    pub expired_ids: Vec<Uuid>,

    /// IDs of delegations with warnings sent.
    pub warned_ids: Vec<Uuid>,
}

/// An entry in the delegation audit trail (F053).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DelegationAuditEntry {
    /// Unique identifier of the audit record.
    pub id: Uuid,

    /// ID of the delegation that authorized this action.
    pub delegation_id: Uuid,

    /// ID of the user who performed the action (deputy).
    pub deputy_id: Uuid,

    /// Display name/email of the deputy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deputy_display: Option<String>,

    /// ID of the user on whose behalf the action was taken (delegator).
    pub delegator_id: Uuid,

    /// Display name/email of the delegator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegator_display: Option<String>,

    /// The type of action performed.
    pub action_type: String,

    /// The ID of the work item that was actioned.
    pub work_item_id: Uuid,

    /// The type of work item.
    pub work_item_type: String,

    /// Additional metadata (comments, decision details, etc.).
    pub metadata: serde_json::Value,

    /// When the action was performed.
    pub created_at: DateTime<Utc>,
}

/// Paginated list of delegation audit entries (F053).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DelegationAuditListResponse {
    /// List of audit entries.
    pub items: Vec<DelegationAuditEntry>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

/// Query parameters for listing delegation audit records (F053).
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListDelegationAuditQuery {
    /// Filter by delegation ID.
    pub delegation_id: Option<Uuid>,

    /// Filter by deputy ID.
    pub deputy_id: Option<Uuid>,

    /// Filter by delegator ID.
    pub delegator_id: Option<Uuid>,

    /// Filter by action type (`approve_request`, `reject_request`, `certify_access`, etc.).
    pub action_type: Option<String>,

    /// Filter by work item type (`access_request`, certification, `state_transition`).
    pub work_item_type: Option<String>,

    /// Filter by date range start.
    pub from_date: Option<DateTime<Utc>>,

    /// Filter by date range end.
    pub to_date: Option<DateTime<Utc>>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}
