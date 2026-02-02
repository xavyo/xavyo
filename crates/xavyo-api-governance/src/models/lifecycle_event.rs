//! Request and response models for lifecycle event and action endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{
    AccessSnapshotType, GovAccessSnapshot, GovLifecycleAction, GovLifecycleEvent,
    LifecycleActionType, LifecycleEventType, SnapshotAssignment, SnapshotContent,
};

// ============================================================================
// Lifecycle Event Request Models
// ============================================================================

/// Request to create a lifecycle event (joiner, mover, or leaver).
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateLifecycleEventRequest {
    /// User ID this event affects.
    pub user_id: Uuid,

    /// Type of lifecycle event.
    pub event_type: LifecycleEventType,

    /// User attributes before the change (required for mover events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes_before: Option<serde_json::Value>,

    /// User attributes after the change (required for joiner and mover events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes_after: Option<serde_json::Value>,

    /// Source of the event (e.g., "api", "scim", "webhook", "trigger").
    #[validate(length(max = 50, message = "Source must be at most 50 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

// ============================================================================
// Lifecycle Event Query Models
// ============================================================================

/// Query parameters for listing lifecycle events.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListLifecycleEventsQuery {
    /// Filter by user ID.
    pub user_id: Option<Uuid>,

    /// Filter by event type.
    pub event_type: Option<LifecycleEventType>,

    /// Filter events created after this time.
    pub from: Option<DateTime<Utc>>,

    /// Filter events created before this time.
    pub to: Option<DateTime<Utc>>,

    /// Filter by processed status.
    pub processed: Option<bool>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListLifecycleEventsQuery {
    fn default() -> Self {
        Self {
            user_id: None,
            event_type: None,
            from: None,
            to: None,
            processed: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Query parameters for listing lifecycle actions.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListLifecycleActionsQuery {
    /// Filter by event ID.
    pub event_id: Option<Uuid>,

    /// Filter by action type.
    pub action_type: Option<LifecycleActionType>,

    /// Filter by assignment ID.
    pub assignment_id: Option<Uuid>,

    /// Filter for pending scheduled actions only.
    pub pending: Option<bool>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListLifecycleActionsQuery {
    fn default() -> Self {
        Self {
            event_id: None,
            action_type: None,
            assignment_id: None,
            pending: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Query parameters for listing access snapshots.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListAccessSnapshotsQuery {
    /// Filter by user ID.
    pub user_id: Option<Uuid>,

    /// Filter by event ID.
    pub event_id: Option<Uuid>,

    /// Filter by snapshot type.
    pub snapshot_type: Option<AccessSnapshotType>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListAccessSnapshotsQuery {
    fn default() -> Self {
        Self {
            user_id: None,
            event_id: None,
            snapshot_type: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

// ============================================================================
// Lifecycle Event Response Models
// ============================================================================

/// Lifecycle event response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LifecycleEventResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// User ID this event affects.
    pub user_id: Uuid,

    /// Type of lifecycle event.
    pub event_type: LifecycleEventType,

    /// User attributes before the change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes_before: Option<serde_json::Value>,

    /// User attributes after the change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes_after: Option<serde_json::Value>,

    /// Source of the event.
    pub source: String,

    /// When the event was processed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processed_at: Option<DateTime<Utc>>,

    /// When the event was created.
    pub created_at: DateTime<Utc>,
}

impl From<GovLifecycleEvent> for LifecycleEventResponse {
    fn from(event: GovLifecycleEvent) -> Self {
        Self {
            id: event.id,
            tenant_id: event.tenant_id,
            user_id: event.user_id,
            event_type: event.event_type,
            attributes_before: event.attributes_before,
            attributes_after: event.attributes_after,
            source: event.source,
            processed_at: event.processed_at,
            created_at: event.created_at,
        }
    }
}

/// Lifecycle event response with actions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LifecycleEventWithActionsResponse {
    /// Event details.
    #[serde(flatten)]
    pub event: LifecycleEventResponse,

    /// Actions resulting from this event.
    pub actions: Vec<LifecycleActionResponse>,

    /// Access snapshot if created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<AccessSnapshotSummary>,
}

/// Paginated list of lifecycle events.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LifecycleEventListResponse {
    /// List of events.
    pub items: Vec<LifecycleEventResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Page number.
    pub page: i64,

    /// Page size.
    pub page_size: i64,
}

// ============================================================================
// Lifecycle Action Response Models
// ============================================================================

/// Lifecycle action response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LifecycleActionResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Event that triggered this action.
    pub event_id: Uuid,

    /// Type of action.
    pub action_type: LifecycleActionType,

    /// Assignment created/modified (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignment_id: Option<Uuid>,

    /// Policy that triggered this action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<Uuid>,

    /// Target entitlement.
    pub entitlement_id: Uuid,

    /// When scheduled revocation should execute.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduled_at: Option<DateTime<Utc>>,

    /// When the action was executed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executed_at: Option<DateTime<Utc>>,

    /// When the scheduled action was cancelled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancelled_at: Option<DateTime<Utc>>,

    /// Error message if action failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,

    /// When the action was created.
    pub created_at: DateTime<Utc>,

    /// Whether the action is pending.
    pub is_pending: bool,

    /// Whether the action was executed.
    pub is_executed: bool,

    /// Whether the action was cancelled.
    pub is_cancelled: bool,
}

impl From<GovLifecycleAction> for LifecycleActionResponse {
    fn from(action: GovLifecycleAction) -> Self {
        let is_pending = action.is_pending();
        let is_executed = action.is_executed();
        let is_cancelled = action.is_cancelled();

        Self {
            id: action.id,
            tenant_id: action.tenant_id,
            event_id: action.event_id,
            action_type: action.action_type,
            assignment_id: action.assignment_id,
            policy_id: action.policy_id,
            entitlement_id: action.entitlement_id,
            scheduled_at: action.scheduled_at,
            executed_at: action.executed_at,
            cancelled_at: action.cancelled_at,
            error_message: action.error_message,
            created_at: action.created_at,
            is_pending,
            is_executed,
            is_cancelled,
        }
    }
}

/// Paginated list of lifecycle actions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LifecycleActionListResponse {
    /// List of actions.
    pub items: Vec<LifecycleActionResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Page number.
    pub page: i64,

    /// Page size.
    pub page_size: i64,
}

// ============================================================================
// Access Snapshot Response Models
// ============================================================================

/// Access snapshot response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AccessSnapshotResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// User whose access was captured.
    pub user_id: Uuid,

    /// Event that triggered this snapshot.
    pub event_id: Uuid,

    /// Type of snapshot.
    pub snapshot_type: AccessSnapshotType,

    /// Assignment details.
    pub assignments: SnapshotContentResponse,

    /// When the snapshot was created.
    pub created_at: DateTime<Utc>,
}

impl From<GovAccessSnapshot> for AccessSnapshotResponse {
    fn from(snapshot: GovAccessSnapshot) -> Self {
        let content = snapshot.parse_assignments();

        Self {
            id: snapshot.id,
            tenant_id: snapshot.tenant_id,
            user_id: snapshot.user_id,
            event_id: snapshot.event_id,
            snapshot_type: snapshot.snapshot_type,
            assignments: SnapshotContentResponse::from(content),
            created_at: snapshot.created_at,
        }
    }
}

/// Snapshot content response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SnapshotContentResponse {
    /// Assignment details.
    pub assignments: Vec<SnapshotAssignmentResponse>,

    /// Total count of assignments.
    pub total_count: i32,

    /// When the snapshot was taken.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_at: Option<DateTime<Utc>>,
}

impl From<SnapshotContent> for SnapshotContentResponse {
    fn from(content: SnapshotContent) -> Self {
        Self {
            assignments: content
                .assignments
                .into_iter()
                .map(SnapshotAssignmentResponse::from)
                .collect(),
            total_count: content.total_count,
            snapshot_at: content.snapshot_at,
        }
    }
}

/// Snapshot assignment response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SnapshotAssignmentResponse {
    /// Assignment ID.
    pub id: Uuid,

    /// Entitlement ID.
    pub entitlement_id: Uuid,

    /// Entitlement name.
    pub entitlement_name: String,

    /// Entitlement external ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitlement_external_id: Option<String>,

    /// Application ID.
    pub application_id: Uuid,

    /// Application name.
    pub application_name: String,

    /// Source of the assignment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    /// Policy that granted this assignment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<Uuid>,

    /// When the assignment was granted.
    pub granted_at: DateTime<Utc>,

    /// Who granted the assignment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub granted_by: Option<Uuid>,
}

impl From<SnapshotAssignment> for SnapshotAssignmentResponse {
    fn from(assignment: SnapshotAssignment) -> Self {
        Self {
            id: assignment.id,
            entitlement_id: assignment.entitlement_id,
            entitlement_name: assignment.entitlement_name,
            entitlement_external_id: assignment.entitlement_external_id,
            application_id: assignment.application_id,
            application_name: assignment.application_name,
            source: assignment.source,
            policy_id: assignment.policy_id,
            granted_at: assignment.granted_at,
            granted_by: assignment.granted_by,
        }
    }
}

/// Summary of an access snapshot (for embedded use).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AccessSnapshotSummary {
    /// Snapshot ID.
    pub id: Uuid,

    /// Snapshot type.
    pub snapshot_type: AccessSnapshotType,

    /// Number of assignments captured.
    pub assignment_count: i32,

    /// When the snapshot was created.
    pub created_at: DateTime<Utc>,
}

impl From<GovAccessSnapshot> for AccessSnapshotSummary {
    fn from(snapshot: GovAccessSnapshot) -> Self {
        Self {
            id: snapshot.id,
            snapshot_type: snapshot.snapshot_type,
            assignment_count: snapshot.assignment_count(),
            created_at: snapshot.created_at,
        }
    }
}

/// Paginated list of access snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AccessSnapshotListResponse {
    /// List of snapshots.
    pub items: Vec<AccessSnapshotResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Page number.
    pub page: i64,

    /// Page size.
    pub page_size: i64,
}

// ============================================================================
// Event Processing Result Models
// ============================================================================

/// Result of processing a lifecycle event.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProcessEventResult {
    /// The processed event.
    pub event: LifecycleEventResponse,

    /// Actions taken as result of processing.
    pub actions: Vec<LifecycleActionResponse>,

    /// Access snapshot if created (for leaver/mover events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<AccessSnapshotSummary>,

    /// Summary of changes.
    pub summary: ProcessingSummary,
}

/// Summary of lifecycle event processing.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct ProcessingSummary {
    /// Number of entitlements provisioned.
    #[serde(default)]
    pub provisioned: i32,

    /// Number of entitlements revoked.
    #[serde(default)]
    pub revoked: i32,

    /// Number of scheduled revocations.
    #[serde(default)]
    pub scheduled: i32,

    /// Number of skipped (duplicate) assignments.
    #[serde(default)]
    pub skipped: i32,

    /// Number of cancelled scheduled revocations.
    #[serde(default)]
    pub cancelled: i32,
}
