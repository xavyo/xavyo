//! Request and response models for object lifecycle state endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{
    AuditActionType, BulkOperationStatus, EntitlementAction, GovBulkStateOperation,
    GovLifecycleState, GovLifecycleTransitionWithStates, GovScheduleStatus,
    GovStateTransitionAudit, GovStateTransitionRequestWithStates, LifecycleObjectType,
    TransitionRequestStatus,
};

// ============================================================================
// Lifecycle Configuration Models
// ============================================================================

/// Request to create a new lifecycle configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateLifecycleConfigRequest {
    /// Display name for the configuration.
    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))]
    pub name: String,

    /// Object type this configuration applies to.
    pub object_type: LifecycleObjectType,

    /// Optional description.
    #[validate(length(max = 1000, message = "Description must not exceed 1000 characters"))]
    pub description: Option<String>,

    /// Whether to auto-assign initial state to new objects (default: true).
    #[serde(default = "default_auto_assign")]
    pub auto_assign_initial_state: bool,
}

fn default_auto_assign() -> bool {
    true
}

/// Request to update a lifecycle configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateLifecycleConfigRequest {
    /// Updated display name.
    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))]
    pub name: Option<String>,

    /// Updated description.
    #[validate(length(max = 1000, message = "Description must not exceed 1000 characters"))]
    pub description: Option<String>,

    /// Whether the configuration is active.
    pub is_active: Option<bool>,

    /// Whether to auto-assign initial state to new objects.
    pub auto_assign_initial_state: Option<bool>,
}

/// Query parameters for listing lifecycle configurations.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListLifecycleConfigsQuery {
    /// Filter by object type.
    pub object_type: Option<LifecycleObjectType>,

    /// Filter by active status.
    pub is_active: Option<bool>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListLifecycleConfigsQuery {
    fn default() -> Self {
        Self {
            object_type: None,
            is_active: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Lifecycle configuration response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LifecycleConfigResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Display name.
    pub name: String,

    /// Object type.
    pub object_type: LifecycleObjectType,

    /// Optional description.
    pub description: Option<String>,

    /// Whether the configuration is active.
    pub is_active: bool,

    /// Whether to auto-assign initial state to new objects.
    pub auto_assign_initial_state: bool,

    /// Number of states in this configuration.
    pub state_count: i64,

    /// Number of transitions in this configuration.
    pub transition_count: i64,

    /// When created.
    pub created_at: DateTime<Utc>,

    /// When last updated.
    pub updated_at: DateTime<Utc>,
}

/// Full lifecycle configuration with states and transitions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LifecycleConfigDetailResponse {
    /// Configuration details.
    #[serde(flatten)]
    pub config: LifecycleConfigResponse,

    /// States in this configuration.
    pub states: Vec<LifecycleStateResponse>,

    /// Transitions in this configuration.
    pub transitions: Vec<LifecycleTransitionResponse>,
}

/// Paginated list of lifecycle configurations.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LifecycleConfigListResponse {
    /// List of configurations.
    pub items: Vec<LifecycleConfigResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Maximum results per page.
    pub limit: i64,

    /// Number of results skipped.
    pub offset: i64,
}

// ============================================================================
// Lifecycle State Models
// ============================================================================

/// Request to create a new lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateLifecycleStateRequest {
    /// State name (e.g., Draft, Active, Suspended).
    #[validate(length(min = 1, max = 50, message = "Name must be 1-50 characters"))]
    pub name: String,

    /// Optional description.
    #[validate(length(max = 500, message = "Description must not exceed 500 characters"))]
    pub description: Option<String>,

    /// Whether this is the initial state for new objects.
    #[serde(default)]
    pub is_initial: bool,

    /// Whether this is a terminal state (no outgoing transitions).
    #[serde(default)]
    pub is_terminal: bool,

    /// Action to take on entitlements when entering this state.
    #[serde(default)]
    pub entitlement_action: EntitlementAction,

    /// Display order position.
    pub position: i32,
}

/// Request to update a lifecycle state.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateLifecycleStateRequest {
    /// Updated state name.
    #[validate(length(min = 1, max = 50, message = "Name must be 1-50 characters"))]
    pub name: Option<String>,

    /// Updated description.
    #[validate(length(max = 500, message = "Description must not exceed 500 characters"))]
    pub description: Option<String>,

    /// Whether this is the initial state.
    pub is_initial: Option<bool>,

    /// Whether this is a terminal state.
    pub is_terminal: Option<bool>,

    /// Updated entitlement action.
    pub entitlement_action: Option<EntitlementAction>,

    /// Updated display position.
    pub position: Option<i32>,
}

/// Lifecycle state response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LifecycleStateResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// State name.
    pub name: String,

    /// Optional description.
    pub description: Option<String>,

    /// Whether this is the initial state.
    pub is_initial: bool,

    /// Whether this is a terminal state.
    pub is_terminal: bool,

    /// Action on entitlements.
    pub entitlement_action: EntitlementAction,

    /// Display position.
    pub position: i32,

    /// Number of objects currently in this state.
    pub object_count: i64,

    /// When created.
    pub created_at: DateTime<Utc>,
}

impl LifecycleStateResponse {
    /// Create from database model.
    #[must_use] 
    pub fn from_model(state: GovLifecycleState, object_count: i64) -> Self {
        Self {
            id: state.id,
            name: state.name,
            description: state.description,
            is_initial: state.is_initial,
            is_terminal: state.is_terminal,
            entitlement_action: state.entitlement_action,
            position: state.position,
            object_count,
            created_at: state.created_at,
        }
    }
}

// ============================================================================
// Lifecycle Transition Models
// ============================================================================

/// Request to create a new lifecycle transition.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateLifecycleTransitionRequest {
    /// Transition name (e.g., activate, suspend, archive).
    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))]
    pub name: String,

    /// Source state ID.
    pub from_state_id: Uuid,

    /// Target state ID.
    pub to_state_id: Uuid,

    /// Whether this transition requires approval.
    #[serde(default)]
    pub requires_approval: bool,

    /// Approval workflow ID (required if `requires_approval` is true).
    pub approval_workflow_id: Option<Uuid>,

    /// Grace period in hours for rollback (0-720).
    #[validate(range(min = 0, max = 720, message = "Grace period must be 0-720 hours"))]
    #[serde(default)]
    pub grace_period_hours: i32,
}

/// Request to update a lifecycle transition.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateLifecycleTransitionRequest {
    /// Updated transition name.
    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))]
    pub name: Option<String>,

    /// Whether this transition requires approval.
    pub requires_approval: Option<bool>,

    /// Updated approval workflow ID.
    pub approval_workflow_id: Option<Uuid>,

    /// Updated grace period.
    #[validate(range(min = 0, max = 720, message = "Grace period must be 0-720 hours"))]
    pub grace_period_hours: Option<i32>,
}

/// Lifecycle transition response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LifecycleTransitionResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Transition name.
    pub name: String,

    /// Source state ID.
    pub from_state_id: Uuid,

    /// Source state name.
    pub from_state_name: String,

    /// Target state ID.
    pub to_state_id: Uuid,

    /// Target state name.
    pub to_state_name: String,

    /// Whether approval is required.
    pub requires_approval: bool,

    /// Approval workflow ID.
    pub approval_workflow_id: Option<Uuid>,

    /// Grace period in hours.
    pub grace_period_hours: i32,

    /// When created.
    pub created_at: DateTime<Utc>,
}

impl From<GovLifecycleTransitionWithStates> for LifecycleTransitionResponse {
    fn from(t: GovLifecycleTransitionWithStates) -> Self {
        Self {
            id: t.id,
            name: t.name,
            from_state_id: t.from_state_id,
            from_state_name: t.from_state_name,
            to_state_id: t.to_state_id,
            to_state_name: t.to_state_name,
            requires_approval: t.requires_approval,
            approval_workflow_id: t.approval_workflow_id,
            grace_period_hours: t.grace_period_hours,
            created_at: t.created_at,
        }
    }
}

// ============================================================================
// State Transition Request Models
// ============================================================================

/// Request to execute a state transition.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ExecuteTransitionRequest {
    /// ID of the object to transition.
    pub object_id: Uuid,

    /// Object type.
    pub object_type: LifecycleObjectType,

    /// Transition to execute (by ID or name).
    pub transition_id: Uuid,

    /// Optional scheduled time (if not provided, executes immediately).
    pub scheduled_for: Option<DateTime<Utc>>,

    /// Optional reason/comment for the transition.
    #[validate(length(max = 1000, message = "Reason must not exceed 1000 characters"))]
    pub reason: Option<String>,
}

/// Request to rollback a state transition.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct RollbackTransitionRequest {
    /// Reason for rollback.
    #[validate(length(max = 1000, message = "Reason must not exceed 1000 characters"))]
    pub reason: Option<String>,
}

/// Query parameters for listing transition requests.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListTransitionRequestsQuery {
    /// Filter by object ID.
    pub object_id: Option<Uuid>,

    /// Filter by object type.
    pub object_type: Option<LifecycleObjectType>,

    /// Filter by status.
    pub status: Option<TransitionRequestStatus>,

    /// Filter by requester.
    pub requested_by: Option<Uuid>,

    /// Only show requests with rollback available.
    pub rollback_available: Option<bool>,

    /// Maximum number of results.
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListTransitionRequestsQuery {
    fn default() -> Self {
        Self {
            object_id: None,
            object_type: None,
            status: None,
            requested_by: None,
            rollback_available: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// State transition request response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TransitionRequestResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Object being transitioned.
    pub object_id: Uuid,

    /// Object type.
    pub object_type: LifecycleObjectType,

    /// Transition name.
    pub transition_name: String,

    /// Source state.
    pub from_state: TransitionStateInfo,

    /// Target state.
    pub to_state: TransitionStateInfo,

    /// User who requested.
    pub requested_by: Uuid,

    /// Current status.
    pub status: TransitionRequestStatus,

    /// Scheduled execution time.
    pub scheduled_for: Option<DateTime<Utc>>,

    /// Approval request ID (if pending approval).
    pub approval_request_id: Option<Uuid>,

    /// When executed.
    pub executed_at: Option<DateTime<Utc>>,

    /// Grace period end time.
    pub grace_period_ends_at: Option<DateTime<Utc>>,

    /// Whether rollback is available.
    pub rollback_available: bool,

    /// Error message if failed.
    pub error_message: Option<String>,

    /// When created.
    pub created_at: DateTime<Utc>,

    /// When last updated.
    pub updated_at: DateTime<Utc>,
}

/// State information for transition response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TransitionStateInfo {
    /// State ID.
    pub id: Uuid,

    /// State name.
    pub name: String,
}

impl From<GovStateTransitionRequestWithStates> for TransitionRequestResponse {
    fn from(r: GovStateTransitionRequestWithStates) -> Self {
        Self {
            id: r.id,
            object_id: r.object_id,
            object_type: r.object_type,
            transition_name: r.transition_name,
            from_state: TransitionStateInfo {
                id: r.from_state_id,
                name: r.from_state_name,
            },
            to_state: TransitionStateInfo {
                id: r.to_state_id,
                name: r.to_state_name,
            },
            requested_by: r.requested_by,
            status: r.status,
            scheduled_for: r.scheduled_for,
            approval_request_id: r.approval_request_id,
            executed_at: r.executed_at,
            grace_period_ends_at: r.grace_period_ends_at,
            rollback_available: r.rollback_available,
            error_message: r.error_message,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

/// Paginated list of transition requests.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TransitionRequestListResponse {
    /// List of requests.
    pub items: Vec<TransitionRequestResponse>,

    /// Total count.
    pub total: i64,

    /// Limit.
    pub limit: i64,

    /// Offset.
    pub offset: i64,
}

/// Object lifecycle status response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ObjectLifecycleStatusResponse {
    /// Object ID.
    pub object_id: Uuid,

    /// Object type.
    pub object_type: LifecycleObjectType,

    /// Current state.
    pub current_state: Option<LifecycleStateResponse>,

    /// Available transitions from current state.
    pub available_transitions: Vec<LifecycleTransitionResponse>,

    /// Active rollback window (if any).
    pub active_rollback: Option<RollbackInfo>,

    /// Pending scheduled transitions.
    pub pending_schedules: Vec<ScheduledTransitionResponse>,
}

/// Rollback availability information.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RollbackInfo {
    /// The request that can be rolled back.
    pub request_id: Uuid,

    /// State that would be restored.
    pub restore_to_state: String,

    /// When rollback window expires.
    pub expires_at: DateTime<Utc>,
}

// ============================================================================
// Scheduled Transition Models
// ============================================================================

/// Query parameters for listing scheduled transitions.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListScheduledTransitionsQuery {
    /// Filter by status.
    pub status: Option<GovScheduleStatus>,

    /// Only show schedules before this time.
    pub scheduled_before: Option<DateTime<Utc>>,

    /// Only show schedules after this time.
    pub scheduled_after: Option<DateTime<Utc>>,

    /// Maximum number of results.
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListScheduledTransitionsQuery {
    fn default() -> Self {
        Self {
            status: None,
            scheduled_before: None,
            scheduled_after: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Scheduled transition response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScheduledTransitionResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Associated transition request ID.
    pub transition_request_id: Uuid,

    /// Object being transitioned.
    pub object_id: Uuid,

    /// Object type.
    pub object_type: LifecycleObjectType,

    /// Transition name.
    pub transition_name: String,

    /// Source state name.
    pub from_state: String,

    /// Target state name.
    pub to_state: String,

    /// Scheduled execution time.
    pub scheduled_for: DateTime<Utc>,

    /// Current status.
    pub status: GovScheduleStatus,

    /// When actually executed.
    pub executed_at: Option<DateTime<Utc>>,

    /// When cancelled.
    pub cancelled_at: Option<DateTime<Utc>>,

    /// Who cancelled.
    pub cancelled_by: Option<Uuid>,

    /// Error message if failed.
    pub error_message: Option<String>,

    /// When created.
    pub created_at: DateTime<Utc>,
}

/// Paginated list of scheduled transitions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScheduledTransitionListResponse {
    /// List of scheduled transitions.
    pub items: Vec<ScheduledTransitionResponse>,

    /// Total count.
    pub total: i64,

    /// Limit.
    pub limit: i64,

    /// Offset.
    pub offset: i64,
}

/// Request to reschedule a transition.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct RescheduleTransitionRequest {
    /// New scheduled time.
    pub scheduled_for: DateTime<Utc>,
}

// ============================================================================
// Bulk Operation Models
// ============================================================================

/// Request to start a bulk state operation.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateBulkOperationRequest {
    /// Transition to apply.
    pub transition_id: Uuid,

    /// Object IDs to transition (max 1000).
    #[validate(length(min = 1, max = 1000, message = "Must provide 1-1000 object IDs"))]
    pub object_ids: Vec<Uuid>,
}

/// Query parameters for listing bulk operations.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListBulkOperationsQuery {
    /// Filter by status.
    pub status: Option<BulkOperationStatus>,

    /// Filter by transition.
    pub transition_id: Option<Uuid>,

    /// Filter by requester.
    pub requested_by: Option<Uuid>,

    /// Maximum number of results.
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListBulkOperationsQuery {
    fn default() -> Self {
        Self {
            status: None,
            transition_id: None,
            requested_by: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Bulk operation response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BulkOperationResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Transition being applied.
    pub transition_id: Uuid,

    /// Current status.
    pub status: BulkOperationStatus,

    /// Total objects.
    pub total_count: i32,

    /// Objects processed.
    pub processed_count: i32,

    /// Successful transitions.
    pub success_count: i32,

    /// Failed transitions.
    pub failure_count: i32,

    /// Progress percentage (0-100).
    pub progress_percent: u8,

    /// Who requested.
    pub requested_by: Uuid,

    /// When created.
    pub created_at: DateTime<Utc>,

    /// When started.
    pub started_at: Option<DateTime<Utc>>,

    /// When completed.
    pub completed_at: Option<DateTime<Utc>>,
}

impl From<GovBulkStateOperation> for BulkOperationResponse {
    fn from(op: GovBulkStateOperation) -> Self {
        let progress = op.get_progress();
        Self {
            id: op.id,
            transition_id: op.transition_id,
            status: op.status,
            total_count: op.total_count,
            processed_count: op.processed_count,
            success_count: op.success_count,
            failure_count: op.failure_count,
            progress_percent: progress.progress_percent,
            requested_by: op.requested_by,
            created_at: op.created_at,
            started_at: op.started_at,
            completed_at: op.completed_at,
        }
    }
}

/// Detailed bulk operation results.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BulkOperationDetailResponse {
    /// Operation summary.
    #[serde(flatten)]
    pub operation: BulkOperationResponse,

    /// Per-object results.
    pub results: Option<JsonValue>,
}

/// Paginated list of bulk operations.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BulkOperationListResponse {
    /// List of operations.
    pub items: Vec<BulkOperationResponse>,

    /// Total count.
    pub total: i64,

    /// Limit.
    pub limit: i64,

    /// Offset.
    pub offset: i64,
}

// ============================================================================
// Audit Models
// ============================================================================

/// Query parameters for listing audit records.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListTransitionAuditQuery {
    /// Filter by object ID.
    pub object_id: Option<Uuid>,

    /// Filter by object type.
    pub object_type: Option<LifecycleObjectType>,

    /// Filter by actor.
    pub actor_id: Option<Uuid>,

    /// Filter by action type.
    pub action_type: Option<AuditActionType>,

    /// Only records after this date.
    pub from_date: Option<DateTime<Utc>>,

    /// Only records before this date.
    pub to_date: Option<DateTime<Utc>>,

    /// Maximum number of results.
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListTransitionAuditQuery {
    fn default() -> Self {
        Self {
            object_id: None,
            object_type: None,
            actor_id: None,
            action_type: None,
            from_date: None,
            to_date: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Audit record response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TransitionAuditResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Original request ID.
    pub request_id: Uuid,

    /// Object that was transitioned.
    pub object_id: Uuid,

    /// Object type.
    pub object_type: LifecycleObjectType,

    /// Source state name.
    pub from_state: String,

    /// Target state name.
    pub to_state: String,

    /// Transition name.
    pub transition_name: String,

    /// Who performed the action.
    pub actor_id: Uuid,

    /// Action type.
    pub action_type: AuditActionType,

    /// Approval details (if applicable).
    pub approval_details: Option<JsonValue>,

    /// Entitlements before transition.
    pub entitlements_before: JsonValue,

    /// Entitlements after transition.
    pub entitlements_after: JsonValue,

    /// Additional metadata.
    pub metadata: Option<JsonValue>,

    /// When the audit was created.
    pub created_at: DateTime<Utc>,
}

impl From<GovStateTransitionAudit> for TransitionAuditResponse {
    fn from(a: GovStateTransitionAudit) -> Self {
        Self {
            id: a.id,
            request_id: a.request_id,
            object_id: a.object_id,
            object_type: a.object_type,
            from_state: a.from_state,
            to_state: a.to_state,
            transition_name: a.transition_name,
            actor_id: a.actor_id,
            action_type: a.action_type,
            approval_details: a.approval_details,
            entitlements_before: a.entitlements_before,
            entitlements_after: a.entitlements_after,
            metadata: a.metadata,
            created_at: a.created_at,
        }
    }
}

/// Paginated list of audit records.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TransitionAuditListResponse {
    /// List of audit records.
    pub items: Vec<TransitionAuditResponse>,

    /// Total count.
    pub total: i64,

    /// Limit.
    pub limit: i64,

    /// Offset.
    pub offset: i64,
}
