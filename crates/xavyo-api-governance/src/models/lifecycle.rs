//! Request and response models for object lifecycle state endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{
    AuditActionType, BulkOperationStatus, EntitlementAction, GovBulkStateOperation,
    GovLifecycleActionExecution, GovLifecycleState, GovLifecycleTransitionWithStates,
    GovScheduleStatus, GovStateTransitionAudit, GovStateTransitionRequestWithStates,
    LifecycleObjectType, TransitionRequestStatus,
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

// ============================================================================
// Transition Condition Models (F-193)
// ============================================================================

/// Types of conditions that can be applied to transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransitionConditionType {
    /// Check if termination_date is set on the user.
    TerminationDateSet,
    /// Check if termination_date has been reached (current time >= termination_date).
    TerminationDateReached,
    /// Check if manager approval has been received for the transition.
    ManagerApprovalReceived,
    /// Check if an access review is complete for the user.
    AccessReviewComplete,
    /// Check if the user has no active sessions.
    NoActiveSessions,
    /// Check if a custom attribute equals a specific value.
    CustomAttributeEquals,
}

impl std::fmt::Display for TransitionConditionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TerminationDateSet => write!(f, "termination_date_set"),
            Self::TerminationDateReached => write!(f, "termination_date_reached"),
            Self::ManagerApprovalReceived => write!(f, "manager_approval_received"),
            Self::AccessReviewComplete => write!(f, "access_review_complete"),
            Self::NoActiveSessions => write!(f, "no_active_sessions"),
            Self::CustomAttributeEquals => write!(f, "custom_attribute_equals"),
        }
    }
}

/// A condition that must be satisfied for a transition to be allowed.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct TransitionCondition {
    /// Type of condition to evaluate.
    #[serde(rename = "type")]
    pub condition_type: TransitionConditionType,

    /// Configuration for the condition (depends on type).
    /// For CustomAttributeEquals: {"attribute": "department", "value": "Sales"}
    #[serde(default)]
    pub config: JsonValue,

    /// Optional human-readable description.
    #[validate(length(max = 500, message = "Description must not exceed 500 characters"))]
    pub description: Option<String>,
}

impl TransitionCondition {
    /// Create a new condition.
    #[must_use]
    pub fn new(condition_type: TransitionConditionType) -> Self {
        Self {
            condition_type,
            config: JsonValue::Object(serde_json::Map::new()),
            description: None,
        }
    }

    /// Create a condition with configuration.
    #[must_use]
    pub fn with_config(condition_type: TransitionConditionType, config: JsonValue) -> Self {
        Self {
            condition_type,
            config,
            description: None,
        }
    }
}

/// Result of evaluating a single transition condition.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TransitionConditionResult {
    /// The condition that was evaluated.
    pub condition: TransitionCondition,

    /// Whether the condition was satisfied.
    pub satisfied: bool,

    /// Human-readable explanation of the result.
    pub reason: String,
}

/// Result of evaluating all conditions for a transition.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TransitionConditionsEvaluationResult {
    /// Whether all conditions are satisfied.
    pub all_satisfied: bool,

    /// Individual condition results.
    pub conditions: Vec<TransitionConditionResult>,

    /// Summary message.
    pub summary: String,
}

// ============================================================================
// Lifecycle Action Models (F-193)
// ============================================================================

/// Types of actions that can be executed on state entry/exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleActionType {
    /// Disable user access (set is_active = false).
    DisableAccess,
    /// Enable user access (set is_active = true).
    EnableAccess,
    /// Revoke all active sessions for the user.
    RevokeSessions,
    /// Send notification to the user's manager.
    NotifyManager,
    /// Schedule an access review (micro-certification) for the user.
    ScheduleAccessReview,
    /// Anonymize PII data for the user.
    AnonymizeData,
    /// Send a notification (email, webhook, etc.).
    SendNotification,
    /// Call an external webhook.
    Webhook,
}

impl std::fmt::Display for LifecycleActionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DisableAccess => write!(f, "disable_access"),
            Self::EnableAccess => write!(f, "enable_access"),
            Self::RevokeSessions => write!(f, "revoke_sessions"),
            Self::NotifyManager => write!(f, "notify_manager"),
            Self::ScheduleAccessReview => write!(f, "schedule_access_review"),
            Self::AnonymizeData => write!(f, "anonymize_data"),
            Self::SendNotification => write!(f, "send_notification"),
            Self::Webhook => write!(f, "webhook"),
        }
    }
}

/// An action to execute on state entry or exit.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct LifecycleAction {
    /// Type of action to execute.
    #[serde(rename = "type")]
    pub action_type: LifecycleActionType,

    /// Configuration for the action (depends on type).
    /// For Webhook: {"url": "https://...", "method": "POST", "headers": {}}
    /// For SendNotification: {"template": "...", "recipients": [...]}
    #[serde(default)]
    pub config: JsonValue,

    /// Optional human-readable description.
    #[validate(length(max = 500, message = "Description must not exceed 500 characters"))]
    pub description: Option<String>,

    /// Whether to continue if this action fails (default: false).
    #[serde(default)]
    pub continue_on_failure: bool,
}

impl LifecycleAction {
    /// Create a new action.
    #[must_use]
    pub fn new(action_type: LifecycleActionType) -> Self {
        Self {
            action_type,
            config: JsonValue::Object(serde_json::Map::new()),
            description: None,
            continue_on_failure: false,
        }
    }

    /// Create an action with configuration.
    #[must_use]
    pub fn with_config(action_type: LifecycleActionType, config: JsonValue) -> Self {
        Self {
            action_type,
            config,
            description: None,
            continue_on_failure: false,
        }
    }
}

// ============================================================================
// Condition and Action DTOs (F-193)
// ============================================================================

/// Request to get transition conditions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GetTransitionConditionsResponse {
    /// The transition ID.
    pub transition_id: Uuid,

    /// Transition name.
    pub transition_name: String,

    /// Conditions configured for this transition.
    pub conditions: Vec<TransitionCondition>,
}

/// Request to update transition conditions.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateTransitionConditionsRequest {
    /// Conditions to set on the transition.
    pub conditions: Vec<TransitionCondition>,
}

/// Request to evaluate conditions for a transition.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EvaluateTransitionConditionsRequest {
    /// The object ID to evaluate conditions against.
    pub object_id: Uuid,

    /// Object type.
    pub object_type: LifecycleObjectType,
}

/// Response for condition evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EvaluateTransitionConditionsResponse {
    /// Transition ID.
    pub transition_id: Uuid,

    /// Object ID that was evaluated.
    pub object_id: Uuid,

    /// Whether all conditions are satisfied.
    pub can_transition: bool,

    /// Detailed evaluation results.
    pub evaluation: TransitionConditionsEvaluationResult,
}

/// Request to get state actions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GetStateActionsResponse {
    /// The state ID.
    pub state_id: Uuid,

    /// State name.
    pub state_name: String,

    /// Actions to execute when entering this state.
    pub entry_actions: Vec<LifecycleAction>,

    /// Actions to execute when leaving this state.
    pub exit_actions: Vec<LifecycleAction>,
}

/// Request to update state actions.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateStateActionsRequest {
    /// Entry actions to set (if provided, replaces all entry actions).
    pub entry_actions: Option<Vec<LifecycleAction>>,

    /// Exit actions to set (if provided, replaces all exit actions).
    pub exit_actions: Option<Vec<LifecycleAction>>,
}

/// Query parameters for listing action executions.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListActionExecutionsQuery {
    /// Filter by transition audit ID.
    pub transition_audit_id: Option<Uuid>,

    /// Filter by state ID.
    pub state_id: Option<Uuid>,

    /// Filter by action type.
    pub action_type: Option<String>,

    /// Filter by status.
    pub status: Option<String>,

    /// Maximum number of results.
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListActionExecutionsQuery {
    fn default() -> Self {
        Self {
            transition_audit_id: None,
            state_id: None,
            action_type: None,
            status: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Action execution response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ActionExecutionResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// The transition audit ID this action belongs to.
    pub transition_audit_id: Uuid,

    /// The state ID.
    pub state_id: Uuid,

    /// Action type.
    pub action_type: String,

    /// Action configuration.
    pub action_config: JsonValue,

    /// Whether this was an entry or exit action.
    pub trigger_type: String,

    /// Current status.
    pub status: String,

    /// When executed.
    pub executed_at: Option<DateTime<Utc>>,

    /// Error message if failed.
    pub error_message: Option<String>,

    /// When created.
    pub created_at: DateTime<Utc>,
}

impl From<GovLifecycleActionExecution> for ActionExecutionResponse {
    fn from(e: GovLifecycleActionExecution) -> Self {
        Self {
            id: e.id,
            transition_audit_id: e.transition_audit_id,
            state_id: e.state_id,
            action_type: e.action_type,
            action_config: e.action_config,
            trigger_type: e.trigger_type,
            status: e.status,
            executed_at: e.executed_at,
            error_message: e.error_message,
            created_at: e.created_at,
        }
    }
}

/// Paginated list of action executions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ActionExecutionListResponse {
    /// List of action executions.
    pub items: Vec<ActionExecutionResponse>,

    /// Total count.
    pub total: i64,

    /// Limit.
    pub limit: i64,

    /// Offset.
    pub offset: i64,
}

/// Enhanced user lifecycle status response with condition evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserLifecycleStatusResponse {
    /// User ID.
    pub user_id: Uuid,

    /// Current lifecycle state.
    pub current_state: Option<LifecycleStateResponse>,

    /// Available transitions with condition evaluation.
    pub available_transitions: Vec<AvailableTransitionWithConditions>,

    /// Pending scheduled transitions.
    pub pending_schedules: Vec<ScheduledTransitionResponse>,

    /// Active rollback window (if any).
    pub active_rollback: Option<RollbackInfo>,

    /// Effective lifecycle model (from archetype or direct assignment).
    pub lifecycle_model: Option<LifecycleModelInfo>,
}

/// Information about a lifecycle model.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LifecycleModelInfo {
    /// Model ID.
    pub id: Uuid,

    /// Model name.
    pub name: String,

    /// Source of the model assignment.
    pub source: LifecycleModelSource,
}

/// Source of lifecycle model assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleModelSource {
    /// Directly assigned to the identity.
    Direct,
    /// Inherited from archetype.
    Archetype,
    /// System default.
    SystemDefault,
}

/// Transition with pre-evaluated conditions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AvailableTransitionWithConditions {
    /// Transition details.
    #[serde(flatten)]
    pub transition: LifecycleTransitionResponse,

    /// Whether all conditions are satisfied.
    pub conditions_satisfied: bool,

    /// Condition evaluation results.
    pub condition_results: Vec<TransitionConditionResult>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transition_condition_type_display() {
        assert_eq!(
            TransitionConditionType::TerminationDateSet.to_string(),
            "termination_date_set"
        );
        assert_eq!(
            TransitionConditionType::NoActiveSessions.to_string(),
            "no_active_sessions"
        );
    }

    #[test]
    fn test_lifecycle_action_type_display() {
        assert_eq!(
            LifecycleActionType::DisableAccess.to_string(),
            "disable_access"
        );
        assert_eq!(LifecycleActionType::Webhook.to_string(), "webhook");
    }

    #[test]
    fn test_transition_condition_serialization() {
        let condition = TransitionCondition::new(TransitionConditionType::TerminationDateSet);
        let json = serde_json::to_string(&condition).unwrap();
        assert!(json.contains("\"type\":\"termination_date_set\""));
    }

    #[test]
    fn test_lifecycle_action_serialization() {
        let action = LifecycleAction::new(LifecycleActionType::DisableAccess);
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("\"type\":\"disable_access\""));
    }

    #[test]
    fn test_condition_with_config() {
        let config = serde_json::json!({
            "attribute": "department",
            "value": "Sales"
        });
        let condition = TransitionCondition::with_config(
            TransitionConditionType::CustomAttributeEquals,
            config.clone(),
        );
        assert_eq!(condition.config, config);
    }

    #[test]
    fn test_action_with_config() {
        let config = serde_json::json!({
            "url": "https://example.com/webhook",
            "method": "POST"
        });
        let action = LifecycleAction::with_config(LifecycleActionType::Webhook, config.clone());
        assert_eq!(action.config, config);
        assert!(!action.continue_on_failure);
    }

    // =========================================================================
    // T027: Unit tests for LifecycleAction validation
    // =========================================================================

    #[test]
    fn test_lifecycle_action_all_types_serialize() {
        let action_types = vec![
            LifecycleActionType::DisableAccess,
            LifecycleActionType::EnableAccess,
            LifecycleActionType::RevokeSessions,
            LifecycleActionType::NotifyManager,
            LifecycleActionType::ScheduleAccessReview,
            LifecycleActionType::AnonymizeData,
            LifecycleActionType::SendNotification,
            LifecycleActionType::Webhook,
        ];

        for action_type in action_types {
            let action = LifecycleAction::new(action_type);
            let json = serde_json::to_string(&action).unwrap();
            let parsed: LifecycleAction = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.action_type, action_type);
        }
    }

    #[test]
    fn test_lifecycle_action_continue_on_failure_default() {
        let action = LifecycleAction::new(LifecycleActionType::DisableAccess);
        assert!(!action.continue_on_failure, "Default should be false");
    }

    #[test]
    fn test_lifecycle_action_with_continue_on_failure() {
        let mut action = LifecycleAction::new(LifecycleActionType::NotifyManager);
        action.continue_on_failure = true;
        let json = serde_json::to_string(&action).unwrap();
        let parsed: LifecycleAction = serde_json::from_str(&json).unwrap();
        assert!(parsed.continue_on_failure);
    }

    #[test]
    fn test_lifecycle_action_webhook_config() {
        let config = serde_json::json!({
            "url": "https://hooks.example.com/lifecycle",
            "method": "POST",
            "headers": {
                "Authorization": "Bearer token123",
                "Content-Type": "application/json"
            },
            "timeout_seconds": 30
        });
        let action = LifecycleAction::with_config(LifecycleActionType::Webhook, config.clone());
        assert_eq!(action.config["url"], "https://hooks.example.com/lifecycle");
        assert_eq!(action.config["method"], "POST");
        assert_eq!(action.config["timeout_seconds"], 30);
    }

    #[test]
    fn test_lifecycle_action_send_notification_config() {
        let config = serde_json::json!({
            "template": "lifecycle_state_change",
            "recipients": ["user", "manager"],
            "channel": "email"
        });
        let action =
            LifecycleAction::with_config(LifecycleActionType::SendNotification, config.clone());
        assert_eq!(action.config["template"], "lifecycle_state_change");
        assert!(action.config["recipients"].is_array());
    }

    #[test]
    fn test_lifecycle_action_schedule_access_review_config() {
        let config = serde_json::json!({
            "review_type": "micro_certification",
            "scope": "all_entitlements",
            "deadline_days": 7
        });
        let action =
            LifecycleAction::with_config(LifecycleActionType::ScheduleAccessReview, config.clone());
        assert_eq!(action.config["review_type"], "micro_certification");
        assert_eq!(action.config["deadline_days"], 7);
    }

    #[test]
    fn test_lifecycle_action_with_description() {
        let mut action = LifecycleAction::new(LifecycleActionType::DisableAccess);
        action.description = Some("Disable user access upon termination".to_string());
        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("Disable user access upon termination"));
    }

    #[test]
    fn test_lifecycle_action_description_validation() {
        use validator::Validate;

        let mut action = LifecycleAction::new(LifecycleActionType::DisableAccess);
        // Valid description
        action.description = Some("Short description".to_string());
        assert!(action.validate().is_ok());

        // Description too long (> 500 chars)
        action.description = Some("x".repeat(501));
        assert!(action.validate().is_err());
    }

    #[test]
    fn test_update_state_actions_request_validation() {
        use validator::Validate;

        let request = UpdateStateActionsRequest {
            entry_actions: Some(vec![LifecycleAction::new(
                LifecycleActionType::DisableAccess,
            )]),
            exit_actions: None,
        };
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_lifecycle_action_empty_config() {
        let action = LifecycleAction::new(LifecycleActionType::EnableAccess);
        assert!(action.config.is_object());
        assert!(action.config.as_object().unwrap().is_empty());
    }

    #[test]
    fn test_lifecycle_action_deserialize_from_json() {
        let json = r#"{
            "type": "revoke_sessions",
            "config": {"force": true},
            "description": "Force revoke all sessions",
            "continue_on_failure": true
        }"#;
        let action: LifecycleAction = serde_json::from_str(json).unwrap();
        assert_eq!(action.action_type, LifecycleActionType::RevokeSessions);
        assert_eq!(action.config["force"], true);
        assert_eq!(
            action.description,
            Some("Force revoke all sessions".to_string())
        );
        assert!(action.continue_on_failure);
    }

    #[test]
    fn test_lifecycle_action_deserialize_minimal() {
        let json = r#"{"type": "disable_access"}"#;
        let action: LifecycleAction = serde_json::from_str(json).unwrap();
        assert_eq!(action.action_type, LifecycleActionType::DisableAccess);
        assert!(!action.continue_on_failure);
        assert!(action.description.is_none());
    }

    #[test]
    fn test_get_state_actions_response_structure() {
        let response = GetStateActionsResponse {
            state_id: Uuid::new_v4(),
            state_name: "terminated".to_string(),
            entry_actions: vec![LifecycleAction::new(LifecycleActionType::DisableAccess)],
            exit_actions: vec![],
        };
        assert_eq!(response.state_name, "terminated");
        assert_eq!(response.entry_actions.len(), 1);
        assert!(response.exit_actions.is_empty());
    }
}
