//! Request and response models for escalation policy endpoints (F054).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::models::{
    EscalationReason, EscalationTargetType, FinalFallbackAction, GovApprovalGroup,
    GovEscalationEvent, GovEscalationLevel, GovEscalationPolicy,
};

// ============================================================================
// Escalation Policy Models
// ============================================================================

/// Request to create a new escalation policy.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateEscalationPolicyRequest {
    /// Display name for the policy.
    #[validate(length(min = 1, max = 255, message = "Name must be 1-255 characters"))]
    pub name: String,

    /// Optional description.
    #[validate(length(max = 1000, message = "Description must not exceed 1000 characters"))]
    pub description: Option<String>,

    /// Default timeout in seconds (minimum 60).
    #[validate(range(min = 60, message = "Timeout must be at least 60 seconds"))]
    pub default_timeout_secs: i64,

    /// Warning threshold in seconds before timeout (optional).
    pub warning_threshold_secs: Option<i64>,

    /// Final fallback action when all escalation levels are exhausted.
    pub final_fallback: FinalFallbackAction,
}

/// Request to update an existing escalation policy.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateEscalationPolicyRequest {
    /// Updated display name.
    #[validate(length(min = 1, max = 255, message = "Name must be 1-255 characters"))]
    pub name: Option<String>,

    /// Updated description.
    #[validate(length(max = 1000, message = "Description must not exceed 1000 characters"))]
    pub description: Option<String>,

    /// Updated default timeout in seconds.
    #[validate(range(min = 60, message = "Timeout must be at least 60 seconds"))]
    pub default_timeout_secs: Option<i64>,

    /// Updated warning threshold in seconds.
    pub warning_threshold_secs: Option<i64>,

    /// Updated final fallback action.
    pub final_fallback: Option<FinalFallbackAction>,

    /// Whether the policy is active.
    pub is_active: Option<bool>,
}

/// Query parameters for listing escalation policies.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListEscalationPoliciesQuery {
    /// Filter by active status.
    pub is_active: Option<bool>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListEscalationPoliciesQuery {
    fn default() -> Self {
        Self {
            is_active: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Escalation level response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EscalationLevelResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Level order (1 = first escalation).
    pub level_order: i32,

    /// Display name for this level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level_name: Option<String>,

    /// Timeout in seconds before escalating to this level.
    pub timeout_secs: i64,

    /// Type of escalation target.
    pub target_type: EscalationTargetType,

    /// Target ID (user, group, or null for manager types).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_id: Option<Uuid>,

    /// Depth for manager_chain type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manager_chain_depth: Option<i32>,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

impl From<GovEscalationLevel> for EscalationLevelResponse {
    fn from(level: GovEscalationLevel) -> Self {
        let timeout_secs = level.timeout_secs();
        Self {
            id: level.id,
            level_order: level.level_order,
            level_name: level.level_name,
            timeout_secs,
            target_type: level.target_type,
            target_id: level.target_id,
            manager_chain_depth: level.manager_chain_depth,
            created_at: level.created_at,
        }
    }
}

/// Escalation policy response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EscalationPolicyResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Display name.
    pub name: String,

    /// Optional description.
    pub description: Option<String>,

    /// Default timeout in seconds.
    pub default_timeout_secs: i64,

    /// Warning threshold in seconds.
    pub warning_threshold_secs: Option<i64>,

    /// Final fallback action.
    pub final_fallback: FinalFallbackAction,

    /// Whether this is the active default policy.
    pub is_active: bool,

    /// Escalation levels.
    pub levels: Vec<EscalationLevelResponse>,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl EscalationPolicyResponse {
    /// Create response from policy and levels.
    pub fn from_policy_and_levels(
        policy: GovEscalationPolicy,
        levels: Vec<GovEscalationLevel>,
    ) -> Self {
        let default_timeout_secs = policy.timeout_secs();
        let warning_threshold_secs = policy.warning_threshold_secs();
        Self {
            id: policy.id,
            name: policy.name,
            description: policy.description,
            default_timeout_secs,
            warning_threshold_secs,
            final_fallback: policy.final_fallback,
            is_active: policy.is_active,
            levels: levels
                .into_iter()
                .map(EscalationLevelResponse::from)
                .collect(),
            created_at: policy.created_at,
            updated_at: policy.updated_at,
        }
    }
}

/// Policy summary for list views.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EscalationPolicySummary {
    /// Unique identifier.
    pub id: Uuid,

    /// Display name.
    pub name: String,

    /// Optional description.
    pub description: Option<String>,

    /// Default timeout in seconds.
    pub default_timeout_secs: i64,

    /// Final fallback action.
    pub final_fallback: FinalFallbackAction,

    /// Whether the policy is active.
    pub is_active: bool,

    /// Number of escalation levels.
    pub level_count: i32,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Paginated list of escalation policies.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EscalationPolicyListResponse {
    /// List of policies.
    pub items: Vec<EscalationPolicySummary>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

/// Request to add an escalation level.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateEscalationLevelRequest {
    /// Level order (1 = first escalation).
    #[validate(range(min = 1, max = 10, message = "Level order must be between 1 and 10"))]
    pub level_order: i32,

    /// Display name for this level.
    #[validate(length(max = 255, message = "Level name must not exceed 255 characters"))]
    pub level_name: Option<String>,

    /// Timeout in seconds before escalating to this level.
    #[validate(range(min = 60, message = "Timeout must be at least 60 seconds"))]
    pub timeout_secs: i64,

    /// Type of escalation target.
    pub target_type: EscalationTargetType,

    /// Target ID (user or group ID, required for specific_user and approval_group types).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_id: Option<Uuid>,

    /// Depth for manager_chain type (1-10).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manager_chain_depth: Option<i32>,
}

// ============================================================================
// Approval Group Models
// ============================================================================

/// Request to create a new approval group.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateApprovalGroupRequest {
    /// Display name for the group.
    #[validate(length(min = 1, max = 255, message = "Name must be 1-255 characters"))]
    pub name: String,

    /// Optional description.
    #[validate(length(max = 1000, message = "Description must not exceed 1000 characters"))]
    pub description: Option<String>,

    /// Initial member user IDs.
    #[serde(default)]
    pub member_ids: Vec<Uuid>,
}

/// Request to update an existing approval group.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateApprovalGroupRequest {
    /// Updated display name.
    #[validate(length(min = 1, max = 255, message = "Name must be 1-255 characters"))]
    pub name: Option<String>,

    /// Updated description.
    #[validate(length(max = 1000, message = "Description must not exceed 1000 characters"))]
    pub description: Option<String>,

    /// Whether the group is active.
    pub is_active: Option<bool>,
}

/// Request to modify group members.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ModifyMembersRequest {
    /// Member user IDs to add or remove.
    #[validate(length(min = 1, message = "At least one member ID required"))]
    pub member_ids: Vec<Uuid>,
}

/// Query parameters for listing approval groups.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListApprovalGroupsQuery {
    /// Filter by active status.
    pub is_active: Option<bool>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListApprovalGroupsQuery {
    fn default() -> Self {
        Self {
            is_active: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Approval group response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApprovalGroupResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Display name.
    pub name: String,

    /// Optional description.
    pub description: Option<String>,

    /// Member user IDs.
    pub member_ids: Vec<Uuid>,

    /// Number of members.
    pub member_count: usize,

    /// Whether the group is active.
    pub is_active: bool,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl From<GovApprovalGroup> for ApprovalGroupResponse {
    fn from(group: GovApprovalGroup) -> Self {
        let member_count = group.member_count();
        Self {
            id: group.id,
            name: group.name,
            description: group.description,
            member_ids: group.member_ids,
            member_count,
            is_active: group.is_active,
            created_at: group.created_at,
            updated_at: group.updated_at,
        }
    }
}

/// Approval group summary for list views.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApprovalGroupSummary {
    /// Unique identifier.
    pub id: Uuid,

    /// Display name.
    pub name: String,

    /// Optional description.
    pub description: Option<String>,

    /// Number of members.
    pub member_count: usize,

    /// Whether the group is active.
    pub is_active: bool,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl From<GovApprovalGroup> for ApprovalGroupSummary {
    fn from(group: GovApprovalGroup) -> Self {
        let member_count = group.member_count();
        Self {
            id: group.id,
            name: group.name,
            description: group.description,
            member_count,
            is_active: group.is_active,
            created_at: group.created_at,
            updated_at: group.updated_at,
        }
    }
}

/// Paginated list of approval groups.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApprovalGroupListResponse {
    /// List of groups.
    pub items: Vec<ApprovalGroupSummary>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

// ============================================================================
// Step Escalation Models
// ============================================================================

/// Request to configure escalation for an approval step.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ConfigureStepEscalationRequest {
    /// Timeout in seconds before escalation (minimum 60 seconds).
    #[validate(range(min = 60, message = "Timeout must be at least 60 seconds"))]
    pub timeout_secs: i64,

    /// Warning threshold in seconds before timeout (optional).
    pub warning_threshold_secs: Option<i64>,

    /// Override final fallback action for this step.
    pub final_fallback: Option<FinalFallbackAction>,
}

/// Response for step escalation configuration.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct StepEscalationResponse {
    /// The step ID.
    pub step_id: Uuid,

    /// Rule ID if configured.
    pub rule_id: Option<Uuid>,

    /// Whether escalation is enabled for this step.
    pub escalation_enabled: bool,

    /// Timeout in seconds.
    pub timeout_secs: Option<i64>,

    /// Warning threshold in seconds.
    pub warning_threshold_secs: Option<i64>,

    /// Final fallback action.
    pub final_fallback: Option<FinalFallbackAction>,

    /// Whether a rule is configured (vs using tenant defaults).
    pub has_custom_rule: bool,

    /// Creation timestamp.
    pub created_at: Option<DateTime<Utc>>,

    /// Last update timestamp.
    pub updated_at: Option<DateTime<Utc>>,
}

impl StepEscalationResponse {
    /// Create response from step with optional rule.
    pub fn from_step_and_rule(
        step_id: Uuid,
        escalation_enabled: bool,
        rule: Option<xavyo_db::models::GovEscalationRule>,
    ) -> Self {
        match rule {
            Some(r) => {
                let timeout_secs = r.timeout_secs();
                let warning_threshold_secs = r.warning_threshold_secs();
                Self {
                    step_id,
                    rule_id: Some(r.id),
                    escalation_enabled,
                    timeout_secs: Some(timeout_secs),
                    warning_threshold_secs,
                    final_fallback: r.final_fallback,
                    has_custom_rule: true,
                    created_at: Some(r.created_at),
                    updated_at: Some(r.updated_at),
                }
            }
            None => Self {
                step_id,
                rule_id: None,
                escalation_enabled,
                timeout_secs: None,
                warning_threshold_secs: None,
                final_fallback: None,
                has_custom_rule: false,
                created_at: None,
                updated_at: None,
            },
        }
    }
}

// ============================================================================
// Escalation Event Models (Audit Trail)
// ============================================================================

/// Query parameters for listing escalation events.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListEscalationEventsQuery {
    /// Filter by request ID.
    pub request_id: Option<Uuid>,

    /// Filter by original approver ID.
    pub original_approver_id: Option<Uuid>,

    /// Filter by escalation target ID (any user who received an escalation).
    pub escalation_target_id: Option<Uuid>,

    /// Filter by escalation reason.
    pub reason: Option<EscalationReason>,

    /// Filter events from this date (inclusive).
    pub from_date: Option<DateTime<Utc>>,

    /// Filter events to this date (inclusive).
    pub to_date: Option<DateTime<Utc>>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListEscalationEventsQuery {
    fn default() -> Self {
        Self {
            request_id: None,
            original_approver_id: None,
            escalation_target_id: None,
            reason: None,
            from_date: None,
            to_date: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Escalation event response for audit trail.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EscalationEventResponse {
    /// Unique event identifier.
    pub id: Uuid,

    /// The access request this escalation belongs to.
    pub request_id: Uuid,

    /// The approval step order (1-indexed).
    pub step_order: i32,

    /// The escalation level reached (1 = first escalation).
    pub escalation_level: i32,

    /// Original approver who didn't respond (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_approver_id: Option<Uuid>,

    /// Type of escalation target.
    pub escalation_target_type: EscalationTargetType,

    /// User IDs who received the escalated work item.
    pub escalation_target_ids: Vec<Uuid>,

    /// Reason for escalation.
    pub reason: EscalationReason,

    /// Previous deadline before escalation (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_deadline: Option<DateTime<Utc>>,

    /// New deadline after escalation (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_deadline: Option<DateTime<Utc>>,

    /// Additional metadata (e.g., fallback action, levels_exhausted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,

    /// When the escalation occurred.
    pub created_at: DateTime<Utc>,
}

impl From<GovEscalationEvent> for EscalationEventResponse {
    fn from(event: GovEscalationEvent) -> Self {
        Self {
            id: event.id,
            request_id: event.request_id,
            step_order: event.step_order,
            escalation_level: event.escalation_level,
            original_approver_id: event.original_approver_id,
            escalation_target_type: event.escalation_target_type,
            escalation_target_ids: event.escalation_target_ids,
            reason: event.reason,
            previous_deadline: event.previous_deadline,
            new_deadline: event.new_deadline,
            metadata: event.metadata,
            created_at: event.created_at,
        }
    }
}

/// Paginated list of escalation events.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EscalationEventListResponse {
    /// List of escalation events.
    pub items: Vec<EscalationEventResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

/// Escalation history for a specific access request.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EscalationHistoryResponse {
    /// The access request ID.
    pub request_id: Uuid,

    /// Escalation events in chronological order.
    pub events: Vec<EscalationEventResponse>,

    /// Current escalation level (0 = not escalated).
    pub current_level: i32,

    /// Whether all escalation levels have been exhausted.
    pub levels_exhausted: bool,

    /// Total number of escalation events.
    pub total_escalations: usize,
}

// ============================================================================
// Cancel/Reset Escalation Models (T067-T070)
// ============================================================================

/// Response for cancel escalation operation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CancelEscalationResponse {
    /// Whether the cancellation was successful.
    pub success: bool,

    /// The escalation level that was active before cancellation.
    pub previous_level: i32,

    /// The user who currently has the work item (kept as assignee).
    pub current_assignee_id: Uuid,

    /// Message describing the result.
    pub message: String,
}

/// Response for reset escalation operation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ResetEscalationResponse {
    /// Whether the reset was successful.
    pub success: bool,

    /// The escalation level that was active before reset.
    pub previous_level: i32,

    /// The original approver who now has the work item.
    pub original_approver_id: Uuid,

    /// New deadline for the approval (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_deadline: Option<DateTime<Utc>>,

    /// Message describing the result.
    pub message: String,
}
