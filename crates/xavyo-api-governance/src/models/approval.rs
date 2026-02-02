//! Request and response models for approval endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{GovApprovalDecision, GovDecisionType, GovRequestStatus, GovSodSeverity};

/// Request to approve an access request.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ApproveRequestRequest {
    /// Optional comments from the approver.
    #[validate(length(max = 2000, message = "Comments must not exceed 2000 characters"))]
    pub comments: Option<String>,
}

/// Request to reject an access request.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct RejectRequestRequest {
    /// Required comments explaining the rejection.
    #[validate(length(
        min = 1,
        max = 2000,
        message = "Comments are required (1-2000 characters)"
    ))]
    pub comments: String,
}

/// Query parameters for listing pending approvals.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListPendingApprovalsQuery {
    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListPendingApprovalsQuery {
    fn default() -> Self {
        Self {
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// A pending approval item.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PendingApprovalItem {
    /// Access request ID.
    pub request_id: Uuid,

    /// Requester user ID.
    pub requester_id: Uuid,

    /// Requester display name (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requester_name: Option<String>,

    /// Entitlement ID.
    pub entitlement_id: Uuid,

    /// Entitlement name.
    pub entitlement_name: String,

    /// Business justification.
    pub justification: String,

    /// Current step in the workflow.
    pub current_step: i32,

    /// Total steps in the workflow.
    pub total_steps: i32,

    /// Whether SoD violations were detected.
    pub has_sod_warning: bool,

    /// SoD violation summaries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sod_warnings: Option<Vec<SodWarningSummary>>,

    /// Whether this is a delegated approval.
    pub is_delegate: bool,

    /// Original approver (if delegated).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegator_id: Option<Uuid>,

    /// When the request was submitted.
    pub submitted_at: DateTime<Utc>,

    /// Previous decisions in this request.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub previous_decisions: Vec<DecisionSummary>,
}

/// Summary of an SoD warning for approver review.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SodWarningSummary {
    /// Rule name.
    pub rule_name: String,

    /// Severity level.
    pub severity: GovSodSeverity,

    /// Conflicting entitlement name.
    pub conflicting_entitlement_name: String,
}

/// Summary of a previous decision.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DecisionSummary {
    /// Step this decision was for.
    pub step_order: i32,

    /// Decision type.
    pub decision: GovDecisionType,

    /// Approver ID.
    pub approver_id: Uuid,

    /// Approver name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approver_name: Option<String>,

    /// Comments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comments: Option<String>,

    /// When the decision was made.
    pub decided_at: DateTime<Utc>,
}

impl From<GovApprovalDecision> for DecisionSummary {
    fn from(decision: GovApprovalDecision) -> Self {
        Self {
            step_order: decision.step_order,
            decision: decision.decision,
            approver_id: decision.approver_id,
            approver_name: None, // To be populated by service
            comments: decision.comments,
            decided_at: decision.decided_at,
        }
    }
}

/// Paginated list of pending approvals.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PendingApprovalListResponse {
    /// List of pending approval items.
    pub items: Vec<PendingApprovalItem>,

    /// Total count.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

/// Response after an approval/rejection action.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApprovalActionResponse {
    /// Request ID.
    pub request_id: Uuid,

    /// New status after the action.
    pub new_status: GovRequestStatus,

    /// Decision that was recorded.
    pub decision: GovDecisionType,

    /// Message about the action.
    pub message: String,

    /// Assignment ID if provisioned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provisioned_assignment_id: Option<Uuid>,
}
