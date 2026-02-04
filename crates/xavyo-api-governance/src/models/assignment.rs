//! Assignment request/response models for governance API.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

use xavyo_db::models::{
    BulkAssignmentFailure, BulkAssignmentResult, GovAssignmentStatus, GovAssignmentTargetType,
    GovEntitlementAssignment,
};

/// Request to create a new assignment.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateAssignmentRequest {
    /// The entitlement to assign.
    pub entitlement_id: Uuid,

    /// The type of target (user or group).
    pub target_type: GovAssignmentTargetType,

    /// The target ID (`user_id` or `group_id`).
    pub target_id: Uuid,

    /// When the assignment expires (optional).
    pub expires_at: Option<DateTime<Utc>>,

    /// Business justification for the assignment.
    #[validate(length(max = 2000, message = "Justification cannot exceed 2000 characters"))]
    pub justification: Option<String>,
}

/// Request to create multiple assignments at once.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct BulkCreateAssignmentsRequest {
    /// The entitlement to assign.
    pub entitlement_id: Uuid,

    /// The type of target (user or group).
    pub target_type: GovAssignmentTargetType,

    /// The target IDs (`user_ids` or `group_ids`).
    #[validate(length(min = 1, max = 100, message = "Must have between 1 and 100 targets"))]
    pub target_ids: Vec<Uuid>,

    /// When the assignments expire (optional).
    pub expires_at: Option<DateTime<Utc>>,

    /// Business justification for the assignments.
    #[validate(length(max = 2000, message = "Justification cannot exceed 2000 characters"))]
    pub justification: Option<String>,
}

/// Query parameters for listing assignments.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListAssignmentsQuery {
    /// Filter by entitlement ID.
    pub entitlement_id: Option<Uuid>,

    /// Filter by target type.
    pub target_type: Option<GovAssignmentTargetType>,

    /// Filter by target ID.
    pub target_id: Option<Uuid>,

    /// Filter by status.
    pub status: Option<GovAssignmentStatus>,

    /// Maximum number of results to return.
    #[serde(default = "default_limit")]
    pub limit: i64,

    /// Number of results to skip.
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

/// Assignment response model.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AssignmentResponse {
    /// Unique identifier for the assignment.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// The entitlement being assigned.
    pub entitlement_id: Uuid,

    /// The type of target (user or group).
    pub target_type: GovAssignmentTargetType,

    /// The target ID (`user_id` or `group_id`).
    pub target_id: Uuid,

    /// Who assigned this entitlement.
    pub assigned_by: Uuid,

    /// When the assignment was made.
    pub assigned_at: DateTime<Utc>,

    /// When the assignment expires (optional).
    pub expires_at: Option<DateTime<Utc>>,

    /// Assignment status.
    pub status: GovAssignmentStatus,

    /// Business justification for the assignment.
    pub justification: Option<String>,

    /// When the assignment was created.
    pub created_at: DateTime<Utc>,

    /// When the assignment was last updated.
    pub updated_at: DateTime<Utc>,
}

impl From<GovEntitlementAssignment> for AssignmentResponse {
    fn from(asg: GovEntitlementAssignment) -> Self {
        Self {
            id: asg.id,
            tenant_id: asg.tenant_id,
            entitlement_id: asg.entitlement_id,
            target_type: asg.target_type,
            target_id: asg.target_id,
            assigned_by: asg.assigned_by,
            assigned_at: asg.assigned_at,
            expires_at: asg.expires_at,
            status: asg.status,
            justification: asg.justification,
            created_at: asg.created_at,
            updated_at: asg.updated_at,
        }
    }
}

/// Paginated list of assignments.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AssignmentListResponse {
    /// List of assignments.
    pub items: Vec<AssignmentResponse>,

    /// Total count of matching assignments.
    pub total: i64,

    /// Maximum number of results returned.
    pub limit: i64,

    /// Number of results skipped.
    pub offset: i64,
}

/// Bulk assignment failure detail.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BulkAssignmentFailureResponse {
    /// The target ID that failed.
    pub target_id: Uuid,

    /// The reason for the failure.
    pub reason: String,
}

impl From<BulkAssignmentFailure> for BulkAssignmentFailureResponse {
    fn from(failure: BulkAssignmentFailure) -> Self {
        Self {
            target_id: failure.target_id,
            reason: failure.reason,
        }
    }
}

/// Response for bulk assignment creation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BulkAssignmentResponse {
    /// IDs of successfully created assignments.
    pub successful: Vec<Uuid>,

    /// Details of failed assignments.
    pub failed: Vec<BulkAssignmentFailureResponse>,

    /// Total number of targets processed.
    pub total_processed: usize,

    /// Number of successful assignments.
    pub success_count: usize,

    /// Number of failed assignments.
    pub failure_count: usize,
}

impl From<BulkAssignmentResult> for BulkAssignmentResponse {
    fn from(result: BulkAssignmentResult) -> Self {
        let success_count = result.successful.len();
        let failure_count = result.failed.len();
        Self {
            successful: result.successful,
            failed: result.failed.into_iter().map(Into::into).collect(),
            total_processed: success_count + failure_count,
            success_count,
            failure_count,
        }
    }
}
