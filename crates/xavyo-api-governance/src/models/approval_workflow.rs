//! Request and response models for approval workflow endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{GovApprovalStep, GovApprovalWorkflow, GovApproverType};

/// Request to create a new approval workflow.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateApprovalWorkflowRequest {
    /// Display name for the workflow.
    #[validate(length(min = 1, max = 255, message = "Name must be 1-255 characters"))]
    pub name: String,

    /// Optional description.
    #[validate(length(max = 1000, message = "Description must not exceed 1000 characters"))]
    pub description: Option<String>,

    /// Whether this should be the default workflow.
    #[serde(default)]
    pub is_default: bool,

    /// Approval steps (1-5 required).
    #[validate(length(min = 1, max = 5, message = "Workflow must have 1-5 steps"))]
    pub steps: Vec<CreateApprovalStepRequest>,
}

/// Request to create an approval step.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateApprovalStepRequest {
    /// Type of approver for this step.
    pub approver_type: GovApproverType,

    /// Specific approver user IDs (required for SpecificUsers type).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub specific_approvers: Option<Vec<Uuid>>,
}

/// Request to update an existing workflow.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateApprovalWorkflowRequest {
    /// Updated display name.
    #[validate(length(min = 1, max = 255, message = "Name must be 1-255 characters"))]
    pub name: Option<String>,

    /// Updated description.
    #[validate(length(max = 1000, message = "Description must not exceed 1000 characters"))]
    pub description: Option<String>,

    /// Whether this should be the default workflow.
    pub is_default: Option<bool>,

    /// Whether the workflow is active.
    pub is_active: Option<bool>,

    /// Updated steps (replaces all existing steps if provided).
    #[validate(length(min = 1, max = 5, message = "Workflow must have 1-5 steps"))]
    pub steps: Option<Vec<CreateApprovalStepRequest>>,
}

/// Query parameters for listing workflows.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListWorkflowsQuery {
    /// Filter by active status.
    pub is_active: Option<bool>,

    /// Filter by default status.
    pub is_default: Option<bool>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListWorkflowsQuery {
    fn default() -> Self {
        Self {
            is_active: None,
            is_default: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Approval step response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApprovalStepResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Order in the approval chain.
    pub step_order: i32,

    /// Type of approver.
    pub approver_type: GovApproverType,

    /// Specific approver user IDs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub specific_approvers: Option<Vec<Uuid>>,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

impl From<GovApprovalStep> for ApprovalStepResponse {
    fn from(step: GovApprovalStep) -> Self {
        Self {
            id: step.id,
            step_order: step.step_order,
            approver_type: step.approver_type,
            specific_approvers: step.specific_approvers,
            created_at: step.created_at,
        }
    }
}

/// Approval workflow response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApprovalWorkflowResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Display name.
    pub name: String,

    /// Optional description.
    pub description: Option<String>,

    /// Whether this is the default workflow.
    pub is_default: bool,

    /// Whether the workflow is active.
    pub is_active: bool,

    /// Approval steps.
    pub steps: Vec<ApprovalStepResponse>,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl ApprovalWorkflowResponse {
    /// Create response from workflow and steps.
    pub fn from_workflow_and_steps(
        workflow: GovApprovalWorkflow,
        steps: Vec<GovApprovalStep>,
    ) -> Self {
        Self {
            id: workflow.id,
            name: workflow.name,
            description: workflow.description,
            is_default: workflow.is_default,
            is_active: workflow.is_active,
            steps: steps.into_iter().map(ApprovalStepResponse::from).collect(),
            created_at: workflow.created_at,
            updated_at: workflow.updated_at,
        }
    }
}

/// Workflow summary for list views.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApprovalWorkflowSummary {
    /// Unique identifier.
    pub id: Uuid,

    /// Display name.
    pub name: String,

    /// Optional description.
    pub description: Option<String>,

    /// Whether this is the default workflow.
    pub is_default: bool,

    /// Whether the workflow is active.
    pub is_active: bool,

    /// Number of steps.
    pub step_count: i32,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Paginated list of workflows.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApprovalWorkflowListResponse {
    /// List of workflows.
    pub items: Vec<ApprovalWorkflowSummary>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}
