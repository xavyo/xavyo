//! Request and response models for access request endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{GovAccessRequest, GovRequestStatus, GovSodSeverity};

/// Request to submit a new access request.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateAccessRequestRequest {
    /// ID of the entitlement being requested.
    pub entitlement_id: Uuid,

    /// Business justification for the request (minimum 20 characters).
    #[validate(length(min = 20, message = "Justification must be at least 20 characters"))]
    pub justification: String,

    /// Optional requested access expiration date.
    pub requested_expires_at: Option<DateTime<Utc>>,
}

/// Query parameters for listing access requests.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListAccessRequestsQuery {
    /// Filter by entitlement ID.
    pub entitlement_id: Option<Uuid>,

    /// Filter by status.
    pub status: Option<GovRequestStatus>,

    /// Filter by SoD warning presence.
    pub has_sod_warning: Option<bool>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListAccessRequestsQuery {
    fn default() -> Self {
        Self {
            entitlement_id: None,
            status: None,
            has_sod_warning: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Access request response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AccessRequestResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// User who submitted the request.
    pub requester_id: Uuid,

    /// Entitlement being requested.
    pub entitlement_id: Uuid,

    /// Workflow used for approval.
    pub workflow_id: Option<Uuid>,

    /// Current step in approval chain.
    pub current_step: i32,

    /// Request status.
    pub status: GovRequestStatus,

    /// Business justification.
    pub justification: String,

    /// Requested access expiration.
    pub requested_expires_at: Option<DateTime<Utc>>,

    /// Whether SoD violations were detected.
    pub has_sod_warning: bool,

    /// SoD violation details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sod_violations: Option<Vec<SodViolationSummary>>,

    /// Assignment ID after provisioning.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provisioned_assignment_id: Option<Uuid>,

    /// When the request was submitted.
    pub created_at: DateTime<Utc>,

    /// When the request was last updated.
    pub updated_at: DateTime<Utc>,

    /// When the request expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Summary of an SoD violation for display.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SodViolationSummary {
    /// Rule that would be violated.
    pub rule_id: Uuid,

    /// Rule name.
    pub rule_name: String,

    /// Severity level.
    pub severity: GovSodSeverity,

    /// Conflicting entitlement.
    pub conflicting_entitlement_id: Uuid,
}

impl From<GovAccessRequest> for AccessRequestResponse {
    fn from(request: GovAccessRequest) -> Self {
        let sod_violations: Option<Vec<SodViolationSummary>> = request
            .sod_violations
            .as_ref()
            .and_then(|v| serde_json::from_value::<Vec<SodViolationSummary>>(v.clone()).ok());

        Self {
            id: request.id,
            requester_id: request.requester_id,
            entitlement_id: request.entitlement_id,
            workflow_id: request.workflow_id,
            current_step: request.current_step,
            status: request.status,
            justification: request.justification,
            requested_expires_at: request.requested_expires_at,
            has_sod_warning: request.has_sod_warning,
            sod_violations,
            provisioned_assignment_id: request.provisioned_assignment_id,
            created_at: request.created_at,
            updated_at: request.updated_at,
            expires_at: request.expires_at,
        }
    }
}

/// Paginated list of access requests.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AccessRequestListResponse {
    /// List of requests.
    pub items: Vec<AccessRequestResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

/// Response when creating an access request.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AccessRequestCreatedResponse {
    /// The created request.
    #[serde(flatten)]
    pub request: AccessRequestResponse,

    /// Message about SoD warnings if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sod_warning_message: Option<String>,
}
