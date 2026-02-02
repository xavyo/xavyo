//! Request and response models for orphan detection endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{DetectionReason, GovOrphanDetection, OrphanStatus, RemediationAction};

// =============================================================================
// Orphan Detection Models
// =============================================================================

/// Orphan detection response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OrphanDetectionResponse {
    /// Detection ID.
    pub id: Uuid,

    /// The user identified as orphan.
    pub user_id: Uuid,

    /// The reconciliation run that detected this.
    pub run_id: Uuid,

    /// Why this user was flagged.
    pub detection_reason: DetectionReason,

    /// Current status.
    pub status: OrphanStatus,

    /// When this orphan was detected.
    pub detected_at: DateTime<Utc>,

    /// Last activity time for the user (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_activity_at: Option<DateTime<Utc>>,

    /// Days since last activity (for inactive detection).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_inactive: Option<i32>,

    /// Remediation action taken (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation_action: Option<RemediationAction>,

    /// Who performed the remediation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation_by: Option<Uuid>,

    /// When remediation was performed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation_at: Option<DateTime<Utc>>,

    /// Notes or justification for remediation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation_notes: Option<String>,

    /// New owner for reassignment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_owner_id: Option<Uuid>,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl From<GovOrphanDetection> for OrphanDetectionResponse {
    fn from(detection: GovOrphanDetection) -> Self {
        Self {
            id: detection.id,
            user_id: detection.user_id,
            run_id: detection.run_id,
            detection_reason: detection.detection_reason,
            status: detection.status,
            detected_at: detection.detected_at,
            last_activity_at: detection.last_activity_at,
            days_inactive: detection.days_inactive,
            remediation_action: detection.remediation_action,
            remediation_by: detection.remediation_by,
            remediation_at: detection.remediation_at,
            remediation_notes: detection.remediation_notes.clone(),
            new_owner_id: detection.new_owner_id,
            created_at: detection.created_at,
            updated_at: detection.updated_at,
        }
    }
}

/// Query parameters for listing orphan detections.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListOrphanDetectionsQuery {
    /// Filter by status.
    pub status: Option<OrphanStatus>,

    /// Filter by detection reason.
    pub reason: Option<DetectionReason>,

    /// Filter by reconciliation run.
    pub run_id: Option<Uuid>,

    /// Filter by user.
    pub user_id: Option<Uuid>,

    /// Filter detections since this date.
    pub since: Option<DateTime<Utc>>,

    /// Filter detections until this date.
    pub until: Option<DateTime<Utc>>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListOrphanDetectionsQuery {
    fn default() -> Self {
        Self {
            status: None,
            reason: None,
            run_id: None,
            user_id: None,
            since: None,
            until: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Paginated list of orphan detections.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OrphanDetectionListResponse {
    /// List of detections.
    pub items: Vec<OrphanDetectionResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

/// Summary of orphan detections.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OrphanSummaryResponse {
    /// Count of pending orphans.
    pub total_pending: i64,

    /// Count of orphans under review.
    pub total_under_review: i64,

    /// Count of remediated orphans.
    pub total_remediated: i64,

    /// Count of dismissed orphans.
    pub total_dismissed: i64,

    /// Breakdown by detection reason.
    pub by_reason: ReasonBreakdown,

    /// Average age in days of pending orphans.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub average_age_days: Option<f64>,
}

/// Breakdown of orphan counts by detection reason.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReasonBreakdown {
    /// Orphans with no manager.
    pub no_manager: i64,

    /// Terminated employees.
    pub terminated_employee: i64,

    /// Inactive users.
    pub inactive: i64,

    /// HR data mismatches.
    pub hr_mismatch: i64,
}

// =============================================================================
// Remediation Request Models
// =============================================================================

/// Request to reassign an orphan to a new owner.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ReassignOrphanRequest {
    /// The new owner/manager ID.
    pub new_owner_id: Uuid,

    /// Justification for the reassignment.
    #[validate(length(min = 10, message = "Notes must be at least 10 characters"))]
    #[serde(default)]
    pub notes: Option<String>,
}

/// Request to disable an orphan account.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DisableOrphanRequest {
    /// Justification for disabling.
    #[serde(default)]
    pub notes: Option<String>,
}

/// Request to request deletion of an orphan account.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct DeleteOrphanRequest {
    /// Justification for deletion.
    #[validate(length(min = 20, message = "Justification must be at least 20 characters"))]
    pub justification: String,
}

/// Response for delete request (may need approval).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DeleteOrphanResponse {
    /// Updated orphan detection.
    pub detection: OrphanDetectionResponse,

    /// Whether deletion requires approval.
    pub requires_approval: bool,

    /// Access request ID if approval is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_request_id: Option<Uuid>,
}

/// Request to dismiss an orphan detection as false positive.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct DismissOrphanRequest {
    /// Justification for dismissal.
    #[validate(length(min = 10, message = "Justification must be at least 10 characters"))]
    pub justification: String,
}

/// Request for bulk remediation of orphans.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct BulkRemediateRequest {
    /// Detection IDs to remediate.
    #[validate(length(min = 1, max = 100, message = "Must provide 1-100 detection IDs"))]
    pub detection_ids: Vec<Uuid>,

    /// Action to perform.
    pub action: BulkRemediationAction,

    /// Justification for the bulk action.
    #[validate(length(min = 10, message = "Justification must be at least 10 characters"))]
    pub justification: String,

    /// New owner ID (required for reassign action).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_owner_id: Option<Uuid>,
}

/// Actions available for bulk remediation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BulkRemediationAction {
    /// Disable all specified accounts.
    Disable,
    /// Dismiss all as false positives.
    Dismiss,
    /// Reassign all to new owner.
    Reassign,
}

/// Response for bulk remediation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BulkRemediateResponse {
    /// Number of successful remediations.
    pub succeeded: i64,

    /// Number of failed remediations.
    pub failed: i64,

    /// Details of failures.
    pub errors: Vec<BulkRemediationError>,
}

/// Individual error in bulk remediation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BulkRemediationError {
    /// Detection ID that failed.
    pub detection_id: Uuid,

    /// Error message.
    pub error: String,
}

// =============================================================================
// Report Models
// =============================================================================

/// Age analysis of orphan accounts.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OrphanAgeAnalysis {
    /// Orphans detected within last 7 days.
    pub under_7_days: i64,

    /// Orphans detected 7-30 days ago.
    pub from_7_to_30_days: i64,

    /// Orphans detected 30-90 days ago.
    pub from_30_to_90_days: i64,

    /// Orphans detected more than 90 days ago.
    pub over_90_days: i64,

    /// Average age in days.
    pub average_age_days: f64,

    /// Median age in days.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub median_age_days: Option<f64>,
}

/// Risk assessment of orphan accounts.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OrphanRiskReport {
    /// Total orphan count.
    pub total_orphans: i64,

    /// High-risk orphans (e.g., with sensitive entitlements).
    pub high_risk: i64,

    /// Medium-risk orphans.
    pub medium_risk: i64,

    /// Low-risk orphans.
    pub low_risk: i64,

    /// Orphans with active sessions.
    pub with_active_sessions: i64,

    /// Orphans with recent activity.
    pub with_recent_activity: i64,

    /// Top high-risk orphans.
    pub high_risk_details: Vec<HighRiskOrphan>,
}

/// Details of a high-risk orphan.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HighRiskOrphan {
    /// Detection ID.
    pub detection_id: Uuid,

    /// User ID.
    pub user_id: Uuid,

    /// Detection reason.
    pub reason: DetectionReason,

    /// Risk score (from F039 if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<i32>,

    /// Number of sensitive entitlements.
    pub sensitive_entitlements: i32,

    /// Days since detection.
    pub days_since_detection: i32,
}
