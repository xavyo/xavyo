//! Request and response models for SoD violation endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{GovSodViolation, GovViolationStatus};

/// Query parameters for listing SoD violations.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListSodViolationsQuery {
    /// Filter by rule ID.
    pub rule_id: Option<Uuid>,

    /// Filter by user ID.
    pub user_id: Option<Uuid>,

    /// Filter by violation status.
    pub status: Option<GovViolationStatus>,

    /// Filter violations detected after this timestamp.
    pub detected_after: Option<DateTime<Utc>>,

    /// Filter violations detected before this timestamp.
    pub detected_before: Option<DateTime<Utc>>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListSodViolationsQuery {
    fn default() -> Self {
        Self {
            rule_id: None,
            user_id: None,
            status: None,
            detected_after: None,
            detected_before: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// SoD violation response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SodViolationResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Violated rule ID.
    pub rule_id: Uuid,

    /// User with the conflict.
    pub user_id: Uuid,

    /// Assignment for first entitlement (may be null if deleted).
    pub first_assignment_id: Option<Uuid>,

    /// Assignment for second entitlement (may be null if deleted).
    pub second_assignment_id: Option<Uuid>,

    /// Violation status.
    pub status: GovViolationStatus,

    /// When the violation was detected.
    pub detected_at: DateTime<Utc>,

    /// When the violation was remediated (if applicable).
    pub remediated_at: Option<DateTime<Utc>>,

    /// Who remediated the violation (if applicable).
    pub remediated_by: Option<Uuid>,

    /// Notes about remediation.
    pub remediation_notes: Option<String>,

    /// Record creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl From<GovSodViolation> for SodViolationResponse {
    fn from(violation: GovSodViolation) -> Self {
        Self {
            id: violation.id,
            rule_id: violation.rule_id,
            user_id: violation.user_id,
            first_assignment_id: violation.first_assignment_id,
            second_assignment_id: violation.second_assignment_id,
            status: violation.status,
            detected_at: violation.detected_at,
            remediated_at: violation.remediated_at,
            remediated_by: violation.remediated_by,
            remediation_notes: violation.remediation_notes,
            created_at: violation.created_at,
            updated_at: violation.updated_at,
        }
    }
}

/// Paginated list of SoD violations.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SodViolationListResponse {
    /// List of violations.
    pub items: Vec<SodViolationResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

/// Request to remediate a violation.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct RemediateViolationRequest {
    /// Notes about the remediation action.
    #[validate(length(max = 2000, message = "Notes must not exceed 2000 characters"))]
    pub notes: Option<String>,
}

/// Violation with enriched rule information.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SodViolationDetailResponse {
    /// Violation details.
    #[serde(flatten)]
    pub violation: SodViolationResponse,

    /// Rule name.
    pub rule_name: String,

    /// Rule severity.
    pub rule_severity: String,

    /// Rule description.
    pub rule_description: Option<String>,
}

/// Summary statistics for violations.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ViolationSummary {
    /// Total active violations.
    pub active_count: i64,

    /// Total exempted violations.
    pub exempted_count: i64,

    /// Total remediated violations.
    pub remediated_count: i64,

    /// Breakdown by severity.
    pub by_severity: ViolationBySeverity,
}

/// Violation counts by severity level.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ViolationBySeverity {
    /// Critical severity violations.
    pub critical: i64,

    /// High severity violations.
    pub high: i64,

    /// Medium severity violations.
    pub medium: i64,

    /// Low severity violations.
    pub low: i64,
}
