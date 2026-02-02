//! Request and response models for risk alert endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use xavyo_db::{AlertSeverity, GovRiskAlert};

/// Query parameters for listing risk alerts.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListRiskAlertsQuery {
    /// Filter by user ID.
    pub user_id: Option<Uuid>,

    /// Filter by threshold ID.
    pub threshold_id: Option<Uuid>,

    /// Filter by severity.
    pub severity: Option<AlertSeverity>,

    /// Filter by acknowledged status.
    pub acknowledged: Option<bool>,

    /// Sort order.
    pub sort_by: Option<RiskAlertSortOption>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

/// Sort options for risk alerts.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RiskAlertSortOption {
    /// Sort by creation time descending.
    #[default]
    CreatedAtDesc,
    /// Sort by creation time ascending.
    CreatedAtAsc,
    /// Sort by severity descending.
    SeverityDesc,
    /// Sort by score descending.
    ScoreDesc,
}

impl Default for ListRiskAlertsQuery {
    fn default() -> Self {
        Self {
            user_id: None,
            threshold_id: None,
            severity: None,
            acknowledged: None,
            sort_by: Some(RiskAlertSortOption::CreatedAtDesc),
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Risk alert response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RiskAlertResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// User who triggered the alert.
    pub user_id: Uuid,

    /// Threshold that was exceeded.
    pub threshold_id: Uuid,

    /// Score at time of alert.
    pub score_at_alert: i32,

    /// Alert severity.
    pub severity: AlertSeverity,

    /// Whether acknowledged.
    pub acknowledged: bool,

    /// User who acknowledged.
    pub acknowledged_by: Option<Uuid>,

    /// Acknowledgement timestamp.
    pub acknowledged_at: Option<DateTime<Utc>>,

    /// Alert creation timestamp.
    pub created_at: DateTime<Utc>,
}

impl From<GovRiskAlert> for RiskAlertResponse {
    fn from(a: GovRiskAlert) -> Self {
        Self {
            id: a.id,
            user_id: a.user_id,
            threshold_id: a.threshold_id,
            score_at_alert: a.score_at_alert,
            severity: a.severity,
            acknowledged: a.acknowledged,
            acknowledged_by: a.acknowledged_by,
            acknowledged_at: a.acknowledged_at,
            created_at: a.created_at,
        }
    }
}

/// Paginated list of risk alerts.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RiskAlertListResponse {
    /// List of alerts.
    pub items: Vec<RiskAlertResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

/// Alert summary by severity.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AlertSummary {
    /// Unacknowledged alerts by severity.
    pub unacknowledged: Vec<SeverityCount>,

    /// Total unacknowledged count.
    pub total_unacknowledged: i64,
}

/// Count per severity level.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SeverityCount {
    /// Severity level.
    pub severity: AlertSeverity,

    /// Count of alerts.
    pub count: i64,
}

/// Response for acknowledging an alert.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AcknowledgeAlertResponse {
    /// Alert that was acknowledged.
    pub alert: RiskAlertResponse,
}

/// Response for bulk acknowledgement.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BulkAcknowledgeResponse {
    /// Number of alerts acknowledged.
    pub acknowledged_count: u64,
}
