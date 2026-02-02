//! Request and response models for risk threshold endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{AlertSeverity, GovRiskThreshold, ThresholdAction};

/// Request to create a new risk threshold.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateRiskThresholdRequest {
    /// Display name for the threshold.
    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))]
    pub name: String,

    /// Score value that triggers this threshold (1-100).
    #[validate(range(min = 1, max = 100, message = "Score must be between 1 and 100"))]
    pub score_value: i32,

    /// Alert severity when triggered.
    pub severity: AlertSeverity,

    /// Action to take when triggered.
    pub action: Option<ThresholdAction>,

    /// Hours between re-alerts for same user (1-720).
    #[validate(range(
        min = 1,
        max = 720,
        message = "Cooldown hours must be between 1 and 720"
    ))]
    pub cooldown_hours: Option<i32>,

    /// Whether the threshold is enabled (default: true).
    pub is_enabled: Option<bool>,
}

/// Request to update an existing risk threshold.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateRiskThresholdRequest {
    /// Updated display name.
    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))]
    pub name: Option<String>,

    /// Updated score value (1-100).
    #[validate(range(min = 1, max = 100, message = "Score must be between 1 and 100"))]
    pub score_value: Option<i32>,

    /// Updated severity.
    pub severity: Option<AlertSeverity>,

    /// Updated action.
    pub action: Option<ThresholdAction>,

    /// Updated cooldown hours.
    #[validate(range(
        min = 1,
        max = 720,
        message = "Cooldown hours must be between 1 and 720"
    ))]
    pub cooldown_hours: Option<i32>,

    /// Updated enabled status.
    pub is_enabled: Option<bool>,
}

/// Query parameters for listing risk thresholds.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListRiskThresholdsQuery {
    /// Filter by severity.
    pub severity: Option<AlertSeverity>,

    /// Filter by action type.
    pub action: Option<ThresholdAction>,

    /// Filter by enabled status.
    pub is_enabled: Option<bool>,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListRiskThresholdsQuery {
    fn default() -> Self {
        Self {
            severity: None,
            action: None,
            is_enabled: None,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Risk threshold response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RiskThresholdResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Display name.
    pub name: String,

    /// Score value that triggers.
    pub score_value: i32,

    /// Alert severity.
    pub severity: AlertSeverity,

    /// Action to take.
    pub action: ThresholdAction,

    /// Cooldown hours.
    pub cooldown_hours: i32,

    /// Whether enabled.
    pub is_enabled: bool,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl From<GovRiskThreshold> for RiskThresholdResponse {
    fn from(t: GovRiskThreshold) -> Self {
        Self {
            id: t.id,
            name: t.name,
            score_value: t.score_value,
            severity: t.severity,
            action: t.action,
            cooldown_hours: t.cooldown_hours,
            is_enabled: t.is_enabled,
            created_at: t.created_at,
            updated_at: t.updated_at,
        }
    }
}

/// Paginated list of risk thresholds.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RiskThresholdListResponse {
    /// List of thresholds.
    pub items: Vec<RiskThresholdResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}
