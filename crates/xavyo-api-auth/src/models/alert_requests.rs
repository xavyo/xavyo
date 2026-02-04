//! Request and response types for security alert endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// Query parameters for user security alerts.
#[derive(Debug, Deserialize, IntoParams)]
pub struct SecurityAlertsQuery {
    /// Pagination cursor (`created_at` timestamp).
    pub cursor: Option<DateTime<Utc>>,
    /// Number of items per page (max 100).
    #[serde(default = "default_limit")]
    pub limit: i32,
    /// Filter by alert type.
    #[serde(rename = "type")]
    pub alert_type: Option<String>,
    /// Filter by severity.
    pub severity: Option<String>,
    /// Filter by acknowledgment status.
    pub acknowledged: Option<bool>,
}

fn default_limit() -> i32 {
    20
}

/// Response for a single security alert.
#[derive(Debug, Serialize, ToSchema)]
pub struct SecurityAlertResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub alert_type: String,
    pub severity: String,
    pub title: String,
    pub message: String,
    pub metadata: JsonValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl From<xavyo_db::SecurityAlert> for SecurityAlertResponse {
    fn from(alert: xavyo_db::SecurityAlert) -> Self {
        Self {
            id: alert.id,
            user_id: alert.user_id,
            alert_type: alert.alert_type,
            severity: alert.severity,
            title: alert.title,
            message: alert.message,
            metadata: alert.metadata,
            acknowledged_at: alert.acknowledged_at,
            created_at: alert.created_at,
        }
    }
}

/// Response for paginated security alerts.
#[derive(Debug, Serialize, ToSchema)]
pub struct SecurityAlertsResponse {
    pub items: Vec<SecurityAlertResponse>,
    pub total: i64,
    pub unacknowledged_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<DateTime<Utc>>,
}
