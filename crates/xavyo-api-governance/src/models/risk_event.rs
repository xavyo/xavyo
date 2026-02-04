//! Request and response models for risk event endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::GovRiskEvent;

/// Request to create a risk event.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateRiskEventRequest {
    /// User ID for the event.
    pub user_id: Uuid,

    /// Associated risk factor ID (optional).
    pub factor_id: Option<Uuid>,

    /// Event type identifier.
    #[validate(length(min = 1, max = 50, message = "Event type must be 1-50 characters"))]
    pub event_type: String,

    /// Event magnitude/value (default: 1.0).
    #[validate(range(min = 0.0, message = "Value must be non-negative"))]
    pub value: Option<f64>,

    /// Reference to source (e.g., `login_id`).
    #[validate(length(max = 255, message = "Source ref must not exceed 255 characters"))]
    pub source_ref: Option<String>,

    /// When the event expires (optional).
    pub expires_at: Option<DateTime<Utc>>,
}

/// Query parameters for listing risk events.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListRiskEventsQuery {
    /// Filter by event type.
    pub event_type: Option<String>,

    /// Filter by factor ID.
    pub factor_id: Option<Uuid>,

    /// Include expired events.
    #[serde(default)]
    pub include_expired: bool,

    /// Maximum number of results (default: 50, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListRiskEventsQuery {
    fn default() -> Self {
        Self {
            event_type: None,
            factor_id: None,
            include_expired: false,
            limit: Some(50),
            offset: Some(0),
        }
    }
}

/// Risk event response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RiskEventResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// User ID.
    pub user_id: Uuid,

    /// Associated factor ID.
    pub factor_id: Option<Uuid>,

    /// Event type.
    pub event_type: String,

    /// Event value.
    pub value: f64,

    /// Source reference.
    pub source_ref: Option<String>,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Expiration timestamp.
    pub expires_at: Option<DateTime<Utc>>,
}

impl From<GovRiskEvent> for RiskEventResponse {
    fn from(e: GovRiskEvent) -> Self {
        Self {
            id: e.id,
            user_id: e.user_id,
            factor_id: e.factor_id,
            event_type: e.event_type,
            value: e.value,
            source_ref: e.source_ref,
            created_at: e.created_at,
            expires_at: e.expires_at,
        }
    }
}

/// Paginated list of risk events.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RiskEventListResponse {
    /// List of events.
    pub items: Vec<RiskEventResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

/// Response for cleaning up expired events.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CleanupEventsResponse {
    /// Number of events deleted.
    pub deleted_count: u64,
}
