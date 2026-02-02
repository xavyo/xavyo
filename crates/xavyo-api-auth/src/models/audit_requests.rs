//! Request and response types for audit endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// Query parameters for user login history.
#[derive(Debug, Deserialize, IntoParams)]
pub struct LoginHistoryQuery {
    /// Pagination cursor (created_at timestamp).
    pub cursor: Option<DateTime<Utc>>,
    /// Number of items per page (max 100).
    #[serde(default = "default_limit")]
    pub limit: i32,
    /// Filter by date range start.
    pub start_date: Option<DateTime<Utc>>,
    /// Filter by date range end.
    pub end_date: Option<DateTime<Utc>>,
    /// Filter by success status.
    pub success: Option<bool>,
}

fn default_limit() -> i32 {
    20
}

/// Query parameters for admin login attempts.
#[derive(Debug, Deserialize, IntoParams)]
pub struct AdminLoginAttemptsQuery {
    /// Pagination cursor.
    pub cursor: Option<DateTime<Utc>>,
    /// Number of items per page.
    #[serde(default = "default_limit")]
    pub limit: i32,
    /// Filter by user ID.
    pub user_id: Option<Uuid>,
    /// Filter by email (partial match).
    pub email: Option<String>,
    /// Filter by date range start.
    pub start_date: Option<DateTime<Utc>>,
    /// Filter by date range end.
    pub end_date: Option<DateTime<Utc>>,
    /// Filter by success status.
    pub success: Option<bool>,
    /// Filter by authentication method.
    pub auth_method: Option<String>,
}

/// Query parameters for login attempt statistics.
#[derive(Debug, Deserialize, IntoParams)]
pub struct LoginAttemptStatsQuery {
    /// Start date for statistics (required).
    pub start_date: DateTime<Utc>,
    /// End date for statistics (required).
    pub end_date: DateTime<Utc>,
}

/// Response for a single login attempt.
#[derive(Debug, Serialize, ToSchema)]
pub struct LoginAttemptResponse {
    pub id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Uuid>,
    pub email: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    pub auth_method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo_city: Option<String>,
    pub is_new_device: bool,
    pub is_new_location: bool,
    pub created_at: DateTime<Utc>,
}

impl From<xavyo_db::LoginAttempt> for LoginAttemptResponse {
    fn from(attempt: xavyo_db::LoginAttempt) -> Self {
        Self {
            id: attempt.id,
            user_id: attempt.user_id,
            email: attempt.email,
            success: attempt.success,
            failure_reason: attempt.failure_reason,
            auth_method: attempt.auth_method,
            ip_address: attempt.ip_address,
            user_agent: attempt.user_agent,
            device_fingerprint: attempt.device_fingerprint,
            geo_country: attempt.geo_country,
            geo_city: attempt.geo_city,
            is_new_device: attempt.is_new_device,
            is_new_location: attempt.is_new_location,
            created_at: attempt.created_at,
        }
    }
}

/// Response for paginated login history.
#[derive(Debug, Serialize, ToSchema)]
pub struct LoginHistoryResponse {
    pub items: Vec<LoginAttemptResponse>,
    pub total: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<DateTime<Utc>>,
}

/// Response for admin login attempts.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminLoginAttemptsResponse {
    pub items: Vec<LoginAttemptResponse>,
    pub total: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<DateTime<Utc>>,
}

/// Count of a specific failure reason.
#[derive(Debug, Serialize, ToSchema)]
pub struct FailureReasonCount {
    pub reason: String,
    pub count: i64,
}

/// Count of attempts for a specific hour.
#[derive(Debug, Serialize, ToSchema)]
pub struct HourlyCount {
    pub hour: i32,
    pub count: i64,
}

/// Response for login attempt statistics.
#[derive(Debug, Serialize, ToSchema)]
pub struct LoginAttemptStatsResponse {
    pub total_attempts: i64,
    pub successful_attempts: i64,
    pub failed_attempts: i64,
    pub success_rate: f64,
    pub failure_reasons: Vec<FailureReasonCount>,
    pub hourly_distribution: Vec<HourlyCount>,
    pub unique_users: i64,
    pub new_device_logins: i64,
    pub new_location_logins: i64,
}

impl From<crate::services::audit_service::LoginAttemptStats> for LoginAttemptStatsResponse {
    fn from(stats: crate::services::audit_service::LoginAttemptStats) -> Self {
        Self {
            total_attempts: stats.total_attempts,
            successful_attempts: stats.successful_attempts,
            failed_attempts: stats.failed_attempts,
            success_rate: stats.success_rate,
            failure_reasons: stats
                .failure_reasons
                .into_iter()
                .map(|r| FailureReasonCount {
                    reason: r.reason,
                    count: r.count,
                })
                .collect(),
            hourly_distribution: stats
                .hourly_distribution
                .into_iter()
                .map(|h| HourlyCount {
                    hour: h.hour,
                    count: h.count,
                })
                .collect(),
            unique_users: stats.unique_users,
            new_device_logins: stats.new_device_logins,
            new_location_logins: stats.new_location_logins,
        }
    }
}
