//! Session-related response models.

use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;
use xavyo_db::{SessionInfo, TenantSessionPolicy};

/// Response for listing user sessions.
#[derive(Debug, Serialize, ToSchema)]
pub struct SessionListResponse {
    /// List of active sessions.
    pub sessions: Vec<SessionInfoResponse>,
    /// Total number of active sessions.
    pub total: usize,
}

/// Individual session info in response.
#[derive(Debug, Serialize, ToSchema)]
pub struct SessionInfoResponse {
    /// Session ID.
    pub id: Uuid,
    /// Human-readable device name.
    pub device_name: Option<String>,
    /// Device type (desktop, mobile, tablet).
    pub device_type: Option<String>,
    /// Browser name.
    pub browser: Option<String>,
    /// Operating system.
    pub os: Option<String>,
    /// Client IP address.
    pub ip_address: Option<String>,
    /// Whether this is the current session.
    pub is_current: bool,
    /// When the session was created.
    pub created_at: DateTime<Utc>,
    /// Last activity timestamp.
    pub last_activity_at: DateTime<Utc>,
}

impl From<SessionInfo> for SessionInfoResponse {
    fn from(info: SessionInfo) -> Self {
        Self {
            id: info.id,
            device_name: info.device_name,
            device_type: info.device_type,
            browser: info.browser,
            os: info.os,
            ip_address: info.ip_address,
            is_current: info.is_current,
            created_at: info.created_at,
            last_activity_at: info.last_activity_at,
        }
    }
}

/// Response for revoking all sessions.
#[derive(Debug, Serialize, ToSchema)]
pub struct RevokeAllSessionsResponse {
    /// Number of sessions revoked.
    pub revoked_count: u64,
    /// Confirmation message.
    pub message: String,
}

impl RevokeAllSessionsResponse {
    #[must_use] 
    pub fn new(revoked_count: u64) -> Self {
        Self {
            revoked_count,
            message: format!("{revoked_count} session(s) revoked"),
        }
    }
}

/// Response for session policy.
#[derive(Debug, Serialize, ToSchema)]
pub struct SessionPolicyResponse {
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// Access token validity in minutes.
    pub access_token_ttl_minutes: i32,
    /// Refresh token validity in days.
    pub refresh_token_ttl_days: i32,
    /// Idle timeout in minutes (0 = disabled).
    pub idle_timeout_minutes: i32,
    /// Absolute session timeout in hours.
    pub absolute_timeout_hours: i32,
    /// Maximum concurrent sessions (0 = unlimited).
    pub max_concurrent_sessions: i32,
    /// Whether device info is tracked.
    pub track_device_info: bool,
    /// Remember me duration in days.
    pub remember_me_ttl_days: i32,
    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl From<TenantSessionPolicy> for SessionPolicyResponse {
    fn from(policy: TenantSessionPolicy) -> Self {
        Self {
            tenant_id: policy.tenant_id,
            access_token_ttl_minutes: policy.access_token_ttl_minutes,
            refresh_token_ttl_days: policy.refresh_token_ttl_days,
            idle_timeout_minutes: policy.idle_timeout_minutes,
            absolute_timeout_hours: policy.absolute_timeout_hours,
            max_concurrent_sessions: policy.max_concurrent_sessions,
            track_device_info: policy.track_device_info,
            remember_me_ttl_days: policy.remember_me_ttl_days,
            updated_at: policy.updated_at,
        }
    }
}
