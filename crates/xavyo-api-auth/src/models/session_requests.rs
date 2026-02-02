//! Session-related request models.

use serde::Deserialize;
use utoipa::ToSchema;
use validator::Validate;

/// Request to update tenant session policy.
#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct UpdateSessionPolicyRequest {
    /// Access token validity in minutes (1-60).
    #[validate(range(min = 1, max = 60))]
    pub access_token_ttl_minutes: Option<i32>,

    /// Refresh token validity in days (1-90).
    #[validate(range(min = 1, max = 90))]
    pub refresh_token_ttl_days: Option<i32>,

    /// Idle timeout in minutes (0 = disabled, max 1440 = 24h).
    #[validate(range(min = 0, max = 1440))]
    pub idle_timeout_minutes: Option<i32>,

    /// Absolute session timeout in hours (1-720 = 30 days).
    #[validate(range(min = 1, max = 720))]
    pub absolute_timeout_hours: Option<i32>,

    /// Maximum concurrent sessions per user (0 = unlimited, max 100).
    #[validate(range(min = 0, max = 100))]
    pub max_concurrent_sessions: Option<i32>,

    /// Whether to track device information.
    pub track_device_info: Option<bool>,

    /// Remember me duration in days (1-365).
    #[validate(range(min = 1, max = 365))]
    pub remember_me_ttl_days: Option<i32>,
}
