//! Request and response models for lockout policy endpoints.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

/// Request to update lockout policy.
#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct UpdateLockoutPolicyRequest {
    /// Maximum failed login attempts before lockout (0 = disabled).
    #[validate(range(min = 0))]
    pub max_failed_attempts: Option<i32>,

    /// Lockout duration in minutes (0 = permanent until admin unlock).
    #[validate(range(min = 0))]
    pub lockout_duration_minutes: Option<i32>,

    /// Send email notification when account is locked.
    pub notify_on_lockout: Option<bool>,
}

impl UpdateLockoutPolicyRequest {
    /// Convert to the database upsert type.
    #[must_use]
    pub fn into_upsert(self) -> xavyo_db::UpsertLockoutPolicy {
        xavyo_db::UpsertLockoutPolicy {
            max_failed_attempts: self.max_failed_attempts,
            lockout_duration_minutes: self.lockout_duration_minutes,
            notify_on_lockout: self.notify_on_lockout,
        }
    }
}

/// Response containing lockout policy.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct LockoutPolicyResponse {
    /// Maximum failed login attempts before lockout (0 = disabled).
    pub max_failed_attempts: i32,

    /// Lockout duration in minutes (0 = permanent until admin unlock).
    pub lockout_duration_minutes: i32,

    /// Send email notification when account is locked.
    pub notify_on_lockout: bool,
}

impl From<xavyo_db::TenantLockoutPolicy> for LockoutPolicyResponse {
    fn from(policy: xavyo_db::TenantLockoutPolicy) -> Self {
        Self {
            max_failed_attempts: policy.max_failed_attempts,
            lockout_duration_minutes: policy.lockout_duration_minutes,
            notify_on_lockout: policy.notify_on_lockout,
        }
    }
}

/// Response for unlock user operation.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UnlockUserResponse {
    /// The user ID that was unlocked.
    pub user_id: Uuid,

    /// Whether the user was locked and is now unlocked.
    pub unlocked: bool,

    /// Human-readable message.
    pub message: String,
}

impl UnlockUserResponse {
    /// Create a response for a successfully unlocked user.
    #[must_use]
    pub fn unlocked(user_id: Uuid) -> Self {
        Self {
            user_id,
            unlocked: true,
            message: "User account unlocked successfully".to_string(),
        }
    }

    /// Create a response when user was not locked.
    #[must_use]
    pub fn not_locked(user_id: Uuid) -> Self {
        Self {
            user_id,
            unlocked: false,
            message: "User account was not locked".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_request_into_upsert() {
        let request = UpdateLockoutPolicyRequest {
            max_failed_attempts: Some(3),
            lockout_duration_minutes: Some(60),
            notify_on_lockout: Some(true),
        };

        let upsert = request.into_upsert();
        assert_eq!(upsert.max_failed_attempts, Some(3));
        assert_eq!(upsert.lockout_duration_minutes, Some(60));
        assert_eq!(upsert.notify_on_lockout, Some(true));
    }

    #[test]
    fn test_unlock_response() {
        let user_id = Uuid::new_v4();

        let response = UnlockUserResponse::unlocked(user_id);
        assert_eq!(response.user_id, user_id);
        assert!(response.unlocked);

        let response = UnlockUserResponse::not_locked(user_id);
        assert_eq!(response.user_id, user_id);
        assert!(!response.unlocked);
    }
}
