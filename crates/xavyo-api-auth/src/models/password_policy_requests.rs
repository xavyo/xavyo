//! Request and response models for password policy endpoints.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

/// Request to update password policy.
#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct UpdatePasswordPolicyRequest {
    /// Minimum password length (8-128).
    #[validate(range(min = 8, max = 128))]
    pub min_length: Option<i32>,

    /// Maximum password length (8-128).
    #[validate(range(min = 8, max = 128))]
    pub max_length: Option<i32>,

    /// Require at least one uppercase letter.
    pub require_uppercase: Option<bool>,

    /// Require at least one lowercase letter.
    pub require_lowercase: Option<bool>,

    /// Require at least one digit.
    pub require_digit: Option<bool>,

    /// Require at least one special character.
    pub require_special: Option<bool>,

    /// Days until password expires (0 = never).
    #[validate(range(min = 0))]
    pub expiration_days: Option<i32>,

    /// Number of previous passwords to check (0-24).
    #[validate(range(min = 0, max = 24))]
    pub history_count: Option<i32>,

    /// Minimum hours before password can be changed (0 = immediate).
    #[validate(range(min = 0))]
    pub min_age_hours: Option<i32>,

    /// Whether to check passwords against the HIBP breached password database.
    pub check_breached_passwords: Option<bool>,
}

impl UpdatePasswordPolicyRequest {
    /// Convert to the database upsert type.
    #[must_use]
    pub fn into_upsert(self) -> xavyo_db::UpsertPasswordPolicy {
        xavyo_db::UpsertPasswordPolicy {
            min_length: self.min_length,
            max_length: self.max_length,
            require_uppercase: self.require_uppercase,
            require_lowercase: self.require_lowercase,
            require_digit: self.require_digit,
            require_special: self.require_special,
            expiration_days: self.expiration_days,
            history_count: self.history_count,
            min_age_hours: self.min_age_hours,
            check_breached_passwords: self.check_breached_passwords,
        }
    }
}

/// Response containing password policy.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PasswordPolicyResponse {
    /// Minimum password length.
    pub min_length: i32,

    /// Maximum password length.
    pub max_length: i32,

    /// Require at least one uppercase letter.
    pub require_uppercase: bool,

    /// Require at least one lowercase letter.
    pub require_lowercase: bool,

    /// Require at least one digit.
    pub require_digit: bool,

    /// Require at least one special character.
    pub require_special: bool,

    /// Days until password expires (0 = never).
    pub expiration_days: i32,

    /// Number of previous passwords to check (0 = no check).
    pub history_count: i32,

    /// Minimum hours before password can be changed (0 = immediate).
    pub min_age_hours: i32,

    /// Whether to check passwords against the HIBP breached password database.
    pub check_breached_passwords: bool,
}

impl From<xavyo_db::TenantPasswordPolicy> for PasswordPolicyResponse {
    fn from(policy: xavyo_db::TenantPasswordPolicy) -> Self {
        Self {
            min_length: policy.min_length,
            max_length: policy.max_length,
            require_uppercase: policy.require_uppercase,
            require_lowercase: policy.require_lowercase,
            require_digit: policy.require_digit,
            require_special: policy.require_special,
            expiration_days: policy.expiration_days,
            history_count: policy.history_count,
            min_age_hours: policy.min_age_hours,
            check_breached_passwords: policy.check_breached_passwords,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_request_into_upsert() {
        let request = UpdatePasswordPolicyRequest {
            min_length: Some(12),
            max_length: Some(64),
            require_uppercase: Some(true),
            require_lowercase: None,
            require_digit: Some(true),
            require_special: None,
            expiration_days: Some(90),
            history_count: Some(5),
            min_age_hours: Some(24),
            check_breached_passwords: Some(true),
        };

        let upsert = request.into_upsert();
        assert_eq!(upsert.min_length, Some(12));
        assert_eq!(upsert.max_length, Some(64));
        assert_eq!(upsert.require_uppercase, Some(true));
        assert_eq!(upsert.require_lowercase, None);
        assert_eq!(upsert.expiration_days, Some(90));
    }
}
