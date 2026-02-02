//! Request DTOs for passwordless authentication endpoints.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

/// Request to initiate passwordless authentication (magic link or email OTP).
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct PasswordlessRequest {
    /// User email address.
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
}

/// Request to verify a magic link token.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct MagicLinkVerifyRequest {
    /// Magic link token from email.
    #[validate(length(min = 43, max = 43, message = "Invalid token format"))]
    pub token: String,
}

/// Request to verify an email OTP code.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct EmailOtpVerifyRequest {
    /// User email address.
    #[validate(email(message = "Invalid email format"))]
    pub email: String,

    /// 6-digit OTP code from email.
    #[validate(length(equal = 6, message = "Code must be exactly 6 digits"))]
    pub code: String,
}

/// Request to update tenant passwordless policy.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdatePasswordlessPolicyRequest {
    /// Which passwordless methods are enabled.
    /// Valid values: "disabled", "magic_link_only", "otp_only", "all_methods".
    pub enabled_methods: String,

    /// Magic link expiry in minutes (must be > 0).
    #[validate(range(min = 1, max = 1440, message = "Must be between 1 and 1440 minutes"))]
    pub magic_link_expiry_minutes: i32,

    /// OTP expiry in minutes (must be > 0).
    #[validate(range(min = 1, max = 1440, message = "Must be between 1 and 1440 minutes"))]
    pub otp_expiry_minutes: i32,

    /// Maximum OTP verification attempts (must be > 0).
    #[validate(range(min = 1, max = 20, message = "Must be between 1 and 20"))]
    pub otp_max_attempts: i32,

    /// Whether MFA is required after passwordless authentication.
    pub require_mfa_after_passwordless: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passwordless_request_validation() {
        let valid = PasswordlessRequest {
            email: "test@example.com".to_string(),
        };
        assert!(valid.validate().is_ok());

        let invalid = PasswordlessRequest {
            email: "not-an-email".to_string(),
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_magic_link_verify_request_validation() {
        // 43-character token (32 bytes base64url)
        let valid = MagicLinkVerifyRequest {
            token: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ".to_string(),
        };
        assert!(valid.validate().is_ok());

        let invalid = MagicLinkVerifyRequest {
            token: "short".to_string(),
        };
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_email_otp_verify_request_validation() {
        let valid = EmailOtpVerifyRequest {
            email: "test@example.com".to_string(),
            code: "123456".to_string(),
        };
        assert!(valid.validate().is_ok());

        let invalid_code = EmailOtpVerifyRequest {
            email: "test@example.com".to_string(),
            code: "12345".to_string(), // too short
        };
        assert!(invalid_code.validate().is_err());
    }

    #[test]
    fn test_update_policy_request_validation() {
        let valid = UpdatePasswordlessPolicyRequest {
            enabled_methods: "all_methods".to_string(),
            magic_link_expiry_minutes: 15,
            otp_expiry_minutes: 10,
            otp_max_attempts: 5,
            require_mfa_after_passwordless: false,
        };
        assert!(valid.validate().is_ok());

        let invalid = UpdatePasswordlessPolicyRequest {
            enabled_methods: "all_methods".to_string(),
            magic_link_expiry_minutes: 0, // too low
            otp_expiry_minutes: 10,
            otp_max_attempts: 5,
            require_mfa_after_passwordless: false,
        };
        assert!(invalid.validate().is_err());
    }
}
