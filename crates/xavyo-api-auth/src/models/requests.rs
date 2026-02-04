//! Request DTOs for authentication endpoints.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

/// Registration request payload.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct RegisterRequest {
    /// User email address.
    #[validate(email(message = "Invalid email format"))]
    #[validate(length(max = 255, message = "Email too long"))]
    pub email: String,

    /// User password.
    #[validate(length(min = 8, max = 128, message = "Password must be 8-128 characters"))]
    pub password: String,
}

/// Login request payload.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct LoginRequest {
    /// User email address.
    #[validate(email(message = "Invalid email format"))]
    pub email: String,

    /// User password.
    /// Length validation prevents `DoS` attacks via extremely long passwords
    /// that could consume excessive CPU during hashing.
    #[validate(length(min = 1, max = 1024, message = "Password must be 1-1024 characters"))]
    pub password: String,
}

/// Token refresh request payload.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RefreshRequest {
    /// Refresh token from login response.
    pub refresh_token: String,
}

/// Logout request payload.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct LogoutRequest {
    /// Refresh token to invalidate.
    pub refresh_token: String,
}

/// Forgot password request payload.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ForgotPasswordRequest {
    /// User email address.
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
}

/// Reset password request payload.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ResetPasswordRequest {
    /// Password reset token from email.
    #[validate(length(min = 43, max = 43, message = "Invalid token format"))]
    pub token: String,

    /// New password.
    #[validate(length(min = 8, max = 128, message = "Password must be 8-128 characters"))]
    pub new_password: String,
}

/// Verify email request payload.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct VerifyEmailRequest {
    /// Email verification token from email.
    #[validate(length(min = 43, max = 43, message = "Invalid token format"))]
    pub token: String,
}

/// Resend verification request payload.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ResendVerificationRequest {
    /// User email address.
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
}

/// Change password request payload.
///
/// Used by authenticated users to change their password.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct PasswordChangeRequest {
    /// Current password for verification.
    pub current_password: String,

    /// New password.
    #[validate(length(min = 8, max = 128, message = "Password must be 8-128 characters"))]
    pub new_password: String,

    /// Whether to revoke all other sessions after password change.
    /// Defaults to true for security.
    #[serde(default = "default_revoke_sessions")]
    pub revoke_other_sessions: bool,
}

fn default_revoke_sessions() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_request_validation() {
        let valid = RegisterRequest {
            email: "test@example.com".to_string(),
            password: "SecureP@ss123".to_string(),
        };
        assert!(valid.validate().is_ok());

        let invalid_email = RegisterRequest {
            email: "not-an-email".to_string(),
            password: "SecureP@ss123".to_string(),
        };
        assert!(invalid_email.validate().is_err());

        let short_password = RegisterRequest {
            email: "test@example.com".to_string(),
            password: "short".to_string(),
        };
        assert!(short_password.validate().is_err());
    }

    #[test]
    fn test_login_request_validation() {
        let valid = LoginRequest {
            email: "test@example.com".to_string(),
            password: "any".to_string(),
        };
        assert!(valid.validate().is_ok());
    }
}
