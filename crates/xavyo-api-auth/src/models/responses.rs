//! Response DTOs for authentication endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Registration response payload.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RegisterResponse {
    /// User ID.
    pub id: Uuid,

    /// User email.
    pub email: String,

    /// Account creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// Token response payload (for login and refresh).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TokenResponse {
    /// JWT access token.
    pub access_token: String,

    /// Opaque refresh token.
    pub refresh_token: String,

    /// Token type (always "Bearer").
    pub token_type: String,

    /// Access token validity in seconds.
    pub expires_in: i64,
}

impl TokenResponse {
    /// Create a new token response.
    #[must_use]
    pub fn new(access_token: String, refresh_token: String, expires_in: i64) -> Self {
        Self {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in,
        }
    }
}

/// Forgot password response payload.
///
/// Always returns success to prevent email enumeration.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ForgotPasswordResponse {
    /// Generic success message.
    pub message: String,
}

impl Default for ForgotPasswordResponse {
    fn default() -> Self {
        Self {
            message:
                "If an account exists with this email, you will receive a password reset link."
                    .to_string(),
        }
    }
}

/// Reset password response payload.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ResetPasswordResponse {
    /// Success message.
    pub message: String,
}

impl Default for ResetPasswordResponse {
    fn default() -> Self {
        Self {
            message: "Password has been reset successfully. Please log in with your new password."
                .to_string(),
        }
    }
}

/// Verify email response payload.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VerifyEmailResponse {
    /// Success message.
    pub message: String,

    /// True if email was already verified (idempotent).
    pub already_verified: bool,

    /// Access token issued for automatic sign-in immediately after a fresh
    /// verification, so the user is not forced to log in again. Absent on the
    /// idempotent already-verified path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,

    /// Refresh token paired with `access_token` (see above).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,

    /// Token type for the issued session (always `Bearer` when present).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,

    /// Access-token lifetime in seconds (present with `access_token`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<i64>,
}

impl VerifyEmailResponse {
    /// Create a new response for a newly verified email (no auto-login session).
    #[must_use]
    pub fn verified() -> Self {
        Self {
            message: "Email verified successfully.".to_string(),
            already_verified: false,
            access_token: None,
            refresh_token: None,
            token_type: None,
            expires_in: None,
        }
    }

    /// Create a response for a freshly verified email that also carries a session
    /// so the frontend can sign the user in automatically.
    #[must_use]
    pub fn verified_with_session(
        access_token: String,
        refresh_token: String,
        expires_in: i64,
    ) -> Self {
        Self {
            message: "Email verified successfully.".to_string(),
            already_verified: false,
            access_token: Some(access_token),
            refresh_token: Some(refresh_token),
            token_type: Some("Bearer".to_string()),
            expires_in: Some(expires_in),
        }
    }

    /// Create a response for an already verified email.
    #[must_use]
    pub fn already_verified() -> Self {
        Self {
            message: "Email verified successfully.".to_string(),
            already_verified: true,
            access_token: None,
            refresh_token: None,
            token_type: None,
            expires_in: None,
        }
    }
}

/// Resend verification response payload.
///
/// Always returns success to prevent email enumeration.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ResendVerificationResponse {
    /// Generic success message.
    pub message: String,
}

impl Default for ResendVerificationResponse {
    fn default() -> Self {
        Self {
            message: "If an unverified account exists with this email, you will receive a verification link.".to_string(),
        }
    }
}

/// Password change response payload.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PasswordChangeResponse {
    /// Success message.
    pub message: String,

    /// Number of other sessions revoked (if `revoke_other_sessions` was true).
    pub sessions_revoked: i64,
}

impl PasswordChangeResponse {
    /// Create a response for successful password change.
    #[must_use]
    pub fn success(sessions_revoked: i64) -> Self {
        Self {
            message: "Password changed successfully.".to_string(),
            sessions_revoked,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_response_creation() {
        let response =
            TokenResponse::new("access_token".to_string(), "refresh_token".to_string(), 900);
        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, 900);
    }

    #[test]
    fn test_register_response_serialization() {
        let response = RegisterResponse {
            id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"email\":\"test@example.com\""));
    }
}
