//! Request and response DTOs for self-service profile endpoints (F027).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

// ============================================================================
// Profile Endpoints
// ============================================================================

/// Response for GET /me/profile.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ProfileResponse {
    /// User's unique identifier.
    pub id: uuid::Uuid,

    /// User's email address.
    pub email: String,

    /// User's display name.
    pub display_name: Option<String>,

    /// User's first name.
    pub first_name: Option<String>,

    /// User's last name.
    pub last_name: Option<String>,

    /// URL to user's avatar image.
    pub avatar_url: Option<String>,

    /// Whether the user's email has been verified.
    pub email_verified: bool,

    /// When the user account was created.
    pub created_at: DateTime<Utc>,
}

/// Request for PUT /me/profile.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateProfileRequest {
    /// New display name (optional).
    #[validate(length(min = 1, max = 100, message = "Display name must be 1-100 characters"))]
    pub display_name: Option<String>,

    /// New first name (optional).
    #[validate(length(min = 1, max = 100, message = "First name must be 1-100 characters"))]
    pub first_name: Option<String>,

    /// New last name (optional).
    #[validate(length(min = 1, max = 100, message = "Last name must be 1-100 characters"))]
    pub last_name: Option<String>,

    /// New avatar URL (optional).
    #[validate(url(message = "Invalid avatar URL format"))]
    #[validate(length(max = 2048, message = "Avatar URL must be at most 2048 characters"))]
    pub avatar_url: Option<String>,
}

// ============================================================================
// Email Change Endpoints
// ============================================================================

/// Request for POST /me/email/change.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct EmailChangeRequest {
    /// The new email address.
    #[validate(email(message = "Invalid email format"))]
    #[validate(length(max = 255, message = "Email too long"))]
    pub new_email: String,

    /// Current password for verification.
    pub current_password: String,
}

/// Response for POST /me/email/change (success).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EmailChangeInitiatedResponse {
    /// Success message.
    pub message: String,

    /// When the verification token expires.
    pub expires_at: DateTime<Utc>,
}

/// Request for POST /me/email/verify.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct EmailVerifyChangeRequest {
    /// The verification token from the email.
    #[validate(length(min = 43, max = 43, message = "Invalid token format"))]
    pub token: String,
}

/// Response for POST /me/email/verify (success).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct EmailChangeCompletedResponse {
    /// Success message.
    pub message: String,

    /// The new email address.
    pub new_email: String,
}

// ============================================================================
// Security Overview Endpoints
// ============================================================================

/// Response for GET /me/security.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SecurityOverviewResponse {
    /// Whether MFA is enabled.
    pub mfa_enabled: bool,

    /// List of enabled MFA methods (e.g., ["totp"]).
    pub mfa_methods: Vec<String>,

    /// Number of trusted devices.
    pub trusted_devices_count: i64,

    /// Number of active sessions.
    pub active_sessions_count: i64,

    /// When the password was last changed.
    pub last_password_change: Option<DateTime<Utc>>,

    /// Number of recent unacknowledged security alerts.
    pub recent_security_alerts_count: i64,

    /// When the current password expires.
    pub password_expires_at: Option<DateTime<Utc>>,
}

// Note: MfaStatusResponse is defined in mfa_responses.rs and re-exported from models/mod.rs
// Use that one for /me/mfa endpoint to avoid duplication

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_profile_request_validation() {
        let valid = UpdateProfileRequest {
            display_name: Some("John Doe".to_string()),
            first_name: Some("John".to_string()),
            last_name: Some("Doe".to_string()),
            avatar_url: Some("https://example.com/avatar.png".to_string()),
        };
        assert!(valid.validate().is_ok());

        // Empty display name should fail
        let empty_name = UpdateProfileRequest {
            display_name: Some("".to_string()),
            first_name: None,
            last_name: None,
            avatar_url: None,
        };
        assert!(empty_name.validate().is_err());

        // Invalid URL should fail
        let invalid_url = UpdateProfileRequest {
            display_name: None,
            first_name: None,
            last_name: None,
            avatar_url: Some("not-a-valid-url".to_string()),
        };
        assert!(invalid_url.validate().is_err());
    }

    #[test]
    fn test_email_change_request_validation() {
        let valid = EmailChangeRequest {
            new_email: "newemail@example.com".to_string(),
            current_password: "password123".to_string(),
        };
        assert!(valid.validate().is_ok());

        let invalid_email = EmailChangeRequest {
            new_email: "not-an-email".to_string(),
            current_password: "password123".to_string(),
        };
        assert!(invalid_email.validate().is_err());
    }

    #[test]
    fn test_email_verify_change_request_validation() {
        let valid = EmailVerifyChangeRequest {
            token: "a".repeat(43),
        };
        assert!(valid.validate().is_ok());

        let invalid = EmailVerifyChangeRequest {
            token: "short".to_string(),
        };
        assert!(invalid.validate().is_err());
    }
}
