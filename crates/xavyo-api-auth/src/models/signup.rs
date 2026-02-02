//! Request and response models for self-service signup endpoint.
//!
//! This module provides the DTOs for the POST /auth/signup endpoint
//! that allows new users to create accounts in the system tenant.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

/// Signup request payload.
///
/// Used for self-service account creation in the system tenant.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct SignupRequest {
    /// User email address.
    #[validate(email(message = "Invalid email format"))]
    #[validate(length(max = 255, message = "Email must not exceed 255 characters"))]
    pub email: String,

    /// User password.
    /// Password complexity is validated separately via `validate_password_complexity`.
    #[validate(length(min = 8, max = 128, message = "Password must be 8-128 characters"))]
    pub password: String,

    /// Optional display name for the user.
    #[validate(length(max = 255, message = "Display name must not exceed 255 characters"))]
    #[serde(default)]
    pub display_name: Option<String>,
}

/// Signup response payload.
///
/// Returns the created user's information and an access token for immediate use.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SignupResponse {
    /// UUID of the created user.
    pub user_id: Uuid,

    /// Normalized email address.
    pub email: String,

    /// Whether email has been verified (always false on signup).
    pub email_verified: bool,

    /// JWT access token for immediate use.
    pub access_token: String,

    /// Token type (always "Bearer").
    pub token_type: String,

    /// Access token validity in seconds.
    pub expires_in: i64,
}

impl SignupResponse {
    /// Create a new signup response.
    pub fn new(user_id: Uuid, email: String, access_token: String, expires_in: i64) -> Self {
        Self {
            user_id,
            email,
            email_verified: false,
            access_token,
            token_type: "Bearer".to_string(),
            expires_in,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signup_request_validation_valid() {
        let request = SignupRequest {
            email: "user@example.com".to_string(),
            password: "SecurePass123".to_string(),
            display_name: Some("John Doe".to_string()),
        };
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_signup_request_validation_invalid_email() {
        let request = SignupRequest {
            email: "not-an-email".to_string(),
            password: "SecurePass123".to_string(),
            display_name: None,
        };
        assert!(request.validate().is_err());
    }

    #[test]
    fn test_signup_request_validation_short_password() {
        let request = SignupRequest {
            email: "user@example.com".to_string(),
            password: "short".to_string(),
            display_name: None,
        };
        assert!(request.validate().is_err());
    }

    #[test]
    fn test_signup_request_validation_long_display_name() {
        let request = SignupRequest {
            email: "user@example.com".to_string(),
            password: "SecurePass123".to_string(),
            display_name: Some("a".repeat(256)),
        };
        assert!(request.validate().is_err());
    }

    #[test]
    fn test_signup_response_creation() {
        let response = SignupResponse::new(
            Uuid::new_v4(),
            "user@example.com".to_string(),
            "jwt.token.here".to_string(),
            3600,
        );
        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, 3600);
        assert!(!response.email_verified);
    }

    #[test]
    fn test_signup_response_serialization() {
        let response = SignupResponse::new(
            Uuid::nil(),
            "user@example.com".to_string(),
            "token".to_string(),
            3600,
        );
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"email\":\"user@example.com\""));
        assert!(json.contains("\"email_verified\":false"));
        assert!(json.contains("\"token_type\":\"Bearer\""));
    }
}
