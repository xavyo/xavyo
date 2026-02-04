//! Device code login request and response models.
//!
//! DTOs for the device code flow login integration (F112).
//! These endpoints allow users to authenticate during the device verification flow.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

/// Request body for POST /device/login.
///
/// Authenticates a user during the device code flow and creates a session.
#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct DeviceLoginRequest {
    /// User's email address.
    #[validate(email(message = "Invalid email format"))]
    pub email: String,

    /// User's password.
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,

    /// User code from device flow (format: XXXX-XXXX or XXXXXXXX).
    /// Used to preserve context through authentication.
    #[validate(length(min = 8, max = 9, message = "Invalid user code format"))]
    pub user_code: String,

    /// CSRF token for form validation.
    #[serde(default)]
    pub csrf_token: Option<String>,
}

/// Response for successful device login.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DeviceLoginResponse {
    /// Authenticated user's ID.
    pub user_id: Uuid,

    /// User's email address.
    pub email: String,

    /// Whether MFA verification is required before proceeding.
    pub mfa_required: bool,

    /// Session ID for MFA flow (only present if `mfa_required=true`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mfa_session_id: Option<Uuid>,

    /// URL to redirect user after successful authentication.
    pub redirect_url: String,
}

impl DeviceLoginResponse {
    /// Create a response for successful login (no MFA).
    #[must_use] 
    pub fn success(user_id: Uuid, email: String, user_code: &str) -> Self {
        Self {
            user_id,
            email,
            mfa_required: false,
            mfa_session_id: None,
            // F112: Fixed redirect to correct endpoint /device/authorize
            redirect_url: format!("/device/authorize?user_code={user_code}"),
        }
    }

    /// Create a response requiring MFA verification.
    #[must_use] 
    pub fn mfa_required(
        user_id: Uuid,
        email: String,
        mfa_session_id: Uuid,
        user_code: &str,
    ) -> Self {
        Self {
            user_id,
            email,
            mfa_required: true,
            mfa_session_id: Some(mfa_session_id),
            // F112: Redirect to MFA page with session ID
            redirect_url: format!(
                "/device/mfa?session_id={mfa_session_id}&user_code={user_code}"
            ),
        }
    }
}

/// Request body for POST /device/login/mfa.
///
/// Completes MFA verification during the device code login flow.
#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct DeviceMfaRequest {
    /// MFA session ID from login response.
    pub mfa_session_id: Uuid,

    /// 6-digit TOTP code.
    #[validate(length(equal = 6, message = "MFA code must be 6 digits"))]
    pub code: String,

    /// Device flow user code to preserve context.
    pub user_code: String,

    /// CSRF token for form validation.
    #[serde(default)]
    pub csrf_token: Option<String>,
}

/// Response for successful MFA verification.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DeviceMfaResponse {
    /// Authenticated user's ID.
    pub user_id: Uuid,

    /// User's email address.
    pub email: String,

    /// URL to redirect user to device approval page.
    pub redirect_url: String,
}

impl DeviceMfaResponse {
    /// Create a response for successful MFA verification.
    #[must_use] 
    pub fn success(user_id: Uuid, email: String, user_code: &str) -> Self {
        Self {
            user_id,
            email,
            // F112: Fixed redirect to correct endpoint /device/authorize
            redirect_url: format!("/device/authorize?user_code={user_code}"),
        }
    }
}

/// Error response for device login endpoints.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DeviceLoginErrorResponse {
    /// Error code.
    pub error: String,

    /// Human-readable error message.
    pub message: String,

    /// When the account will be unlocked (only for `account_locked` error).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked_until: Option<chrono::DateTime<chrono::Utc>>,
}

impl DeviceLoginErrorResponse {
    /// Create a validation error response.
    pub fn validation_error(message: impl Into<String>) -> Self {
        Self {
            error: "validation_error".to_string(),
            message: message.into(),
            locked_until: None,
        }
    }

    /// Create an invalid credentials error response.
    #[must_use] 
    pub fn invalid_credentials() -> Self {
        Self {
            error: "invalid_credentials".to_string(),
            message: "Invalid email or password".to_string(),
            locked_until: None,
        }
    }

    /// Create an account locked error response.
    #[must_use] 
    pub fn account_locked(locked_until: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            error: "account_locked".to_string(),
            message: format!(
                "Account is locked. Try again after {}.",
                locked_until.format("%Y-%m-%d %H:%M:%S UTC")
            ),
            locked_until: Some(locked_until),
        }
    }

    /// Create an account inactive error response.
    #[must_use] 
    pub fn account_inactive() -> Self {
        Self {
            error: "account_inactive".to_string(),
            message: "Account is deactivated. Contact support.".to_string(),
            locked_until: None,
        }
    }

    /// Create a device code not found error response.
    #[must_use] 
    pub fn device_code_not_found() -> Self {
        Self {
            error: "device_code_not_found".to_string(),
            message: "Device code not found or expired. Please restart the CLI login.".to_string(),
            locked_until: None,
        }
    }

    /// Create an invalid MFA code error response.
    #[must_use] 
    pub fn invalid_mfa_code() -> Self {
        Self {
            error: "invalid_mfa_code".to_string(),
            message: "Invalid verification code. Please try again.".to_string(),
            locked_until: None,
        }
    }

    /// Create an MFA session not found error response.
    #[must_use] 
    pub fn mfa_session_not_found() -> Self {
        Self {
            error: "mfa_session_not_found".to_string(),
            message: "MFA session expired. Please login again.".to_string(),
            locked_until: None,
        }
    }

    /// Create a rate limit exceeded error response.
    #[must_use] 
    pub fn rate_limit_exceeded() -> Self {
        Self {
            error: "rate_limit_exceeded".to_string(),
            message: "Too many login attempts. Try again later.".to_string(),
            locked_until: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_login_request_validation_valid() {
        let request = DeviceLoginRequest {
            email: "user@example.com".to_string(),
            password: "password123".to_string(),
            user_code: "ABCD-EFGH".to_string(),
            csrf_token: None,
        };
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_device_login_request_validation_invalid_email() {
        let request = DeviceLoginRequest {
            email: "not-an-email".to_string(),
            password: "password123".to_string(),
            user_code: "ABCD-EFGH".to_string(),
            csrf_token: None,
        };
        assert!(request.validate().is_err());
    }

    #[test]
    fn test_device_login_request_validation_empty_password() {
        let request = DeviceLoginRequest {
            email: "user@example.com".to_string(),
            password: String::new(),
            user_code: "ABCD-EFGH".to_string(),
            csrf_token: None,
        };
        assert!(request.validate().is_err());
    }

    #[test]
    fn test_device_login_request_validation_short_user_code() {
        let request = DeviceLoginRequest {
            email: "user@example.com".to_string(),
            password: "password123".to_string(),
            user_code: "ABC".to_string(),
            csrf_token: None,
        };
        assert!(request.validate().is_err());
    }

    #[test]
    fn test_device_login_response_success() {
        let response =
            DeviceLoginResponse::success(Uuid::nil(), "user@example.com".to_string(), "ABCD-EFGH");
        assert!(!response.mfa_required);
        assert!(response.mfa_session_id.is_none());
        assert!(response.redirect_url.contains("ABCD-EFGH"));
        // F112: Verify correct endpoint
        assert!(response.redirect_url.contains("/device/authorize"));
    }

    #[test]
    fn test_device_login_response_mfa_required() {
        let mfa_session_id = Uuid::new_v4();
        let response = DeviceLoginResponse::mfa_required(
            Uuid::nil(),
            "user@example.com".to_string(),
            mfa_session_id,
            "ABCD-EFGH",
        );
        assert!(response.mfa_required);
        assert_eq!(response.mfa_session_id, Some(mfa_session_id));
        assert!(response.redirect_url.contains("mfa"));
        assert!(response.redirect_url.contains(&mfa_session_id.to_string()));
    }

    #[test]
    fn test_device_mfa_request_validation_valid() {
        let request = DeviceMfaRequest {
            mfa_session_id: Uuid::new_v4(),
            code: "123456".to_string(),
            user_code: "ABCD-EFGH".to_string(),
            csrf_token: None,
        };
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_device_mfa_request_validation_invalid_code_length() {
        let request = DeviceMfaRequest {
            mfa_session_id: Uuid::new_v4(),
            code: "12345".to_string(), // 5 digits instead of 6
            user_code: "ABCD-EFGH".to_string(),
            csrf_token: None,
        };
        assert!(request.validate().is_err());
    }

    #[test]
    fn test_error_response_serialization() {
        let response = DeviceLoginErrorResponse::invalid_credentials();
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"error\":\"invalid_credentials\""));
        assert!(!json.contains("locked_until")); // Should be skipped when None
    }

    #[test]
    fn test_account_locked_includes_timestamp() {
        let locked_until = chrono::Utc::now() + chrono::Duration::minutes(15);
        let response = DeviceLoginErrorResponse::account_locked(locked_until);
        assert!(response.locked_until.is_some());
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("locked_until"));
    }
}
