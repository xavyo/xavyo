//! Response DTOs for passwordless authentication endpoints.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Response after requesting a magic link or email OTP.
///
/// Always returns a generic success message to prevent email enumeration.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PasswordlessInitResponse {
    /// Generic success message (same regardless of user existence).
    pub message: String,

    /// Token expiry in seconds.
    pub expires_in_seconds: i64,
}

impl PasswordlessInitResponse {
    /// Create a response for magic link initiation.
    #[must_use] 
    pub fn magic_link(expires_in_minutes: i32) -> Self {
        Self {
            message: "If an account exists with this email, you will receive a sign-in link."
                .to_string(),
            expires_in_seconds: i64::from(expires_in_minutes) * 60,
        }
    }

    /// Create a response for email OTP initiation.
    #[must_use] 
    pub fn email_otp(expires_in_minutes: i32) -> Self {
        Self {
            message: "If an account exists with this email, you will receive a verification code."
                .to_string(),
            expires_in_seconds: i64::from(expires_in_minutes) * 60,
        }
    }
}

/// Response when MFA is required after passwordless authentication.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PasswordlessMfaRequiredResponse {
    /// Partial token for MFA verification.
    pub partial_token: String,

    /// Partial token validity in seconds.
    pub expires_in: i64,

    /// Whether MFA is required.
    pub mfa_required: bool,
}

impl PasswordlessMfaRequiredResponse {
    /// Create a new MFA required response.
    #[must_use] 
    pub fn new(partial_token: String, expires_in: i64) -> Self {
        Self {
            partial_token,
            expires_in,
            mfa_required: true,
        }
    }
}

/// Response showing available passwordless methods for the tenant.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AvailableMethodsResponse {
    /// Whether magic link authentication is available.
    pub magic_link: bool,

    /// Whether email OTP authentication is available.
    pub email_otp: bool,
}

/// Response for passwordless policy CRUD operations.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PasswordlessPolicyResponse {
    /// Which methods are enabled.
    pub enabled_methods: String,

    /// Magic link expiry in minutes.
    pub magic_link_expiry_minutes: i32,

    /// OTP expiry in minutes.
    pub otp_expiry_minutes: i32,

    /// Maximum OTP verification attempts.
    pub otp_max_attempts: i32,

    /// Whether MFA is required after passwordless authentication.
    pub require_mfa_after_passwordless: bool,
}

impl From<xavyo_db::PasswordlessPolicy> for PasswordlessPolicyResponse {
    fn from(policy: xavyo_db::PasswordlessPolicy) -> Self {
        Self {
            enabled_methods: policy.enabled_methods,
            magic_link_expiry_minutes: policy.magic_link_expiry_minutes,
            otp_expiry_minutes: policy.otp_expiry_minutes,
            otp_max_attempts: policy.otp_max_attempts,
            require_mfa_after_passwordless: policy.require_mfa_after_passwordless,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passwordless_init_response_magic_link() {
        let response = PasswordlessInitResponse::magic_link(15);
        assert_eq!(response.expires_in_seconds, 900);
        assert!(response.message.contains("sign-in link"));
    }

    #[test]
    fn test_passwordless_init_response_email_otp() {
        let response = PasswordlessInitResponse::email_otp(10);
        assert_eq!(response.expires_in_seconds, 600);
        assert!(response.message.contains("verification code"));
    }

    #[test]
    fn test_mfa_required_response() {
        let response = PasswordlessMfaRequiredResponse::new("partial_token".to_string(), 300);
        assert!(response.mfa_required);
        assert_eq!(response.expires_in, 300);
    }

    #[test]
    fn test_policy_response_from() {
        let tenant_id = uuid::Uuid::new_v4();
        let policy = xavyo_db::PasswordlessPolicy::default_for_tenant(tenant_id);
        let response = PasswordlessPolicyResponse::from(policy);
        assert_eq!(response.enabled_methods, "all_methods");
        assert_eq!(response.magic_link_expiry_minutes, 15);
        assert_eq!(response.otp_expiry_minutes, 10);
        assert_eq!(response.otp_max_attempts, 5);
        assert!(!response.require_mfa_after_passwordless);
    }
}
