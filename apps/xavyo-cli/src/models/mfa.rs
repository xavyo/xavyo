//! MFA (Multi-Factor Authentication) models for TOTP verification

use serde::{Deserialize, Serialize};
use std::time::Instant;

/// MFA challenge returned by the server when MFA is required
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaChallenge {
    /// Unique identifier for this MFA session
    pub challenge_id: String,

    /// MFA methods available (e.g., ["totp"])
    pub supported_methods: Vec<String>,

    /// Seconds until challenge expires
    pub expires_in: u64,

    /// Timestamp when challenge was received (not serialized)
    #[serde(skip)]
    received_at: Option<Instant>,
}

#[allow(dead_code)]
impl MfaChallenge {
    /// Create a new MFA challenge and mark the receive time
    pub fn new(challenge_id: String, supported_methods: Vec<String>, expires_in: u64) -> Self {
        Self {
            challenge_id,
            supported_methods,
            expires_in,
            received_at: Some(Instant::now()),
        }
    }

    /// Mark the challenge as received (sets the timestamp)
    pub fn mark_received(mut self) -> Self {
        self.received_at = Some(Instant::now());
        self
    }

    /// Check if the challenge has expired
    pub fn is_expired(&self) -> bool {
        match self.received_at {
            Some(received) => received.elapsed().as_secs() >= self.expires_in,
            None => false, // If no timestamp, assume not expired
        }
    }

    /// Check if TOTP is a supported method
    pub fn supports_totp(&self) -> bool {
        self.supported_methods.iter().any(|m| m == "totp")
    }
}

/// Request payload for verifying an MFA code
#[derive(Debug, Clone, Serialize)]
pub struct MfaVerifyRequest {
    /// Challenge ID being verified
    pub challenge_id: String,

    /// MFA method used (always "totp" for this feature)
    pub method: String,

    /// 6-digit TOTP code
    pub code: String,

    /// Whether to trust this device for future logins
    pub remember_device: bool,

    /// Existing device ID for re-trust (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

#[allow(dead_code)]
impl MfaVerifyRequest {
    /// Create a new TOTP verification request
    pub fn new_totp(challenge_id: String, code: String, remember_device: bool) -> Self {
        Self {
            challenge_id,
            method: "totp".to_string(),
            code,
            remember_device,
            device_id: None,
        }
    }

    /// Set the device ID for re-trust
    pub fn with_device_id(mut self, device_id: String) -> Self {
        self.device_id = Some(device_id);
        self
    }
}

/// Successful MFA verification response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaVerifyResponse {
    /// JWT access token
    pub access_token: String,

    /// Token type (always "Bearer")
    pub token_type: String,

    /// Seconds until access token expires
    pub expires_in: u64,

    /// Refresh token for obtaining new access tokens
    pub refresh_token: Option<String>,

    /// OAuth scopes
    pub scope: Option<String>,

    /// Device trust token (only if remember_device=true)
    pub device_token: Option<String>,

    /// Seconds until device token expires
    pub device_token_expires_in: Option<u64>,
}

/// Error response from MFA verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaError {
    /// Error code
    pub error: String,

    /// Human-readable error description
    pub error_description: Option<String>,

    /// Remaining retry attempts
    pub retries_remaining: Option<u32>,
}

impl MfaError {
    /// Check if this is an invalid TOTP code error
    pub fn is_invalid_code(&self) -> bool {
        self.error == "invalid_totp" || self.error == "expired_totp"
    }

    /// Check if this is a timeout error
    pub fn is_timeout(&self) -> bool {
        self.error == "mfa_timeout"
    }

    /// Check if MFA is not configured for the user
    pub fn is_not_configured(&self) -> bool {
        self.error == "mfa_not_configured"
    }

    /// Check if this is a rate limit error
    pub fn is_rate_limited(&self) -> bool {
        self.error == "rate_limited"
    }

    /// Check if this might be a clock skew error
    pub fn is_clock_skew(&self) -> bool {
        self.error == "clock_skew"
            || self
                .error_description
                .as_ref()
                .map(|d| d.to_lowercase().contains("time") || d.to_lowercase().contains("clock"))
                .unwrap_or(false)
    }

    /// Get the error message for display
    pub fn message(&self) -> String {
        self.error_description
            .clone()
            .unwrap_or_else(|| self.error.clone())
    }
}

/// MFA preference for login requests
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MfaPreference {
    /// Use server's default MFA policy
    #[default]
    Default,
    /// Always require MFA
    Required,
    /// Skip MFA if server allows
    Skip,
}

impl MfaPreference {
    /// Convert to query parameter value
    pub fn as_query_param(&self) -> Option<&'static str> {
        match self {
            MfaPreference::Default => None,
            MfaPreference::Required => Some("required"),
            MfaPreference::Skip => Some("skip"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mfa_challenge_supports_totp() {
        let challenge = MfaChallenge::new("test-id".to_string(), vec!["totp".to_string()], 300);
        assert!(challenge.supports_totp());
    }

    #[test]
    fn test_mfa_challenge_no_totp() {
        let challenge = MfaChallenge::new("test-id".to_string(), vec!["sms".to_string()], 300);
        assert!(!challenge.supports_totp());
    }

    #[test]
    fn test_mfa_verify_request_new_totp() {
        let request =
            MfaVerifyRequest::new_totp("challenge-123".to_string(), "123456".to_string(), true);
        assert_eq!(request.method, "totp");
        assert_eq!(request.code, "123456");
        assert!(request.remember_device);
        assert!(request.device_id.is_none());
    }

    #[test]
    fn test_mfa_verify_request_with_device_id() {
        let request =
            MfaVerifyRequest::new_totp("challenge-123".to_string(), "123456".to_string(), true)
                .with_device_id("device-abc".to_string());
        assert_eq!(request.device_id, Some("device-abc".to_string()));
    }

    #[test]
    fn test_mfa_error_is_invalid_code() {
        let error = MfaError {
            error: "invalid_totp".to_string(),
            error_description: Some("Invalid code".to_string()),
            retries_remaining: Some(2),
        };
        assert!(error.is_invalid_code());
        assert!(!error.is_timeout());
    }

    #[test]
    fn test_mfa_error_is_timeout() {
        let error = MfaError {
            error: "mfa_timeout".to_string(),
            error_description: None,
            retries_remaining: None,
        };
        assert!(error.is_timeout());
        assert!(!error.is_invalid_code());
    }

    #[test]
    fn test_mfa_error_is_clock_skew() {
        let error = MfaError {
            error: "invalid_totp".to_string(),
            error_description: Some("Time synchronization error".to_string()),
            retries_remaining: Some(2),
        };
        assert!(error.is_clock_skew());
    }

    #[test]
    fn test_mfa_preference_query_param() {
        assert_eq!(MfaPreference::Default.as_query_param(), None);
        assert_eq!(MfaPreference::Required.as_query_param(), Some("required"));
        assert_eq!(MfaPreference::Skip.as_query_param(), Some("skip"));
    }

    #[test]
    fn test_mfa_verify_response_deserialization() {
        let json = r#"{
            "access_token": "test-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh-token",
            "device_token": "device-trust-token",
            "device_token_expires_in": 2592000
        }"#;

        let response: MfaVerifyResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.access_token, "test-token");
        assert_eq!(
            response.device_token,
            Some("device-trust-token".to_string())
        );
    }
}
