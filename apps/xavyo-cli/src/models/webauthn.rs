//! WebAuthn/Passkey models for CLI authentication
//!
//! These models correspond to the WebAuthn API contract in contracts/webauthn-api.yaml

use serde::{Deserialize, Serialize};

/// Server-provided WebAuthn challenge for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyChallenge {
    /// Unique identifier for this challenge session
    pub challenge_id: String,

    /// Random challenge bytes (base64url encoded)
    pub challenge: String,

    /// Relying party identifier (e.g., "xavyo.io")
    pub rp_id: String,

    /// Credentials user can authenticate with
    #[serde(default)]
    pub allowed_credentials: Vec<AllowedCredential>,

    /// User verification requirement
    #[serde(default)]
    pub user_verification: UserVerification,

    /// Challenge validity in milliseconds
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

fn default_timeout() -> u64 {
    60000 // 60 seconds
}

/// A credential the user can use for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowedCredential {
    /// Credential ID (base64url encoded)
    pub id: String,

    /// Always "public-key"
    #[serde(rename = "type")]
    pub type_: String,

    /// Transport hints: "usb", "nfc", "ble", "internal", "hybrid"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

/// User verification requirement
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UserVerification {
    /// Must verify user (PIN, biometric)
    Required,
    /// Prefer verification but not required
    #[default]
    Preferred,
    /// Skip verification if possible
    Discouraged,
}

/// Client response proving possession of credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyAssertion {
    /// ID of credential used (base64url encoded)
    pub credential_id: String,

    /// Authenticator data structure (base64url encoded)
    pub authenticator_data: String,

    /// JSON of client data
    pub client_data_json: String,

    /// Signature over authenticator data + client data hash (base64url encoded)
    pub signature: String,

    /// User ID if returned by authenticator (base64url encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
}

/// Request to verify passkey assertion
#[derive(Debug, Clone, Serialize)]
pub struct PasskeyVerifyRequest {
    /// Challenge ID being verified
    pub challenge_id: String,

    /// Credential ID used (base64url encoded)
    pub credential_id: String,

    /// Authenticator data (base64url encoded)
    pub authenticator_data: String,

    /// Client data JSON string
    pub client_data_json: String,

    /// Signature (base64url encoded)
    pub signature: String,

    /// User handle if available
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,

    /// Whether to trust this device for future logins
    pub remember_device: bool,
}

/// Response from successful passkey verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyVerifyResponse {
    /// JWT access token
    pub access_token: String,

    /// Token type (always "Bearer")
    pub token_type: String,

    /// Token validity in seconds
    pub expires_in: u64,

    /// Refresh token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,

    /// OAuth scopes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Device trust token (if remember_device=true)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_token: Option<String>,

    /// Device token validity in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_token_expires_in: Option<u64>,
}

/// Session for browser-based passkey authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserHandoffSession {
    /// Unique session identifier
    pub session_id: String,

    /// URL user opens in browser
    pub verification_url: String,

    /// Short code for user verification (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_code: Option<String>,

    /// Unix timestamp when session expires
    pub expires_at: u64,

    /// Recommended poll interval in seconds
    #[serde(default = "default_poll_interval")]
    pub poll_interval: u64,
}

fn default_poll_interval() -> u64 {
    2
}

/// Status of a browser handoff session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserHandoffStatus {
    /// Session state
    pub state: HandoffState,

    /// Access token if authentication succeeded
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,

    /// Refresh token if succeeded
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,

    /// Token expiry in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,

    /// Device trust token
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_token: Option<String>,

    /// Error code if failed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Error description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

/// State of browser handoff session
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HandoffState {
    /// Waiting for user to complete browser auth
    Pending,
    /// Authentication succeeded
    Completed,
    /// Authentication failed
    Failed,
    /// Session timed out
    Expired,
}

/// Detected WebAuthn capabilities of the current environment
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct AuthenticatorCapability {
    /// USB/NFC security key detected
    pub hardware_key_available: bool,

    /// Touch ID/Windows Hello available (via browser)
    pub platform_available: bool,

    /// Can open browser for handoff
    pub browser_handoff_possible: bool,

    /// Running in non-interactive environment
    pub headless: bool,

    /// List of detected hardware keys
    pub detected_keys: Vec<DetectedKey>,
}

/// Information about a detected hardware security key
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DetectedKey {
    /// Key name (e.g., "YubiKey 5")
    pub name: String,

    /// USB vendor ID
    pub vendor_id: u16,

    /// USB product ID
    pub product_id: u16,

    /// Whether PIN is configured
    pub has_pin: bool,

    /// Supports discoverable credentials
    pub supports_resident_key: bool,
}

/// Information about user's registered passkeys (for whoami display)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyInfo {
    /// Number of registered passkeys
    pub count: u32,

    /// Individual passkey details
    pub passkeys: Vec<PasskeyEntry>,
}

/// Single passkey registration details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyEntry {
    /// User-assigned name for this passkey
    pub name: String,

    /// Device type: "platform", "cross-platform", or "unknown"
    pub device_type: String,

    /// ISO 8601 timestamp of registration
    pub registered_at: String,

    /// ISO 8601 timestamp of last use
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
}

/// WebAuthn error response from server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnError {
    /// Error code
    pub error: String,

    /// Human-readable error description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,

    /// Remaining retry attempts
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retries_remaining: Option<u32>,
}

#[allow(dead_code)]
impl WebAuthnError {
    /// Check if this is a "no passkeys" error
    pub fn is_no_passkeys(&self) -> bool {
        self.error == "no_passkeys"
    }

    /// Check if challenge expired
    pub fn is_timeout(&self) -> bool {
        self.error == "timeout"
    }

    /// Check if user cancelled
    pub fn is_user_cancelled(&self) -> bool {
        self.error == "user_cancelled"
    }

    /// Check if credential not found
    pub fn is_credential_not_found(&self) -> bool {
        self.error == "credential_not_found"
    }

    /// Get error message for display
    pub fn message(&self) -> String {
        self.error_description
            .clone()
            .unwrap_or_else(|| self.error.clone())
    }
}

/// Request to create browser handoff session
#[derive(Debug, Clone, Serialize)]
pub struct BrowserHandoffRequest {
    /// Challenge ID from passkey challenge endpoint
    pub challenge_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passkey_challenge_deserialization() {
        let json = r#"{
            "challenge_id": "test-123",
            "challenge": "dGVzdC1jaGFsbGVuZ2U",
            "rp_id": "xavyo.io",
            "allowed_credentials": [
                {"id": "Y3JlZC0xMjM", "type": "public-key", "transports": ["usb"]}
            ],
            "user_verification": "preferred",
            "timeout": 60000
        }"#;

        let challenge: PasskeyChallenge = serde_json::from_str(json).unwrap();
        assert_eq!(challenge.challenge_id, "test-123");
        assert_eq!(challenge.rp_id, "xavyo.io");
        assert_eq!(challenge.allowed_credentials.len(), 1);
        assert_eq!(challenge.user_verification, UserVerification::Preferred);
    }

    #[test]
    fn test_passkey_challenge_default_timeout() {
        let json = r#"{
            "challenge_id": "test-123",
            "challenge": "dGVzdA",
            "rp_id": "xavyo.io"
        }"#;

        let challenge: PasskeyChallenge = serde_json::from_str(json).unwrap();
        assert_eq!(challenge.timeout, 60000);
    }

    #[test]
    fn test_browser_handoff_status_completed() {
        let json = r#"{
            "state": "completed",
            "access_token": "test-token",
            "refresh_token": "refresh-token",
            "expires_in": 3600
        }"#;

        let status: BrowserHandoffStatus = serde_json::from_str(json).unwrap();
        assert_eq!(status.state, HandoffState::Completed);
        assert_eq!(status.access_token, Some("test-token".to_string()));
    }

    #[test]
    fn test_browser_handoff_status_pending() {
        let json = r#"{"state": "pending"}"#;

        let status: BrowserHandoffStatus = serde_json::from_str(json).unwrap();
        assert_eq!(status.state, HandoffState::Pending);
        assert!(status.access_token.is_none());
    }

    #[test]
    fn test_passkey_info_deserialization() {
        let json = r#"{
            "count": 2,
            "passkeys": [
                {"name": "MacBook Pro", "device_type": "platform", "registered_at": "2026-01-15T10:00:00Z"},
                {"name": "YubiKey 5", "device_type": "cross-platform", "registered_at": "2026-01-10T10:00:00Z", "last_used_at": "2026-02-04T08:00:00Z"}
            ]
        }"#;

        let info: PasskeyInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.count, 2);
        assert_eq!(info.passkeys.len(), 2);
        assert_eq!(info.passkeys[0].name, "MacBook Pro");
        assert_eq!(info.passkeys[1].device_type, "cross-platform");
    }

    #[test]
    fn test_webauthn_error_helpers() {
        let error = WebAuthnError {
            error: "no_passkeys".to_string(),
            error_description: Some("No passkeys configured".to_string()),
            retries_remaining: None,
        };

        assert!(error.is_no_passkeys());
        assert!(!error.is_timeout());
        assert_eq!(error.message(), "No passkeys configured");
    }

    #[test]
    fn test_user_verification_default() {
        let uv = UserVerification::default();
        assert_eq!(uv, UserVerification::Preferred);
    }

    #[test]
    fn test_passkey_verify_request_serialization() {
        let request = PasskeyVerifyRequest {
            challenge_id: "challenge-123".to_string(),
            credential_id: "cred-456".to_string(),
            authenticator_data: "auth-data".to_string(),
            client_data_json: "{}".to_string(),
            signature: "sig".to_string(),
            user_handle: None,
            remember_device: true,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("challenge-123"));
        assert!(json.contains("remember_device"));
        assert!(!json.contains("user_handle")); // Should be skipped when None
    }
}
