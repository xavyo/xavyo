//! SSO Session types
//!
//! Types for tracking SSO authentication sessions and IdP information.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// SSO session state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SSOState {
    /// Waiting for browser authentication
    Pending,
    /// Authentication successful
    Completed,
    /// Authentication failed
    Failed,
    /// Session timed out
    Expired,
    /// User cancelled authentication
    Cancelled,
}

impl std::fmt::Display for SSOState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SSOState::Pending => write!(f, "pending"),
            SSOState::Completed => write!(f, "completed"),
            SSOState::Failed => write!(f, "failed"),
            SSOState::Expired => write!(f, "expired"),
            SSOState::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// SSO protocol types
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SSOProtocol {
    /// SAML 2.0
    #[default]
    Saml,
    /// OpenID Connect
    Oidc,
}

impl std::fmt::Display for SSOProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SSOProtocol::Saml => write!(f, "SAML"),
            SSOProtocol::Oidc => write!(f, "OIDC"),
        }
    }
}

/// Identity Provider information from discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdPInfo {
    /// IdP login URL
    pub idp_url: String,

    /// IdP entity identifier
    pub entity_id: String,

    /// Human-readable display name
    pub display_name: String,

    /// SSO protocol (SAML/OIDC)
    #[serde(default)]
    pub protocol: SSOProtocol,
}

impl IdPInfo {
    /// Create a new IdP info
    pub fn new(
        idp_url: impl Into<String>,
        entity_id: impl Into<String>,
        display_name: impl Into<String>,
    ) -> Self {
        Self {
            idp_url: idp_url.into(),
            entity_id: entity_id.into(),
            display_name: display_name.into(),
            protocol: SSOProtocol::default(),
        }
    }

    /// Set the protocol
    pub fn with_protocol(mut self, protocol: SSOProtocol) -> Self {
        self.protocol = protocol;
        self
    }
}

/// SSO session tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSOSession {
    /// Unique session identifier (UUID)
    pub session_id: String,

    /// CSRF protection token
    pub state: String,

    /// URL for browser authentication
    pub verification_url: String,

    /// Session creation time
    pub created_at: DateTime<Utc>,

    /// Session expiration time
    pub expires_at: DateTime<Utc>,

    /// Poll interval in seconds
    #[serde(default = "default_poll_interval")]
    pub poll_interval: u64,
}

fn default_poll_interval() -> u64 {
    2
}

impl SSOSession {
    /// Check if the session has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Get remaining time until expiration in seconds
    pub fn remaining_secs(&self) -> i64 {
        (self.expires_at - Utc::now()).num_seconds().max(0)
    }
}

/// SSO session status response from polling
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSOSessionStatus {
    /// Current session state
    pub state: SSOState,

    /// Access token (if completed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,

    /// Refresh token (if completed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,

    /// Token expiration in seconds (if completed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,

    /// Error code (if failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Error description (if failed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,

    /// Device trust token (if remember_device was requested)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_token: Option<String>,
}

impl SSOSessionStatus {
    /// Create a pending status
    pub fn pending() -> Self {
        Self {
            state: SSOState::Pending,
            access_token: None,
            refresh_token: None,
            expires_in: None,
            error: None,
            error_description: None,
            device_token: None,
        }
    }

    /// Create a completed status with tokens
    pub fn completed(access_token: String, refresh_token: Option<String>, expires_in: u64) -> Self {
        Self {
            state: SSOState::Completed,
            access_token: Some(access_token),
            refresh_token,
            expires_in: Some(expires_in),
            error: None,
            error_description: None,
            device_token: None,
        }
    }

    /// Create a failed status
    pub fn failed(error: impl Into<String>, description: Option<String>) -> Self {
        Self {
            state: SSOState::Failed,
            access_token: None,
            refresh_token: None,
            expires_in: None,
            error: Some(error.into()),
            error_description: description,
            device_token: None,
        }
    }

    /// Create an expired status
    pub fn expired() -> Self {
        Self {
            state: SSOState::Expired,
            access_token: None,
            refresh_token: None,
            expires_in: None,
            error: None,
            error_description: None,
            device_token: None,
        }
    }

    /// Get the error message for display
    pub fn error_message(&self) -> Option<String> {
        match (&self.error, &self.error_description) {
            (Some(err), Some(desc)) => Some(format!("{}: {}", err, desc)),
            (Some(err), None) => Some(err.clone()),
            (None, Some(desc)) => Some(desc.clone()),
            (None, None) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sso_state_display() {
        assert_eq!(SSOState::Pending.to_string(), "pending");
        assert_eq!(SSOState::Completed.to_string(), "completed");
        assert_eq!(SSOState::Failed.to_string(), "failed");
        assert_eq!(SSOState::Expired.to_string(), "expired");
        assert_eq!(SSOState::Cancelled.to_string(), "cancelled");
    }

    #[test]
    fn test_sso_protocol_display() {
        assert_eq!(SSOProtocol::Saml.to_string(), "SAML");
        assert_eq!(SSOProtocol::Oidc.to_string(), "OIDC");
    }

    #[test]
    fn test_sso_protocol_default() {
        assert_eq!(SSOProtocol::default(), SSOProtocol::Saml);
    }

    #[test]
    fn test_idp_info_new() {
        let info = IdPInfo::new("https://idp.example.com", "urn:example", "Example Corp SSO");
        assert_eq!(info.idp_url, "https://idp.example.com");
        assert_eq!(info.entity_id, "urn:example");
        assert_eq!(info.display_name, "Example Corp SSO");
        assert_eq!(info.protocol, SSOProtocol::Saml);
    }

    #[test]
    fn test_idp_info_with_protocol() {
        let info = IdPInfo::new("https://idp.example.com", "urn:example", "Example")
            .with_protocol(SSOProtocol::Oidc);
        assert_eq!(info.protocol, SSOProtocol::Oidc);
    }

    #[test]
    fn test_sso_session_is_expired() {
        let session = SSOSession {
            session_id: "test".to_string(),
            state: "xyz".to_string(),
            verification_url: "https://example.com".to_string(),
            created_at: Utc::now() - chrono::Duration::seconds(600),
            expires_at: Utc::now() - chrono::Duration::seconds(300),
            poll_interval: 2,
        };
        assert!(session.is_expired());

        let session = SSOSession {
            session_id: "test".to_string(),
            state: "xyz".to_string(),
            verification_url: "https://example.com".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(300),
            poll_interval: 2,
        };
        assert!(!session.is_expired());
    }

    #[test]
    fn test_sso_session_remaining_secs() {
        let session = SSOSession {
            session_id: "test".to_string(),
            state: "xyz".to_string(),
            verification_url: "https://example.com".to_string(),
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(100),
            poll_interval: 2,
        };
        let remaining = session.remaining_secs();
        assert!(remaining > 0 && remaining <= 100);

        // Expired session should return 0
        let session = SSOSession {
            session_id: "test".to_string(),
            state: "xyz".to_string(),
            verification_url: "https://example.com".to_string(),
            created_at: Utc::now() - chrono::Duration::seconds(600),
            expires_at: Utc::now() - chrono::Duration::seconds(300),
            poll_interval: 2,
        };
        assert_eq!(session.remaining_secs(), 0);
    }

    #[test]
    fn test_sso_session_status_pending() {
        let status = SSOSessionStatus::pending();
        assert_eq!(status.state, SSOState::Pending);
        assert!(status.access_token.is_none());
    }

    #[test]
    fn test_sso_session_status_completed() {
        let status = SSOSessionStatus::completed(
            "access_token".to_string(),
            Some("refresh_token".to_string()),
            3600,
        );
        assert_eq!(status.state, SSOState::Completed);
        assert_eq!(status.access_token, Some("access_token".to_string()));
        assert_eq!(status.refresh_token, Some("refresh_token".to_string()));
        assert_eq!(status.expires_in, Some(3600));
    }

    #[test]
    fn test_sso_session_status_failed() {
        let status = SSOSessionStatus::failed("auth_error", Some("User denied access".to_string()));
        assert_eq!(status.state, SSOState::Failed);
        assert_eq!(status.error, Some("auth_error".to_string()));
        assert_eq!(
            status.error_description,
            Some("User denied access".to_string())
        );
    }

    #[test]
    fn test_sso_session_status_expired() {
        let status = SSOSessionStatus::expired();
        assert_eq!(status.state, SSOState::Expired);
    }

    #[test]
    fn test_sso_session_status_error_message() {
        let status = SSOSessionStatus::failed("error_code", Some("description".to_string()));
        assert_eq!(
            status.error_message(),
            Some("error_code: description".to_string())
        );

        let status = SSOSessionStatus::failed("error_code", None);
        assert_eq!(status.error_message(), Some("error_code".to_string()));

        let status = SSOSessionStatus::pending();
        assert!(status.error_message().is_none());
    }

    #[test]
    fn test_sso_state_serialization() {
        let state = SSOState::Pending;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"pending\"");

        let state: SSOState = serde_json::from_str("\"completed\"").unwrap();
        assert_eq!(state, SSOState::Completed);
    }

    #[test]
    fn test_sso_protocol_serialization() {
        let protocol = SSOProtocol::Saml;
        let json = serde_json::to_string(&protocol).unwrap();
        assert_eq!(json, "\"saml\"");

        let protocol: SSOProtocol = serde_json::from_str("\"oidc\"").unwrap();
        assert_eq!(protocol, SSOProtocol::Oidc);
    }
}
