//! Token response model

use serde::{Deserialize, Serialize};

/// Response from token endpoint (device token or refresh)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// JWT access token
    pub access_token: String,

    /// Token type (always "Bearer")
    pub token_type: String,

    /// Seconds until access token expires
    pub expires_in: u64,

    /// Refresh token for obtaining new access tokens
    pub refresh_token: Option<String>,

    /// Granted scopes
    pub scope: Option<String>,
}

/// OAuth error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthError {
    /// Error code
    pub error: String,

    /// Human-readable error description
    pub error_description: Option<String>,
}

impl OAuthError {
    /// Check if this is an `authorization_pending` error
    pub fn is_authorization_pending(&self) -> bool {
        self.error == "authorization_pending"
    }

    /// Check if this is a `slow_down` error
    pub fn is_slow_down(&self) -> bool {
        self.error == "slow_down"
    }

    /// Check if this is an `access_denied` error
    pub fn is_access_denied(&self) -> bool {
        self.error == "access_denied"
    }

    /// Check if this is an `expired_token` error
    pub fn is_expired_token(&self) -> bool {
        self.error == "expired_token"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_response_deserialization() {
        let json = r#"{
            "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4...",
            "scope": "openid profile email"
        }"#;

        let response: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.token_type, "Bearer");
        assert_eq!(response.expires_in, 3600);
        assert!(response.refresh_token.is_some());
    }

    #[test]
    fn test_token_response_without_refresh() {
        let json = r#"{
            "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
            "token_type": "Bearer",
            "expires_in": 3600
        }"#;

        let response: TokenResponse = serde_json::from_str(json).unwrap();
        assert!(response.refresh_token.is_none());
        assert!(response.scope.is_none());
    }

    #[test]
    fn test_oauth_error_types() {
        let pending = OAuthError {
            error: "authorization_pending".to_string(),
            error_description: Some("The user has not yet authorized".to_string()),
        };
        assert!(pending.is_authorization_pending());
        assert!(!pending.is_access_denied());

        let denied = OAuthError {
            error: "access_denied".to_string(),
            error_description: None,
        };
        assert!(denied.is_access_denied());
        assert!(!denied.is_authorization_pending());
    }
}
