//! Stored credentials model

use crate::models::TokenResponse;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Stored credentials for API access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credentials {
    /// JWT access token
    pub access_token: String,

    /// OAuth refresh token
    pub refresh_token: String,

    /// Access token expiration time
    pub expires_at: DateTime<Utc>,

    /// Token type (always "Bearer")
    pub token_type: String,
}

impl Credentials {
    /// Create new credentials with explicit values
    pub fn new(access_token: String, refresh_token: Option<String>, expires_in: i64) -> Self {
        let expires_at = Utc::now() + Duration::seconds(expires_in);

        Self {
            access_token,
            refresh_token: refresh_token.unwrap_or_default(),
            expires_at,
            token_type: "Bearer".to_string(),
        }
    }

    /// Create credentials from a token response
    pub fn from_token_response(response: TokenResponse) -> Self {
        let expires_at = Utc::now() + Duration::seconds(response.expires_in as i64);

        Self {
            access_token: response.access_token,
            refresh_token: response.refresh_token.unwrap_or_default(),
            expires_at,
            token_type: response.token_type,
        }
    }

    /// Check if the access token is expired
    pub fn is_expired(&self) -> bool {
        self.expires_at <= Utc::now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credentials_from_token_response() {
        let response = TokenResponse {
            access_token: "access_token_here".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            refresh_token: Some("refresh_token_here".to_string()),
            scope: None,
        };

        let credentials = Credentials::from_token_response(response);
        assert_eq!(credentials.access_token, "access_token_here");
        assert_eq!(credentials.refresh_token, "refresh_token_here");
        assert_eq!(credentials.token_type, "Bearer");
        assert!(!credentials.is_expired());
    }

    #[test]
    fn test_credentials_expiration() {
        let credentials = Credentials {
            access_token: "test".to_string(),
            refresh_token: "test".to_string(),
            expires_at: Utc::now() - Duration::hours(1),
            token_type: "Bearer".to_string(),
        };

        assert!(credentials.is_expired());
    }

    #[test]
    fn test_credentials_not_expired() {
        let credentials = Credentials {
            access_token: "test".to_string(),
            refresh_token: "test".to_string(),
            expires_at: Utc::now() + Duration::hours(1),
            token_type: "Bearer".to_string(),
        };

        assert!(!credentials.is_expired());
    }
}
