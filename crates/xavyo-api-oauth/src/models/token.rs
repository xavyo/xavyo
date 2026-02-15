//! Token request and response models.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Device code grant type URN (RFC 8628).
pub const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Token request for POST /oauth/token.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct TokenRequest {
    /// Grant type (`authorization_code`, `client_credentials`, `refresh_token`, urn:ietf:params:oauth:grant-type:device_code).
    pub grant_type: String,
    /// Authorization code (for `authorization_code` grant).
    pub code: Option<String>,
    /// Redirect URI (for `authorization_code` grant).
    pub redirect_uri: Option<String>,
    /// Client ID.
    pub client_id: Option<String>,
    /// Client secret (for confidential clients).
    pub client_secret: Option<String>,
    /// PKCE code verifier (for `authorization_code` grant).
    pub code_verifier: Option<String>,
    /// Refresh token (for `refresh_token` grant).
    pub refresh_token: Option<String>,
    /// Requested scopes (for `client_credentials` or scope downgrade).
    pub scope: Option<String>,
    /// Device code (for `device_code` grant, RFC 8628).
    pub device_code: Option<String>,
    /// Subject token (for token_exchange grant, RFC 8693).
    pub subject_token: Option<String>,
    /// Subject token type (for token_exchange grant).
    pub subject_token_type: Option<String>,
    /// Actor token (for token_exchange grant).
    pub actor_token: Option<String>,
    /// Actor token type (for token_exchange grant).
    pub actor_token_type: Option<String>,
    /// Target audience (for token_exchange grant).
    pub audience: Option<String>,
}

/// Token response for POST /oauth/token.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TokenResponse {
    /// Access token (JWT).
    pub access_token: String,
    /// Token type (always "Bearer").
    pub token_type: String,
    /// Token lifetime in seconds.
    pub expires_in: i64,
    /// Refresh token (not included for `client_credentials`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// ID token (for `authorization_code` with openid scope).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// Granted scopes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl TokenResponse {
    /// Create a new token response.
    #[must_use]
    pub fn new(access_token: String, expires_in: i64) -> Self {
        Self {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in,
            refresh_token: None,
            id_token: None,
            scope: None,
        }
    }

    /// Add refresh token.
    #[must_use]
    pub fn with_refresh_token(mut self, refresh_token: String) -> Self {
        self.refresh_token = Some(refresh_token);
        self
    }

    /// Add ID token.
    #[must_use]
    pub fn with_id_token(mut self, id_token: String) -> Self {
        self.id_token = Some(id_token);
        self
    }

    /// Add scope.
    #[must_use]
    pub fn with_scope(mut self, scope: String) -> Self {
        self.scope = Some(scope);
        self
    }
}
