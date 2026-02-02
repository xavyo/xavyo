//! Authorization request and response models.

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// Authorization request query parameters for GET /oauth/authorize.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct AuthorizationRequest {
    /// Response type (must be "code").
    pub response_type: String,
    /// Client ID.
    pub client_id: String,
    /// Redirect URI (must match registered URI).
    pub redirect_uri: String,
    /// Requested scopes (space-separated).
    pub scope: String,
    /// State for CSRF protection.
    pub state: String,
    /// PKCE code challenge.
    pub code_challenge: String,
    /// PKCE code challenge method (must be "S256").
    pub code_challenge_method: String,
    /// OIDC nonce (echoed in ID token).
    pub nonce: Option<String>,
}

/// Authorization response (redirect parameters).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuthorizationResponse {
    /// Authorization code.
    pub code: String,
    /// State (echoed from request).
    pub state: String,
}

/// Authorization error response (redirect parameters).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuthorizationErrorResponse {
    /// Error code.
    pub error: String,
    /// Error description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    /// State (echoed from request).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

/// Consent request (submitted by user).
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ConsentRequest {
    /// Client ID.
    pub client_id: String,
    /// Redirect URI.
    pub redirect_uri: String,
    /// Requested scopes.
    pub scope: String,
    /// State.
    pub state: String,
    /// PKCE code challenge.
    pub code_challenge: String,
    /// PKCE code challenge method.
    pub code_challenge_method: String,
    /// OIDC nonce.
    pub nonce: Option<String>,
    /// Whether user approved the request.
    pub approved: bool,
    /// CSRF token (F082-US6).
    #[serde(default)]
    pub csrf_token: Option<String>,
    /// CSRF signature (F082-US6).
    #[serde(default)]
    pub csrf_sig: Option<String>,
}
