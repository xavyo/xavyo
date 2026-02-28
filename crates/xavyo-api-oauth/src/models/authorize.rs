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
    /// Tenant ID (optional, for browser-redirect flows that cannot set X-Tenant-ID header).
    pub tenant: Option<String>,
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

/// Query parameters for GET /oauth/authorize/info.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct AuthorizeInfoQuery {
    /// Client ID (public string identifier).
    pub client_id: String,
    /// Redirect URI.
    pub redirect_uri: String,
    /// Requested scopes (space-separated).
    #[serde(default)]
    pub scope: String,
}

/// Response from GET /oauth/authorize/info.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuthorizeInfoResponse {
    /// Display name of the OAuth client application.
    pub client_name: String,
    /// Public client ID.
    pub client_id: String,
    /// Validated scopes as individual strings.
    pub scopes: Vec<String>,
    /// Validated redirect URI.
    pub redirect_uri: String,
    /// Client logo URL (for consent page branding).
    pub client_logo_url: Option<String>,
    /// Client description (for consent page branding).
    pub client_description: Option<String>,
}

/// Request body for POST /oauth/authorize/grant.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct AuthorizeGrantRequest {
    /// Client ID (public string identifier).
    pub client_id: String,
    /// Redirect URI.
    pub redirect_uri: String,
    /// Requested scopes (space-separated).
    pub scope: String,
    /// State parameter (echoed back to client).
    pub state: String,
    /// PKCE code challenge.
    pub code_challenge: String,
    /// PKCE code challenge method (must be "S256").
    pub code_challenge_method: String,
    /// OIDC nonce (optional).
    pub nonce: Option<String>,
}

/// Response from POST /oauth/authorize/grant.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuthorizeGrantResponse {
    /// The generated authorization code.
    pub authorization_code: String,
    /// State parameter (echoed from request).
    pub state: String,
    /// Redirect URI to send user back to.
    pub redirect_uri: String,
}
