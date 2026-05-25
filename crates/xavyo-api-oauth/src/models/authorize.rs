//! Authorization request and response models.

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// Authorization request query parameters for GET /oauth/authorize.
///
/// When `request_uri` (RFC 9126 PAR) is present the client sends only
/// `client_id` + `request_uri`; the remaining parameters are loaded from the
/// pushed request. They are therefore `#[serde(default)]` so the query
/// deserializes in that case — `validate_authorization_request` still rejects
/// the direct flow if they are missing/invalid.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct AuthorizationRequest {
    /// Response type (must be "code").
    #[serde(default)]
    pub response_type: String,
    /// Client ID.
    pub client_id: String,
    /// Redirect URI (must match registered URI).
    #[serde(default)]
    pub redirect_uri: String,
    /// Requested scopes (space-separated).
    #[serde(default)]
    pub scope: String,
    /// State for CSRF protection.
    #[serde(default)]
    pub state: String,
    /// PKCE code challenge.
    #[serde(default)]
    pub code_challenge: String,
    /// PKCE code challenge method (must be "S256").
    #[serde(default)]
    pub code_challenge_method: String,
    /// OIDC nonce (echoed in ID token).
    pub nonce: Option<String>,
    /// Tenant ID (optional, for browser-redirect flows that cannot set X-Tenant-ID header).
    pub tenant: Option<String>,
    /// RFC 9126 `request_uri` referencing a pushed authorization request.
    #[serde(default)]
    pub request_uri: Option<String>,
    /// RFC 9396 `authorization_details` (JSON array string) for fine-grained,
    /// structured permissions (e.g. `tool_access`).
    #[serde(default)]
    pub authorization_details: Option<String>,
}

/// Form body for `POST /oauth/par` (RFC 9126). Same parameters as the
/// front-channel authorization request, plus optional `client_secret` for
/// confidential-client authentication (client_secret_post). Basic-auth header
/// is also accepted by the handler.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct PushedAuthRequestForm {
    /// Response type (must be "code").
    pub response_type: String,
    /// Client ID.
    pub client_id: String,
    /// Client secret (confidential clients; optional for public + PKCE).
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Redirect URI.
    pub redirect_uri: String,
    /// Requested scopes (space-separated).
    pub scope: String,
    /// State for CSRF protection.
    pub state: String,
    /// PKCE code challenge.
    pub code_challenge: String,
    /// PKCE code challenge method (must be "S256").
    pub code_challenge_method: String,
    /// OIDC nonce.
    #[serde(default)]
    pub nonce: Option<String>,
    /// Tenant ID (when the X-Tenant-ID header isn't set).
    #[serde(default)]
    pub tenant: Option<String>,
    /// RFC 9396 `authorization_details` (JSON array string).
    #[serde(default)]
    pub authorization_details: Option<String>,
    /// `private_key_jwt` client assertion (RFC 7523) — confidential-client auth.
    #[serde(default)]
    pub client_assertion: Option<String>,
    /// Client assertion type; MUST be the jwt-bearer URN when present.
    #[serde(default)]
    pub client_assertion_type: Option<String>,
}

/// Response from `POST /oauth/par` (RFC 9126 §2.2).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ParResponse {
    /// Opaque single-use reference: `urn:ietf:params:oauth:request_uri:<ref>`.
    pub request_uri: String,
    /// Lifetime of the `request_uri` in seconds.
    pub expires_in: i64,
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
    /// RFC 9396 `authorization_details` (JSON array string).
    #[serde(default)]
    pub authorization_details: Option<String>,
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
    /// RFC 9207 issuer identifier. The consent frontend MUST include this as the
    /// `iss` parameter in the redirect to `redirect_uri` so the client can detect
    /// authorization-server mix-up attacks.
    pub iss: String,
}
