//! OAuth2/OIDC error types.
//!
//! Provides error types for `OAuth2` flows following RFC 6749.

use axum::{
    http::{
        header::{HeaderName, HeaderValue, WWW_AUTHENTICATE},
        StatusCode,
    },
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// `OAuth2` error codes as defined in RFC 6749 and RFC 8628.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthErrorCode {
    /// The request is missing a required parameter.
    InvalidRequest,
    /// Client authentication failed.
    InvalidClient,
    /// The provided authorization grant or refresh token is invalid.
    InvalidGrant,
    /// The client is not authorized to request an authorization code.
    UnauthorizedClient,
    /// The authorization server does not support the grant type.
    UnsupportedGrantType,
    /// The requested scope is invalid, unknown, or malformed.
    InvalidScope,
    /// RFC 9396 §5: the `authorization_details` is malformed or contains an
    /// unknown/unsupported type.
    InvalidAuthorizationDetails,
    /// The resource owner denied the request.
    AccessDenied,
    /// The authorization server does not support the response type.
    UnsupportedResponseType,
    /// The authorization server encountered an unexpected condition.
    ServerError,
    /// The authorization server is temporarily unavailable.
    TemporarilyUnavailable,
    /// The access token is invalid (for resource server errors).
    InvalidToken,
    /// The request requires higher privileges.
    InsufficientScope,
    /// RFC 8628: The authorization request is still pending (device code flow).
    AuthorizationPending,
    /// RFC 8628: The client is polling too frequently (device code flow).
    SlowDown,
    /// RFC 8628: The device code has expired (device code flow).
    ExpiredToken,
    /// RFC 9449 §8–9: the request requires a server-issued DPoP nonce.
    UseDpopNonce,
}

impl std::fmt::Display for OAuthErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidAuthorizationDetails => "invalid_authorization_details",
            Self::AccessDenied => "access_denied",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::InvalidToken => "invalid_token",
            Self::InsufficientScope => "insufficient_scope",
            Self::AuthorizationPending => "authorization_pending",
            Self::SlowDown => "slow_down",
            Self::ExpiredToken => "expired_token",
            Self::UseDpopNonce => "use_dpop_nonce",
        };
        write!(f, "{s}")
    }
}

/// `OAuth2` error response following RFC 6749 Section 5.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthErrorResponse {
    /// Error code.
    pub error: OAuthErrorCode,
    /// Human-readable error description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    /// URI with more information about the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,
}

impl OAuthErrorResponse {
    /// Create a new error response.
    pub fn new(error: OAuthErrorCode, description: impl Into<String>) -> Self {
        Self {
            error,
            error_description: Some(description.into()),
            error_uri: None,
        }
    }
}

/// OAuth2/OIDC API errors.
#[derive(Debug, Error)]
pub enum OAuthError {
    /// Invalid request parameters.
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// Client authentication failed.
    #[error("Invalid client: {0}")]
    InvalidClient(String),

    /// Invalid authorization code or refresh token.
    #[error("Invalid grant: {0}")]
    InvalidGrant(String),

    /// Client not authorized for grant type.
    #[error("Unauthorized client: {0}")]
    UnauthorizedClient(String),

    /// Unsupported grant type.
    #[error("Unsupported grant type: {0}")]
    UnsupportedGrantType(String),

    /// Invalid scope.
    #[error("Invalid scope: {0}")]
    InvalidScope(String),

    /// RFC 9396 §5: malformed or unsupported `authorization_details`.
    #[error("Invalid authorization_details: {0}")]
    InvalidAuthorizationDetails(String),

    /// Access denied by user.
    #[error("Access denied: {0}")]
    AccessDenied(String),

    /// Unsupported response type.
    #[error("Unsupported response type: {0}")]
    UnsupportedResponseType(String),

    /// Invalid or expired access token.
    #[error("Invalid token: {0}")]
    InvalidToken(String),

    /// Insufficient scope for the request.
    #[error("Insufficient scope: {0}")]
    InsufficientScope(String),

    /// RFC 9449 §9: the token endpoint requires a DPoP nonce. The client must
    /// retry with the carried nonce echoed in the proof's `nonce` claim. HTTP
    /// 400 + `DPoP-Nonce` response header.
    #[error("Use DPoP nonce")]
    UseDpopNonceToken {
        /// Fresh server-issued nonce for the client to echo on retry.
        nonce: String,
    },

    /// RFC 9449 §8: a resource endpoint requires a DPoP nonce. HTTP 401 with a
    /// `WWW-Authenticate: DPoP error="use_dpop_nonce"` challenge + `DPoP-Nonce`
    /// response header.
    #[error("Use DPoP nonce")]
    UseDpopNonceResource {
        /// Fresh server-issued nonce for the client to echo on retry.
        nonce: String,
    },

    /// RFC 8628: Authorization request is still pending.
    #[error("The authorization request is still pending")]
    AuthorizationPending,

    /// RFC 8628: Client is polling too frequently.
    #[error("Polling too frequently, slow down. New interval: {0} seconds")]
    SlowDown(i32),

    /// RFC 8628: Device code has expired.
    #[error("Expired token: {0}")]
    ExpiredToken(String),

    /// User not found.
    #[error("User not found")]
    UserNotFound,

    /// Client not found.
    #[error("Client not found")]
    ClientNotFound,

    /// Database error.
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// JWT error.
    #[error("JWT error: {0}")]
    Jwt(#[from] xavyo_auth::AuthError),

    /// Internal server error.
    #[error("Internal error: {0}")]
    Internal(String),
}

impl OAuthError {
    /// Get the HTTP status code for this error.
    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            Self::InvalidClient(_) => StatusCode::UNAUTHORIZED,
            Self::InvalidGrant(_) => StatusCode::BAD_REQUEST,
            Self::UnauthorizedClient(_) => StatusCode::UNAUTHORIZED,
            Self::UnsupportedGrantType(_) => StatusCode::BAD_REQUEST,
            Self::InvalidScope(_) => StatusCode::BAD_REQUEST,
            Self::InvalidAuthorizationDetails(_) => StatusCode::BAD_REQUEST,
            Self::AccessDenied(_) => StatusCode::FORBIDDEN,
            Self::UnsupportedResponseType(_) => StatusCode::BAD_REQUEST,
            Self::InvalidToken(_) => StatusCode::UNAUTHORIZED,
            Self::InsufficientScope(_) => StatusCode::FORBIDDEN,
            // RFC 9449: token-endpoint nonce challenge is 400; resource-endpoint
            // nonce challenge is 401 (it's an access-token authorization error).
            Self::UseDpopNonceToken { .. } => StatusCode::BAD_REQUEST,
            Self::UseDpopNonceResource { .. } => StatusCode::UNAUTHORIZED,
            // RFC 8628 device code errors are 400 Bad Request per spec
            Self::AuthorizationPending => StatusCode::BAD_REQUEST,
            Self::SlowDown(_) => StatusCode::BAD_REQUEST,
            Self::ExpiredToken(_) => StatusCode::BAD_REQUEST,
            Self::UserNotFound => StatusCode::NOT_FOUND,
            // SECURITY: Return 401 for ClientNotFound to prevent client enumeration (RFC 6749)
            Self::ClientNotFound => StatusCode::UNAUTHORIZED,
            Self::Database(_) | Self::Jwt(_) | Self::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    /// Get the `OAuth2` error code for this error.
    #[must_use]
    pub fn error_code(&self) -> OAuthErrorCode {
        match self {
            Self::InvalidRequest(_) => OAuthErrorCode::InvalidRequest,
            Self::InvalidClient(_) => OAuthErrorCode::InvalidClient,
            Self::InvalidGrant(_) => OAuthErrorCode::InvalidGrant,
            Self::UnauthorizedClient(_) => OAuthErrorCode::UnauthorizedClient,
            Self::UnsupportedGrantType(_) => OAuthErrorCode::UnsupportedGrantType,
            Self::InvalidScope(_) => OAuthErrorCode::InvalidScope,
            Self::InvalidAuthorizationDetails(_) => OAuthErrorCode::InvalidAuthorizationDetails,
            Self::AccessDenied(_) => OAuthErrorCode::AccessDenied,
            Self::UnsupportedResponseType(_) => OAuthErrorCode::UnsupportedResponseType,
            Self::InvalidToken(_) => OAuthErrorCode::InvalidToken,
            Self::InsufficientScope(_) => OAuthErrorCode::InsufficientScope,
            Self::UseDpopNonceToken { .. } | Self::UseDpopNonceResource { .. } => {
                OAuthErrorCode::UseDpopNonce
            }
            Self::AuthorizationPending => OAuthErrorCode::AuthorizationPending,
            Self::SlowDown(_) => OAuthErrorCode::SlowDown,
            Self::ExpiredToken(_) => OAuthErrorCode::ExpiredToken,
            Self::UserNotFound => OAuthErrorCode::InvalidRequest,
            Self::ClientNotFound => OAuthErrorCode::InvalidClient,
            Self::Database(_) | Self::Jwt(_) | Self::Internal(_) => OAuthErrorCode::ServerError,
        }
    }

    /// Convert to `OAuth2` error response.
    ///
    /// Internal errors and grant-level diagnostics are sanitized to prevent
    /// information leakage per RFC 6749 Section 5.2.
    #[must_use]
    pub fn to_response(&self) -> OAuthErrorResponse {
        let description = match self {
            Self::Database(ref e) => {
                tracing::error!("OAuth database error: {:?}", e);
                "An internal error occurred".to_string()
            }
            Self::Jwt(ref e) => {
                tracing::error!("OAuth JWT error: {:?}", e);
                "An internal error occurred".to_string()
            }
            Self::Internal(ref msg) => {
                tracing::error!("OAuth internal error: {}", msg);
                "An internal error occurred".to_string()
            }
            // SECURITY: Sanitize grant errors to avoid leaking internal diagnostics
            // (e.g., delegation depth, NHI lifecycle state, token family details).
            Self::InvalidGrant(ref msg) => {
                tracing::debug!("OAuth invalid_grant detail: {}", msg);
                "The provided authorization grant is invalid".to_string()
            }
            Self::InvalidClient(ref msg) => {
                tracing::debug!("OAuth invalid_client detail: {}", msg);
                "Client authentication failed".to_string()
            }
            Self::ClientNotFound => "Client authentication failed".to_string(),
            _ => self.to_string(),
        };
        OAuthErrorResponse::new(self.error_code(), description)
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = Json(self.to_response());

        // RFC 9449 §8–9: a DPoP-nonce challenge carries the fresh nonce in a
        // `DPoP-Nonce` response header; the resource-server form (§8) also sends
        // a `WWW-Authenticate: DPoP error="use_dpop_nonce"` challenge with the
        // accepted proof algorithms (§7.1).
        match self {
            Self::UseDpopNonceToken { nonce } => {
                (status, [dpop_nonce_header(&nonce)], body).into_response()
            }
            Self::UseDpopNonceResource { nonce } => (
                status,
                [
                    dpop_nonce_header(&nonce),
                    (
                        WWW_AUTHENTICATE,
                        HeaderValue::from_static(
                            "DPoP error=\"use_dpop_nonce\", \
                             error_description=\"DPoP nonce required\", \
                             algs=\"RS256 PS256 ES256\"",
                        ),
                    ),
                ],
                body,
            )
                .into_response(),
            _ => (status, body).into_response(),
        }
    }
}

/// Build the `DPoP-Nonce` response header. The nonce is base64url (RFC 9449
/// §8.1), so it is always a valid header value; the fallback is unreachable.
fn dpop_nonce_header(nonce: &str) -> (HeaderName, HeaderValue) {
    (
        HeaderName::from_static("dpop-nonce"),
        HeaderValue::from_str(nonce).unwrap_or(HeaderValue::from_static("")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_display() {
        assert_eq!(
            OAuthErrorCode::InvalidRequest.to_string(),
            "invalid_request"
        );
        assert_eq!(OAuthErrorCode::InvalidClient.to_string(), "invalid_client");
        assert_eq!(OAuthErrorCode::InvalidGrant.to_string(), "invalid_grant");
    }

    #[test]
    fn test_error_response_serialization() {
        let response =
            OAuthErrorResponse::new(OAuthErrorCode::InvalidRequest, "Missing required parameter");

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"error\":\"invalid_request\""));
        assert!(json.contains("\"error_description\":\"Missing required parameter\""));
    }

    #[test]
    fn test_oauth_error_status_codes() {
        assert_eq!(
            OAuthError::InvalidRequest("test".into()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            OAuthError::InvalidClient("test".into()).status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            OAuthError::AccessDenied("test".into()).status_code(),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn dpop_nonce_token_challenge_sets_header_and_400() {
        // RFC 9449 §9: token-endpoint challenge is 400 with the fresh nonce in a
        // DPoP-Nonce header. Guards the IntoResponse header plumbing.
        let err = OAuthError::UseDpopNonceToken {
            nonce: "test-nonce-value".to_string(),
        };
        assert_eq!(err.error_code().to_string(), "use_dpop_nonce");
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.headers()
                .get("dpop-nonce")
                .and_then(|v| v.to_str().ok()),
            Some("test-nonce-value")
        );
        // The token form does NOT carry a WWW-Authenticate challenge.
        assert!(resp.headers().get(WWW_AUTHENTICATE).is_none());
    }

    #[test]
    fn dpop_nonce_resource_challenge_sets_headers_and_401() {
        // RFC 9449 §8: resource-endpoint challenge is 401 with both DPoP-Nonce
        // and a WWW-Authenticate: DPoP error="use_dpop_nonce" challenge.
        let err = OAuthError::UseDpopNonceResource {
            nonce: "resource-nonce".to_string(),
        };
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers()
                .get("dpop-nonce")
                .and_then(|v| v.to_str().ok()),
            Some("resource-nonce")
        );
        let www = resp
            .headers()
            .get(WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .expect("WWW-Authenticate present");
        assert!(www.starts_with("DPoP "));
        assert!(www.contains("error=\"use_dpop_nonce\""));
        assert!(www.contains("algs="));
    }
}
