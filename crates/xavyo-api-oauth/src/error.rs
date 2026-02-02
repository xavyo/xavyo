//! OAuth2/OIDC error types.
//!
//! Provides error types for OAuth2 flows following RFC 6749.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// OAuth2 error codes as defined in RFC 6749 and RFC 8628.
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
            Self::AccessDenied => "access_denied",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::InvalidToken => "invalid_token",
            Self::InsufficientScope => "insufficient_scope",
            Self::AuthorizationPending => "authorization_pending",
            Self::SlowDown => "slow_down",
            Self::ExpiredToken => "expired_token",
        };
        write!(f, "{}", s)
    }
}

/// OAuth2 error response following RFC 6749 Section 5.2.
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
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            Self::InvalidClient(_) => StatusCode::UNAUTHORIZED,
            Self::InvalidGrant(_) => StatusCode::BAD_REQUEST,
            Self::UnauthorizedClient(_) => StatusCode::UNAUTHORIZED,
            Self::UnsupportedGrantType(_) => StatusCode::BAD_REQUEST,
            Self::InvalidScope(_) => StatusCode::BAD_REQUEST,
            Self::AccessDenied(_) => StatusCode::FORBIDDEN,
            Self::UnsupportedResponseType(_) => StatusCode::BAD_REQUEST,
            Self::InvalidToken(_) => StatusCode::UNAUTHORIZED,
            Self::InsufficientScope(_) => StatusCode::FORBIDDEN,
            // RFC 8628 device code errors are 400 Bad Request per spec
            Self::AuthorizationPending => StatusCode::BAD_REQUEST,
            Self::SlowDown(_) => StatusCode::BAD_REQUEST,
            Self::ExpiredToken(_) => StatusCode::BAD_REQUEST,
            Self::UserNotFound | Self::ClientNotFound => StatusCode::NOT_FOUND,
            Self::Database(_) | Self::Jwt(_) | Self::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    /// Get the OAuth2 error code for this error.
    pub fn error_code(&self) -> OAuthErrorCode {
        match self {
            Self::InvalidRequest(_) => OAuthErrorCode::InvalidRequest,
            Self::InvalidClient(_) => OAuthErrorCode::InvalidClient,
            Self::InvalidGrant(_) => OAuthErrorCode::InvalidGrant,
            Self::UnauthorizedClient(_) => OAuthErrorCode::UnauthorizedClient,
            Self::UnsupportedGrantType(_) => OAuthErrorCode::UnsupportedGrantType,
            Self::InvalidScope(_) => OAuthErrorCode::InvalidScope,
            Self::AccessDenied(_) => OAuthErrorCode::AccessDenied,
            Self::UnsupportedResponseType(_) => OAuthErrorCode::UnsupportedResponseType,
            Self::InvalidToken(_) => OAuthErrorCode::InvalidToken,
            Self::InsufficientScope(_) => OAuthErrorCode::InsufficientScope,
            Self::AuthorizationPending => OAuthErrorCode::AuthorizationPending,
            Self::SlowDown(_) => OAuthErrorCode::SlowDown,
            Self::ExpiredToken(_) => OAuthErrorCode::ExpiredToken,
            Self::UserNotFound | Self::ClientNotFound => OAuthErrorCode::InvalidRequest,
            Self::Database(_) | Self::Jwt(_) | Self::Internal(_) => OAuthErrorCode::ServerError,
        }
    }

    /// Convert to OAuth2 error response.
    pub fn to_response(&self) -> OAuthErrorResponse {
        OAuthErrorResponse::new(self.error_code(), self.to_string())
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = Json(self.to_response());
        (status, body).into_response()
    }
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
}
