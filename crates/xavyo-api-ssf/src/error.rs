//! Error type for the SSF API.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// Errors surfaced by SSF stream-management endpoints.
#[derive(Debug, Error)]
pub enum SsfApiError {
    /// Request was malformed or referenced an unsupported value.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// The referenced stream does not exist (in this tenant).
    #[error("stream not found")]
    StreamNotFound,

    /// The poll bearer token was missing or did not resolve to a stream
    /// (RFC 8936 receiver auth).
    #[error("invalid or missing poll credentials")]
    Unauthorized,

    /// Authenticated but not an admin.
    #[error("admin role required")]
    Forbidden,

    /// A database error (sanitized in the response).
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    /// An internal error (sanitized in the response).
    #[error("internal error: {0}")]
    Internal(String),
}

impl SsfApiError {
    fn status(&self) -> StatusCode {
        match self {
            Self::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            Self::StreamNotFound => StatusCode::NOT_FOUND,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::Database(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for SsfApiError {
    fn into_response(self) -> Response {
        // Sanitize internal/database detail; surface a tenant-safe message.
        let message = match &self {
            Self::Database(e) => {
                tracing::error!(target: "ssf", error = %e, "SSF database error");
                "internal error".to_string()
            }
            Self::Internal(msg) => {
                tracing::error!(target: "ssf", detail = %msg, "SSF internal error");
                "internal error".to_string()
            }
            other => other.to_string(),
        };
        (self.status(), Json(json!({ "error": message }))).into_response()
    }
}
