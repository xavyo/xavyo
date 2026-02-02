//! API error types for the authorization API (F083).

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use xavyo_authorization::AuthorizationError;

/// Errors returned by the authorization API endpoints.
#[derive(Debug, thiserror::Error)]
pub enum ApiAuthorizationError {
    /// Authentication required.
    #[error("Authentication required")]
    Unauthorized,

    /// Access denied.
    #[error("Access denied")]
    Forbidden,

    /// Resource not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// Input validation error.
    #[error("Validation error: {0}")]
    Validation(String),

    /// Duplicate resource conflict.
    #[error("Conflict: {0}")]
    Conflict(String),

    /// Database error.
    #[error("Database error")]
    Database(#[from] sqlx::Error),

    /// Authorization engine error.
    #[error(transparent)]
    Authorization(#[from] AuthorizationError),
}

impl IntoResponse for ApiAuthorizationError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match &self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", self.to_string()),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden", self.to_string()),
            Self::NotFound(m) => (StatusCode::NOT_FOUND, "not_found", m.clone()),
            Self::Validation(m) => (StatusCode::BAD_REQUEST, "validation_error", m.clone()),
            Self::Conflict(m) => (StatusCode::CONFLICT, "conflict", m.clone()),
            Self::Database(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Internal server error".to_string(),
            ),
            Self::Authorization(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "authorization_error",
                e.to_string(),
            ),
        };
        let body = json!({ "error": error_code, "message": message });
        (status, Json(body)).into_response()
    }
}

/// Result type alias for authorization API handlers.
pub type ApiResult<T> = Result<T, ApiAuthorizationError>;
