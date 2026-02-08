//! Error types for the unified NHI API.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

/// Error response body.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    /// Error code for client handling.
    pub error: String,
    /// Human-readable error message.
    pub message: String,
}

/// Error type for the NHI API endpoints.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NhiApiError {
    /// Resource not found.
    #[error("NHI entity not found")]
    NotFound,

    /// Bad request with validation errors.
    #[error("Bad request: {0}")]
    BadRequest(String),

    /// Forbidden: insufficient permissions.
    #[error("Forbidden")]
    Forbidden,

    /// Conflict error (e.g., duplicate resource).
    #[error("Conflict: {0}")]
    Conflict(String),

    /// Invalid lifecycle transition.
    #[error("Invalid lifecycle transition: {0}")]
    InvalidTransition(String),

    /// Validation error.
    #[error("Validation error: {0}")]
    ValidationError(String),

    /// Internal server error.
    #[error("Internal error")]
    Internal(String),

    /// Database error.
    #[error("Database error")]
    Database(#[from] sqlx::Error),
}

impl IntoResponse for NhiApiError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match &self {
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "NHI entity not found".to_string(),
            ),
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, "bad_request", msg.clone()),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "Access denied".to_string(),
            ),
            Self::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg.clone()),
            Self::InvalidTransition(msg) => {
                (StatusCode::BAD_REQUEST, "invalid_transition", msg.clone())
            }
            Self::ValidationError(msg) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "validation_error",
                msg.clone(),
            ),
            Self::Internal(msg) => {
                tracing::error!("Internal error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "An internal error occurred".to_string(),
                )
            }
            Self::Database(ref e) => {
                tracing::error!("Database error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "database_error",
                    "A database error occurred".to_string(),
                )
            }
        };

        let body = Json(ErrorResponse {
            error: error_code.to_string(),
            message,
        });

        (status, body).into_response()
    }
}

/// Result type alias for NHI API operations.
pub type ApiResult<T> = Result<T, NhiApiError>;

impl From<validator::ValidationErrors> for NhiApiError {
    fn from(err: validator::ValidationErrors) -> Self {
        Self::ValidationError(err.to_string())
    }
}
