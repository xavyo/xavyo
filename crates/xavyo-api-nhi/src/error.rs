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

    /// Upstream gateway error (502).
    #[error("Bad gateway: {0}")]
    BadGateway(String),

    /// Capability is not implemented (HTTP 501).
    #[error("Not implemented: {0}")]
    NotImplemented(String),

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
            Self::BadGateway(msg) => {
                tracing::warn!("Bad gateway: {}", msg);
                (StatusCode::BAD_GATEWAY, "bad_gateway", msg.clone())
            }
            Self::NotImplemented(msg) => {
                (StatusCode::NOT_IMPLEMENTED, "not_implemented", msg.clone())
            }
            Self::Internal(msg) => {
                tracing::error!("Internal error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "An internal error occurred".to_string(),
                )
            }
            Self::Database(ref e) => {
                // Constraint violations are caused by bad client input (e.g. a
                // referenced entity id that doesn't exist, or a duplicate). Surfacing
                // them as a raw 500 "database error" is misleading — map them to a
                // clear 4xx instead.
                if let Some(db_err) = e.as_database_error() {
                    match db_err.code().as_deref() {
                        // foreign_key_violation
                        Some("23503") => {
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(ErrorResponse {
                                    error: "invalid_reference".to_string(),
                                    message: "A referenced entity does not exist".to_string(),
                                }),
                            )
                                .into_response();
                        }
                        // unique_violation
                        Some("23505") => {
                            return (
                                StatusCode::CONFLICT,
                                Json(ErrorResponse {
                                    error: "conflict".to_string(),
                                    message: "A conflicting record already exists".to_string(),
                                }),
                            )
                                .into_response();
                        }
                        _ => {}
                    }
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::response::IntoResponse;

    /// Regression: DB constraint violations from bad client input (e.g. a
    /// non-existent referenced id) must map to a clear 4xx, not a raw 500
    /// "database error". Previously creating a delegation with a non-existent
    /// actor_nhi_id 500'd.
    #[test]
    fn database_error_maps_constraint_violations_to_4xx() {
        let src = include_str!("error.rs");
        let arm = src
            .split("Self::Database(ref e) =>")
            .nth(1)
            .and_then(|s| s.split("let body = Json").next())
            .expect("Database arm");
        assert!(
            arm.contains("23503") && arm.contains("StatusCode::BAD_REQUEST"),
            "foreign_key_violation (23503) must map to 400"
        );
        assert!(
            arm.contains("23505") && arm.contains("StatusCode::CONFLICT"),
            "unique_violation (23505) must map to 409"
        );
    }

    #[tokio::test]
    async fn not_implemented_into_response_is_501() {
        let err = NhiApiError::NotImplemented("MCP tool execution is not implemented".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);

        let body = to_bytes(response.into_body(), 1024).await.expect("body");
        let text = String::from_utf8(body.to_vec()).expect("utf8");
        assert!(
            !text.contains(r#""status":"simulated""#),
            "501 body must not look like a successful simulated invocation: {text}"
        );
        assert!(
            !text.contains(r#""status": "simulated""#),
            "501 body must not look like a successful simulated invocation: {text}"
        );
        assert!(text.contains("not_implemented"), "{text}");
    }
}
