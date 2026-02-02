//! Gateway error types and HTTP response handling.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

/// Gateway-specific errors with structured responses.
#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum GatewayError {
    #[error("Missing or invalid authorization header")]
    Unauthorized,

    #[error("Access denied")]
    Forbidden,

    #[error("Rate limit exceeded. Try again in {retry_after} seconds.")]
    RateLimited { retry_after: u64 },

    #[error("Backend service '{backend}' is unavailable")]
    ServiceUnavailable { backend: String },

    #[error("Backend service timed out")]
    GatewayTimeout,

    #[error("No backend configured for path: {path}")]
    NotFound { path: String },

    #[error("Invalid request: {message}")]
    BadRequest { message: String },

    #[error("Internal gateway error: {0}")]
    Internal(#[from] anyhow::Error),

    #[error("Configuration error: {0}")]
    Config(String),
}

/// Structured error response returned to clients.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<Uuid>,
}

impl GatewayError {
    /// Get the error code string for the response.
    pub fn error_code(&self) -> &'static str {
        match self {
            GatewayError::Unauthorized => "UNAUTHORIZED",
            GatewayError::Forbidden => "FORBIDDEN",
            GatewayError::RateLimited { .. } => "RATE_LIMITED",
            GatewayError::ServiceUnavailable { .. } => "SERVICE_UNAVAILABLE",
            GatewayError::GatewayTimeout => "GATEWAY_TIMEOUT",
            GatewayError::NotFound { .. } => "NOT_FOUND",
            GatewayError::BadRequest { .. } => "BAD_REQUEST",
            GatewayError::Internal(_) => "INTERNAL_ERROR",
            GatewayError::Config(_) => "CONFIG_ERROR",
        }
    }

    /// Get the HTTP status code for this error.
    pub fn status_code(&self) -> StatusCode {
        match self {
            GatewayError::Unauthorized => StatusCode::UNAUTHORIZED,
            GatewayError::Forbidden => StatusCode::FORBIDDEN,
            GatewayError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            GatewayError::ServiceUnavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
            GatewayError::GatewayTimeout => StatusCode::GATEWAY_TIMEOUT,
            GatewayError::NotFound { .. } => StatusCode::NOT_FOUND,
            GatewayError::BadRequest { .. } => StatusCode::BAD_REQUEST,
            GatewayError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            GatewayError::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Create an error response with optional request ID.
    pub fn to_response(&self, request_id: Option<Uuid>) -> ErrorResponse {
        ErrorResponse {
            error: self.error_code().to_string(),
            message: self.to_string(),
            request_id,
        }
    }
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = self.to_response(None);

        let mut response = (status, Json(body)).into_response();

        // Add Retry-After header for rate limiting
        if let GatewayError::RateLimited { retry_after } = &self {
            response
                .headers_mut()
                .insert("Retry-After", retry_after.to_string().parse().unwrap());
        }

        response
    }
}

/// Result type alias for gateway operations.
pub type GatewayResult<T> = Result<T, GatewayError>;
