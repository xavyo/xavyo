//! Error types for tenant middleware.
//!
//! Provides structured error responses for tenant-related failures.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use thiserror::Error;

/// Errors that can occur during tenant context extraction.
///
/// # Example
///
/// ```rust
/// use xavyo_tenant::TenantError;
///
/// fn handle_error(err: TenantError) {
///     match err {
///         TenantError::Missing => eprintln!("No tenant context provided"),
///         TenantError::InvalidFormat(msg) => eprintln!("Invalid format: {}", msg),
///         TenantError::DatabaseError(msg) => eprintln!("Database error: {}", msg),
///     }
/// }
/// ```
#[derive(Debug, Clone, Error)]
pub enum TenantError {
    /// No tenant context was found in the request.
    ///
    /// This occurs when neither the X-Tenant-ID header nor JWT tid claim
    /// contains a tenant identifier.
    #[error("Tenant context required")]
    Missing,

    /// The tenant ID format is invalid.
    ///
    /// The tenant ID must be a valid UUID. This error occurs when the
    /// provided value cannot be parsed as a UUID.
    #[error("Invalid tenant ID format: {0}")]
    InvalidFormat(String),

    /// A database error occurred while setting tenant context.
    #[error("Database error: {0}")]
    DatabaseError(String),
}

impl TenantError {
    /// Get the HTTP status code for this error.
    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        match self {
            TenantError::Missing | TenantError::InvalidFormat(_) => StatusCode::UNAUTHORIZED,
            TenantError::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get the error code string for JSON response.
    #[must_use]
    pub fn error_code(&self) -> &'static str {
        match self {
            TenantError::Missing | TenantError::InvalidFormat(_) => "unauthorized",
            TenantError::DatabaseError(_) => "internal_error",
        }
    }
}

/// Structured JSON error response.
///
/// # Example Response
///
/// ```json
/// {
///     "error": "unauthorized",
///     "message": "Tenant context required"
/// }
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct ErrorResponse {
    /// Machine-readable error code (e.g., "unauthorized", "internal_error")
    pub error: String,
    /// Human-readable error message
    pub message: String,
}

impl ErrorResponse {
    /// Create a new error response.
    #[must_use]
    pub fn new(error: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            message: message.into(),
        }
    }

    /// Create an unauthorized error response.
    #[must_use]
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new("unauthorized", message)
    }

    /// Create an internal error response.
    #[must_use]
    pub fn internal_error(message: impl Into<String>) -> Self {
        Self::new("internal_error", message)
    }
}

impl From<TenantError> for ErrorResponse {
    fn from(err: TenantError) -> Self {
        Self::new(err.error_code(), err.to_string())
    }
}

impl IntoResponse for TenantError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = ErrorResponse::from(self);

        (
            status,
            [("content-type", "application/json")],
            serde_json::to_string(&body).unwrap_or_else(|_| {
                r#"{"error":"internal_error","message":"Failed to serialize error"}"#.to_string()
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_error_missing_display() {
        let err = TenantError::Missing;
        assert_eq!(err.to_string(), "Tenant context required");
    }

    #[test]
    fn test_tenant_error_invalid_format_display() {
        let err = TenantError::InvalidFormat("not a uuid".to_string());
        assert_eq!(err.to_string(), "Invalid tenant ID format: not a uuid");
    }

    #[test]
    fn test_tenant_error_database_error_display() {
        let err = TenantError::DatabaseError("connection failed".to_string());
        assert_eq!(err.to_string(), "Database error: connection failed");
    }

    #[test]
    fn test_tenant_error_missing_status_code() {
        let err = TenantError::Missing;
        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_tenant_error_invalid_format_status_code() {
        let err = TenantError::InvalidFormat("bad".to_string());
        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_tenant_error_database_error_status_code() {
        let err = TenantError::DatabaseError("fail".to_string());
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_error_response_serialization() {
        let response = ErrorResponse::unauthorized("Tenant context required");
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains(r#""error":"unauthorized""#));
        assert!(json.contains(r#""message":"Tenant context required""#));
    }

    #[test]
    fn test_error_response_from_tenant_error() {
        let err = TenantError::Missing;
        let response = ErrorResponse::from(err);
        assert_eq!(response.error, "unauthorized");
        assert_eq!(response.message, "Tenant context required");
    }
}
