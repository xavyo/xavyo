//! Error types for the Tenant Provisioning API.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

/// Errors that can occur during tenant provisioning operations.
#[derive(Debug, Error)]
pub enum TenantError {
    /// Validation error for request input (with optional field).
    #[error("Validation error: {message}")]
    ValidationField {
        message: String,
        field: Option<String>,
    },

    /// Simple validation error (string only).
    #[error("Validation error: {0}")]
    Validation(String),

    /// F-056: Validation error with required field information.
    #[error("{message}")]
    ValidationWithField { field: String, message: String },

    /// Authentication required (with optional message).
    #[error("{0}")]
    Unauthorized(String),

    /// Not authorized to perform this action.
    #[error("{0}")]
    Forbidden(String),

    /// Tenant not found (unit variant for generic cases).
    #[error("Tenant not found")]
    NotFound,

    /// Tenant not found with specific tenant ID.
    #[error("Tenant {0} not found")]
    TenantNotFound(uuid::Uuid),

    /// Resource not found with specific message.
    #[error("{0}")]
    NotFoundWithMessage(String),

    /// Slug already exists (should not happen with auto-suffix).
    #[error("Slug already exists: {0}")]
    SlugConflict(String),

    /// General conflict error (e.g., resource already in requested state).
    #[error("{0}")]
    Conflict(String),

    /// F-057: Resource is gone (expired, cancelled, or already used).
    #[error("{0}")]
    Gone(String),

    /// Database error.
    #[error("Database error: {0}")]
    Database(String),

    /// Internal server error.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Error response format for API errors.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

impl TenantError {
    /// Create a validation error for a specific field.
    pub fn validation_field(message: impl Into<String>, field: impl Into<String>) -> Self {
        Self::ValidationField {
            message: message.into(),
            field: Some(field.into()),
        }
    }

    /// Create a validation error without a specific field.
    pub fn validation_general(message: impl Into<String>) -> Self {
        Self::ValidationField {
            message: message.into(),
            field: None,
        }
    }

    /// Create a forbidden error.
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::Forbidden(message.into())
    }

    /// Create an internal error.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }

    /// Create a database error from a string.
    pub fn database(message: impl Into<String>) -> Self {
        Self::Database(message.into())
    }
}

impl IntoResponse for TenantError {
    fn into_response(self) -> Response {
        let (status, error_code, message, field) = match &self {
            TenantError::ValidationField { message, field } => (
                StatusCode::BAD_REQUEST,
                "validation_error",
                message.clone(),
                field.clone(),
            ),
            TenantError::Validation(msg) => (
                StatusCode::BAD_REQUEST,
                "validation_error",
                msg.clone(),
                None,
            ),
            TenantError::ValidationWithField { field, message } => (
                StatusCode::BAD_REQUEST,
                "validation",
                message.clone(),
                Some(field.clone()),
            ),
            TenantError::Unauthorized(msg) => {
                (StatusCode::UNAUTHORIZED, "unauthorized", msg.clone(), None)
            }
            TenantError::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg.clone(), None),
            TenantError::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "Tenant not found".to_string(),
                None,
            ),
            TenantError::TenantNotFound(id) => (
                StatusCode::NOT_FOUND,
                "not_found",
                format!("Tenant {id} not found"),
                None,
            ),
            TenantError::NotFoundWithMessage(msg) => {
                (StatusCode::NOT_FOUND, "not_found", msg.clone(), None)
            }
            TenantError::SlugConflict(slug) => (
                StatusCode::CONFLICT,
                "conflict",
                format!("Slug already exists: {slug}"),
                None,
            ),
            TenantError::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg.clone(), None),
            TenantError::Gone(msg) => (StatusCode::GONE, "gone", msg.clone(), None),
            TenantError::Database(e) => {
                tracing::error!("Database error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "An unexpected error occurred".to_string(),
                    None,
                )
            }
            TenantError::Internal(msg) => {
                tracing::error!("Internal error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "An unexpected error occurred".to_string(),
                    None,
                )
            }
        };

        let body = ErrorResponse {
            error: error_code.to_string(),
            message,
            field,
        };

        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_error_with_field() {
        let error = TenantError::validation_field("Name is required", "organization_name");
        match error {
            TenantError::ValidationField { message, field } => {
                assert_eq!(message, "Name is required");
                assert_eq!(field, Some("organization_name".to_string()));
            }
            _ => panic!("Expected ValidationField error"),
        }
    }

    #[test]
    fn test_validation_error_general() {
        let error = TenantError::validation_general("Invalid request");
        match error {
            TenantError::ValidationField { message, field } => {
                assert_eq!(message, "Invalid request");
                assert_eq!(field, None);
            }
            _ => panic!("Expected ValidationField error"),
        }
    }

    #[test]
    fn test_validation_error_simple() {
        let error = TenantError::Validation("Simple validation error".to_string());
        match error {
            TenantError::Validation(msg) => {
                assert_eq!(msg, "Simple validation error");
            }
            _ => panic!("Expected Validation error"),
        }
    }

    #[test]
    fn test_forbidden_error() {
        let error = TenantError::forbidden("System tenant auth required");
        match error {
            TenantError::Forbidden(msg) => {
                assert_eq!(msg, "System tenant auth required");
            }
            _ => panic!("Expected Forbidden error"),
        }
    }
}
