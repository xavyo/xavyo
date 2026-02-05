//! SCIM-specific error types conforming to RFC 7644 Section 3.12

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// SCIM error types as defined in RFC 7644 Section 3.12
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ScimErrorType {
    /// Filter syntax is invalid
    InvalidFilter,
    /// Rate limit exceeded
    TooMany,
    /// Uniqueness constraint violated (e.g., duplicate userName)
    Uniqueness,
    /// Attempted to modify immutable attribute
    Mutability,
    /// Request syntax is invalid
    InvalidSyntax,
    /// Attribute path is invalid
    InvalidPath,
    /// Target resource not found for operation
    NoTarget,
    /// Attribute value is invalid
    InvalidValue,
    /// SCIM protocol version mismatch
    InvalidVers,
    /// Operation not permitted due to sensitivity
    Sensitive,
}

impl std::fmt::Display for ScimErrorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ScimErrorType::InvalidFilter => "invalidFilter",
            ScimErrorType::TooMany => "tooMany",
            ScimErrorType::Uniqueness => "uniqueness",
            ScimErrorType::Mutability => "mutability",
            ScimErrorType::InvalidSyntax => "invalidSyntax",
            ScimErrorType::InvalidPath => "invalidPath",
            ScimErrorType::NoTarget => "noTarget",
            ScimErrorType::InvalidValue => "invalidValue",
            ScimErrorType::InvalidVers => "invalidVers",
            ScimErrorType::Sensitive => "sensitive",
        };
        write!(f, "{s}")
    }
}

/// SCIM error response as defined in RFC 7644
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScimErrorResponse {
    /// Always ["urn:ietf:params:scim:api:messages:2.0:Error"]
    pub schemas: Vec<String>,
    /// Optional SCIM error type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scim_type: Option<String>,
    /// Human-readable error message
    pub detail: String,
    /// HTTP status code as string
    pub status: String,
}

impl ScimErrorResponse {
    /// Create a new SCIM error response
    pub fn new(
        status: StatusCode,
        detail: impl Into<String>,
        scim_type: Option<ScimErrorType>,
    ) -> Self {
        Self {
            schemas: vec!["urn:ietf:params:scim:api:messages:2.0:Error".to_string()],
            scim_type: scim_type.map(|t| t.to_string()),
            detail: detail.into(),
            status: status.as_u16().to_string(),
        }
    }
}

/// SCIM API errors
#[derive(Debug, Error)]
pub enum ScimError {
    /// Invalid or expired Bearer token
    #[error("Invalid or expired bearer token")]
    Unauthorized,

    /// Resource not found
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Uniqueness constraint violated
    #[error("A {resource_type} with {field} '{value}' already exists")]
    Conflict {
        resource_type: String,
        field: String,
        value: String,
    },

    /// Invalid SCIM filter syntax
    #[error("Invalid filter: {0}")]
    InvalidFilter(String),

    /// Invalid request syntax
    #[error("Invalid request: {0}")]
    BadRequest(String),

    /// Rate limit exceeded
    #[error("Rate limit exceeded. Try again in {retry_after} seconds.")]
    RateLimitExceeded { retry_after: u32 },

    /// Internal server error
    #[error("Internal server error: {0}")]
    Internal(String),

    /// Database error
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Validation error
    #[error("Validation error: {0}")]
    Validation(String),

    /// Forbidden - tenant mismatch
    #[error("Access denied: tenant mismatch")]
    Forbidden,

    /// Invalid PATCH operation
    #[error("Invalid PATCH operation: {0}")]
    InvalidPatchOp(String),
}

impl ScimError {
    /// Get the HTTP status code for this error
    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        match self {
            ScimError::Unauthorized => StatusCode::UNAUTHORIZED,
            ScimError::NotFound(_) => StatusCode::NOT_FOUND,
            ScimError::Conflict { .. } => StatusCode::CONFLICT,
            ScimError::InvalidFilter(_) => StatusCode::BAD_REQUEST,
            ScimError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ScimError::RateLimitExceeded { .. } => StatusCode::TOO_MANY_REQUESTS,
            ScimError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ScimError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ScimError::Validation(_) => StatusCode::BAD_REQUEST,
            ScimError::Forbidden => StatusCode::FORBIDDEN,
            ScimError::InvalidPatchOp(_) => StatusCode::BAD_REQUEST,
        }
    }

    /// Get the SCIM error type for this error
    #[must_use]
    pub fn scim_type(&self) -> Option<ScimErrorType> {
        match self {
            ScimError::Conflict { .. } => Some(ScimErrorType::Uniqueness),
            ScimError::InvalidFilter(_) => Some(ScimErrorType::InvalidFilter),
            ScimError::RateLimitExceeded { .. } => Some(ScimErrorType::TooMany),
            ScimError::BadRequest(_) => Some(ScimErrorType::InvalidSyntax),
            ScimError::Validation(_) => Some(ScimErrorType::InvalidValue),
            ScimError::InvalidPatchOp(_) => Some(ScimErrorType::InvalidPath),
            _ => None,
        }
    }

    /// Convert to SCIM error response
    #[must_use]
    pub fn to_response(&self) -> ScimErrorResponse {
        ScimErrorResponse::new(self.status_code(), self.to_string(), self.scim_type())
    }
}

impl IntoResponse for ScimError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let mut response = (status, Json(self.to_response())).into_response();

        // Add Retry-After header for rate limiting
        if let ScimError::RateLimitExceeded { retry_after } = &self {
            response
                .headers_mut()
                .insert("Retry-After", retry_after.to_string().parse().unwrap());
        }

        // Set SCIM content type
        response
            .headers_mut()
            .insert("Content-Type", "application/scim+json".parse().unwrap());

        response
    }
}

/// Result type alias for SCIM operations
pub type ScimResult<T> = Result<T, ScimError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scim_error_type_display() {
        assert_eq!(ScimErrorType::InvalidFilter.to_string(), "invalidFilter");
        assert_eq!(ScimErrorType::TooMany.to_string(), "tooMany");
        assert_eq!(ScimErrorType::Uniqueness.to_string(), "uniqueness");
    }

    #[test]
    fn test_scim_error_response() {
        let response = ScimErrorResponse::new(
            StatusCode::CONFLICT,
            "User already exists",
            Some(ScimErrorType::Uniqueness),
        );

        assert_eq!(response.schemas.len(), 1);
        assert_eq!(response.status, "409");
        assert_eq!(response.scim_type, Some("uniqueness".to_string()));
    }

    #[test]
    fn test_conflict_error() {
        let err = ScimError::Conflict {
            resource_type: "user".to_string(),
            field: "userName".to_string(),
            value: "john@example.com".to_string(),
        };

        assert_eq!(err.status_code(), StatusCode::CONFLICT);
        assert_eq!(err.scim_type(), Some(ScimErrorType::Uniqueness));
    }

    #[test]
    fn test_rate_limit_error() {
        let err = ScimError::RateLimitExceeded { retry_after: 2 };

        assert_eq!(err.status_code(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(err.scim_type(), Some(ScimErrorType::TooMany));
    }
}
