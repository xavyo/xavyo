//! Error types for the unified NHI API.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

/// Error type for the NHI API endpoints.
#[derive(Debug, Error)]
pub enum ApiNhiError {
    /// Missing or invalid authentication.
    #[error("Unauthorized: missing or invalid authentication")]
    Unauthorized,

    /// Resource not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// Bad request with validation errors.
    #[error("Bad request: {0}")]
    BadRequest(String),

    /// Forbidden: insufficient permissions.
    #[error("Forbidden: {0}")]
    Forbidden(String),

    /// Conflict error (e.g., duplicate resource).
    #[error("Conflict: {0}")]
    Conflict(String),

    /// Internal server error.
    #[error("Internal error: {0}")]
    Internal(String),

    /// Error from governance service.
    #[error("Governance error: {0}")]
    Governance(#[from] xavyo_api_governance::ApiGovernanceError),

    /// Error from agents service.
    #[error("Agents error: {0}")]
    Agents(#[from] xavyo_api_agents::ApiAgentsError),

    /// Database error.
    #[error("Database error: {0}")]
    DatabaseSqlx(#[from] sqlx::Error),

    /// Database error (string variant for service layer).
    #[error("Database error: {0}")]
    Database(String),

    // =========================================================================
    // Agent Credential Errors (F110)
    // =========================================================================
    /// Agent not found.
    #[error("Agent not found: {0}")]
    AgentNotFound(uuid::Uuid),

    /// Agent is suspended.
    #[error("Agent is suspended: {0}")]
    AgentSuspended(uuid::Uuid),

    /// Credential not found.
    #[error("Credential not found: {0}")]
    CredentialNotFound(uuid::Uuid),

    /// Credential already revoked.
    #[error("Credential already revoked: {0}")]
    CredentialAlreadyRevoked(uuid::Uuid),

    /// Invalid expiration date.
    #[error("Invalid expiration date: must be in the future")]
    InvalidExpirationDate,

    /// Invalid credential.
    #[error("Invalid credential")]
    InvalidCredential,

    /// Credential expired.
    #[error("Credential expired: {0}")]
    CredentialExpired(uuid::Uuid),

    /// Rate limit exceeded for credential rotation.
    #[error("Rate limit exceeded: {0}")]
    RotationRateLimitExceeded(String),
}

/// Error response body.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

impl IntoResponse for ApiNhiError {
    fn into_response(self) -> Response {
        // Handle delegated errors first (they need to consume self)
        match self {
            ApiNhiError::Governance(e) => {
                // Delegate to governance error handling
                e.into_response()
            }
            ApiNhiError::Agents(e) => {
                // Delegate to agents error handling
                e.into_response()
            }
            other => {
                // Handle our own error types
                let (status, error_type, message) = match &other {
                    ApiNhiError::Unauthorized => {
                        (StatusCode::UNAUTHORIZED, "unauthorized", other.to_string())
                    }
                    ApiNhiError::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg.clone()),
                    ApiNhiError::BadRequest(msg) => {
                        (StatusCode::BAD_REQUEST, "bad_request", msg.clone())
                    }
                    ApiNhiError::Forbidden(msg) => {
                        (StatusCode::FORBIDDEN, "forbidden", msg.clone())
                    }
                    ApiNhiError::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg.clone()),
                    ApiNhiError::Internal(msg) => {
                        tracing::error!("Internal error: {}", msg);
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "internal_error",
                            "An internal error occurred".to_string(),
                        )
                    }
                    ApiNhiError::DatabaseSqlx(e) => {
                        tracing::error!("Database error: {}", e);
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "database_error",
                            "A database error occurred".to_string(),
                        )
                    }
                    ApiNhiError::Database(msg) => {
                        tracing::error!("Database error: {}", msg);
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "database_error",
                            "A database error occurred".to_string(),
                        )
                    }
                    // Agent credential errors (F110)
                    ApiNhiError::AgentNotFound(id) => (
                        StatusCode::NOT_FOUND,
                        "agent_not_found",
                        format!("Agent not found: {id}"),
                    ),
                    ApiNhiError::AgentSuspended(id) => (
                        StatusCode::BAD_REQUEST,
                        "agent_suspended",
                        format!("Agent is suspended: {id}"),
                    ),
                    ApiNhiError::CredentialNotFound(id) => (
                        StatusCode::NOT_FOUND,
                        "credential_not_found",
                        format!("Credential not found: {id}"),
                    ),
                    ApiNhiError::CredentialAlreadyRevoked(id) => (
                        StatusCode::BAD_REQUEST,
                        "credential_already_revoked",
                        format!("Credential already revoked: {id}"),
                    ),
                    ApiNhiError::InvalidExpirationDate => (
                        StatusCode::BAD_REQUEST,
                        "invalid_expiration_date",
                        "Expiration date must be in the future".to_string(),
                    ),
                    ApiNhiError::InvalidCredential => (
                        StatusCode::UNAUTHORIZED,
                        "invalid_credential",
                        "Invalid or expired credential".to_string(),
                    ),
                    ApiNhiError::CredentialExpired(id) => (
                        StatusCode::UNAUTHORIZED,
                        "credential_expired",
                        format!("Credential expired: {id}"),
                    ),
                    ApiNhiError::RotationRateLimitExceeded(msg) => (
                        StatusCode::TOO_MANY_REQUESTS,
                        "rate_limit_exceeded",
                        msg.clone(),
                    ),
                    // These are handled above, but needed for exhaustive match
                    ApiNhiError::Governance(_) | ApiNhiError::Agents(_) => unreachable!(),
                };

                let body = ErrorResponse {
                    error: error_type.to_string(),
                    message,
                };

                (status, Json(body)).into_response()
            }
        }
    }
}

/// Result type alias for NHI API operations.
pub type ApiResult<T> = Result<T, ApiNhiError>;

impl From<validator::ValidationErrors> for ApiNhiError {
    fn from(err: validator::ValidationErrors) -> Self {
        Self::BadRequest(err.to_string())
    }
}

/// Conversion from governance domain error to API error.
impl From<xavyo_governance::error::GovernanceError> for ApiNhiError {
    fn from(e: xavyo_governance::error::GovernanceError) -> Self {
        ApiNhiError::Governance(xavyo_api_governance::ApiGovernanceError::from(e))
    }
}
