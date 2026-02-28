//! Error types for the authorization engine.

use thiserror::Error;

/// Errors that can occur during authorization evaluation.
#[derive(Debug, Error)]
pub enum AuthorizationError {
    /// The specified policy was not found.
    #[error("Policy not found: {0}")]
    PolicyNotFound(String),

    /// The specified mapping was not found.
    #[error("Mapping not found: {0}")]
    MappingNotFound(String),

    /// A condition in a policy is invalid or malformed.
    #[error("Invalid condition: {0}")]
    InvalidCondition(String),

    /// Evaluation of a policy or condition failed.
    #[error("Evaluation failed: {0}")]
    EvaluationFailed(String),

    /// A database error occurred during evaluation.
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// The request is unauthorized (no matching allow policy or entitlement).
    #[error("Unauthorized")]
    Unauthorized,

    /// A generic resource was not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// A Cedar policy error.
    #[error("Cedar policy error: {0}")]
    CedarError(String),
}

/// Convenience Result type for the authorization engine.
pub type Result<T> = std::result::Result<T, AuthorizationError>;
