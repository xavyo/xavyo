use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScimClientError {
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Authentication failed: {0}")]
    AuthError(String),

    #[error("Rate limited by target (retry after {retry_after_secs:?}s)")]
    RateLimited { retry_after_secs: Option<u64> },

    #[error("Request timed out after {timeout_secs}s")]
    Timeout { timeout_secs: u64 },

    #[error("SCIM conflict (409): {0}")]
    Conflict(String),

    #[error("SCIM resource not found (404): {0}")]
    NotFound(String),

    #[error("SCIM error response ({status}): {detail}")]
    ScimError { status: u16, detail: String },

    #[error("Failed to parse SCIM response: {0}")]
    ParseError(String),

    #[error("Credential encryption/decryption failed: {0}")]
    EncryptionError(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Target is unreachable: {0}")]
    Unreachable(String),

    #[error("Operation permanently failed after {attempts} attempts: {message}")]
    MaxRetriesExceeded { attempts: u32, message: String },

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

pub type ScimClientResult<T> = Result<T, ScimClientError>;

impl ScimClientError {
    /// Returns true if this error should be retried.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ScimClientError::HttpError(_)
                | ScimClientError::RateLimited { .. }
                | ScimClientError::Timeout { .. }
                | ScimClientError::Unreachable(_)
        )
    }

    /// Returns true if this is a SCIM server error (5xx) that may be retried.
    #[must_use]
    pub fn is_server_error(&self) -> bool {
        matches!(self, ScimClientError::ScimError { status, .. } if *status >= 500)
    }
}
