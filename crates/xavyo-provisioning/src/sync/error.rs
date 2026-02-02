//! Sync error types.

use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur during synchronization.
#[derive(Debug, Error)]
pub enum SyncError {
    /// Database error.
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Connector error.
    #[error("Connector error: {message}")]
    Connector { message: String },

    /// Configuration error.
    #[error("Configuration error: {message}")]
    Configuration { message: String },

    /// Token error (invalid or expired).
    #[error("Sync token error: {message}")]
    Token { message: String },

    /// Correlation error.
    #[error("Correlation error: {message}")]
    Correlation { message: String },

    /// Mapping error.
    #[error("Mapping error: attribute '{attribute}' - {message}")]
    Mapping { attribute: String, message: String },

    /// Conflict detected.
    #[error("Conflict detected for change {change_id}: {message}")]
    Conflict { change_id: Uuid, message: String },

    /// Rate limited.
    #[error("Rate limited: {message}")]
    RateLimited { message: String },

    /// Sync disabled.
    #[error("Sync is disabled for connector {connector_id}")]
    Disabled { connector_id: Uuid },

    /// Not found.
    #[error("{entity} not found: {id}")]
    NotFound { entity: String, id: String },

    /// Invalid state transition.
    #[error("Invalid state transition from {from} to {to}")]
    InvalidStateTransition { from: String, to: String },

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Internal error.
    #[error("Internal error: {message}")]
    Internal { message: String },
}

impl SyncError {
    /// Create a connector error.
    pub fn connector(message: impl Into<String>) -> Self {
        Self::Connector {
            message: message.into(),
        }
    }

    /// Create a configuration error.
    pub fn configuration(message: impl Into<String>) -> Self {
        Self::Configuration {
            message: message.into(),
        }
    }

    /// Create a token error.
    pub fn token(message: impl Into<String>) -> Self {
        Self::Token {
            message: message.into(),
        }
    }

    /// Create a correlation error.
    pub fn correlation(message: impl Into<String>) -> Self {
        Self::Correlation {
            message: message.into(),
        }
    }

    /// Create a mapping error.
    pub fn mapping(attribute: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Mapping {
            attribute: attribute.into(),
            message: message.into(),
        }
    }

    /// Create a conflict error.
    pub fn conflict(change_id: Uuid, message: impl Into<String>) -> Self {
        Self::Conflict {
            change_id,
            message: message.into(),
        }
    }

    /// Create a rate limited error.
    pub fn rate_limited(message: impl Into<String>) -> Self {
        Self::RateLimited {
            message: message.into(),
        }
    }

    /// Create a disabled error.
    pub fn disabled(connector_id: Uuid) -> Self {
        Self::Disabled { connector_id }
    }

    /// Create a not found error.
    pub fn not_found(entity: impl Into<String>, id: impl Into<String>) -> Self {
        Self::NotFound {
            entity: entity.into(),
            id: id.into(),
        }
    }

    /// Create an invalid state transition error.
    pub fn invalid_state_transition(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self::InvalidStateTransition {
            from: from.into(),
            to: to.into(),
        }
    }

    /// Create an internal error.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    /// Check if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            SyncError::Database(_)
                | SyncError::Connector { .. }
                | SyncError::RateLimited { .. }
                | SyncError::Io(_)
        )
    }

    /// Check if this error indicates a conflict.
    pub fn is_conflict(&self) -> bool {
        matches!(self, SyncError::Conflict { .. })
    }
}

/// Result type for sync operations.
pub type SyncResult<T> = Result<T, SyncError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = SyncError::connector("Connection refused");
        assert!(err.to_string().contains("Connection refused"));

        let err = SyncError::mapping("email", "Invalid format");
        assert!(err.to_string().contains("email"));
        assert!(err.to_string().contains("Invalid format"));
    }

    #[test]
    fn test_is_retryable() {
        assert!(SyncError::connector("timeout").is_retryable());
        assert!(SyncError::rate_limited("too many requests").is_retryable());
        assert!(!SyncError::configuration("invalid").is_retryable());
        assert!(!SyncError::disabled(Uuid::new_v4()).is_retryable());
    }

    #[test]
    fn test_is_conflict() {
        let change_id = Uuid::new_v4();
        assert!(SyncError::conflict(change_id, "concurrent update").is_conflict());
        assert!(!SyncError::connector("error").is_conflict());
    }
}
