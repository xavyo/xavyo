//! Connector Framework error types
//!
//! Error definitions with transient/permanent classification for retry logic.

use thiserror::Error;

use crate::ids::{ConnectorId, MappingId, OperationId};

/// Error that can occur during connector operations.
#[derive(Debug, Error)]
pub enum ConnectorError {
    // Connection errors (usually transient)
    /// Failed to establish connection to target system.
    #[error("connection failed: {message}")]
    ConnectionFailed {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Connection timed out.
    #[error("connection timeout after {timeout_secs} seconds")]
    ConnectionTimeout { timeout_secs: u64 },

    /// Target system is temporarily unavailable.
    #[error("target system unavailable: {message}")]
    TargetUnavailable { message: String },

    /// Network error during communication.
    #[error("network error: {message}")]
    NetworkError {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    // Authentication errors (usually permanent)
    /// Invalid credentials provided.
    #[error("authentication failed: invalid credentials")]
    AuthenticationFailed,

    /// Credentials have expired.
    #[error("authentication failed: credentials expired")]
    CredentialsExpired,

    /// Insufficient permissions for the operation.
    #[error("authorization failed: insufficient permissions for {operation}")]
    AuthorizationFailed { operation: String },

    // Configuration errors (permanent)
    /// Connector configuration is invalid.
    #[error("invalid configuration: {message}")]
    InvalidConfiguration { message: String },

    /// Connector type is not supported.
    #[error("unsupported connector type: {connector_type}")]
    UnsupportedConnectorType { connector_type: String },

    /// Connector not found.
    #[error("connector not found: {connector_id}")]
    ConnectorNotFound { connector_id: ConnectorId },

    /// Connector is not in the correct state for the operation.
    #[error("connector {connector_id} is not active (current status: {status})")]
    ConnectorNotActive {
        connector_id: ConnectorId,
        status: String,
    },

    // Schema errors
    /// Failed to discover schema.
    #[error("schema discovery failed: {message}")]
    SchemaDiscoveryFailed { message: String },

    /// Object class not found in schema.
    #[error("object class '{object_class}' not found in schema")]
    ObjectClassNotFound { object_class: String },

    /// Attribute not found in schema.
    #[error("attribute '{attribute}' not found in object class '{object_class}'")]
    AttributeNotFound {
        attribute: String,
        object_class: String,
    },

    /// Schema is expired and needs refresh.
    #[error("schema expired for connector {connector_id}")]
    SchemaExpired { connector_id: ConnectorId },

    // Mapping errors
    /// Attribute mapping not found.
    #[error("mapping not found: {mapping_id}")]
    MappingNotFound { mapping_id: MappingId },

    /// Invalid mapping configuration.
    #[error("invalid mapping: {message}")]
    InvalidMapping { message: String },

    /// Transformation failed during attribute mapping.
    #[error("transformation failed for attribute '{attribute}': {message}")]
    TransformationFailed { attribute: String, message: String },

    // Operation errors
    /// Operation not found.
    #[error("operation not found: {operation_id}")]
    OperationNotFound { operation_id: OperationId },

    /// Operation failed.
    #[error("operation failed: {message}")]
    OperationFailed {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Object already exists in target system (create conflict).
    #[error("object already exists: {identifier}")]
    ObjectAlreadyExists { identifier: String },

    /// Object not found in target system (update/delete target missing).
    #[error("object not found: {identifier}")]
    ObjectNotFound { identifier: String },

    /// Constraint violation in target system.
    #[error("constraint violation: {message}")]
    ConstraintViolation { message: String },

    /// Invalid data format.
    #[error("invalid data: {message}")]
    InvalidData { message: String },

    // Correlation errors
    /// Correlation failed - no match found.
    #[error("correlation failed: no match found for {attribute}={value}")]
    CorrelationNoMatch { attribute: String, value: String },

    /// Correlation failed - multiple matches found.
    #[error("correlation failed: multiple matches found for {attribute}={value}")]
    CorrelationMultipleMatches { attribute: String, value: String },

    // Encryption errors
    /// Credential encryption failed.
    #[error("encryption failed: {message}")]
    EncryptionFailed { message: String },

    /// Credential decryption failed.
    #[error("decryption failed: {message}")]
    DecryptionFailed { message: String },

    /// Key version not found for decryption.
    #[error("key version {version} not found")]
    KeyVersionNotFound { version: i32 },

    // Queue/retry errors
    /// Maximum retries exceeded.
    #[error("maximum retries ({max_retries}) exceeded for operation {operation_id}")]
    MaxRetriesExceeded {
        operation_id: OperationId,
        max_retries: i32,
    },

    /// Circuit breaker is open.
    #[error("circuit breaker open for connector {connector_id}")]
    CircuitOpen { connector_id: ConnectorId },

    // Internal errors
    /// Internal error.
    #[error("internal error: {message}")]
    Internal {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Database error.
    #[error("database error: {message}")]
    Database {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Serialization error.
    #[error("serialization error: {message}")]
    Serialization { message: String },
}

impl ConnectorError {
    /// Check if this error is transient and the operation should be retried.
    ///
    /// Transient errors are those caused by temporary conditions that may resolve
    /// themselves, such as network issues or temporary unavailability.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            ConnectorError::ConnectionFailed { .. }
                | ConnectorError::ConnectionTimeout { .. }
                | ConnectorError::TargetUnavailable { .. }
                | ConnectorError::NetworkError { .. }
                | ConnectorError::CircuitOpen { .. }
        )
    }

    /// Check if this error is permanent and retry won't help.
    ///
    /// Permanent errors require human intervention or configuration changes.
    pub fn is_permanent(&self) -> bool {
        !self.is_transient()
    }

    /// Get an error code for classification.
    pub fn error_code(&self) -> &'static str {
        match self {
            ConnectorError::ConnectionFailed { .. } => "CONNECTION_FAILED",
            ConnectorError::ConnectionTimeout { .. } => "CONNECTION_TIMEOUT",
            ConnectorError::TargetUnavailable { .. } => "TARGET_UNAVAILABLE",
            ConnectorError::NetworkError { .. } => "NETWORK_ERROR",
            ConnectorError::AuthenticationFailed => "AUTH_FAILED",
            ConnectorError::CredentialsExpired => "CREDENTIALS_EXPIRED",
            ConnectorError::AuthorizationFailed { .. } => "AUTHORIZATION_FAILED",
            ConnectorError::InvalidConfiguration { .. } => "INVALID_CONFIG",
            ConnectorError::UnsupportedConnectorType { .. } => "UNSUPPORTED_TYPE",
            ConnectorError::ConnectorNotFound { .. } => "CONNECTOR_NOT_FOUND",
            ConnectorError::ConnectorNotActive { .. } => "CONNECTOR_NOT_ACTIVE",
            ConnectorError::SchemaDiscoveryFailed { .. } => "SCHEMA_DISCOVERY_FAILED",
            ConnectorError::ObjectClassNotFound { .. } => "OBJECT_CLASS_NOT_FOUND",
            ConnectorError::AttributeNotFound { .. } => "ATTRIBUTE_NOT_FOUND",
            ConnectorError::SchemaExpired { .. } => "SCHEMA_EXPIRED",
            ConnectorError::MappingNotFound { .. } => "MAPPING_NOT_FOUND",
            ConnectorError::InvalidMapping { .. } => "INVALID_MAPPING",
            ConnectorError::TransformationFailed { .. } => "TRANSFORMATION_FAILED",
            ConnectorError::OperationNotFound { .. } => "OPERATION_NOT_FOUND",
            ConnectorError::OperationFailed { .. } => "OPERATION_FAILED",
            ConnectorError::ObjectAlreadyExists { .. } => "OBJECT_EXISTS",
            ConnectorError::ObjectNotFound { .. } => "OBJECT_NOT_FOUND",
            ConnectorError::ConstraintViolation { .. } => "CONSTRAINT_VIOLATION",
            ConnectorError::InvalidData { .. } => "INVALID_DATA",
            ConnectorError::CorrelationNoMatch { .. } => "CORRELATION_NO_MATCH",
            ConnectorError::CorrelationMultipleMatches { .. } => "CORRELATION_MULTIPLE_MATCHES",
            ConnectorError::EncryptionFailed { .. } => "ENCRYPTION_FAILED",
            ConnectorError::DecryptionFailed { .. } => "DECRYPTION_FAILED",
            ConnectorError::KeyVersionNotFound { .. } => "KEY_VERSION_NOT_FOUND",
            ConnectorError::MaxRetriesExceeded { .. } => "MAX_RETRIES_EXCEEDED",
            ConnectorError::CircuitOpen { .. } => "CIRCUIT_OPEN",
            ConnectorError::Internal { .. } => "INTERNAL_ERROR",
            ConnectorError::Database { .. } => "DATABASE_ERROR",
            ConnectorError::Serialization { .. } => "SERIALIZATION_ERROR",
        }
    }

    // Convenience constructors

    /// Create a connection failed error.
    pub fn connection_failed(message: impl Into<String>) -> Self {
        ConnectorError::ConnectionFailed {
            message: message.into(),
            source: None,
        }
    }

    /// Create a connection failed error with source.
    pub fn connection_failed_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        ConnectorError::ConnectionFailed {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create an operation failed error.
    pub fn operation_failed(message: impl Into<String>) -> Self {
        ConnectorError::OperationFailed {
            message: message.into(),
            source: None,
        }
    }

    /// Create an operation failed error with source.
    pub fn operation_failed_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        ConnectorError::OperationFailed {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create an internal error.
    pub fn internal(message: impl Into<String>) -> Self {
        ConnectorError::Internal {
            message: message.into(),
            source: None,
        }
    }

    /// Create an internal error with source.
    pub fn internal_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        ConnectorError::Internal {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create a database error.
    pub fn database(message: impl Into<String>) -> Self {
        ConnectorError::Database {
            message: message.into(),
            source: None,
        }
    }

    /// Create a database error with source.
    pub fn database_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        ConnectorError::Database {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    /// Create a network error.
    pub fn network(message: impl Into<String>) -> Self {
        ConnectorError::NetworkError {
            message: message.into(),
            source: None,
        }
    }

    /// Create a network error with source.
    pub fn network_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        ConnectorError::NetworkError {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }
}

/// Result type for connector operations.
pub type ConnectorResult<T> = Result<T, ConnectorError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transient_errors() {
        let transient_errors = vec![
            ConnectorError::connection_failed("test"),
            ConnectorError::ConnectionTimeout { timeout_secs: 30 },
            ConnectorError::TargetUnavailable {
                message: "test".to_string(),
            },
            ConnectorError::network("test"),
            ConnectorError::CircuitOpen {
                connector_id: ConnectorId::new(),
            },
        ];

        for err in transient_errors {
            assert!(
                err.is_transient(),
                "Expected {} to be transient",
                err.error_code()
            );
            assert!(
                !err.is_permanent(),
                "Expected {} to not be permanent",
                err.error_code()
            );
        }
    }

    #[test]
    fn test_permanent_errors() {
        let permanent_errors = vec![
            ConnectorError::AuthenticationFailed,
            ConnectorError::AuthorizationFailed {
                operation: "create".to_string(),
            },
            ConnectorError::InvalidConfiguration {
                message: "test".to_string(),
            },
            ConnectorError::ObjectAlreadyExists {
                identifier: "test".to_string(),
            },
            ConnectorError::ObjectNotFound {
                identifier: "test".to_string(),
            },
        ];

        for err in permanent_errors {
            assert!(
                err.is_permanent(),
                "Expected {} to be permanent",
                err.error_code()
            );
            assert!(
                !err.is_transient(),
                "Expected {} to not be transient",
                err.error_code()
            );
        }
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(
            ConnectorError::AuthenticationFailed.error_code(),
            "AUTH_FAILED"
        );
        assert_eq!(
            ConnectorError::connection_failed("test").error_code(),
            "CONNECTION_FAILED"
        );
        assert_eq!(
            ConnectorError::operation_failed("test").error_code(),
            "OPERATION_FAILED"
        );
    }

    #[test]
    fn test_error_display() {
        let err = ConnectorError::ConnectionTimeout { timeout_secs: 30 };
        assert_eq!(err.to_string(), "connection timeout after 30 seconds");

        let err = ConnectorError::AuthorizationFailed {
            operation: "delete".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "authorization failed: insufficient permissions for delete"
        );
    }

    #[test]
    fn test_error_with_source() {
        let source_err = std::io::Error::new(std::io::ErrorKind::Other, "underlying error");
        let err = ConnectorError::connection_failed_with_source("failed", source_err);

        assert!(err.is_transient());
        // Check that we can get the source error
        if let ConnectorError::ConnectionFailed { source, .. } = &err {
            assert!(source.is_some());
        } else {
            panic!("Expected ConnectionFailed variant");
        }
    }
}
