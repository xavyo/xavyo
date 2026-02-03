//! API Connectors error types.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;
use tracing::error;
use uuid::Uuid;

/// Error type for connector API operations.
#[derive(Debug, Error)]
pub enum ConnectorApiError {
    /// Resource not found.
    #[error("{resource} not found: {id}")]
    NotFound { resource: String, id: String },

    /// Connector not found.
    #[error("connector not found: {0}")]
    ConnectorNotFound(Uuid),

    /// Connector name already exists.
    #[error("connector name already exists: {0}")]
    ConnectorNameExists(String),

    /// Connector is not active.
    #[error("connector {0} is not active (status: {1})")]
    ConnectorNotActive(Uuid, String),

    /// Connector connection test failed.
    #[error("connection test failed: {0}")]
    ConnectionTestFailed(String),

    /// Invalid connector configuration.
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),

    /// Unsupported connector type.
    #[error("unsupported connector type: {0}")]
    UnsupportedConnectorType(String),

    /// Credential encryption failed.
    #[error("credential encryption failed: {0}")]
    EncryptionFailed(String),

    /// Credential decryption failed.
    #[error("credential decryption failed: {0}")]
    DecryptionFailed(String),

    /// Validation error.
    #[error("validation error: {0}")]
    Validation(String),

    /// Database error.
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Connector framework error.
    #[error("connector error: {0}")]
    Connector(#[from] xavyo_connector::error::ConnectorError),

    /// Unauthorized access.
    #[error("unauthorized: {message}")]
    Unauthorized { message: String },

    /// Operation not found.
    #[error("operation not found: {0}")]
    OperationNotFound(Uuid),

    /// Invalid operation state.
    #[error("invalid operation state for {operation_id}: cannot {action} from {current_state}")]
    InvalidOperationState {
        operation_id: Uuid,
        current_state: String,
        action: String,
    },

    /// Operation queue error.
    #[error("queue error: {0}")]
    QueueError(String),

    /// Conflict error (resource already exists or operation in progress).
    #[error("conflict: {0}")]
    Conflict(String),

    /// Health service error.
    #[error("health service error: {0}")]
    HealthError(String),

    /// Sync service error.
    #[error("sync error: {0}")]
    SyncError(String),

    /// Internal server error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for ConnectorApiError {
    fn into_response(self) -> Response {
        let (status, error_type, message) = match &self {
            ConnectorApiError::NotFound { .. } => {
                (StatusCode::NOT_FOUND, "not_found", self.to_string())
            }
            ConnectorApiError::ConnectorNotFound(_) => (
                StatusCode::NOT_FOUND,
                "connector_not_found",
                self.to_string(),
            ),
            ConnectorApiError::ConnectorNameExists(_) => (
                StatusCode::CONFLICT,
                "connector_name_exists",
                self.to_string(),
            ),
            ConnectorApiError::ConnectorNotActive(_, _) => (
                StatusCode::CONFLICT,
                "connector_not_active",
                self.to_string(),
            ),
            ConnectorApiError::ConnectionTestFailed(_) => (
                StatusCode::BAD_GATEWAY,
                "connection_test_failed",
                self.to_string(),
            ),
            ConnectorApiError::InvalidConfiguration(_) => (
                StatusCode::BAD_REQUEST,
                "invalid_configuration",
                self.to_string(),
            ),
            ConnectorApiError::UnsupportedConnectorType(_) => (
                StatusCode::BAD_REQUEST,
                "unsupported_connector_type",
                self.to_string(),
            ),
            ConnectorApiError::EncryptionFailed(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "encryption_failed",
                self.to_string(),
            ),
            ConnectorApiError::DecryptionFailed(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "decryption_failed",
                self.to_string(),
            ),
            ConnectorApiError::Validation(_) => (
                StatusCode::BAD_REQUEST,
                "validation_error",
                self.to_string(),
            ),
            ConnectorApiError::Database(ref e) => {
                error!("Database error occurred: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "database_error",
                    "Internal database error".to_string(),
                )
            }
            ConnectorApiError::Connector(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "connector_error",
                self.to_string(),
            ),
            ConnectorApiError::Unauthorized { .. } => {
                (StatusCode::UNAUTHORIZED, "unauthorized", self.to_string())
            }
            ConnectorApiError::OperationNotFound(_) => (
                StatusCode::NOT_FOUND,
                "operation_not_found",
                self.to_string(),
            ),
            ConnectorApiError::InvalidOperationState { .. } => (
                StatusCode::BAD_REQUEST,
                "invalid_operation_state",
                self.to_string(),
            ),
            ConnectorApiError::QueueError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "queue_error",
                self.to_string(),
            ),
            ConnectorApiError::Conflict(_) => (StatusCode::CONFLICT, "conflict", self.to_string()),
            ConnectorApiError::HealthError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "health_error",
                self.to_string(),
            ),
            ConnectorApiError::SyncError(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "sync_error",
                self.to_string(),
            ),
            ConnectorApiError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                self.to_string(),
            ),
        };

        let body = json!({
            "error": error_type,
            "message": message,
        });

        (status, Json(body)).into_response()
    }
}

impl From<crate::services::OperationServiceError> for ConnectorApiError {
    fn from(err: crate::services::OperationServiceError) -> Self {
        use crate::services::OperationServiceError;
        match err {
            OperationServiceError::Database(e) => ConnectorApiError::Database(e),
            OperationServiceError::Queue(e) => ConnectorApiError::QueueError(e.to_string()),
            OperationServiceError::NotFound(id) => ConnectorApiError::OperationNotFound(id),
            OperationServiceError::InvalidState {
                operation_id,
                current_state,
                action,
            } => ConnectorApiError::InvalidOperationState {
                operation_id,
                current_state,
                action,
            },
            OperationServiceError::ConnectorNotFound(id) => {
                ConnectorApiError::ConnectorNotFound(id)
            }
        }
    }
}

impl From<crate::services::JobServiceError> for ConnectorApiError {
    fn from(err: crate::services::JobServiceError) -> Self {
        use crate::services::JobServiceError;
        match err {
            JobServiceError::Database(e) => ConnectorApiError::Database(e),
            JobServiceError::NotFound(id) => ConnectorApiError::OperationNotFound(id),
            JobServiceError::CannotCancel(id, status) => ConnectorApiError::InvalidOperationState {
                operation_id: id,
                current_state: status,
                action: "cancel".to_string(),
            },
            JobServiceError::DlqNotFound(id) => ConnectorApiError::NotFound {
                resource: "DLQ entry".to_string(),
                id: id.to_string(),
            },
            JobServiceError::AlreadyReplayed(id) => {
                ConnectorApiError::Conflict(format!("DLQ entry {} has already been replayed", id))
            }
        }
    }
}

/// Result type for connector API operations.
pub type Result<T> = std::result::Result<T, ConnectorApiError>;

// Aliases for backward compatibility and convenience
pub type ApiError = ConnectorApiError;

impl ConnectorApiError {
    /// Create an internal error.
    pub fn internal(message: impl Into<String>) -> Self {
        ConnectorApiError::Internal(message.into())
    }

    /// Create a not found error.
    pub fn not_found(message: impl Into<String>) -> Self {
        ConnectorApiError::NotFound {
            resource: "resource".to_string(),
            id: message.into(),
        }
    }

    /// Create a sync error.
    pub fn sync_error(message: impl Into<String>) -> Self {
        ConnectorApiError::SyncError(message.into())
    }

    /// Create a bad request (validation) error.
    pub fn bad_request(message: impl Into<String>) -> Self {
        ConnectorApiError::Validation(message.into())
    }

    /// Create a conflict error.
    pub fn conflict(message: impl Into<String>) -> Self {
        ConnectorApiError::Conflict(message.into())
    }
}
