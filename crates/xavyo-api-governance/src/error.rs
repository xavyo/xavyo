//! API error types for governance endpoints.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;
use xavyo_governance::error::GovernanceError;

/// API error response body.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    /// Error code for client handling.
    pub error: String,
    /// Human-readable error message.
    pub message: String,
    /// Optional additional details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Governance API error type.
#[derive(Debug, Error)]
pub enum ApiGovernanceError {
    /// Domain error from governance crate.
    #[error(transparent)]
    Governance(#[from] GovernanceError),

    /// Validation error.
    #[error("Validation error: {0}")]
    Validation(String),

    /// Authentication required.
    #[error("Authentication required")]
    Unauthorized,

    /// Access denied.
    #[error("Access denied")]
    Forbidden,

    /// Resource not found.
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Approval step not found.
    #[error("Approval step not found: {0}")]
    StepNotFound(Uuid),

    /// Micro-certification not found.
    #[error("Micro-certification not found: {0}")]
    MicroCertificationNotFound(Uuid),

    /// Micro-certification trigger rule not found.
    #[error("Micro-certification trigger rule not found: {0}")]
    MicroCertTriggerNotFound(Uuid),

    // Semi-manual Resources errors (F064)
    /// Ticketing configuration not found.
    #[error("Ticketing configuration not found: {0}")]
    TicketingConfigurationNotFound(Uuid),

    /// SLA policy not found.
    #[error("SLA policy not found: {0}")]
    SlaPolicyNotFound(Uuid),

    /// Manual provisioning task not found.
    #[error("Manual provisioning task not found: {0}")]
    ManualProvisioningTaskNotFound(Uuid),

    /// External ticket not found.
    #[error("External ticket not found: {0}")]
    ExternalTicketNotFound(Uuid),

    /// Ticketing integration failure.
    #[error("Ticketing integration failed: {0}")]
    TicketingIntegrationFailed(String),

    /// Task already completed.
    #[error("Task is already completed: {0}")]
    TaskAlreadyCompleted(Uuid),

    /// Invalid task status transition.
    #[error("Invalid task status transition from {from} to {to}")]
    InvalidTaskStatusTransition { from: String, to: String },

    /// Application is not configured as semi-manual.
    #[error("Application {0} is not configured for semi-manual provisioning")]
    ApplicationNotSemiManual(Uuid),

    /// Ticket creation failed.
    #[error("Ticket creation failed: {0}")]
    TicketCreationFailed(String),

    /// External ticket sync failed.
    #[error("External ticket sync failed: {0}")]
    TicketSyncFailed(String),

    /// SLA breach detected.
    #[error("SLA breach detected for task {0}")]
    SlaBreached(Uuid),

    // Identity Archetype errors (F-058)
    /// Identity archetype not found.
    #[error("Identity archetype not found: {0}")]
    ArchetypeNotFound(Uuid),

    /// Archetype name already exists.
    #[error("Archetype name already exists: {0}")]
    ArchetypeNameExists(String),

    /// Circular inheritance detected.
    #[error("Circular inheritance detected: setting parent would create a cycle")]
    CircularInheritance,

    /// Cannot delete archetype with assigned users.
    #[error("Cannot delete archetype: {count} users are assigned to archetype {id}")]
    ArchetypeHasAssignedUsers { id: Uuid, count: i64 },

    /// Invalid schema extension.
    #[error("Invalid schema extension: {0}")]
    InvalidSchemaExtension(String),

    /// Invalid archetype custom attributes.
    #[error("Invalid archetype custom attributes: {0}")]
    InvalidArchetypeCustomAttrs(String),

    /// Conflict (duplicate resource).
    #[error("Conflict: {0}")]
    Conflict(String),

    /// Internal server error.
    #[error("Internal server error: {0}")]
    Internal(String),

    /// Database error.
    #[error("Database error")]
    Database(#[from] sqlx::Error),

    // Bulk Action Engine errors (F-064)
    /// Bulk action not found.
    #[error("Bulk action not found: {0}")]
    BulkActionNotFound(Uuid),

    /// Invalid filter expression.
    #[error("Invalid filter expression: {0}")]
    InvalidExpression(String),

    /// Bulk action already executed.
    #[error("Bulk action already executed or cancelled: {0}")]
    BulkActionAlreadyExecuted(Uuid),

    /// Bulk action cannot be cancelled.
    #[error("Bulk action cannot be cancelled (status: {status}): {id}")]
    BulkActionCannotCancel { id: Uuid, status: String },

    /// Bulk action cannot be cancelled (simple version).
    #[error("Bulk action cannot be cancelled: {0}")]
    BulkActionCannotBeCancelled(Uuid),

    /// Bulk action cannot be deleted.
    #[error("Bulk action cannot be deleted (status: {status}): {id}")]
    BulkActionCannotDelete { id: Uuid, status: String },
}

impl IntoResponse for ApiGovernanceError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match &self {
            Self::Governance(e) => {
                if e.is_not_found() {
                    (StatusCode::NOT_FOUND, "not_found", e.to_string())
                } else if e.is_conflict() {
                    (StatusCode::CONFLICT, "conflict", e.to_string())
                } else if e.is_forbidden() {
                    (StatusCode::FORBIDDEN, "forbidden", e.to_string())
                } else if e.is_precondition_failed() {
                    (
                        StatusCode::PRECONDITION_FAILED,
                        "precondition_failed",
                        e.to_string(),
                    )
                } else {
                    match e {
                        GovernanceError::Validation(msg) => {
                            (StatusCode::BAD_REQUEST, "validation_error", msg.clone())
                        }
                        GovernanceError::InvalidExpirationDate
                        | GovernanceError::JustificationTooShort
                        | GovernanceError::RejectionCommentsRequired
                        | GovernanceError::InvalidDelegationPeriod
                        | GovernanceError::InvalidRequestedExpiration
                        | GovernanceError::InvalidWorkflowSteps
                        | GovernanceError::InvalidWeight(_)
                        | GovernanceError::InvalidThresholdScore(_)
                        | GovernanceError::InvalidCooldownHours(_)
                        | GovernanceError::PeerGroupTooSmall(_)
                        | GovernanceError::InvalidRemediationAction { .. }
                        | GovernanceError::NewOwnerRequiredForReassignment
                        | GovernanceError::InvalidScheduleHour(_)
                        | GovernanceError::InvalidScheduleDayOfWeek(_)
                        | GovernanceError::InvalidScheduleDayOfMonth(_)
                        | GovernanceError::MissingScheduleDayOfWeek
                        | GovernanceError::MissingScheduleDayOfMonth
                        | GovernanceError::NoRecipientsSpecified
                        | GovernanceError::InvalidRecipientEmail(_)
                        | GovernanceError::ReportGenerationFailed(_)
                        | GovernanceError::PersonaExtensionExceedsMax { .. }
                        | GovernanceError::InvalidMiningParameters(_) => {
                            (StatusCode::BAD_REQUEST, "validation_error", e.to_string())
                        }
                        GovernanceError::Database(ref db_err) => {
                            tracing::error!("GovernanceError::Database: {:?}", db_err);
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "database_error",
                                "Database error".to_string(),
                            )
                        }
                        _ => {
                            tracing::error!("Unhandled governance error: {:?}", e);
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "internal_error",
                                "An internal error occurred".to_string(),
                            )
                        }
                    }
                }
            }
            Self::Validation(msg) => (StatusCode::BAD_REQUEST, "validation_error", msg.clone()),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Authentication required".to_string(),
            ),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "Access denied".to_string(),
            ),
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg.clone()),
            Self::StepNotFound(id) => (
                StatusCode::NOT_FOUND,
                "step_not_found",
                format!("Approval step not found: {id}"),
            ),
            Self::MicroCertificationNotFound(id) => (
                StatusCode::NOT_FOUND,
                "micro_certification_not_found",
                format!("Micro-certification not found: {id}"),
            ),
            Self::MicroCertTriggerNotFound(id) => (
                StatusCode::NOT_FOUND,
                "micro_cert_trigger_not_found",
                format!("Micro-certification trigger rule not found: {id}"),
            ),
            // Semi-manual Resources errors (F064)
            Self::TicketingConfigurationNotFound(id) => (
                StatusCode::NOT_FOUND,
                "ticketing_configuration_not_found",
                format!("Ticketing configuration not found: {id}"),
            ),
            Self::SlaPolicyNotFound(id) => (
                StatusCode::NOT_FOUND,
                "sla_policy_not_found",
                format!("SLA policy not found: {id}"),
            ),
            Self::ManualProvisioningTaskNotFound(id) => (
                StatusCode::NOT_FOUND,
                "manual_provisioning_task_not_found",
                format!("Manual provisioning task not found: {id}"),
            ),
            Self::ExternalTicketNotFound(id) => (
                StatusCode::NOT_FOUND,
                "external_ticket_not_found",
                format!("External ticket not found: {id}"),
            ),
            Self::TicketingIntegrationFailed(msg) => (
                StatusCode::BAD_GATEWAY,
                "ticketing_integration_failed",
                msg.clone(),
            ),
            Self::TaskAlreadyCompleted(id) => (
                StatusCode::CONFLICT,
                "task_already_completed",
                format!("Task is already completed: {id}"),
            ),
            Self::InvalidTaskStatusTransition { from, to } => (
                StatusCode::BAD_REQUEST,
                "invalid_task_status_transition",
                format!("Invalid task status transition from {from} to {to}"),
            ),
            Self::ApplicationNotSemiManual(id) => (
                StatusCode::BAD_REQUEST,
                "application_not_semi_manual",
                format!("Application {id} is not configured for semi-manual provisioning"),
            ),
            Self::TicketCreationFailed(msg) => (
                StatusCode::BAD_GATEWAY,
                "ticket_creation_failed",
                msg.clone(),
            ),
            Self::TicketSyncFailed(msg) => {
                (StatusCode::BAD_GATEWAY, "ticket_sync_failed", msg.clone())
            }
            Self::SlaBreached(id) => (
                StatusCode::CONFLICT,
                "sla_breached",
                format!("SLA breach detected for task {id}"),
            ),
            // Identity Archetype errors (F-058)
            Self::ArchetypeNotFound(id) => (
                StatusCode::NOT_FOUND,
                "archetype_not_found",
                format!("Identity archetype not found: {id}"),
            ),
            Self::ArchetypeNameExists(name) => (
                StatusCode::CONFLICT,
                "archetype_name_exists",
                format!("Archetype name already exists: {name}"),
            ),
            Self::CircularInheritance => (
                StatusCode::BAD_REQUEST,
                "circular_inheritance",
                "Circular inheritance detected: setting parent would create a cycle".to_string(),
            ),
            Self::ArchetypeHasAssignedUsers { id, count } => (
                StatusCode::CONFLICT,
                "archetype_has_assigned_users",
                format!("Cannot delete archetype: {count} users are assigned to archetype {id}"),
            ),
            Self::InvalidSchemaExtension(msg) => (
                StatusCode::BAD_REQUEST,
                "invalid_schema_extension",
                msg.clone(),
            ),
            Self::InvalidArchetypeCustomAttrs(msg) => (
                StatusCode::BAD_REQUEST,
                "invalid_archetype_custom_attrs",
                msg.clone(),
            ),
            Self::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg.clone()),
            Self::Internal(msg) => {
                tracing::error!("Internal error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "An internal error occurred".to_string(),
                )
            }
            Self::Database(ref e) => {
                tracing::error!("Database error in governance: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "database_error",
                    "Database error".to_string(),
                )
            }
            // Bulk Action Engine errors (F-064)
            Self::BulkActionNotFound(id) => (
                StatusCode::NOT_FOUND,
                "bulk_action_not_found",
                format!("Bulk action not found: {id}"),
            ),
            Self::InvalidExpression(msg) => {
                (StatusCode::BAD_REQUEST, "invalid_expression", msg.clone())
            }
            Self::BulkActionAlreadyExecuted(id) => (
                StatusCode::BAD_REQUEST,
                "bulk_action_already_executed",
                format!("Bulk action already executed or cancelled: {id}"),
            ),
            Self::BulkActionCannotCancel { id, status } => (
                StatusCode::BAD_REQUEST,
                "bulk_action_cannot_cancel",
                format!("Bulk action cannot be cancelled (status: {status}): {id}"),
            ),
            Self::BulkActionCannotDelete { id, status } => (
                StatusCode::BAD_REQUEST,
                "bulk_action_cannot_delete",
                format!("Bulk action cannot be deleted (status: {status}): {id}"),
            ),
            Self::BulkActionCannotBeCancelled(id) => (
                StatusCode::BAD_REQUEST,
                "bulk_action_cannot_cancel",
                format!("Bulk action cannot be cancelled: {id}"),
            ),
        };

        let body = Json(ErrorResponse {
            error: error_code.to_string(),
            message,
            details: None,
        });

        (status, body).into_response()
    }
}

impl From<validator::ValidationErrors> for ApiGovernanceError {
    fn from(err: validator::ValidationErrors) -> Self {
        Self::Validation(err.to_string())
    }
}

/// Result type alias for API operations.
pub type ApiResult<T> = std::result::Result<T, ApiGovernanceError>;
