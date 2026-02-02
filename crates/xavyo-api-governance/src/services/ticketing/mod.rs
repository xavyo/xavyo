//! Ticketing system integrations for semi-manual resources (F064).
//!
//! Provides integrations with external ticketing systems:
//! - ServiceNow
//! - Jira
//! - Custom webhooks

mod encryption;
mod jira;
mod servicenow;
mod webhook;

pub use encryption::{decrypt_credentials, encrypt_credentials};
pub use jira::JiraProvider;
pub use servicenow::ServiceNowProvider;
pub use webhook::WebhookProvider;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use xavyo_db::{GovTicketingConfiguration, TicketingType};

/// Result type for ticketing operations.
pub type TicketingResult<T> = Result<T, TicketingError>;

/// Errors that can occur during ticketing operations.
#[derive(Debug, thiserror::Error)]
pub enum TicketingError {
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("API error: {status} - {message}")]
    ApiError { status: u16, message: String },

    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Ticket not found: {0}")]
    TicketNotFound(String),

    #[error("Rate limited, retry after {retry_after_seconds}s")]
    RateLimited { retry_after_seconds: u64 },

    #[error("Provider unavailable: {0}")]
    ProviderUnavailable(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Request to create a ticket in an external system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTicketRequest {
    /// The manual task ID this ticket is for.
    pub task_id: Uuid,
    /// Summary/title of the ticket.
    pub summary: String,
    /// Detailed description of what needs to be done.
    pub description: String,
    /// Priority level (1=Critical, 2=High, 3=Medium, 4=Low).
    pub priority: i32,
    /// User who needs access (for context).
    pub user_display_name: String,
    /// User's email.
    pub user_email: Option<String>,
    /// Application/resource name.
    pub application_name: String,
    /// Entitlement being granted/revoked.
    pub entitlement_name: String,
    /// Operation type (grant, revoke, modify).
    pub operation_type: String,
    /// Optional custom fields from configuration.
    pub custom_fields: Option<serde_json::Value>,
}

/// Response from creating a ticket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTicketResponse {
    /// External ticket ID/key (e.g., "INC0012345" or "PROJ-123").
    pub external_reference: String,
    /// URL to view the ticket in the external system.
    pub external_url: Option<String>,
    /// Raw response from the external system (for debugging).
    pub raw_response: Option<serde_json::Value>,
}

/// Status of a ticket in an external system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TicketStatus {
    /// Ticket is open and awaiting work.
    Open,
    /// Ticket is being worked on.
    InProgress,
    /// Ticket is pending external action (e.g., waiting for info).
    Pending,
    /// Ticket has been resolved/completed.
    Resolved,
    /// Ticket was closed without resolution.
    Closed,
    /// Ticket was cancelled.
    Cancelled,
    /// Unknown status (external system returned unexpected value).
    Unknown(String),
}

impl TicketStatus {
    /// Check if this status represents a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TicketStatus::Resolved | TicketStatus::Closed | TicketStatus::Cancelled
        )
    }

    /// Check if this status represents successful completion.
    pub fn is_success(&self) -> bool {
        matches!(self, TicketStatus::Resolved)
    }

    /// Get the string representation of this status.
    pub fn as_str(&self) -> &str {
        match self {
            TicketStatus::Open => "open",
            TicketStatus::InProgress => "in_progress",
            TicketStatus::Pending => "pending",
            TicketStatus::Resolved => "resolved",
            TicketStatus::Closed => "closed",
            TicketStatus::Cancelled => "cancelled",
            TicketStatus::Unknown(s) => s,
        }
    }
}

/// Response from checking ticket status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketStatusResponse {
    /// Current status of the ticket.
    pub status: TicketStatus,
    /// Resolution notes (if resolved).
    pub resolution_notes: Option<String>,
    /// Who resolved/closed the ticket.
    pub resolved_by: Option<String>,
    /// When the ticket was last updated.
    pub last_updated: Option<chrono::DateTime<chrono::Utc>>,
    /// Raw response from the external system.
    pub raw_response: Option<serde_json::Value>,
}

/// Response from testing connectivity to a ticketing system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectivityTestResponse {
    /// Whether the connection succeeded.
    pub success: bool,
    /// Error message if connection failed.
    pub error_message: Option<String>,
    /// Additional details about the connection.
    pub details: Option<serde_json::Value>,
}

/// Trait for ticketing system providers.
#[async_trait]
pub trait TicketingProvider: Send + Sync {
    /// Get the provider type.
    fn provider_type(&self) -> TicketingType;

    /// Test connectivity to the ticketing system.
    async fn test_connectivity(&self) -> TicketingResult<ConnectivityTestResponse>;

    /// Create a ticket in the external system.
    async fn create_ticket(
        &self,
        request: CreateTicketRequest,
    ) -> TicketingResult<CreateTicketResponse>;

    /// Get the current status of a ticket.
    async fn get_ticket_status(
        &self,
        external_reference: &str,
    ) -> TicketingResult<TicketStatusResponse>;

    /// Add a comment to an existing ticket.
    async fn add_comment(&self, external_reference: &str, comment: &str) -> TicketingResult<()>;
}

/// Create a ticketing provider from configuration.
pub fn create_provider(
    config: &GovTicketingConfiguration,
    decrypted_credentials: &serde_json::Value,
) -> TicketingResult<Box<dyn TicketingProvider>> {
    match config.ticketing_type {
        TicketingType::ServiceNow => Ok(Box::new(ServiceNowProvider::new(
            config,
            decrypted_credentials,
        )?)),
        TicketingType::Jira => Ok(Box::new(JiraProvider::new(config, decrypted_credentials)?)),
        TicketingType::Webhook => Ok(Box::new(WebhookProvider::new(
            config,
            decrypted_credentials,
        )?)),
    }
}

use sqlx::PgPool;
use xavyo_db::{
    CreateExternalTicket, GovApplication, GovEntitlement, GovExternalTicket,
    GovManualProvisioningTask, ManualTaskStatus, TicketStatusCategory,
};

/// Service for orchestrating ticket creation and management.
pub struct TicketingService {
    pool: PgPool,
}

impl TicketingService {
    /// Create a new ticketing service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get the database pool reference.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Create a ticket for a manual provisioning task.
    ///
    /// This method:
    /// 1. Loads the task and its associated application
    /// 2. Gets the ticketing configuration
    /// 3. Creates a ticket in the external system
    /// 4. Records the external ticket in the database
    /// 5. Updates the task status
    pub async fn create_ticket_for_task(
        &self,
        tenant_id: Uuid,
        task_id: Uuid,
    ) -> TicketingResult<GovExternalTicket> {
        // Load the task
        let task = GovManualProvisioningTask::find_by_id(&self.pool, tenant_id, task_id)
            .await
            .map_err(|e| TicketingError::InvalidConfiguration(format!("Database error: {}", e)))?
            .ok_or_else(|| {
                TicketingError::InvalidConfiguration(format!("Task {} not found", task_id))
            })?;

        // Check if task already has a ticket
        if task.external_ticket_id.is_some() {
            return Err(TicketingError::InvalidConfiguration(
                "Task already has a ticket".to_string(),
            ));
        }

        // Load the application to get ticketing configuration
        let application = GovApplication::find_by_id(&self.pool, tenant_id, task.application_id)
            .await
            .map_err(|e| TicketingError::InvalidConfiguration(format!("Database error: {}", e)))?
            .ok_or_else(|| {
                TicketingError::InvalidConfiguration(format!(
                    "Application {} not found",
                    task.application_id
                ))
            })?;

        // Get the ticketing configuration
        let ticketing_config_id = application.ticketing_config_id.ok_or_else(|| {
            TicketingError::InvalidConfiguration(
                "Application has no ticketing configuration".to_string(),
            )
        })?;

        let config =
            GovTicketingConfiguration::find_by_id(&self.pool, tenant_id, ticketing_config_id)
                .await
                .map_err(|e| {
                    TicketingError::InvalidConfiguration(format!("Database error: {}", e))
                })?
                .ok_or_else(|| {
                    TicketingError::InvalidConfiguration(format!(
                        "Ticketing configuration {} not found",
                        ticketing_config_id
                    ))
                })?;

        // Load the entitlement for details
        let entitlement = GovEntitlement::find_by_id(&self.pool, tenant_id, task.entitlement_id)
            .await
            .map_err(|e| TicketingError::InvalidConfiguration(format!("Database error: {}", e)))?
            .ok_or_else(|| {
                TicketingError::InvalidConfiguration(format!(
                    "Entitlement {} not found",
                    task.entitlement_id
                ))
            })?;

        // Decrypt credentials
        let encrypted_creds = String::from_utf8_lossy(&config.credentials);
        let decrypted_creds = decrypt_credentials(&encrypted_creds)?;

        // Create the provider
        let provider = create_provider(&config, &decrypted_creds)?;

        // Update task status to pending_ticket
        GovManualProvisioningTask::update_status(
            &self.pool,
            tenant_id,
            task_id,
            ManualTaskStatus::PendingTicket,
        )
        .await
        .map_err(|e| TicketingError::InvalidConfiguration(format!("Database error: {}", e)))?;

        // Build the ticket request
        let request = CreateTicketRequest {
            task_id,
            summary: format!(
                "Access Provisioning: {} for {}",
                entitlement.name, application.name
            ),
            description: format!(
                "A manual provisioning task has been created.\n\n\
                Operation: {:?}\n\
                Application: {}\n\
                Entitlement: {}\n\
                User ID: {}\n\n\
                Please complete the provisioning and update the ticket status when done.",
                task.operation_type, application.name, entitlement.name, task.user_id
            ),
            priority: 3,                                 // Medium priority
            user_display_name: task.user_id.to_string(), // TODO: Look up user name
            user_email: None,
            application_name: application.name.clone(),
            entitlement_name: entitlement.name.clone(),
            operation_type: format!("{:?}", task.operation_type),
            custom_fields: config.field_mappings.clone(),
        };

        // Create the ticket
        let response = provider.create_ticket(request).await?;

        // Save the external ticket record
        let input = CreateExternalTicket {
            task_id,
            ticketing_config_id: config.id,
            external_reference: response.external_reference.clone(),
            external_url: response.external_url.clone(),
            external_status: Some("open".to_string()),
            status_category: TicketStatusCategory::Open,
            created_externally_at: Some(chrono::Utc::now()),
            raw_response: response.raw_response.clone(),
        };

        let external_ticket = GovExternalTicket::create(&self.pool, tenant_id, input)
            .await
            .map_err(|e| TicketingError::InvalidConfiguration(format!("Database error: {}", e)))?;

        // Update the task with the ticket ID and status
        sqlx::query(
            r#"
            UPDATE gov_manual_provisioning_tasks
            SET external_ticket_id = $1, status = $2, updated_at = NOW()
            WHERE id = $3 AND tenant_id = $4
            "#,
        )
        .bind(external_ticket.id)
        .bind(ManualTaskStatus::TicketCreated)
        .bind(task_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await
        .map_err(|e| TicketingError::InvalidConfiguration(format!("Database error: {}", e)))?;

        tracing::info!(
            tenant_id = %tenant_id,
            task_id = %task_id,
            external_reference = %response.external_reference,
            "Ticket created successfully"
        );

        Ok(external_ticket)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ticket_status_is_terminal() {
        assert!(TicketStatus::Resolved.is_terminal());
        assert!(TicketStatus::Closed.is_terminal());
        assert!(TicketStatus::Cancelled.is_terminal());
        assert!(!TicketStatus::Open.is_terminal());
        assert!(!TicketStatus::InProgress.is_terminal());
        assert!(!TicketStatus::Pending.is_terminal());
    }

    #[test]
    fn test_ticket_status_is_success() {
        assert!(TicketStatus::Resolved.is_success());
        assert!(!TicketStatus::Closed.is_success());
        assert!(!TicketStatus::Open.is_success());
    }
}
