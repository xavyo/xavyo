//! Request and response models for Semi-manual Resources endpoints (F064).
//!
//! Semi-manual resources are target systems that cannot be provisioned automatically
//! and require manual intervention through ticketing integrations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;
use xavyo_db::{
    DashboardMetrics, GovExternalTicket, GovManualProvisioningTask, GovManualTaskAuditEvent,
    GovSlaPolicy, GovTicketingConfiguration, ManualTaskOperation, ManualTaskStatus, RetryQueueItem,
    TicketStatusCategory, TicketingType,
};

// ============================================================================
// Ticketing Configuration Models
// ============================================================================

/// Request to create a ticketing configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateTicketingConfigurationRequest {
    /// Display name for the configuration (1-255 characters).
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name: String,

    /// Type of ticketing system.
    pub ticketing_type: TicketingType,

    /// API endpoint URL (must be valid HTTPS URL).
    #[validate(url(message = "Must be a valid URL"))]
    pub endpoint_url: String,

    /// Credentials (API key, username/password, etc.) - will be encrypted.
    pub credentials: String,

    /// Custom field mappings for ticket creation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_mappings: Option<serde_json::Value>,

    /// Default assignee for tickets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_assignee: Option<String>,

    /// ServiceNow assignment group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_assignment_group: Option<String>,

    /// Jira project key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_key: Option<String>,

    /// Jira issue type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue_type: Option<String>,

    /// Polling interval in seconds (60-3600).
    #[validate(range(
        min = 60,
        max = 3600,
        message = "Poll interval must be 60-3600 seconds"
    ))]
    #[serde(default = "default_poll_interval")]
    pub polling_interval_seconds: i32,
}

fn default_poll_interval() -> i32 {
    300 // 5 minutes
}

fn default_true() -> bool {
    true
}

fn default_priority() -> i32 {
    5
}

/// Request to update a ticketing configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateTicketingConfigurationRequest {
    /// Updated name.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Updated API endpoint URL.
    #[validate(url(message = "Must be a valid URL"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<String>,

    /// Updated credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<String>,

    /// Updated field mappings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_mappings: Option<serde_json::Value>,

    /// Updated default assignee.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_assignee: Option<String>,

    /// Updated assignment group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_assignment_group: Option<String>,

    /// Updated project key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_key: Option<String>,

    /// Updated issue type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue_type: Option<String>,

    /// Updated polling interval.
    #[validate(range(
        min = 60,
        max = 3600,
        message = "Poll interval must be 60-3600 seconds"
    ))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub polling_interval_seconds: Option<i32>,

    /// Whether the configuration is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
}

/// Ticketing configuration response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TicketingConfigurationResponse {
    pub id: Uuid,
    pub name: String,
    pub ticketing_type: TicketingType,
    pub endpoint_url: String,
    /// Note: credentials are never returned in responses for security.
    pub polling_interval_seconds: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_assignee: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_assignment_group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue_type: Option<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<GovTicketingConfiguration> for TicketingConfigurationResponse {
    fn from(config: GovTicketingConfiguration) -> Self {
        Self {
            id: config.id,
            name: config.name,
            ticketing_type: config.ticketing_type,
            endpoint_url: config.endpoint_url,
            polling_interval_seconds: config.polling_interval_seconds,
            default_assignee: config.default_assignee,
            default_assignment_group: config.default_assignment_group,
            project_key: config.project_key,
            issue_type: config.issue_type,
            is_active: config.is_active,
            created_at: config.created_at,
            updated_at: config.updated_at,
        }
    }
}

/// List of ticketing configurations response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TicketingConfigurationListResponse {
    pub items: Vec<TicketingConfigurationResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Query parameters for listing ticketing configurations.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListTicketingConfigurationsQuery {
    /// Filter by ticketing type.
    pub ticketing_type: Option<TicketingType>,
    /// Filter by active status.
    pub is_active: Option<bool>,
    /// Maximum number of items to return.
    #[param(default = 50, maximum = 100)]
    pub limit: Option<i64>,
    /// Number of items to skip.
    #[param(default = 0)]
    pub offset: Option<i64>,
}

/// Request to test ticketing configuration connectivity.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TestTicketingConfigurationRequest {
    /// Optional custom test data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test_data: Option<serde_json::Value>,
}

/// Response for ticketing configuration test.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TestTicketingConfigurationResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_time_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ============================================================================
// SLA Policy Models
// ============================================================================

/// Request to create an SLA policy.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateSlaPolicyRequest {
    /// Display name for the policy (1-255 characters).
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    pub name: String,

    /// Optional description.
    #[validate(length(max = 1000, message = "Description cannot exceed 1000 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Target resolution time in seconds (60 to 604800 = 7 days).
    #[validate(range(
        min = 60,
        max = 604800,
        message = "Target duration must be 60 seconds to 7 days"
    ))]
    pub target_duration_seconds: i32,

    /// Warning threshold as percentage of target (1-100, default 75).
    #[validate(range(min = 1, max = 100, message = "Warning threshold must be 1-100"))]
    #[serde(default = "default_warning_threshold")]
    pub warning_threshold_percent: i32,

    /// Whether to enable breach notifications.
    #[serde(default = "default_true")]
    pub breach_notification_enabled: bool,

    /// Escalation contacts (email addresses, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escalation_contacts: Option<serde_json::Value>,
}

fn default_warning_threshold() -> i32 {
    75 // 75% of target time
}

/// Request to update an SLA policy.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateSlaPolicyRequest {
    /// Updated name.
    #[validate(length(
        min = 1,
        max = 255,
        message = "Name must be between 1 and 255 characters"
    ))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Updated description.
    #[validate(length(max = 1000, message = "Description cannot exceed 1000 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Updated target duration in seconds.
    #[validate(range(
        min = 60,
        max = 604800,
        message = "Target duration must be 60 seconds to 7 days"
    ))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_duration_seconds: Option<i32>,

    /// Updated warning threshold.
    #[validate(range(min = 1, max = 100, message = "Warning threshold must be 1-100"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning_threshold_percent: Option<i32>,

    /// Updated breach notification setting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breach_notification_enabled: Option<bool>,

    /// Updated escalation contacts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escalation_contacts: Option<serde_json::Value>,

    /// Whether the policy is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
}

/// SLA policy response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SlaPolicyResponse {
    pub id: Uuid,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub target_duration_seconds: i32,
    /// Human-readable target duration (e.g., "4 hours").
    pub target_duration_human: String,
    pub warning_threshold_percent: i32,
    pub breach_notification_enabled: bool,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<GovSlaPolicy> for SlaPolicyResponse {
    fn from(policy: GovSlaPolicy) -> Self {
        let target_duration_human = policy.target_duration_human();
        Self {
            id: policy.id,
            name: policy.name,
            description: policy.description,
            target_duration_seconds: policy.target_duration_seconds,
            target_duration_human,
            warning_threshold_percent: policy.warning_threshold_percent,
            breach_notification_enabled: policy.breach_notification_enabled,
            is_active: policy.is_active,
            created_at: policy.created_at,
            updated_at: policy.updated_at,
        }
    }
}

/// List of SLA policies response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SlaPolicyListResponse {
    pub items: Vec<SlaPolicyResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Query parameters for listing SLA policies.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListSlaPoliciesQuery {
    /// Filter by active status.
    pub is_active: Option<bool>,
    /// Maximum number of items to return.
    #[param(default = 50, maximum = 100)]
    pub limit: Option<i64>,
    /// Number of items to skip.
    #[param(default = 0)]
    pub offset: Option<i64>,
}

// ============================================================================
// Manual Provisioning Task Models
// ============================================================================

/// Request to create a manual provisioning task.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CreateManualProvisioningTaskRequest {
    /// Application requiring manual provisioning.
    pub application_id: Uuid,

    /// Target user for provisioning.
    pub target_user_id: Uuid,

    /// Operation type (grant, revoke, modify).
    pub operation: ManualTaskOperation,

    /// Entitlement being provisioned (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitlement_id: Option<Uuid>,

    /// Originating access request (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_request_id: Option<Uuid>,

    /// Provisioning details/instructions.
    pub provisioning_data: serde_json::Value,

    /// Override ticketing configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticketing_configuration_id: Option<Uuid>,

    /// Override SLA policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sla_policy_id: Option<Uuid>,

    /// Task priority (1-10, lower = higher priority).
    #[validate(range(min = 1, max = 10, message = "Priority must be 1-10"))]
    #[serde(default = "default_priority")]
    pub priority: i32,
}

/// Request to manually complete a task.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CompleteManualTaskRequest {
    /// Completion notes.
    #[validate(length(
        min = 5,
        max = 2000,
        message = "Notes must be between 5 and 2000 characters"
    ))]
    pub completion_notes: String,

    /// External reference (ticket number, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_reference: Option<String>,

    /// Whether the task was successful.
    #[serde(default = "default_true")]
    pub success: bool,

    /// Additional result data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_data: Option<serde_json::Value>,
}

/// Request to cancel a manual provisioning task.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct CancelManualTaskRequest {
    /// Cancellation reason.
    #[validate(length(
        min = 5,
        max = 1000,
        message = "Reason must be between 5 and 1000 characters"
    ))]
    pub reason: String,
}

/// Request to reassign a manual provisioning task.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct ReassignManualTaskRequest {
    /// New assignee user ID.
    pub new_assignee_id: Uuid,

    /// Reason for reassignment.
    #[validate(length(max = 500, message = "Reason cannot exceed 500 characters"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Manual provisioning task response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ManualProvisioningTaskResponse {
    pub id: Uuid,
    pub assignment_id: Uuid,
    pub application_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_name: Option<String>,
    pub user_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    pub entitlement_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entitlement_name: Option<String>,
    pub operation_type: ManualTaskOperation,
    pub status: ManualTaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sla_deadline: Option<DateTime<Utc>>,
    pub sla_warning_sent: bool,
    pub sla_breached: bool,
    pub retry_count: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retry_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
}

impl From<GovManualProvisioningTask> for ManualProvisioningTaskResponse {
    fn from(task: GovManualProvisioningTask) -> Self {
        Self {
            id: task.id,
            assignment_id: task.assignment_id,
            application_id: task.application_id,
            application_name: None,
            user_id: task.user_id,
            user_name: None,
            entitlement_id: task.entitlement_id,
            entitlement_name: None,
            operation_type: task.operation_type,
            status: task.status,
            assignee_id: task.assignee_id,
            assignee_name: None,
            sla_deadline: task.sla_deadline,
            sla_warning_sent: task.sla_warning_sent,
            sla_breached: task.sla_breached,
            retry_count: task.retry_count,
            next_retry_at: task.next_retry_at,
            notes: task.notes,
            created_at: task.created_at,
            updated_at: task.updated_at,
            completed_at: task.completed_at,
        }
    }
}

/// Detailed task response with provisioning data.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ManualProvisioningTaskDetailResponse {
    #[serde(flatten)]
    pub base: ManualProvisioningTaskResponse,

    /// Provisioning instructions/data.
    pub provisioning_data: serde_json::Value,

    /// External tickets associated with this task.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tickets: Option<Vec<ExternalTicketResponse>>,

    /// Audit events for this task.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_events: Option<Vec<ManualTaskAuditEventResponse>>,

    /// Access request details (if linked).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_request_id: Option<Uuid>,

    /// Completion notes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_notes: Option<String>,

    /// Result data from completion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_data: Option<serde_json::Value>,
}

/// List of manual provisioning tasks response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ManualProvisioningTaskListResponse {
    pub items: Vec<ManualProvisioningTaskResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Query parameters for listing manual provisioning tasks.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListManualTasksQuery {
    /// Filter by status (can be multiple).
    pub status: Option<Vec<ManualTaskStatus>>,
    /// Filter by application.
    pub application_id: Option<Uuid>,
    /// Filter by target user.
    pub user_id: Option<Uuid>,
    /// Filter by assignee.
    pub assignee_id: Option<Uuid>,
    /// Filter by operation type.
    pub operation: Option<ManualTaskOperation>,
    /// Filter for SLA breached tasks.
    pub sla_breached: Option<bool>,
    /// Filter by priority (1-10).
    pub priority: Option<i32>,
    /// Maximum number of items to return.
    #[param(default = 50, maximum = 100)]
    pub limit: Option<i64>,
    /// Number of items to skip.
    #[param(default = 0)]
    pub offset: Option<i64>,
}

// Alias types for handlers (simplified naming)
/// Alias for ManualProvisioningTaskResponse.
pub type ManualTaskResponse = ManualProvisioningTaskResponse;

/// Alias for ManualProvisioningTaskListResponse.
pub type ManualTaskListResponse = ManualProvisioningTaskListResponse;

/// Dashboard response for manual tasks.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ManualTaskDashboardResponse {
    pub pending_count: i64,
    pub in_progress_count: i64,
    pub sla_at_risk_count: i64,
    pub sla_breached_count: i64,
    pub completed_today: i64,
    pub average_completion_time_seconds: Option<f64>,
}

/// Request to confirm a manual task.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ConfirmManualTaskRequest {
    /// Optional completion notes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Request to reject a manual task.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, ToSchema)]
pub struct RejectManualTaskRequest {
    /// Reason for rejection.
    #[validate(length(
        min = 5,
        max = 1000,
        message = "Reason must be between 5 and 1000 characters"
    ))]
    pub reason: String,
}

// ============================================================================
// Dashboard and Metrics Models
// ============================================================================

/// Dashboard metrics response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DashboardMetricsResponse {
    pub pending_count: i64,
    pub in_progress_count: i64,
    pub sla_at_risk_count: i64,
    pub sla_breached_count: i64,
    pub completed_today: i64,
    pub avg_completion_time_secs: Option<f64>,
    /// Human-readable average completion time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_completion_time_human: Option<String>,
}

impl From<DashboardMetrics> for DashboardMetricsResponse {
    fn from(metrics: DashboardMetrics) -> Self {
        let avg_completion_time_human = metrics.average_completion_time_seconds.map(|secs| {
            if secs < 60.0 {
                format!("{:.0} seconds", secs)
            } else if secs < 3600.0 {
                format!("{:.1} minutes", secs / 60.0)
            } else if secs < 86400.0 {
                format!("{:.1} hours", secs / 3600.0)
            } else {
                format!("{:.1} days", secs / 86400.0)
            }
        });

        Self {
            pending_count: metrics.pending_count,
            in_progress_count: metrics.in_progress_count,
            sla_at_risk_count: metrics.sla_at_risk_count,
            sla_breached_count: metrics.sla_breached_count,
            completed_today: metrics.completed_today,
            avg_completion_time_secs: metrics.average_completion_time_seconds,
            avg_completion_time_human,
        }
    }
}

/// Retry queue response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RetryQueueResponse {
    pub items: Vec<RetryQueueItemResponse>,
    pub total: i64,
}

/// Retry queue item response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RetryQueueItemResponse {
    pub task_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_name: Option<String>,
    pub operation: ManualTaskOperation,
    pub retry_count: i32,
    pub next_retry_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl From<RetryQueueItem> for RetryQueueItemResponse {
    fn from(item: RetryQueueItem) -> Self {
        Self {
            task_id: item.task_id,
            application_name: None,
            operation: item.operation,
            retry_count: item.retry_count,
            next_retry_at: item.next_retry_at,
            last_error: item.last_error,
        }
    }
}

// ============================================================================
// External Ticket Models
// ============================================================================

/// External ticket response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExternalTicketResponse {
    pub id: Uuid,
    pub task_id: Uuid,
    pub ticketing_config_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticketing_config_name: Option<String>,
    pub external_reference: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_url: Option<String>,
    pub status_category: TicketStatusCategory,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_synced_at: Option<DateTime<Utc>>,
}

impl From<GovExternalTicket> for ExternalTicketResponse {
    fn from(ticket: GovExternalTicket) -> Self {
        Self {
            id: ticket.id,
            task_id: ticket.task_id,
            ticketing_config_id: ticket.ticketing_config_id,
            ticketing_config_name: None,
            external_reference: ticket.external_reference,
            external_url: ticket.external_url,
            status_category: ticket.status_category,
            external_status: ticket.external_status,
            sync_error: ticket.sync_error,
            created_at: ticket.created_at,
            updated_at: ticket.updated_at,
            last_synced_at: ticket.last_synced_at,
        }
    }
}

/// Request to manually sync a ticket.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SyncTicketRequest {
    /// Force refresh even if recently synced.
    #[serde(default)]
    pub force: bool,
}

/// Response for ticket sync.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SyncTicketResponse {
    pub success: bool,
    pub ticket: ExternalTicketResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// ============================================================================
// Audit Event Models
// ============================================================================

/// Manual task audit event response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ManualTaskAuditEventResponse {
    pub id: Uuid,
    pub task_id: Uuid,
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

impl From<GovManualTaskAuditEvent> for ManualTaskAuditEventResponse {
    fn from(event: GovManualTaskAuditEvent) -> Self {
        Self {
            id: event.id,
            task_id: event.task_id,
            event_type: event.event_type,
            actor_id: event.actor_id,
            actor_name: None,
            details: event.details,
            created_at: event.created_at,
        }
    }
}

/// List of audit events response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ManualTaskAuditListResponse {
    pub items: Vec<ManualTaskAuditEventResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Query parameters for listing audit events.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListManualTaskAuditQuery {
    /// Filter by task.
    pub task_id: Option<Uuid>,
    /// Filter by event type.
    pub event_type: Option<String>,
    /// Filter by actor.
    pub actor_id: Option<Uuid>,
    /// Filter events from this date.
    pub from_date: Option<DateTime<Utc>>,
    /// Filter events until this date.
    pub to_date: Option<DateTime<Utc>>,
    /// Maximum number of items to return.
    #[param(default = 50, maximum = 100)]
    pub limit: Option<i64>,
    /// Number of items to skip.
    #[param(default = 0)]
    pub offset: Option<i64>,
}

// ============================================================================
// Semi-manual Application Configuration Models
// ============================================================================

/// Response for a semi-manual application configuration.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SemiManualApplicationResponse {
    pub id: Uuid,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub is_semi_manual: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticketing_config_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sla_policy_id: Option<Uuid>,
    /// Whether approval must complete before ticket creation.
    pub requires_approval_before_ticket: bool,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// List of semi-manual applications response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SemiManualApplicationsListResponse {
    pub items: Vec<SemiManualApplicationResponse>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Query parameters for listing semi-manual applications.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListSemiManualApplicationsQuery {
    /// Maximum number of items to return.
    #[param(default = 50, maximum = 100)]
    pub limit: Option<i64>,
    /// Number of items to skip.
    #[param(default = 0)]
    pub offset: Option<i64>,
}

/// Request to configure an application as semi-manual.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, Validate)]
pub struct ConfigureSemiManualRequest {
    /// Whether the application requires manual provisioning.
    pub is_semi_manual: bool,
    /// Default ticketing configuration for this application.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ticketing_config_id: Option<Uuid>,
    /// Default SLA policy for this application.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sla_policy_id: Option<Uuid>,
    /// Whether approval must complete before ticket creation.
    /// When true, tickets are only created after access request approval completes.
    #[serde(default)]
    pub requires_approval_before_ticket: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use validator::Validate;

    #[test]
    fn test_create_ticketing_configuration_request_validation() {
        let request = CreateTicketingConfigurationRequest {
            name: "ServiceNow Production".to_string(),
            ticketing_type: TicketingType::ServiceNow,
            endpoint_url: "https://company.service-now.com/api".to_string(),
            credentials: "api_user:encrypted_value".to_string(),
            field_mappings: None,
            default_assignee: Some("admin".to_string()),
            default_assignment_group: Some("IT Ops".to_string()),
            project_key: None,
            issue_type: None,
            polling_interval_seconds: 300,
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_create_ticketing_configuration_invalid_url_fails() {
        let request = CreateTicketingConfigurationRequest {
            name: "Invalid Config".to_string(),
            ticketing_type: TicketingType::ServiceNow,
            endpoint_url: "not-a-valid-url".to_string(),
            credentials: "test".to_string(),
            field_mappings: None,
            default_assignee: None,
            default_assignment_group: None,
            project_key: None,
            issue_type: None,
            polling_interval_seconds: 300,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_create_sla_policy_request_validation() {
        let request = CreateSlaPolicyRequest {
            name: "Standard SLA".to_string(),
            description: Some("4-hour resolution target".to_string()),
            target_duration_seconds: 14400, // 4 hours
            warning_threshold_percent: 75,
            breach_notification_enabled: true,
            escalation_contacts: None,
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_create_sla_policy_invalid_threshold_fails() {
        let request = CreateSlaPolicyRequest {
            name: "Invalid SLA".to_string(),
            description: None,
            target_duration_seconds: 14400,
            warning_threshold_percent: 150, // Invalid: > 100
            breach_notification_enabled: true,
            escalation_contacts: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_complete_manual_task_request_validation() {
        let request = CompleteManualTaskRequest {
            completion_notes: "Task completed successfully via ServiceNow ticket INC123456"
                .to_string(),
            external_reference: Some("INC123456".to_string()),
            success: true,
            result_data: None,
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_complete_manual_task_short_notes_fails() {
        let request = CompleteManualTaskRequest {
            completion_notes: "Done".to_string(), // Too short (< 5 chars)
            external_reference: None,
            success: true,
            result_data: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_dashboard_metrics_human_readable() {
        let metrics = DashboardMetrics {
            pending_count: 10,
            in_progress_count: 5,
            sla_at_risk_count: 3,
            sla_breached_count: 2,
            completed_today: 15,
            average_completion_time_seconds: Some(7200.0), // 2 hours
        };

        let response: DashboardMetricsResponse = metrics.into();
        assert_eq!(
            response.avg_completion_time_human,
            Some("2.0 hours".to_string())
        );
    }
}
