//! API request/response models for provisioning scripts (F066).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

// ============================================================================
// Script CRUD Models
// ============================================================================

/// Request to create a new provisioning script.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateScriptRequest {
    /// Display name for the script.
    pub name: String,

    /// Optional description of the script's purpose.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Request to update an existing provisioning script metadata.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateScriptRequest {
    /// Updated name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Updated description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Request to update a script's body (creates a new version).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateScriptBodyRequest {
    /// The new script body content.
    pub script_body: String,

    /// Optional description of what changed in this version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_description: Option<String>,
}

/// Full provisioning script response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScriptResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Script name.
    pub name: String,

    /// Script description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Current active version number.
    pub current_version: i32,

    /// Script status (e.g., draft, active, archived).
    pub status: String,

    /// Whether this is a system-provided script.
    pub is_system: bool,

    /// User who created the script.
    pub created_by: Uuid,

    /// When the script was created.
    pub created_at: DateTime<Utc>,

    /// When the script was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Paginated list of scripts.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScriptListResponse {
    /// List of scripts.
    pub scripts: Vec<ScriptResponse>,

    /// Total count for pagination.
    pub total: i64,
}

/// Script version response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScriptVersionResponse {
    /// Unique identifier for this version.
    pub id: Uuid,

    /// Reference to the parent script.
    pub script_id: Uuid,

    /// Version number (monotonically increasing).
    pub version_number: i32,

    /// The script body content for this version.
    pub script_body: String,

    /// Description of what changed in this version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change_description: Option<String>,

    /// User who created this version.
    pub created_by: Uuid,

    /// When this version was created.
    pub created_at: DateTime<Utc>,
}

/// Paginated list of script versions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScriptVersionListResponse {
    /// List of versions.
    pub versions: Vec<ScriptVersionResponse>,

    /// Total count for pagination.
    pub total: i64,
}

/// Request to rollback a script to a previous version.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RollbackRequest {
    /// The version number to rollback to.
    pub target_version: i32,

    /// Optional reason for the rollback.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Response comparing two script versions.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct VersionComparisonResponse {
    /// First version number being compared.
    pub version_a: i32,

    /// Second version number being compared.
    pub version_b: i32,

    /// Line-by-line diff between the two versions.
    pub diff_lines: Vec<DiffLine>,
}

/// A single line in a version diff.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DiffLine {
    /// Line number in the output.
    pub line_number: usize,

    /// Type of change for this line.
    pub change_type: DiffChangeType,

    /// Content of the line.
    pub content: String,
}

/// Type of change in a diff line.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiffChangeType {
    /// Line was added in the newer version.
    Added,
    /// Line was removed from the older version.
    Removed,
    /// Line is unchanged between versions.
    Unchanged,
}

// ============================================================================
// Hook Binding Models
// ============================================================================

/// Request to create a new hook binding.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateBindingRequest {
    /// The script to bind.
    pub script_id: Uuid,

    /// The connector to bind to.
    pub connector_id: Uuid,

    /// The provisioning lifecycle phase (e.g., pre_create, post_create).
    pub hook_phase: String,

    /// The operation type (e.g., create, update, delete).
    pub operation_type: String,

    /// Execution order when multiple scripts are bound to the same hook.
    pub execution_order: i32,

    /// What to do when the script fails (e.g., abort, continue, retry).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_policy: Option<String>,

    /// Maximum number of retry attempts on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_retries: Option<i32>,

    /// Maximum execution time in seconds before timeout.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<i32>,
}

/// Request to update an existing hook binding.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateBindingRequest {
    /// Updated execution order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_order: Option<i32>,

    /// Updated failure policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_policy: Option<String>,

    /// Updated max retries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_retries: Option<i32>,

    /// Updated timeout in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<i32>,

    /// Whether the binding is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

/// Hook binding response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BindingResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// The bound script ID.
    pub script_id: Uuid,

    /// The bound connector ID.
    pub connector_id: Uuid,

    /// The provisioning lifecycle phase.
    pub hook_phase: String,

    /// The operation type.
    pub operation_type: String,

    /// Execution order.
    pub execution_order: i32,

    /// Failure policy.
    pub failure_policy: String,

    /// Maximum retry attempts.
    pub max_retries: i32,

    /// Timeout in seconds.
    pub timeout_seconds: i32,

    /// Whether the binding is enabled.
    pub enabled: bool,

    /// Who created the binding.
    pub created_by: Uuid,

    /// When the binding was created.
    pub created_at: DateTime<Utc>,

    /// When the binding was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Paginated list of hook bindings.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BindingListResponse {
    /// List of bindings.
    pub bindings: Vec<BindingResponse>,

    /// Total count for pagination.
    pub total: i64,
}

// ============================================================================
// Testing Models
// ============================================================================

/// Request to validate a script body without saving.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ValidateScriptRequest {
    /// The script body content to validate.
    pub script_body: String,
}

/// Response from script validation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ValidationResponse {
    /// Whether the script is valid.
    pub valid: bool,

    /// List of validation errors (empty if valid).
    pub errors: Vec<ScriptError>,
}

/// A single script error from validation.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScriptError {
    /// Line number where the error occurred (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,

    /// Column number where the error occurred (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,

    /// Error message describing the issue.
    pub message: String,
}

/// Request to perform a dry run of a script.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DryRunRequest {
    /// Simulated provisioning context for the dry run.
    pub context: serde_json::Value,
}

/// Response from a script dry run.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DryRunResponse {
    /// Whether the dry run completed successfully.
    pub success: bool,

    /// Output produced by the script (if successful).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,

    /// Error message (if the script failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Execution duration in milliseconds.
    pub duration_ms: u64,
}

// ============================================================================
// Template Models
// ============================================================================

/// Request to create a new script template.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateTemplateRequest {
    /// Template display name.
    pub name: String,

    /// Optional description of the template's purpose.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Template category (e.g., ldap, rest_api, database).
    pub category: String,

    /// The template body content with placeholders.
    pub template_body: String,

    /// Annotations describing template placeholders and their types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder_annotations: Option<serde_json::Value>,
}

/// Request to update an existing script template.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateTemplateRequest {
    /// Updated name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Updated description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Updated category.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,

    /// Updated template body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_body: Option<String>,

    /// Updated placeholder annotations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder_annotations: Option<serde_json::Value>,
}

/// Script template response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TemplateResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Template name.
    pub name: String,

    /// Template description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Template category.
    pub category: String,

    /// The template body content with placeholders.
    pub template_body: String,

    /// Annotations describing template placeholders.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placeholder_annotations: Option<serde_json::Value>,

    /// Whether this is a system-provided template.
    pub is_system: bool,

    /// Who created the template.
    pub created_by: Uuid,

    /// When the template was created.
    pub created_at: DateTime<Utc>,

    /// When the template was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Paginated list of script templates.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TemplateListResponse {
    /// List of templates.
    pub templates: Vec<TemplateResponse>,

    /// Total count for pagination.
    pub total: i64,
}

/// Request to instantiate a script from a template.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct InstantiateTemplateRequest {
    /// Name for the new script created from the template.
    pub name: String,

    /// Optional description for the new script.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ============================================================================
// Analytics Models
// ============================================================================

/// Dashboard analytics response for provisioning scripts.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DashboardResponse {
    /// Total number of scripts.
    pub total_scripts: i64,

    /// Number of active scripts.
    pub active_scripts: i64,

    /// Total number of script executions.
    pub total_executions: i64,

    /// Overall success rate as a percentage (0.0 - 100.0).
    pub success_rate: f64,

    /// Average execution duration in milliseconds.
    pub avg_duration_ms: f64,

    /// Per-script summary statistics.
    pub scripts: Vec<ScriptSummary>,
}

/// Summary statistics for a single script.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScriptSummary {
    /// Script ID.
    pub script_id: Uuid,

    /// Script name.
    pub name: String,

    /// Total execution count.
    pub total_executions: i64,

    /// Number of successful executions.
    pub success_count: i64,

    /// Number of failed executions.
    pub failure_count: i64,

    /// Average execution duration in milliseconds.
    pub avg_duration_ms: f64,
}

/// Detailed analytics for a single script.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScriptAnalyticsResponse {
    /// Script ID.
    pub script_id: Uuid,

    /// Script name.
    pub name: String,

    /// Total execution count.
    pub total_executions: i64,

    /// Success rate as a percentage (0.0 - 100.0).
    pub success_rate: f64,

    /// Average execution duration in milliseconds.
    pub avg_duration_ms: f64,

    /// 95th percentile execution duration in milliseconds.
    pub p95_duration_ms: f64,

    /// Daily execution trends.
    pub daily_trends: Vec<DailyTrend>,

    /// Most frequent errors.
    pub top_errors: Vec<ErrorSummary>,
}

/// Execution trend data for a single day.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DailyTrend {
    /// Date in YYYY-MM-DD format.
    pub date: String,

    /// Total executions on this date.
    pub executions: i64,

    /// Successful executions on this date.
    pub successes: i64,

    /// Failed executions on this date.
    pub failures: i64,

    /// Average execution duration in milliseconds on this date.
    pub avg_duration_ms: f64,
}

/// Summary of a recurring error.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ErrorSummary {
    /// The error message.
    pub error_message: String,

    /// Number of times this error has occurred.
    pub count: i64,

    /// When this error last occurred.
    pub last_occurred: DateTime<Utc>,
}

// ============================================================================
// Execution Log Models
// ============================================================================

/// Script execution log entry response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExecutionLogResponse {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// The script that was executed.
    pub script_id: Uuid,

    /// The binding that triggered the execution (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_id: Option<Uuid>,

    /// The connector involved in the execution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<Uuid>,

    /// Script version that was executed.
    pub script_version: i32,

    /// Execution status (e.g., success, failure, timeout).
    pub status: String,

    /// Whether this was a dry run.
    pub dry_run: bool,

    /// Input context provided to the script.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_context: Option<serde_json::Value>,

    /// Output produced by the script.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,

    /// Error message (if the execution failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Execution duration in milliseconds.
    pub duration_ms: i64,

    /// Who triggered the execution.
    pub executed_by: Uuid,

    /// When the execution started.
    pub executed_at: DateTime<Utc>,
}

/// Paginated list of execution logs.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExecutionLogListResponse {
    /// List of execution log entries.
    pub logs: Vec<ExecutionLogResponse>,

    /// Total count for pagination.
    pub total: i64,
}

/// Filter criteria for execution logs (used in POST-based filtering).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ExecutionLogFilter {
    /// Filter by script ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub script_id: Option<Uuid>,

    /// Filter by connector ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<Uuid>,

    /// Filter by binding ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_id: Option<Uuid>,

    /// Filter by execution status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    /// Filter by dry run flag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,

    /// Filter executions from this date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_date: Option<DateTime<Utc>>,

    /// Filter executions until this date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_date: Option<DateTime<Utc>>,
}

// ============================================================================
// Query Parameters
// ============================================================================

/// Query parameters for listing scripts.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ScriptListParams {
    /// Filter by script status (e.g., draft, active, archived).
    pub status: Option<String>,

    /// Search scripts by name or description.
    pub search: Option<String>,

    /// Page number (1-based).
    pub page: Option<i64>,

    /// Number of items per page.
    pub page_size: Option<i64>,
}

/// Query parameters for listing hook bindings.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct BindingListParams {
    /// Filter by connector ID.
    pub connector_id: Option<Uuid>,

    /// Filter by script ID.
    pub script_id: Option<Uuid>,

    /// Filter by hook phase.
    pub hook_phase: Option<String>,

    /// Filter by operation type.
    pub operation_type: Option<String>,

    /// Page number (1-based).
    pub page: Option<i64>,

    /// Number of items per page.
    pub page_size: Option<i64>,
}

/// Query parameters for listing script templates.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct TemplateListParams {
    /// Filter by template category.
    pub category: Option<String>,

    /// Search templates by name or description.
    pub search: Option<String>,

    /// Page number (1-based).
    pub page: Option<i64>,

    /// Number of items per page.
    pub page_size: Option<i64>,
}

/// Query parameters for listing execution logs.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ExecutionLogParams {
    /// Filter by script ID.
    pub script_id: Option<Uuid>,

    /// Filter by connector ID.
    pub connector_id: Option<Uuid>,

    /// Filter by binding ID.
    pub binding_id: Option<Uuid>,

    /// Filter by execution status.
    pub status: Option<String>,

    /// Filter by dry run flag.
    pub dry_run: Option<bool>,

    /// Filter executions from this date (ISO 8601 format).
    pub from_date: Option<String>,

    /// Filter executions until this date (ISO 8601 format).
    pub to_date: Option<String>,

    /// Page number (1-based).
    pub page: Option<i64>,

    /// Number of items per page.
    pub page_size: Option<i64>,
}
