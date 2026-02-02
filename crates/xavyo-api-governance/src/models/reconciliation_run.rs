//! Request and response models for reconciliation run endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use xavyo_db::{GovReconciliationRun, ReconciliationStatus};

/// Trigger a new reconciliation run.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct TriggerReconciliationRequest {
    /// Optional notes for this run.
    #[serde(default)]
    pub notes: Option<String>,
}

/// Reconciliation run response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReconciliationRunResponse {
    /// Run ID.
    pub id: Uuid,

    /// Current status.
    pub status: ReconciliationStatus,

    /// When the run started.
    pub started_at: DateTime<Utc>,

    /// When the run completed (if finished).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,

    /// Total accounts scanned.
    pub total_accounts: i32,

    /// Total orphans found.
    pub orphans_found: i32,

    /// Newly detected orphans in this run.
    pub new_orphans: i32,

    /// Orphans that were resolved (no longer orphaned).
    pub resolved_orphans: i32,

    /// User who triggered this run (null if scheduled).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triggered_by: Option<Uuid>,

    /// Error message if failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,

    /// Progress percentage (0-100).
    pub progress_percent: i32,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl From<GovReconciliationRun> for ReconciliationRunResponse {
    fn from(run: GovReconciliationRun) -> Self {
        Self {
            id: run.id,
            status: run.status,
            started_at: run.started_at,
            completed_at: run.completed_at,
            total_accounts: run.total_accounts,
            orphans_found: run.orphans_found,
            new_orphans: run.new_orphans,
            resolved_orphans: run.resolved_orphans,
            triggered_by: run.triggered_by,
            error_message: run.error_message,
            progress_percent: run.progress_percent,
            created_at: run.created_at,
            updated_at: run.updated_at,
        }
    }
}

/// Query parameters for listing reconciliation runs.
#[derive(Debug, Clone, Deserialize, IntoParams)]
pub struct ListReconciliationRunsQuery {
    /// Filter by status.
    pub status: Option<ReconciliationStatus>,

    /// Filter by who triggered the run.
    pub triggered_by: Option<Uuid>,

    /// Filter runs since this date.
    pub since: Option<DateTime<Utc>>,

    /// Maximum number of results (default: 20, max: 100).
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<i64>,

    /// Number of results to skip.
    #[param(minimum = 0)]
    pub offset: Option<i64>,
}

impl Default for ListReconciliationRunsQuery {
    fn default() -> Self {
        Self {
            status: None,
            triggered_by: None,
            since: None,
            limit: Some(20),
            offset: Some(0),
        }
    }
}

/// Paginated list of reconciliation runs.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReconciliationRunListResponse {
    /// List of runs.
    pub items: Vec<ReconciliationRunResponse>,

    /// Total count matching the filter.
    pub total: i64,

    /// Limit used for query.
    pub limit: i64,

    /// Offset used for query.
    pub offset: i64,
}

// =============================================================================
// Schedule Models (for US7)
// =============================================================================

/// Reconciliation schedule response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ReconciliationScheduleResponse {
    /// Schedule ID.
    pub id: Uuid,

    /// Frequency: daily, weekly, or monthly.
    pub frequency: String,

    /// Day of week for weekly schedules (0=Sunday, 6=Saturday).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub day_of_week: Option<i32>,

    /// Day of month for monthly schedules (1-28).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub day_of_month: Option<i32>,

    /// Hour of day (0-23) when to run.
    pub hour_of_day: i32,

    /// Whether the schedule is enabled.
    pub is_enabled: bool,

    /// When the last run occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_run_at: Option<DateTime<Utc>>,

    /// When the next run is scheduled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_run_at: Option<DateTime<Utc>>,

    /// Creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Request to create or update a reconciliation schedule.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpsertScheduleRequest {
    /// Frequency: daily, weekly, or monthly.
    pub frequency: ScheduleFrequency,

    /// Day of week for weekly schedules (0=Sunday, 6=Saturday).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub day_of_week: Option<i32>,

    /// Day of month for monthly schedules (1-28).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub day_of_month: Option<i32>,

    /// Hour of day (0-23) when to run.
    #[serde(default = "default_hour")]
    pub hour_of_day: i32,

    /// Whether the schedule is enabled.
    #[serde(default)]
    pub is_enabled: bool,
}

fn default_hour() -> i32 {
    2 // 2 AM default
}

/// Schedule frequency options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleFrequency {
    /// Run daily.
    Daily,
    /// Run weekly.
    Weekly,
    /// Run monthly.
    Monthly,
}
