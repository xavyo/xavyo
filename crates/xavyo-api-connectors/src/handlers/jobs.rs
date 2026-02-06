//! Job tracking handlers for background operations.
//!
//! Provides endpoints for viewing job status, cancelling jobs,
//! and managing the dead letter queue.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use xavyo_auth::JwtClaims;

use crate::error::ApiError;
use crate::services::JobService;

// ============================================================================
// Job Response Types (T001)
// ============================================================================

/// Query parameters for listing jobs.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ListJobsQuery {
    /// Filter by connector ID.
    pub connector_id: Option<Uuid>,
    /// Filter by status.
    pub status: Option<String>,
    /// Filter jobs created after this time.
    pub from: Option<DateTime<Utc>>,
    /// Filter jobs created before this time.
    pub to: Option<DateTime<Utc>>,
    /// Maximum number of results (default 50, max 100).
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Offset for pagination.
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

/// Summary of a job for list responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSummary {
    /// Job unique identifier.
    pub id: Uuid,
    /// Connector ID.
    pub connector_id: Uuid,
    /// Connector name (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_name: Option<String>,
    /// Type of operation (create, update, delete).
    pub operation_type: String,
    /// Current status.
    pub status: String,
    /// When the job was created.
    pub created_at: DateTime<Utc>,
    /// When processing started.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    /// When processing completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    /// Error message if failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

/// Detailed job response including execution history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobDetailResponse {
    /// Job unique identifier.
    pub id: Uuid,
    /// Connector ID.
    pub connector_id: Uuid,
    /// Connector name (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_name: Option<String>,
    /// Type of operation.
    pub operation_type: String,
    /// Current status.
    pub status: String,
    /// Target user ID.
    pub user_id: Uuid,
    /// When the job was created.
    pub created_at: DateTime<Utc>,
    /// When processing started.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    /// When processing completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    /// Error message if failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    /// Current retry count.
    pub retry_count: i32,
    /// Maximum retries allowed.
    pub max_retries: i32,
    /// Next retry time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retry_at: Option<DateTime<Utc>>,
    /// Who cancelled the job.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancelled_by: Option<Uuid>,
    /// When the job was cancelled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancelled_at: Option<DateTime<Utc>>,
    /// Execution attempts.
    pub attempts: Vec<JobAttempt>,
}

/// A single execution attempt for a job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobAttempt {
    /// Attempt number (1-based).
    pub attempt_number: i32,
    /// When the attempt started.
    pub started_at: DateTime<Utc>,
    /// When the attempt completed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    /// Whether the attempt succeeded.
    pub success: bool,
    /// Error code if failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Error message if failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    /// Duration in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<i64>,
}

/// Response for job list endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobListResponse {
    /// List of jobs.
    pub jobs: Vec<JobSummary>,
    /// Total count matching filters.
    pub total: i64,
    /// Page size.
    pub limit: i64,
    /// Page offset.
    pub offset: i64,
}

/// Response for job cancellation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelJobResponse {
    /// Job ID.
    pub id: Uuid,
    /// New status (cancelled).
    pub status: String,
    /// When cancellation was processed.
    pub cancelled_at: DateTime<Utc>,
    /// Confirmation message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// ============================================================================
// DLQ Response Types (T002)
// ============================================================================

/// Query parameters for listing DLQ entries.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ListDlqQuery {
    /// Filter by connector ID.
    pub connector_id: Option<Uuid>,
    /// Maximum number of results (default 50, max 100).
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Offset for pagination.
    #[serde(default)]
    pub offset: i64,
}

/// A dead letter queue entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlqEntry {
    /// Entry unique identifier.
    pub id: Uuid,
    /// Connector ID.
    pub connector_id: Uuid,
    /// Connector name (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector_name: Option<String>,
    /// Type of operation.
    pub operation_type: String,
    /// Error message explaining the failure.
    pub error_message: String,
    /// When the entry was created.
    pub created_at: DateTime<Utc>,
    /// Number of retry attempts before DLQ.
    pub retry_count: i32,
    /// When the last attempt occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<DateTime<Utc>>,
}

/// Response for DLQ list endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlqListResponse {
    /// List of DLQ entries.
    pub entries: Vec<DlqEntry>,
    /// Total count matching filters.
    pub total: i64,
    /// Page size.
    pub limit: i64,
    /// Page offset.
    pub offset: i64,
}

/// Request to replay a DLQ entry.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ReplayRequest {
    /// Force replay even if already replayed.
    #[serde(default)]
    pub force: bool,
}

/// Response for replay operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayResponse {
    /// Entry ID.
    pub id: Uuid,
    /// Status: "queued" or "`already_replayed`".
    pub status: String,
    /// Additional message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Request to bulk replay DLQ entries.
#[derive(Debug, Clone, Deserialize)]
pub struct BulkReplayRequest {
    /// IDs of entries to replay (max 100).
    pub ids: Vec<Uuid>,
    /// Force replay even if already replayed.
    #[serde(default)]
    pub force: bool,
}

/// Response for bulk replay operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkReplayResponse {
    /// Total entries processed.
    pub total: i32,
    /// Entries successfully queued.
    pub queued: i32,
    /// Entries skipped (already replayed).
    pub skipped: i32,
    /// Entries that failed to replay.
    pub failed: i32,
    /// Individual results.
    pub results: Vec<ReplayResponse>,
}

// ============================================================================
// State and Handler Implementations
// ============================================================================

/// Shared state for job tracking API handlers.
#[derive(Clone)]
pub struct JobState {
    pub job_service: Arc<JobService>,
}

impl JobState {
    /// Create a new job state.
    #[must_use]
    pub fn new(job_service: Arc<JobService>) -> Self {
        Self { job_service }
    }
}

/// Extract tenant ID from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or_else(|| ApiError::Unauthorized {
            message: "Missing tenant ID in claims".to_string(),
        })
}

/// Extract user ID from JWT claims.
fn extract_user_id(claims: &JwtClaims) -> Result<Uuid, ApiError> {
    Uuid::parse_str(&claims.sub).map_err(|_| ApiError::Unauthorized {
        message: "Invalid user ID in claims".to_string(),
    })
}

// ============================================================================
// User Story 1: View Job Status - Handlers (T015-T016)
// ============================================================================

/// List jobs with filtering and pagination.
///
/// GET /jobs
///
/// Query Parameters:
/// - `connector_id`: Filter by connector ID
/// - status: Filter by status (pending, `in_progress`, completed, failed, `dead_letter`, cancelled)
/// - from: Filter jobs created after this time
/// - to: Filter jobs created before this time
/// - limit: Page size (default 50, max 100)
/// - offset: Page offset
pub async fn list_jobs(
    State(state): State<JobState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListJobsQuery>,
) -> Result<Json<JobListResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&claims)?;

    // Validate and clamp pagination
    let limit = query.limit.clamp(1, 100);
    let offset = query.offset.max(0);

    let response = state
        .job_service
        .list_jobs(
            tenant_id,
            query.connector_id,
            query.status.as_deref(),
            query.from,
            query.to,
            limit,
            offset,
        )
        .await?;

    Ok(Json(response))
}

/// Get job details by ID.
///
/// GET /jobs/{id}
///
/// Returns detailed job information including execution attempts.
pub async fn get_job(
    State(state): State<JobState>,
    Extension(claims): Extension<JwtClaims>,
    Path(job_id): Path<Uuid>,
) -> Result<Json<JobDetailResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let response = state.job_service.get_job_detail(tenant_id, job_id).await?;

    Ok(Json(response))
}

// ============================================================================
// User Story 2: Cancel Running Jobs - Handler (T025)
// ============================================================================

/// Cancel a job.
///
/// POST /jobs/{id}/cancel
///
/// Cancels a pending or in-progress job. Cannot cancel completed jobs.
pub async fn cancel_job(
    State(state): State<JobState>,
    Extension(claims): Extension<JwtClaims>,
    Path(job_id): Path<Uuid>,
) -> Result<Json<CancelJobResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&claims)?;
    let cancelled_by = extract_user_id(&claims)?;

    let response = state
        .job_service
        .cancel_job(tenant_id, job_id, cancelled_by)
        .await?;

    Ok(Json(response))
}

// ============================================================================
// User Story 3: Replay Failed Messages - Handlers (T036-T038)
// ============================================================================

/// List dead letter queue entries.
///
/// GET /dlq
///
/// Query Parameters:
/// - `connector_id`: Filter by connector ID
/// - limit: Page size (default 50, max 100)
/// - offset: Page offset
pub async fn list_dlq(
    State(state): State<JobState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListDlqQuery>,
) -> Result<Json<DlqListResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&claims)?;

    // Validate and clamp pagination
    let limit = query.limit.clamp(1, 100);
    let offset = query.offset.max(0);

    let response = state
        .job_service
        .list_dlq(tenant_id, query.connector_id, limit, offset)
        .await?;

    Ok(Json(response))
}

/// Replay a single DLQ entry.
///
/// POST /dlq/{id}/replay
///
/// Re-queues a dead letter entry for processing.
pub async fn replay_dlq_entry(
    State(state): State<JobState>,
    Extension(claims): Extension<JwtClaims>,
    Path(entry_id): Path<Uuid>,
    Json(request): Json<ReplayRequest>,
) -> Result<Json<ReplayResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&claims)?;

    let response = state
        .job_service
        .replay_dlq_entry(tenant_id, entry_id, request.force)
        .await?;

    Ok(Json(response))
}

/// Bulk replay multiple DLQ entries.
///
/// POST /dlq/replay
///
/// Re-queues multiple dead letter entries for processing.
pub async fn bulk_replay_dlq(
    State(state): State<JobState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<BulkReplayRequest>,
) -> Result<Json<BulkReplayResponse>, ApiError> {
    let tenant_id = extract_tenant_id(&claims)?;

    // Limit bulk operations to 100 entries
    if request.ids.len() > 100 {
        return Err(ApiError::Validation(
            "Maximum 100 entries can be replayed at once".to_string(),
        ));
    }

    let response = state
        .job_service
        .bulk_replay_dlq(tenant_id, &request.ids, request.force)
        .await?;

    Ok(Json(response))
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_jobs_query_defaults() {
        let query: ListJobsQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(query.limit, 50);
        assert_eq!(query.offset, 0);
        assert!(query.connector_id.is_none());
        assert!(query.status.is_none());
    }

    #[test]
    fn test_job_summary_serialization() {
        let summary = JobSummary {
            id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            connector_name: Some("Test Connector".to_string()),
            operation_type: "create".to_string(),
            status: "pending".to_string(),
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            error_message: None,
        };

        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"status\":\"pending\""));
        assert!(json.contains("\"operation_type\":\"create\""));
    }

    #[test]
    fn test_job_list_response_serialization() {
        let response = JobListResponse {
            jobs: vec![],
            total: 0,
            limit: 50,
            offset: 0,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"total\":0"));
        assert!(json.contains("\"limit\":50"));
    }

    #[test]
    fn test_job_detail_response_with_attempts() {
        let detail = JobDetailResponse {
            id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            connector_name: None,
            operation_type: "update".to_string(),
            status: "failed".to_string(),
            user_id: Uuid::new_v4(),
            created_at: Utc::now(),
            started_at: Some(Utc::now()),
            completed_at: Some(Utc::now()),
            error_message: Some("Connection timeout".to_string()),
            retry_count: 3,
            max_retries: 5,
            next_retry_at: None,
            cancelled_by: None,
            cancelled_at: None,
            attempts: vec![JobAttempt {
                attempt_number: 1,
                started_at: Utc::now(),
                completed_at: Some(Utc::now()),
                success: false,
                error_code: Some("TIMEOUT".to_string()),
                error_message: Some("Connection timeout".to_string()),
                duration_ms: Some(30000),
            }],
        };

        let json = serde_json::to_string(&detail).unwrap();
        assert!(json.contains("\"retry_count\":3"));
        assert!(json.contains("\"attempts\""));
    }

    #[test]
    fn test_cancel_job_response() {
        let response = CancelJobResponse {
            id: Uuid::new_v4(),
            status: "cancelled".to_string(),
            cancelled_at: Utc::now(),
            message: Some("Job cancellation requested".to_string()),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"cancelled\""));
    }

    #[test]
    fn test_list_dlq_query_defaults() {
        let query: ListDlqQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(query.limit, 50);
        assert_eq!(query.offset, 0);
        assert!(query.connector_id.is_none());
    }

    #[test]
    fn test_dlq_entry_serialization() {
        let entry = DlqEntry {
            id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            connector_name: Some("LDAP Connector".to_string()),
            operation_type: "create".to_string(),
            error_message: "Max retries exceeded".to_string(),
            created_at: Utc::now(),
            retry_count: 5,
            last_attempt_at: Some(Utc::now()),
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"retry_count\":5"));
        assert!(json.contains("\"error_message\":\"Max retries exceeded\""));
    }

    #[test]
    fn test_dlq_list_response() {
        let response = DlqListResponse {
            entries: vec![],
            total: 0,
            limit: 50,
            offset: 0,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"entries\":[]"));
    }

    #[test]
    fn test_replay_request_defaults() {
        let request: ReplayRequest = serde_json::from_str("{}").unwrap();
        assert!(!request.force);
    }

    #[test]
    fn test_replay_response_queued() {
        let response = ReplayResponse {
            id: Uuid::new_v4(),
            status: "queued".to_string(),
            message: Some("Entry requeued for processing".to_string()),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"queued\""));
    }

    #[test]
    fn test_bulk_replay_request() {
        let json = r#"{"ids": ["550e8400-e29b-41d4-a716-446655440000"], "force": true}"#;
        let request: BulkReplayRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.ids.len(), 1);
        assert!(request.force);
    }

    #[test]
    fn test_bulk_replay_response() {
        let response = BulkReplayResponse {
            total: 5,
            queued: 4,
            skipped: 1,
            failed: 0,
            results: vec![],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"total\":5"));
        assert!(json.contains("\"queued\":4"));
        assert!(json.contains("\"skipped\":1"));
    }
}
