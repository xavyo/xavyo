//! Job Tracking Tests for F-044
//!
//! Tests for background job tracking, cancellation, and DLQ management.
//! These tests verify the job tracking API behavior.

mod common;

use chrono::{Duration, Utc};
use uuid::Uuid;
use xavyo_api_connectors::handlers::jobs::{
    BulkReplayRequest, BulkReplayResponse, CancelJobResponse, DlqEntry, DlqListResponse,
    JobAttempt, JobDetailResponse, JobListResponse, JobSummary, ListDlqQuery, ListJobsQuery,
    ReplayRequest, ReplayResponse,
};

// ============================================================================
// User Story 1: View Job Status - Tests (T008-T012)
// ============================================================================

// T008: Test JobSummary and JobListResponse serialization
#[test]
fn test_job_summary_fields() {
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

    assert_eq!(summary.status, "pending");
    assert_eq!(summary.operation_type, "create");
    assert!(summary.connector_name.is_some());
}

#[test]
fn test_job_summary_without_optional_fields() {
    let summary = JobSummary {
        id: Uuid::new_v4(),
        connector_id: Uuid::new_v4(),
        connector_name: None,
        operation_type: "update".to_string(),
        status: "in_progress".to_string(),
        created_at: Utc::now(),
        started_at: Some(Utc::now()),
        completed_at: None,
        error_message: None,
    };

    assert!(summary.connector_name.is_none());
    assert!(summary.started_at.is_some());
    assert!(summary.completed_at.is_none());
}

#[test]
fn test_job_summary_failed_status() {
    let summary = JobSummary {
        id: Uuid::new_v4(),
        connector_id: Uuid::new_v4(),
        connector_name: Some("LDAP Connector".to_string()),
        operation_type: "delete".to_string(),
        status: "failed".to_string(),
        created_at: Utc::now(),
        started_at: Some(Utc::now()),
        completed_at: Some(Utc::now()),
        error_message: Some("Connection refused".to_string()),
    };

    assert_eq!(summary.status, "failed");
    assert!(summary.error_message.is_some());
}

#[test]
fn test_job_list_response_structure() {
    let response = JobListResponse {
        jobs: vec![],
        total: 0,
        limit: 50,
        offset: 0,
    };

    assert!(response.jobs.is_empty());
    assert_eq!(response.total, 0);
    assert_eq!(response.limit, 50);
}

#[test]
fn test_job_list_response_with_jobs() {
    let job1 = JobSummary {
        id: Uuid::new_v4(),
        connector_id: Uuid::new_v4(),
        connector_name: Some("Connector 1".to_string()),
        operation_type: "create".to_string(),
        status: "completed".to_string(),
        created_at: Utc::now(),
        started_at: Some(Utc::now()),
        completed_at: Some(Utc::now()),
        error_message: None,
    };

    let job2 = JobSummary {
        id: Uuid::new_v4(),
        connector_id: Uuid::new_v4(),
        connector_name: Some("Connector 2".to_string()),
        operation_type: "update".to_string(),
        status: "pending".to_string(),
        created_at: Utc::now(),
        started_at: None,
        completed_at: None,
        error_message: None,
    };

    let response = JobListResponse {
        jobs: vec![job1, job2],
        total: 42,
        limit: 10,
        offset: 0,
    };

    assert_eq!(response.jobs.len(), 2);
    assert_eq!(response.total, 42);
}

#[test]
fn test_job_list_response_serialization() {
    let response = JobListResponse {
        jobs: vec![],
        total: 100,
        limit: 50,
        offset: 50,
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("\"total\":100"));
    assert!(json.contains("\"offset\":50"));
}

// T009: Test JobDetailResponse with attempts serialization
#[test]
fn test_job_detail_response_basic() {
    let detail = JobDetailResponse {
        id: Uuid::new_v4(),
        connector_id: Uuid::new_v4(),
        connector_name: Some("Test Connector".to_string()),
        operation_type: "create".to_string(),
        status: "pending".to_string(),
        user_id: Uuid::new_v4(),
        created_at: Utc::now(),
        started_at: None,
        completed_at: None,
        error_message: None,
        retry_count: 0,
        max_retries: 5,
        next_retry_at: None,
        cancelled_by: None,
        cancelled_at: None,
        attempts: vec![],
    };

    assert_eq!(detail.retry_count, 0);
    assert_eq!(detail.max_retries, 5);
    assert!(detail.attempts.is_empty());
}

#[test]
fn test_job_detail_response_with_attempts() {
    let now = Utc::now();
    let attempt1 = JobAttempt {
        attempt_number: 1,
        started_at: now - Duration::minutes(10),
        completed_at: Some(now - Duration::minutes(9)),
        success: false,
        error_code: Some("TIMEOUT".to_string()),
        error_message: Some("Connection timeout after 30s".to_string()),
        duration_ms: Some(30000),
    };

    let attempt2 = JobAttempt {
        attempt_number: 2,
        started_at: now - Duration::minutes(5),
        completed_at: Some(now - Duration::minutes(4)),
        success: false,
        error_code: Some("CONN_REFUSED".to_string()),
        error_message: Some("Connection refused".to_string()),
        duration_ms: Some(1500),
    };

    let detail = JobDetailResponse {
        id: Uuid::new_v4(),
        connector_id: Uuid::new_v4(),
        connector_name: None,
        operation_type: "update".to_string(),
        status: "failed".to_string(),
        user_id: Uuid::new_v4(),
        created_at: now - Duration::minutes(15),
        started_at: Some(now - Duration::minutes(10)),
        completed_at: Some(now),
        error_message: Some("Connection refused".to_string()),
        retry_count: 2,
        max_retries: 3,
        next_retry_at: Some(now + Duration::minutes(5)),
        cancelled_by: None,
        cancelled_at: None,
        attempts: vec![attempt1, attempt2],
    };

    assert_eq!(detail.attempts.len(), 2);
    assert_eq!(detail.attempts[0].attempt_number, 1);
    assert_eq!(detail.attempts[1].attempt_number, 2);
    assert!(!detail.attempts[0].success);
}

#[test]
fn test_job_detail_cancelled() {
    let now = Utc::now();
    let cancelled_by = Uuid::new_v4();

    let detail = JobDetailResponse {
        id: Uuid::new_v4(),
        connector_id: Uuid::new_v4(),
        connector_name: Some("LDAP Connector".to_string()),
        operation_type: "delete".to_string(),
        status: "cancelled".to_string(),
        user_id: Uuid::new_v4(),
        created_at: now - Duration::minutes(30),
        started_at: None,
        completed_at: None,
        error_message: None,
        retry_count: 0,
        max_retries: 5,
        next_retry_at: None,
        cancelled_by: Some(cancelled_by),
        cancelled_at: Some(now),
        attempts: vec![],
    };

    assert_eq!(detail.status, "cancelled");
    assert_eq!(detail.cancelled_by, Some(cancelled_by));
    assert!(detail.cancelled_at.is_some());
}

#[test]
fn test_job_attempt_serialization() {
    let attempt = JobAttempt {
        attempt_number: 1,
        started_at: Utc::now(),
        completed_at: Some(Utc::now()),
        success: true,
        error_code: None,
        error_message: None,
        duration_ms: Some(250),
    };

    let json = serde_json::to_string(&attempt).unwrap();
    assert!(json.contains("\"attempt_number\":1"));
    assert!(json.contains("\"success\":true"));
}

#[test]
fn test_job_detail_serialization() {
    let detail = JobDetailResponse {
        id: Uuid::new_v4(),
        connector_id: Uuid::new_v4(),
        connector_name: None,
        operation_type: "create".to_string(),
        status: "completed".to_string(),
        user_id: Uuid::new_v4(),
        created_at: Utc::now(),
        started_at: Some(Utc::now()),
        completed_at: Some(Utc::now()),
        error_message: None,
        retry_count: 0,
        max_retries: 5,
        next_retry_at: None,
        cancelled_by: None,
        cancelled_at: None,
        attempts: vec![JobAttempt {
            attempt_number: 1,
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            success: true,
            error_code: None,
            error_message: None,
            duration_ms: Some(100),
        }],
    };

    let json = serde_json::to_string(&detail).unwrap();
    assert!(json.contains("\"status\":\"completed\""));
    assert!(json.contains("\"attempts\""));
}

// T010: Test list jobs query parameters
#[test]
fn test_list_jobs_query_defaults() {
    let query: ListJobsQuery = serde_json::from_str("{}").unwrap();

    assert_eq!(query.limit, 50);
    assert_eq!(query.offset, 0);
    assert!(query.connector_id.is_none());
    assert!(query.status.is_none());
    assert!(query.from.is_none());
    assert!(query.to.is_none());
}

#[test]
fn test_list_jobs_query_with_status_filter() {
    let json = r#"{"status": "pending"}"#;
    let query: ListJobsQuery = serde_json::from_str(json).unwrap();

    assert_eq!(query.status, Some("pending".to_string()));
}

#[test]
fn test_list_jobs_query_with_connector_filter() {
    let connector_id = Uuid::new_v4();
    let json = format!(r#"{{"connector_id": "{connector_id}"}}"#);
    let query: ListJobsQuery = serde_json::from_str(&json).unwrap();

    assert_eq!(query.connector_id, Some(connector_id));
}

#[test]
fn test_list_jobs_query_with_date_filters() {
    let json = r#"{
        "from": "2026-02-01T00:00:00Z",
        "to": "2026-02-28T23:59:59Z"
    }"#;
    let query: ListJobsQuery = serde_json::from_str(json).unwrap();

    assert!(query.from.is_some());
    assert!(query.to.is_some());
}

#[test]
fn test_list_jobs_query_with_pagination() {
    let json = r#"{"limit": 25, "offset": 100}"#;
    let query: ListJobsQuery = serde_json::from_str(json).unwrap();

    assert_eq!(query.limit, 25);
    assert_eq!(query.offset, 100);
}

#[test]
fn test_list_jobs_query_combined_filters() {
    let connector_id = Uuid::new_v4();
    let json = format!(
        r#"{{
            "connector_id": "{connector_id}",
            "status": "failed",
            "from": "2026-02-01T00:00:00Z",
            "limit": 10,
            "offset": 20
        }}"#
    );
    let query: ListJobsQuery = serde_json::from_str(&json).unwrap();

    assert_eq!(query.connector_id, Some(connector_id));
    assert_eq!(query.status, Some("failed".to_string()));
    assert!(query.from.is_some());
    assert_eq!(query.limit, 10);
    assert_eq!(query.offset, 20);
}

// T011: Test list jobs empty results and pagination edge cases
#[test]
fn test_list_jobs_empty_results() {
    let response = JobListResponse {
        jobs: vec![],
        total: 0,
        limit: 50,
        offset: 0,
    };

    assert!(response.jobs.is_empty());
    assert_eq!(response.total, 0);
}

#[test]
fn test_list_jobs_pagination_beyond_total() {
    // When offset is beyond total, should return empty list
    let response = JobListResponse {
        jobs: vec![],
        total: 10,
        limit: 50,
        offset: 100,
    };

    assert!(response.jobs.is_empty());
    assert_eq!(response.total, 10);
    assert_eq!(response.offset, 100);
}

#[test]
fn test_list_jobs_partial_page() {
    // When requesting 50 but only 3 remaining
    let jobs = vec![
        JobSummary {
            id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            connector_name: None,
            operation_type: "create".to_string(),
            status: "pending".to_string(),
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            error_message: None,
        },
        JobSummary {
            id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            connector_name: None,
            operation_type: "update".to_string(),
            status: "completed".to_string(),
            created_at: Utc::now(),
            started_at: Some(Utc::now()),
            completed_at: Some(Utc::now()),
            error_message: None,
        },
        JobSummary {
            id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            connector_name: None,
            operation_type: "delete".to_string(),
            status: "failed".to_string(),
            created_at: Utc::now(),
            started_at: Some(Utc::now()),
            completed_at: Some(Utc::now()),
            error_message: Some("Target not found".to_string()),
        },
    ];

    let response = JobListResponse {
        jobs,
        total: 53,
        limit: 50,
        offset: 50,
    };

    assert_eq!(response.jobs.len(), 3);
    assert_eq!(response.total, 53);
}

#[test]
fn test_list_jobs_first_page() {
    let response = JobListResponse {
        jobs: vec![],
        total: 100,
        limit: 10,
        offset: 0,
    };

    // First page
    assert_eq!(response.offset, 0);
    // Can calculate if there are more pages
    let has_more = (response.offset + response.limit) < response.total;
    assert!(has_more);
}

#[test]
fn test_list_jobs_last_page() {
    let response = JobListResponse {
        jobs: vec![],
        total: 95,
        limit: 10,
        offset: 90,
    };

    // Last page when offset + limit >= total
    let has_more = (response.offset + response.limit) < response.total;
    assert!(!has_more);
}

// T012: Test get job by ID success and not found cases
#[test]
fn test_get_job_found_response() {
    let job_id = Uuid::new_v4();
    let detail = JobDetailResponse {
        id: job_id,
        connector_id: Uuid::new_v4(),
        connector_name: Some("Test Connector".to_string()),
        operation_type: "create".to_string(),
        status: "completed".to_string(),
        user_id: Uuid::new_v4(),
        created_at: Utc::now(),
        started_at: Some(Utc::now()),
        completed_at: Some(Utc::now()),
        error_message: None,
        retry_count: 0,
        max_retries: 5,
        next_retry_at: None,
        cancelled_by: None,
        cancelled_at: None,
        attempts: vec![JobAttempt {
            attempt_number: 1,
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            success: true,
            error_code: None,
            error_message: None,
            duration_ms: Some(100),
        }],
    };

    assert_eq!(detail.id, job_id);
    assert_eq!(detail.attempts.len(), 1);
}

#[test]
fn test_job_detail_statuses() {
    let statuses = [
        "pending",
        "in_progress",
        "completed",
        "failed",
        "dead_letter",
        "cancelled",
    ];

    for status in statuses {
        let detail = JobDetailResponse {
            id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            connector_name: None,
            operation_type: "create".to_string(),
            status: status.to_string(),
            user_id: Uuid::new_v4(),
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            error_message: None,
            retry_count: 0,
            max_retries: 5,
            next_retry_at: None,
            cancelled_by: None,
            cancelled_at: None,
            attempts: vec![],
        };

        assert_eq!(detail.status, status);
    }
}

#[test]
fn test_job_operation_types() {
    let types = ["create", "update", "delete"];

    for op_type in types {
        let summary = JobSummary {
            id: Uuid::new_v4(),
            connector_id: Uuid::new_v4(),
            connector_name: None,
            operation_type: op_type.to_string(),
            status: "pending".to_string(),
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            error_message: None,
        };

        assert_eq!(summary.operation_type, op_type);
    }
}

// ============================================================================
// User Story 2: Cancel Running Jobs - Tests (T019-T023)
// ============================================================================

// T019: Test CancelJobResponse serialization
#[test]
fn test_cancel_job_response_basic() {
    let response = CancelJobResponse {
        id: Uuid::new_v4(),
        status: "cancelled".to_string(),
        cancelled_at: Utc::now(),
        message: Some("Job cancellation requested".to_string()),
    };

    assert_eq!(response.status, "cancelled");
    assert!(response.message.is_some());
}

#[test]
fn test_cancel_job_response_serialization() {
    let response = CancelJobResponse {
        id: Uuid::new_v4(),
        status: "cancelled".to_string(),
        cancelled_at: Utc::now(),
        message: None,
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("\"status\":\"cancelled\""));
    // message should be omitted when None
    assert!(!json.contains("\"message\""));
}

#[test]
fn test_cancel_job_response_with_message() {
    let response = CancelJobResponse {
        id: Uuid::new_v4(),
        status: "cancelled".to_string(),
        cancelled_at: Utc::now(),
        message: Some("Cancelled by administrator".to_string()),
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("\"message\":\"Cancelled by administrator\""));
}

// T020-T023: Cancel job scenarios (these tests verify response structure)
#[test]
fn test_cancel_pending_job_response_structure() {
    // Simulates successful cancellation of a pending job
    let response = CancelJobResponse {
        id: Uuid::new_v4(),
        status: "cancelled".to_string(),
        cancelled_at: Utc::now(),
        message: Some("Pending job cancelled before execution".to_string()),
    };

    assert_eq!(response.status, "cancelled");
}

#[test]
fn test_cancel_in_progress_job_response_structure() {
    // Simulates successful cancellation of an in_progress job
    let response = CancelJobResponse {
        id: Uuid::new_v4(),
        status: "cancelled".to_string(),
        cancelled_at: Utc::now(),
        message: Some("Running job cancellation requested".to_string()),
    };

    assert_eq!(response.status, "cancelled");
}

// ============================================================================
// User Story 3: Replay Failed Messages - Tests (T027-T032)
// ============================================================================

// T027: Test DlqEntry and DlqListResponse serialization
#[test]
fn test_dlq_entry_fields() {
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

    assert_eq!(entry.retry_count, 5);
    assert!(entry.connector_name.is_some());
}

#[test]
fn test_dlq_entry_serialization() {
    let entry = DlqEntry {
        id: Uuid::new_v4(),
        connector_id: Uuid::new_v4(),
        connector_name: None,
        operation_type: "update".to_string(),
        error_message: "Connection timeout".to_string(),
        created_at: Utc::now(),
        retry_count: 3,
        last_attempt_at: None,
    };

    let json = serde_json::to_string(&entry).unwrap();
    assert!(json.contains("\"operation_type\":\"update\""));
    assert!(json.contains("\"error_message\":\"Connection timeout\""));
}

#[test]
fn test_dlq_list_response_empty() {
    let response = DlqListResponse {
        entries: vec![],
        total: 0,
        limit: 50,
        offset: 0,
    };

    assert!(response.entries.is_empty());
    assert_eq!(response.total, 0);
}

#[test]
fn test_dlq_list_response_with_entries() {
    let entry1 = DlqEntry {
        id: Uuid::new_v4(),
        connector_id: Uuid::new_v4(),
        connector_name: Some("Connector A".to_string()),
        operation_type: "create".to_string(),
        error_message: "Timeout".to_string(),
        created_at: Utc::now(),
        retry_count: 5,
        last_attempt_at: Some(Utc::now()),
    };

    let entry2 = DlqEntry {
        id: Uuid::new_v4(),
        connector_id: Uuid::new_v4(),
        connector_name: Some("Connector B".to_string()),
        operation_type: "delete".to_string(),
        error_message: "Not found".to_string(),
        created_at: Utc::now(),
        retry_count: 3,
        last_attempt_at: Some(Utc::now()),
    };

    let response = DlqListResponse {
        entries: vec![entry1, entry2],
        total: 25,
        limit: 10,
        offset: 0,
    };

    assert_eq!(response.entries.len(), 2);
    assert_eq!(response.total, 25);
}

// T028: Test ReplayRequest and ReplayResponse serialization
#[test]
fn test_replay_request_defaults() {
    let request: ReplayRequest = serde_json::from_str("{}").unwrap();
    assert!(!request.force);
}

#[test]
fn test_replay_request_with_force() {
    let request: ReplayRequest = serde_json::from_str(r#"{"force": true}"#).unwrap();
    assert!(request.force);
}

#[test]
fn test_replay_response_queued() {
    let response = ReplayResponse {
        id: Uuid::new_v4(),
        status: "queued".to_string(),
        message: Some("Entry requeued for processing".to_string()),
    };

    assert_eq!(response.status, "queued");
}

#[test]
fn test_replay_response_already_replayed() {
    let response = ReplayResponse {
        id: Uuid::new_v4(),
        status: "already_replayed".to_string(),
        message: Some("Use force=true to replay again".to_string()),
    };

    assert_eq!(response.status, "already_replayed");
}

#[test]
fn test_replay_response_serialization() {
    let response = ReplayResponse {
        id: Uuid::new_v4(),
        status: "queued".to_string(),
        message: None,
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("\"status\":\"queued\""));
}

// T029: Test BulkReplayRequest and BulkReplayResponse serialization
#[test]
fn test_bulk_replay_request() {
    let id1 = Uuid::new_v4();
    let id2 = Uuid::new_v4();
    let json = format!(r#"{{"ids": ["{id1}", "{id2}"], "force": false}}"#);

    let request: BulkReplayRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(request.ids.len(), 2);
    assert!(!request.force);
}

#[test]
fn test_bulk_replay_request_with_force() {
    let json = r#"{"ids": ["550e8400-e29b-41d4-a716-446655440000"], "force": true}"#;
    let request: BulkReplayRequest = serde_json::from_str(json).unwrap();

    assert_eq!(request.ids.len(), 1);
    assert!(request.force);
}

#[test]
fn test_bulk_replay_response_all_queued() {
    let response = BulkReplayResponse {
        total: 3,
        queued: 3,
        skipped: 0,
        failed: 0,
        results: vec![
            ReplayResponse {
                id: Uuid::new_v4(),
                status: "queued".to_string(),
                message: None,
            },
            ReplayResponse {
                id: Uuid::new_v4(),
                status: "queued".to_string(),
                message: None,
            },
            ReplayResponse {
                id: Uuid::new_v4(),
                status: "queued".to_string(),
                message: None,
            },
        ],
    };

    assert_eq!(response.total, 3);
    assert_eq!(response.queued, 3);
    assert_eq!(response.skipped, 0);
    assert_eq!(response.failed, 0);
}

#[test]
fn test_bulk_replay_response_mixed() {
    let response = BulkReplayResponse {
        total: 5,
        queued: 3,
        skipped: 1,
        failed: 1,
        results: vec![],
    };

    assert_eq!(response.total, 5);
    assert_eq!(response.queued + response.skipped + response.failed, 5);
}

#[test]
fn test_bulk_replay_response_serialization() {
    let response = BulkReplayResponse {
        total: 2,
        queued: 2,
        skipped: 0,
        failed: 0,
        results: vec![],
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("\"total\":2"));
    assert!(json.contains("\"queued\":2"));
}

// T030: Test list DLQ with connector filter and pagination
#[test]
fn test_list_dlq_query_defaults() {
    let query: ListDlqQuery = serde_json::from_str("{}").unwrap();

    assert_eq!(query.limit, 50);
    assert_eq!(query.offset, 0);
    assert!(query.connector_id.is_none());
}

#[test]
fn test_list_dlq_query_with_connector() {
    let connector_id = Uuid::new_v4();
    let json = format!(r#"{{"connector_id": "{connector_id}"}}"#);

    let query: ListDlqQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(query.connector_id, Some(connector_id));
}

#[test]
fn test_list_dlq_query_with_pagination() {
    let json = r#"{"limit": 25, "offset": 50}"#;
    let query: ListDlqQuery = serde_json::from_str(json).unwrap();

    assert_eq!(query.limit, 25);
    assert_eq!(query.offset, 50);
}

// ============================================================================
// User Story 4: Job History Management - Tests (T040-T042)
// ============================================================================

// T040-T042: Retention tests (verify data structures for cleanup)
#[test]
fn test_completed_job_structure_for_cleanup() {
    // A completed job should have completed_at set
    let detail = JobDetailResponse {
        id: Uuid::new_v4(),
        connector_id: Uuid::new_v4(),
        connector_name: None,
        operation_type: "create".to_string(),
        status: "completed".to_string(),
        user_id: Uuid::new_v4(),
        created_at: Utc::now() - Duration::days(35),
        started_at: Some(Utc::now() - Duration::days(35)),
        completed_at: Some(Utc::now() - Duration::days(35)),
        error_message: None,
        retry_count: 0,
        max_retries: 5,
        next_retry_at: None,
        cancelled_by: None,
        cancelled_at: None,
        attempts: vec![],
    };

    // This job is older than 30 days and completed, should be eligible for cleanup
    let age_days = (Utc::now() - detail.created_at).num_days();
    assert!(age_days >= 30);
    assert_eq!(detail.status, "completed");
}

#[test]
fn test_failed_job_structure_for_retention() {
    // A failed job should be retained longer (90 days)
    let detail = JobDetailResponse {
        id: Uuid::new_v4(),
        connector_id: Uuid::new_v4(),
        connector_name: None,
        operation_type: "update".to_string(),
        status: "failed".to_string(),
        user_id: Uuid::new_v4(),
        created_at: Utc::now() - Duration::days(60),
        started_at: Some(Utc::now() - Duration::days(60)),
        completed_at: Some(Utc::now() - Duration::days(60)),
        error_message: Some("Permanent failure".to_string()),
        retry_count: 5,
        max_retries: 5,
        next_retry_at: None,
        cancelled_by: None,
        cancelled_at: None,
        attempts: vec![],
    };

    // This job is 60 days old and failed - within 90 day retention
    let age_days = (Utc::now() - detail.created_at).num_days();
    assert!((30..90).contains(&age_days));
    assert_eq!(detail.status, "failed");
}

#[test]
fn test_job_tenant_isolation_field() {
    // Verify that job detail includes tenant-related fields for isolation
    let detail = JobDetailResponse {
        id: Uuid::new_v4(),
        connector_id: Uuid::new_v4(),
        connector_name: Some("Tenant A Connector".to_string()),
        operation_type: "create".to_string(),
        status: "completed".to_string(),
        user_id: Uuid::new_v4(),
        created_at: Utc::now(),
        started_at: Some(Utc::now()),
        completed_at: Some(Utc::now()),
        error_message: None,
        retry_count: 0,
        max_retries: 5,
        next_retry_at: None,
        cancelled_by: None,
        cancelled_at: None,
        attempts: vec![],
    };

    // Connector ID and user_id are used for tenant isolation
    assert!(!detail.connector_id.is_nil());
    assert!(!detail.user_id.is_nil());
}
