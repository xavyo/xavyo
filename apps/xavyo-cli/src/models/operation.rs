//! Operation and job tracking data models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Provisioning operation response
#[derive(Debug, Serialize, Deserialize)]
pub struct OperationResponse {
    pub id: Uuid,
    #[serde(default)]
    pub operation_type: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub target_type: Option<String>,
    #[serde(default)]
    pub target_id: Option<Uuid>,
    #[serde(default)]
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub completed_at: Option<DateTime<Utc>>,
}

/// Operation list response
#[derive(Debug, Serialize, Deserialize)]
pub struct OperationListResponse {
    pub operations: Vec<OperationResponse>,
    pub total: i64,
}

/// Queue stats response
#[derive(Debug, Serialize, Deserialize)]
pub struct QueueStatsResponse {
    #[serde(default)]
    pub pending: i64,
    #[serde(default)]
    pub in_progress: i64,
    #[serde(default)]
    pub completed: i64,
    #[serde(default)]
    pub failed: i64,
    #[serde(default)]
    pub dead_letter: i64,
}

/// Connector job response
#[derive(Debug, Serialize, Deserialize)]
pub struct JobResponse {
    pub id: Uuid,
    #[serde(default)]
    pub job_type: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub connector_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub completed_at: Option<DateTime<Utc>>,
}

/// Job list response
#[derive(Debug, Serialize, Deserialize)]
pub struct JobListResponse {
    pub jobs: Vec<JobResponse>,
    pub total: i64,
}

/// Dead letter queue entry
#[derive(Debug, Serialize, Deserialize)]
pub struct DlqEntryResponse {
    pub id: Uuid,
    #[serde(default)]
    pub error_message: Option<String>,
    #[serde(default)]
    pub original_operation_id: Option<Uuid>,
    #[serde(default)]
    pub retry_count: i32,
    pub created_at: DateTime<Utc>,
}

/// DLQ list response
#[derive(Debug, Serialize, Deserialize)]
pub struct DlqListResponse {
    pub entries: Vec<DlqEntryResponse>,
    pub total: i64,
}
