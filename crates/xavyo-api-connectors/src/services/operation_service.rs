//! Operation service for provisioning operations.
//!
//! Provides a high-level interface for triggering, querying, and managing
//! provisioning operations.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use tracing::{info, instrument};
use uuid::Uuid;

use xavyo_connector::types::{OperationStatus, OperationType};
use xavyo_db::models::{
    operation_log::OperationLog, provisioning_operation::ProvisioningOperation,
};
use xavyo_provisioning::{EnqueueResult, OperationQueue, QueueConfig, QueuedOperation};

/// Operation service errors.
#[derive(Debug, Error)]
pub enum OperationServiceError {
    /// Database error.
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Queue error.
    #[error("Queue error: {0}")]
    Queue(#[from] xavyo_provisioning::QueueError),

    /// Operation not found.
    #[error("Operation not found: {0}")]
    NotFound(Uuid),

    /// Invalid operation state.
    #[error("Invalid operation state for {operation_id}: cannot {action} from {current_state}")]
    InvalidState {
        operation_id: Uuid,
        current_state: String,
        action: String,
    },

    /// Connector not found.
    #[error("Connector not found: {0}")]
    ConnectorNotFound(Uuid),
}

/// Result type for operation service.
pub type OperationServiceResult<T> = Result<T, OperationServiceError>;

/// Request to trigger a manual provisioning operation.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TriggerOperationRequest {
    /// The connector to provision to.
    pub connector_id: Uuid,

    /// The user to provision.
    pub user_id: Uuid,

    /// Operation type (create, update, delete).
    pub operation_type: OperationType,

    /// Target object class.
    pub object_class: String,

    /// Target UID (required for update/delete).
    #[serde(default)]
    pub target_uid: Option<String>,

    /// Payload to provision.
    pub payload: serde_json::Value,

    /// Priority (higher = more urgent).
    #[serde(default)]
    pub priority: Option<i32>,
}

/// Response for a provisioning operation.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OperationResponse {
    /// Operation ID.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Connector ID.
    pub connector_id: Uuid,

    /// User ID being provisioned.
    pub user_id: Uuid,

    /// Operation type.
    pub operation_type: String,

    /// Target object class.
    pub object_class: String,

    /// Target UID in external system.
    pub target_uid: Option<String>,

    /// Operation status.
    pub status: String,

    /// Number of retry attempts.
    pub retry_count: i32,

    /// Maximum retries allowed.
    pub max_retries: i32,

    /// Error message if failed.
    pub error_message: Option<String>,

    /// Priority level.
    pub priority: i32,

    /// Idempotency key for duplicate detection.
    pub idempotency_key: Option<String>,

    /// When the next retry is scheduled (if failed).
    pub next_retry_at: Option<chrono::DateTime<chrono::Utc>>,

    /// When the operation was created.
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// When the operation was last updated.
    pub updated_at: chrono::DateTime<chrono::Utc>,

    /// When the operation started processing.
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,

    /// When the operation completed.
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Resolution notes (for resolved DLQ items).
    pub resolution_notes: Option<String>,

    /// Who resolved this operation (for DLQ items).
    pub resolved_by: Option<Uuid>,

    /// When the operation was resolved.
    pub resolved_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Execution attempt history (populated when `include_attempts=true`).
    /// Each attempt records a single execution of the operation (F047).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempts: Option<Vec<AttemptResponse>>,
}

impl From<&QueuedOperation> for OperationResponse {
    fn from(op: &QueuedOperation) -> Self {
        Self {
            id: op.id,
            tenant_id: op.tenant_id,
            connector_id: op.connector_id,
            user_id: op.user_id,
            operation_type: op.operation_type.as_str().to_string(),
            object_class: op.object_class.clone(),
            target_uid: op.target_uid.clone(),
            status: op.status.as_str().to_string(),
            retry_count: op.retry_count,
            max_retries: op.max_retries,
            error_message: op.error_message.clone(),
            priority: op.priority,
            idempotency_key: op.idempotency_key.clone(),
            next_retry_at: op.next_retry_at,
            created_at: op.created_at,
            updated_at: op.updated_at,
            started_at: op.started_at,
            completed_at: op.completed_at,
            resolution_notes: op.resolution_notes.clone(),
            resolved_by: op.resolved_by,
            resolved_at: op.resolved_at,
            attempts: None, // Populated separately when include_attempts=true (F047)
        }
    }
}

impl OperationResponse {
    /// Create a response with attempts populated (F047).
    #[must_use]
    pub fn with_attempts(mut self, attempts: Vec<AttemptResponse>) -> Self {
        self.attempts = Some(attempts);
        self
    }
}

/// Filter for listing operations.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OperationFilter {
    /// Filter by connector.
    pub connector_id: Option<Uuid>,

    /// Filter by user.
    pub user_id: Option<Uuid>,

    /// Filter by status.
    pub status: Option<String>,

    /// Filter by operation type.
    pub operation_type: Option<String>,

    /// Maximum results.
    #[serde(default = "default_limit")]
    pub limit: i64,

    /// Offset for pagination.
    #[serde(default)]
    pub offset: i64,
}

impl Default for OperationFilter {
    fn default() -> Self {
        Self {
            connector_id: None,
            user_id: None,
            status: None,
            operation_type: None,
            limit: 50,
            offset: 0,
        }
    }
}

fn default_limit() -> i64 {
    50
}

/// Paginated list response.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OperationListResponse {
    /// List of operations.
    pub operations: Vec<OperationResponse>,

    /// Total count (for pagination).
    pub total: i64,

    /// Current offset.
    pub offset: i64,

    /// Applied limit.
    pub limit: i64,
}

/// Operation log response.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OperationLogResponse {
    /// Log ID.
    pub id: Uuid,

    /// Operation ID.
    pub operation_id: Uuid,

    /// Connector ID.
    pub connector_id: Uuid,

    /// User ID.
    pub user_id: Option<Uuid>,

    /// Operation type.
    pub operation_type: String,

    /// Target UID.
    pub target_uid: Option<String>,

    /// Log status.
    pub status: String,

    /// Duration in milliseconds.
    pub duration_ms: Option<i32>,

    /// Error message.
    pub error_message: Option<String>,

    /// When logged.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<&OperationLog> for OperationLogResponse {
    fn from(log: &OperationLog) -> Self {
        Self {
            id: log.id,
            operation_id: log.operation_id,
            connector_id: log.connector_id,
            user_id: log.user_id,
            operation_type: log.operation_type.clone(),
            target_uid: log.target_uid.clone(),
            status: log.status.to_string(),
            duration_ms: log.duration_ms,
            error_message: log.error_message.clone(),
            created_at: log.created_at,
        }
    }
}

/// Operation service.
pub struct OperationService {
    pool: PgPool,
    queue: Arc<OperationQueue>,
}

impl OperationService {
    /// Create a new operation service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        let queue = Arc::new(OperationQueue::new(pool.clone()));
        Self { pool, queue }
    }

    /// Create with custom queue configuration.
    #[must_use] 
    pub fn with_queue_config(pool: PgPool, config: QueueConfig) -> Self {
        let queue = Arc::new(OperationQueue::with_config(pool.clone(), config));
        Self { pool, queue }
    }

    /// Get the underlying queue for the processor.
    #[must_use] 
    pub fn queue(&self) -> Arc<OperationQueue> {
        self.queue.clone()
    }

    /// Trigger a manual provisioning operation.
    ///
    /// Uses idempotency key detection to prevent duplicate operations.
    /// If a duplicate is detected, returns the existing operation instead of creating a new one.
    #[instrument(skip(self), fields(connector_id = %request.connector_id, user_id = %request.user_id))]
    pub async fn trigger_operation(
        &self,
        tenant_id: Uuid,
        request: TriggerOperationRequest,
    ) -> OperationServiceResult<OperationResponse> {
        info!(
            operation_type = ?request.operation_type,
            object_class = %request.object_class,
            "Triggering provisioning operation"
        );

        // Create the queued operation
        let mut operation = QueuedOperation::new(
            tenant_id,
            request.connector_id,
            request.user_id,
            request.operation_type,
            request.object_class.clone(),
            request.payload.clone(),
        );

        // Set optional fields
        if let Some(ref target_uid) = request.target_uid {
            operation = operation.with_target_uid(target_uid.clone());
        }
        if let Some(priority) = request.priority {
            operation.priority = priority;
        }

        // Enqueue with idempotency check to detect duplicates
        let result = self.queue.enqueue_idempotent(operation.clone()).await?;

        match result {
            EnqueueResult::Enqueued { id } => {
                operation.id = id;
                info!(operation_id = %id, "Operation enqueued");
                Ok(OperationResponse::from(&operation))
            }
            EnqueueResult::Duplicate { existing_id } => {
                info!(
                    existing_id = %existing_id,
                    "Duplicate operation detected, returning existing"
                );
                // Return the existing operation
                let existing = self
                    .queue
                    .get_operation(existing_id)
                    .await?
                    .ok_or(OperationServiceError::NotFound(existing_id))?;
                Ok(OperationResponse::from(&existing))
            }
        }
    }

    /// Get an operation by ID.
    #[instrument(skip(self))]
    pub async fn get_operation(
        &self,
        tenant_id: Uuid,
        operation_id: Uuid,
    ) -> OperationServiceResult<OperationResponse> {
        let operation = self
            .queue
            .get_operation(operation_id)
            .await?
            .ok_or(OperationServiceError::NotFound(operation_id))?;

        // Verify tenant access
        if operation.tenant_id != tenant_id {
            return Err(OperationServiceError::NotFound(operation_id));
        }

        Ok(OperationResponse::from(&operation))
    }

    /// Get an operation by ID with its execution attempts included (F047).
    ///
    /// This returns the operation along with all its attempt history, useful for
    /// debugging failed operations or understanding execution timeline.
    #[instrument(skip(self))]
    pub async fn get_operation_with_attempts(
        &self,
        tenant_id: Uuid,
        operation_id: Uuid,
    ) -> OperationServiceResult<OperationResponse> {
        // Get the operation first
        let response = self.get_operation(tenant_id, operation_id).await?;

        // Get attempts for this operation
        let attempts = self.get_operation_attempts(tenant_id, operation_id).await?;

        Ok(response.with_attempts(attempts))
    }

    /// List operations with filters.
    #[instrument(skip(self))]
    pub async fn list_operations(
        &self,
        tenant_id: Uuid,
        filter: OperationFilter,
    ) -> OperationServiceResult<OperationListResponse> {
        let operations = ProvisioningOperation::list_by_tenant(
            &self.pool,
            tenant_id,
            filter.connector_id,
            filter.status.as_deref(),
            filter.limit,
            filter.offset,
        )
        .await?;

        // Convert to response format
        let responses: Vec<OperationResponse> = operations
            .iter()
            .map(|op| OperationResponse {
                id: op.id,
                tenant_id: op.tenant_id,
                connector_id: op.connector_id,
                user_id: op.user_id,
                operation_type: op.operation_type.to_string(),
                object_class: op.object_class.clone(),
                target_uid: op.target_uid.clone(),
                status: op.status.to_string(),
                retry_count: op.retry_count,
                max_retries: op.max_retries,
                error_message: op.error_message.clone(),
                priority: op.priority,
                idempotency_key: op.idempotency_key.clone(),
                next_retry_at: op.next_retry_at,
                created_at: op.created_at,
                updated_at: op.updated_at,
                started_at: op.started_at,
                completed_at: op.completed_at,
                resolution_notes: op.resolution_notes.clone(),
                resolved_by: op.resolved_by,
                resolved_at: op.resolved_at,
                attempts: None, // Not included in list operations (F047)
            })
            .collect();

        // Get total count
        let total = ProvisioningOperation::count_by_tenant(
            &self.pool,
            tenant_id,
            filter.connector_id,
            filter.status.as_deref(),
        )
        .await?;

        Ok(OperationListResponse {
            operations: responses,
            total,
            offset: filter.offset,
            limit: filter.limit,
        })
    }

    /// Retry a failed operation.
    #[instrument(skip(self))]
    pub async fn retry_operation(
        &self,
        tenant_id: Uuid,
        operation_id: Uuid,
    ) -> OperationServiceResult<OperationResponse> {
        // Get the operation
        let operation = self
            .queue
            .get_operation(operation_id)
            .await?
            .ok_or(OperationServiceError::NotFound(operation_id))?;

        // Verify tenant access
        if operation.tenant_id != tenant_id {
            return Err(OperationServiceError::NotFound(operation_id));
        }

        // Check if it can be retried
        if operation.status != OperationStatus::Failed
            && operation.status != OperationStatus::DeadLetter
        {
            return Err(OperationServiceError::InvalidState {
                operation_id,
                current_state: operation.status.as_str().to_string(),
                action: "retry".to_string(),
            });
        }

        // Retry the operation
        self.queue.retry_dead_letter(operation_id).await?;

        info!(operation_id = %operation_id, "Operation scheduled for retry");

        // Get the updated operation
        let updated = self
            .queue
            .get_operation(operation_id)
            .await?
            .ok_or(OperationServiceError::NotFound(operation_id))?;

        Ok(OperationResponse::from(&updated))
    }

    /// Cancel a pending operation.
    #[instrument(skip(self))]
    pub async fn cancel_operation(
        &self,
        tenant_id: Uuid,
        operation_id: Uuid,
    ) -> OperationServiceResult<OperationResponse> {
        // Get the operation
        let operation = self
            .queue
            .get_operation(operation_id)
            .await?
            .ok_or(OperationServiceError::NotFound(operation_id))?;

        // Verify tenant access
        if operation.tenant_id != tenant_id {
            return Err(OperationServiceError::NotFound(operation_id));
        }

        // Check if it can be cancelled
        if operation.status != OperationStatus::Pending {
            return Err(OperationServiceError::InvalidState {
                operation_id,
                current_state: operation.status.as_str().to_string(),
                action: "cancel".to_string(),
            });
        }

        // Cancel the operation
        self.queue.cancel(operation_id).await?;

        info!(operation_id = %operation_id, "Operation cancelled");

        // Get the updated operation
        let updated = self
            .queue
            .get_operation(operation_id)
            .await?
            .ok_or(OperationServiceError::NotFound(operation_id))?;

        Ok(OperationResponse::from(&updated))
    }

    /// Get operation logs for an operation.
    #[instrument(skip(self))]
    pub async fn get_operation_logs(
        &self,
        tenant_id: Uuid,
        operation_id: Uuid,
    ) -> OperationServiceResult<Vec<OperationLogResponse>> {
        let logs = OperationLog::list_by_operation(&self.pool, tenant_id, operation_id).await?;

        Ok(logs.iter().map(OperationLogResponse::from).collect())
    }

    /// Get queue statistics.
    #[instrument(skip(self))]
    pub async fn get_queue_stats(
        &self,
        _tenant_id: Uuid,
        connector_id: Option<Uuid>,
    ) -> OperationServiceResult<QueueStatsResponse> {
        let stats = self.queue.stats(connector_id).await?;

        Ok(QueueStatsResponse {
            pending: stats.pending,
            in_progress: stats.in_progress,
            completed: stats.completed,
            failed: stats.failed,
            dead_letter: stats.dead_letter,
            awaiting_system: stats.awaiting_system,
            avg_processing_time_secs: stats.avg_processing_time_secs,
            success_rate: stats.success_rate(),
        })
    }

    /// Release stale operations (operations stuck in `in_progress`).
    #[instrument(skip(self))]
    pub async fn release_stale_operations(&self) -> OperationServiceResult<u64> {
        let count = self.queue.release_stale_operations().await?;
        info!(count = count, "Released stale operations");
        Ok(count)
    }

    /// List dead letter queue operations.
    #[instrument(skip(self))]
    pub async fn list_dead_letter(
        &self,
        tenant_id: Uuid,
        connector_id: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> OperationServiceResult<DlqListResponse> {
        let operations = self
            .queue
            .list_dead_letter(connector_id, limit, offset)
            .await?;

        // Filter by tenant
        let tenant_ops: Vec<_> = operations
            .into_iter()
            .filter(|op| op.tenant_id == tenant_id)
            .collect();

        let responses: Vec<OperationResponse> =
            tenant_ops.iter().map(OperationResponse::from).collect();

        Ok(DlqListResponse {
            operations: responses,
            offset,
            limit,
        })
    }

    /// Resolve a dead letter operation.
    #[instrument(skip(self))]
    pub async fn resolve_operation(
        &self,
        tenant_id: Uuid,
        operation_id: Uuid,
        resolved_by: Uuid,
        notes: Option<&str>,
    ) -> OperationServiceResult<OperationResponse> {
        // Get the operation first to verify access
        let operation = self
            .queue
            .get_operation(operation_id)
            .await?
            .ok_or(OperationServiceError::NotFound(operation_id))?;

        // Verify tenant access
        if operation.tenant_id != tenant_id {
            return Err(OperationServiceError::NotFound(operation_id));
        }

        // Check if it can be resolved
        if operation.status != OperationStatus::DeadLetter {
            return Err(OperationServiceError::InvalidState {
                operation_id,
                current_state: operation.status.as_str().to_string(),
                action: "resolve".to_string(),
            });
        }

        // Resolve the operation
        self.queue.resolve(operation_id, resolved_by, notes).await?;

        info!(operation_id = %operation_id, resolved_by = %resolved_by, "Operation resolved");

        // Get the updated operation
        let updated = self
            .queue
            .get_operation(operation_id)
            .await?
            .ok_or(OperationServiceError::NotFound(operation_id))?;

        Ok(OperationResponse::from(&updated))
    }

    /// Get operation attempts (execution history).
    #[instrument(skip(self))]
    pub async fn get_operation_attempts(
        &self,
        tenant_id: Uuid,
        operation_id: Uuid,
    ) -> OperationServiceResult<Vec<AttemptResponse>> {
        use xavyo_db::models::OperationAttempt;

        let attempts =
            OperationAttempt::list_by_operation(&self.pool, tenant_id, operation_id).await?;

        Ok(attempts.iter().map(AttemptResponse::from).collect())
    }
}

/// Queue statistics response.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct QueueStatsResponse {
    /// Number of pending operations.
    pub pending: u64,

    /// Number of in-progress operations.
    pub in_progress: u64,

    /// Number of completed operations.
    pub completed: u64,

    /// Number of failed operations awaiting retry.
    pub failed: u64,

    /// Number of dead-lettered operations.
    pub dead_letter: u64,

    /// Number of operations awaiting system (offline connector).
    pub awaiting_system: u64,

    /// Average processing time in seconds.
    pub avg_processing_time_secs: Option<f64>,

    /// Success rate as percentage (completed / (completed + `dead_letter`) * 100).
    pub success_rate: f64,
}

/// Dead letter queue list response.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DlqListResponse {
    /// List of dead letter operations.
    pub operations: Vec<OperationResponse>,

    /// Current offset.
    pub offset: i64,

    /// Applied limit.
    pub limit: i64,
}

/// Request to resolve a dead letter operation.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ResolveOperationRequest {
    /// Notes about how the issue was resolved.
    #[serde(default)]
    pub resolution_notes: Option<String>,
}

/// Operation attempt (execution history) response.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AttemptResponse {
    /// Attempt ID.
    pub id: Uuid,

    /// Operation ID.
    pub operation_id: Uuid,

    /// Attempt number (1-based).
    pub attempt_number: i32,

    /// When the attempt started.
    pub started_at: chrono::DateTime<chrono::Utc>,

    /// When the attempt completed.
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Whether the attempt was successful.
    pub success: bool,

    /// Error code if failed.
    pub error_code: Option<String>,

    /// Error message if failed.
    pub error_message: Option<String>,

    /// Duration in milliseconds.
    pub duration_ms: Option<i32>,
}

impl From<&xavyo_db::models::OperationAttempt> for AttemptResponse {
    fn from(attempt: &xavyo_db::models::OperationAttempt) -> Self {
        Self {
            id: attempt.id,
            operation_id: attempt.operation_id,
            attempt_number: attempt.attempt_number,
            started_at: attempt.started_at,
            completed_at: attempt.completed_at,
            success: attempt.success,
            error_code: attempt.error_code.clone(),
            error_message: attempt.error_message.clone(),
            duration_ms: attempt.duration_ms,
        }
    }
}

/// List of operation attempts.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AttemptListResponse {
    /// List of attempts.
    pub attempts: Vec<AttemptResponse>,

    /// Operation ID these attempts belong to.
    pub operation_id: Uuid,
}

/// Conflict response for the API.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ConflictResponse {
    /// Conflict ID.
    pub id: Uuid,

    /// Primary operation ID.
    pub operation_id: Uuid,

    /// Conflicting operation ID (if known).
    pub conflicting_operation_id: Option<Uuid>,

    /// Type of conflict.
    pub conflict_type: String,

    /// Affected attributes.
    pub affected_attributes: Vec<String>,

    /// When the conflict was detected.
    pub detected_at: chrono::DateTime<chrono::Utc>,

    /// Resolution strategy used.
    pub resolution_strategy: String,

    /// When the conflict was resolved.
    pub resolved_at: Option<chrono::DateTime<chrono::Utc>>,

    /// Outcome of the resolution.
    pub resolution_outcome: Option<String>,

    /// Who resolved the conflict.
    pub resolved_by: Option<Uuid>,

    /// Notes about the resolution.
    pub notes: Option<String>,

    /// Whether the conflict is pending resolution.
    pub is_pending: bool,
}

impl From<&xavyo_db::models::ConflictRecord> for ConflictResponse {
    fn from(record: &xavyo_db::models::ConflictRecord) -> Self {
        // Parse affected_attributes from JSON
        let affected_attributes = record
            .affected_attributes
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(std::string::ToString::to_string)
                    .collect()
            })
            .unwrap_or_default();

        Self {
            id: record.id,
            operation_id: record.operation_id,
            conflicting_operation_id: record.conflicting_operation_id,
            conflict_type: record.conflict_type.to_string(),
            affected_attributes,
            detected_at: record.detected_at,
            resolution_strategy: record.resolution_strategy.to_string(),
            resolved_at: record.resolved_at,
            resolution_outcome: record.resolution_outcome.map(|o| o.to_string()),
            resolved_by: record.resolved_by,
            notes: record.notes.clone(),
            is_pending: record.is_pending(),
        }
    }
}

/// List response for conflicts.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ConflictListResponse {
    /// List of conflicts.
    pub conflicts: Vec<ConflictResponse>,

    /// Total pending conflicts count.
    pub pending_count: i64,

    /// Current offset.
    pub offset: i64,

    /// Applied limit.
    pub limit: i64,
}

/// Request to resolve a conflict.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ResolveConflictRequest {
    /// Resolution outcome (applied, superseded, merged, rejected).
    pub outcome: String,

    /// Optional notes about the resolution.
    #[serde(default)]
    pub notes: Option<String>,
}

/// Query parameters for listing conflicts.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::IntoParams)]
pub struct ListConflictsQuery {
    /// Filter by operation ID.
    pub operation_id: Option<Uuid>,

    /// Filter by conflict type.
    pub conflict_type: Option<String>,

    /// Only show pending conflicts.
    #[serde(default)]
    pub pending_only: bool,

    /// Maximum results.
    #[serde(default = "default_limit")]
    pub limit: i64,

    /// Offset for pagination.
    #[serde(default)]
    pub offset: i64,
}

impl Default for ListConflictsQuery {
    fn default() -> Self {
        Self {
            operation_id: None,
            conflict_type: None,
            pending_only: false,
            limit: default_limit(),
            offset: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trigger_request() {
        let request = TriggerOperationRequest {
            connector_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            operation_type: OperationType::Create,
            object_class: "user".to_string(),
            target_uid: None,
            payload: serde_json::json!({"firstName": "John"}),
            priority: Some(10),
        };

        assert_eq!(request.operation_type, OperationType::Create);
        assert_eq!(request.priority, Some(10));
    }

    #[test]
    fn test_operation_filter_defaults() {
        let filter = OperationFilter::default();
        assert_eq!(filter.limit, 50);
        assert_eq!(filter.offset, 0);
        assert!(filter.connector_id.is_none());
    }

    // T022: Unit tests for operation filtering
    #[test]
    fn test_operation_filter_with_connector() {
        let connector_id = Uuid::new_v4();
        let filter = OperationFilter {
            connector_id: Some(connector_id),
            user_id: None,
            status: None,
            operation_type: None,
            limit: 100,
            offset: 0,
        };
        assert_eq!(filter.connector_id, Some(connector_id));
        assert_eq!(filter.limit, 100);
    }

    #[test]
    fn test_operation_filter_with_status() {
        let filter = OperationFilter {
            connector_id: None,
            user_id: None,
            status: Some("failed".to_string()),
            operation_type: None,
            limit: 50,
            offset: 0,
        };
        assert_eq!(filter.status, Some("failed".to_string()));
    }

    #[test]
    fn test_operation_filter_with_user_and_type() {
        let user_id = Uuid::new_v4();
        let filter = OperationFilter {
            connector_id: None,
            user_id: Some(user_id),
            status: None,
            operation_type: Some("create".to_string()),
            limit: 25,
            offset: 10,
        };
        assert_eq!(filter.user_id, Some(user_id));
        assert_eq!(filter.operation_type, Some("create".to_string()));
        assert_eq!(filter.offset, 10);
    }

    // T026: Unit tests for OperationResponse with attempts
    #[test]
    fn test_operation_response_without_attempts() {
        let op_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let connector_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let response = OperationResponse {
            id: op_id,
            tenant_id,
            connector_id,
            user_id,
            operation_type: "create".to_string(),
            object_class: "user".to_string(),
            target_uid: None,
            status: "pending".to_string(),
            retry_count: 0,
            max_retries: 3,
            error_message: None,
            priority: 5,
            idempotency_key: None,
            next_retry_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            started_at: None,
            completed_at: None,
            resolution_notes: None,
            resolved_by: None,
            resolved_at: None,
            attempts: None,
        };

        assert!(response.attempts.is_none());
    }

    #[test]
    fn test_operation_response_with_attempts() {
        let op_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let connector_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let response = OperationResponse {
            id: op_id,
            tenant_id,
            connector_id,
            user_id,
            operation_type: "create".to_string(),
            object_class: "user".to_string(),
            target_uid: None,
            status: "failed".to_string(),
            retry_count: 2,
            max_retries: 3,
            error_message: Some("Connection timeout".to_string()),
            priority: 5,
            idempotency_key: None,
            next_retry_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            started_at: None,
            completed_at: None,
            resolution_notes: None,
            resolved_by: None,
            resolved_at: None,
            attempts: None,
        };

        let attempt1 = AttemptResponse {
            id: Uuid::new_v4(),
            operation_id: op_id,
            attempt_number: 1,
            started_at: chrono::Utc::now() - chrono::Duration::minutes(10),
            completed_at: Some(chrono::Utc::now() - chrono::Duration::minutes(9)),
            success: false,
            error_code: Some("CONN_TIMEOUT".to_string()),
            error_message: Some("Connection timeout".to_string()),
            duration_ms: Some(5000),
        };

        let attempt2 = AttemptResponse {
            id: Uuid::new_v4(),
            operation_id: op_id,
            attempt_number: 2,
            started_at: chrono::Utc::now() - chrono::Duration::minutes(5),
            completed_at: Some(chrono::Utc::now() - chrono::Duration::minutes(4)),
            success: false,
            error_code: Some("CONN_TIMEOUT".to_string()),
            error_message: Some("Connection timeout".to_string()),
            duration_ms: Some(5000),
        };

        let with_attempts = response.with_attempts(vec![attempt1, attempt2]);
        assert!(with_attempts.attempts.is_some());
        assert_eq!(with_attempts.attempts.as_ref().unwrap().len(), 2);
        assert_eq!(
            with_attempts.attempts.as_ref().unwrap()[0].attempt_number,
            1
        );
        assert_eq!(
            with_attempts.attempts.as_ref().unwrap()[1].attempt_number,
            2
        );
    }

    // T041: Unit tests for DLQ operations
    #[test]
    fn test_dlq_list_response() {
        let response = DlqListResponse {
            operations: vec![],
            offset: 0,
            limit: 50,
        };
        assert_eq!(response.offset, 0);
        assert_eq!(response.limit, 50);
        assert!(response.operations.is_empty());
    }

    #[test]
    fn test_resolve_operation_request() {
        let request = ResolveOperationRequest {
            resolution_notes: Some("Fixed by manual intervention".to_string()),
        };
        assert_eq!(
            request.resolution_notes,
            Some("Fixed by manual intervention".to_string())
        );
    }

    #[test]
    fn test_resolve_operation_request_no_notes() {
        let request = ResolveOperationRequest {
            resolution_notes: None,
        };
        assert!(request.resolution_notes.is_none());
    }

    #[test]
    fn test_queue_stats_response_construction() {
        let stats = QueueStatsResponse {
            pending: 10,
            in_progress: 5,
            completed: 100,
            failed: 2,
            dead_letter: 1,
            awaiting_system: 3,
            avg_processing_time_secs: Some(0.25),
            success_rate: 99.0,
        };

        assert_eq!(stats.pending, 10);
        assert_eq!(stats.in_progress, 5);
        assert_eq!(stats.dead_letter, 1);
        assert_eq!(stats.awaiting_system, 3);
        assert_eq!(stats.avg_processing_time_secs, Some(0.25));
        assert_eq!(stats.success_rate, 99.0);
    }

    #[test]
    fn test_conflict_response_construction() {
        let conflict = ConflictResponse {
            id: Uuid::new_v4(),
            operation_id: Uuid::new_v4(),
            conflicting_operation_id: Some(Uuid::new_v4()),
            conflict_type: "attribute_conflict".to_string(),
            affected_attributes: vec!["email".to_string(), "display_name".to_string()],
            detected_at: chrono::Utc::now(),
            resolution_strategy: "source_wins".to_string(),
            resolved_at: None,
            resolution_outcome: None,
            resolved_by: None,
            notes: None,
            is_pending: true,
        };

        assert_eq!(conflict.conflict_type, "attribute_conflict");
        assert_eq!(conflict.affected_attributes.len(), 2);
        assert!(conflict.is_pending);
        assert!(conflict.conflicting_operation_id.is_some());
    }

    #[test]
    fn test_conflict_list_response() {
        let response = ConflictListResponse {
            conflicts: vec![],
            pending_count: 0,
            offset: 0,
            limit: 50,
        };
        assert_eq!(response.pending_count, 0);
        assert!(response.conflicts.is_empty());
    }

    #[test]
    fn test_attempt_response_construction() {
        let op_id = Uuid::new_v4();
        let attempt = AttemptResponse {
            id: Uuid::new_v4(),
            operation_id: op_id,
            attempt_number: 1,
            started_at: chrono::Utc::now(),
            completed_at: None,
            success: false,
            error_code: None,
            error_message: None,
            duration_ms: None,
        };

        assert_eq!(attempt.operation_id, op_id);
        assert_eq!(attempt.attempt_number, 1);
        assert!(!attempt.success);
        assert!(attempt.completed_at.is_none());
    }

    #[test]
    fn test_attempt_list_response() {
        let op_id = Uuid::new_v4();
        let response = AttemptListResponse {
            attempts: vec![],
            operation_id: op_id,
        };
        assert_eq!(response.operation_id, op_id);
        assert!(response.attempts.is_empty());
    }
}
