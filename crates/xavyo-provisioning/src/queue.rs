//! Operation Queue Service
//!
//! Manages the provisioning operation queue backed by `PostgreSQL`.
//! Provides durable storage with retry scheduling and dead letter handling.

use std::str::FromStr;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use thiserror::Error;
use tracing::{debug, error, info, instrument};
use uuid::Uuid;

use xavyo_connector::types::{OperationStatus, OperationType};

/// Result of an enqueue operation with idempotency.
#[derive(Debug, Clone)]
pub enum EnqueueResult {
    /// Operation was successfully enqueued.
    Enqueued { id: Uuid },
    /// A duplicate operation already exists.
    Duplicate { existing_id: Uuid },
}

impl EnqueueResult {
    /// Get the operation ID (either new or existing).
    #[must_use] 
    pub fn operation_id(&self) -> Uuid {
        match self {
            EnqueueResult::Enqueued { id } => *id,
            EnqueueResult::Duplicate { existing_id } => *existing_id,
        }
    }

    /// Check if this was a new operation.
    #[must_use] 
    pub fn is_new(&self) -> bool {
        matches!(self, EnqueueResult::Enqueued { .. })
    }

    /// Check if this was a duplicate.
    #[must_use] 
    pub fn is_duplicate(&self) -> bool {
        matches!(self, EnqueueResult::Duplicate { .. })
    }
}

/// Queue operation errors.
#[derive(Debug, Error)]
pub enum QueueError {
    /// Database error.
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Operation not found.
    #[error("Operation not found: {id}")]
    NotFound { id: Uuid },

    /// Invalid operation state.
    #[error("Invalid operation state: expected {expected}, got {actual}")]
    InvalidState { expected: String, actual: String },

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Result type for queue operations.
pub type QueueResult<T> = Result<T, QueueError>;

/// A provisioning operation in the queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedOperation {
    /// Operation ID.
    pub id: Uuid,

    /// Tenant ID.
    pub tenant_id: Uuid,

    /// Connector ID.
    pub connector_id: Uuid,

    /// User ID being provisioned.
    pub user_id: Uuid,

    /// Type of operation.
    pub operation_type: OperationType,

    /// Object class in target system.
    pub object_class: String,

    /// Unique identifier in target system (for updates/deletes).
    pub target_uid: Option<String>,

    /// Operation payload (attributes, deltas, etc.).
    pub payload: serde_json::Value,

    /// Current status.
    pub status: OperationStatus,

    /// Number of retry attempts.
    pub retry_count: i32,

    /// Maximum retries allowed.
    pub max_retries: i32,

    /// Next retry timestamp.
    pub next_retry_at: Option<DateTime<Utc>>,

    /// Error message from last failure.
    pub error_message: Option<String>,

    /// Priority (lower = higher priority).
    pub priority: i32,

    /// When the operation was created.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,

    /// When the operation started processing (null if not started).
    pub started_at: Option<DateTime<Utc>>,

    /// When the operation completed (null if not complete).
    pub completed_at: Option<DateTime<Utc>>,

    /// Idempotency key for duplicate detection.
    pub idempotency_key: Option<String>,

    /// Resolution notes (for resolved DLQ items).
    pub resolution_notes: Option<String>,

    /// Who resolved this operation (for DLQ items).
    pub resolved_by: Option<Uuid>,

    /// When the operation was resolved.
    pub resolved_at: Option<DateTime<Utc>>,
}

impl QueuedOperation {
    /// Create a new queued operation.
    #[must_use] 
    pub fn new(
        tenant_id: Uuid,
        connector_id: Uuid,
        user_id: Uuid,
        operation_type: OperationType,
        object_class: String,
        payload: serde_json::Value,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            connector_id,
            user_id,
            operation_type,
            object_class,
            target_uid: None,
            payload,
            status: OperationStatus::Pending,
            retry_count: 0,
            max_retries: 10, // Updated per spec: 10 retries
            next_retry_at: None,
            error_message: None,
            priority: 0,
            created_at: now,
            updated_at: now,
            started_at: None,
            completed_at: None,
            idempotency_key: None,
            resolution_notes: None,
            resolved_by: None,
            resolved_at: None,
        }
    }

    /// Set the target UID (for updates/deletes).
    pub fn with_target_uid(mut self, uid: impl Into<String>) -> Self {
        self.target_uid = Some(uid.into());
        self
    }

    /// Set the priority.
    #[must_use] 
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Set max retries.
    #[must_use] 
    pub fn with_max_retries(mut self, max: i32) -> Self {
        self.max_retries = max;
        self
    }

    /// Set the idempotency key.
    pub fn with_idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = Some(key.into());
        self
    }

    /// Check if the operation can be retried.
    #[must_use] 
    pub fn can_retry(&self) -> bool {
        self.retry_count < self.max_retries
    }

    /// Check if the operation is ready for processing.
    #[must_use] 
    pub fn is_ready(&self) -> bool {
        match self.status {
            OperationStatus::Pending => true,
            OperationStatus::Failed => {
                self.can_retry() && self.next_retry_at.is_none_or(|t| Utc::now() >= t)
            }
            _ => false,
        }
    }
}

/// Configuration for the operation queue.
#[derive(Debug, Clone)]
pub struct QueueConfig {
    /// Base delay for exponential backoff (seconds).
    pub base_delay_secs: u64,

    /// Maximum delay between retries (seconds).
    pub max_delay_secs: u64,

    /// Jitter factor (0.0 to 1.0).
    pub jitter_factor: f64,

    /// Default max retries.
    pub default_max_retries: i32,

    /// Batch size for dequeue operations.
    pub batch_size: i32,

    /// Lock timeout for dequeued operations (seconds).
    pub lock_timeout_secs: i64,
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            base_delay_secs: 30,  // Updated per spec: 30s base delay
            max_delay_secs: 3600, // 1 hour
            jitter_factor: 0.25,
            default_max_retries: 10, // Updated per spec: 10 retries
            batch_size: 50,          // Updated per spec: 50 batch size
            lock_timeout_secs: 300,  // 5 minutes
        }
    }
}

/// A batch of operations for a single connector (F047).
///
/// Operations are grouped by connector to enable batch isolation - if one
/// connector fails, operations for other connectors can still be processed.
#[derive(Debug, Clone)]
pub struct OperationBatch {
    /// The connector ID for this batch.
    pub connector_id: Uuid,
    /// Operations in this batch (all for the same connector).
    pub operations: Vec<QueuedOperation>,
}

impl OperationBatch {
    /// Get the number of operations in this batch.
    #[must_use] 
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    /// Check if this batch is empty.
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Get operation IDs in this batch.
    #[must_use] 
    pub fn operation_ids(&self) -> Vec<Uuid> {
        self.operations.iter().map(|op| op.id).collect()
    }
}

/// Operation queue service.
pub struct OperationQueue {
    pool: PgPool,
    config: QueueConfig,
}

impl OperationQueue {
    /// Create a new operation queue.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            config: QueueConfig::default(),
        }
    }

    /// Create with custom configuration.
    #[must_use] 
    pub fn with_config(pool: PgPool, config: QueueConfig) -> Self {
        Self { pool, config }
    }

    /// Enqueue a new operation.
    ///
    /// If the operation has an `idempotency_key` set, duplicates will be detected.
    #[instrument(skip(self, operation), fields(operation_id = %operation.id))]
    pub async fn enqueue(&self, operation: QueuedOperation) -> QueueResult<Uuid> {
        let payload_str = serde_json::to_string(&operation.payload)?;

        sqlx::query(
            r"
            INSERT INTO provisioning_operations (
                id, tenant_id, connector_id, user_id, operation_type,
                object_class, target_uid, payload, status,
                retry_count, max_retries, next_retry_at,
                priority, created_at, updated_at, idempotency_key
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8::jsonb, $9,
                $10, $11, $12,
                $13, $14, $15, $16
            )
            ",
        )
        .bind(operation.id)
        .bind(operation.tenant_id)
        .bind(operation.connector_id)
        .bind(operation.user_id)
        .bind(operation.operation_type.as_str())
        .bind(&operation.object_class)
        .bind(&operation.target_uid)
        .bind(&payload_str)
        .bind(operation.status.as_str())
        .bind(operation.retry_count)
        .bind(operation.max_retries)
        .bind(operation.next_retry_at)
        .bind(operation.priority)
        .bind(operation.created_at)
        .bind(operation.updated_at)
        .bind(&operation.idempotency_key)
        .execute(&self.pool)
        .await?;

        info!(
            operation_id = %operation.id,
            operation_type = ?operation.operation_type,
            connector_id = %operation.connector_id,
            idempotency_key = ?operation.idempotency_key,
            "Operation enqueued"
        );

        Ok(operation.id)
    }

    /// Enqueue a new operation with automatic idempotency key generation.
    ///
    /// Returns the operation ID if enqueued, or the existing operation ID if a duplicate is found.
    #[instrument(skip(self, operation), fields(operation_id = %operation.id))]
    pub async fn enqueue_idempotent(
        &self,
        mut operation: QueuedOperation,
    ) -> QueueResult<EnqueueResult> {
        use crate::idempotency::{IdempotencyError, IdempotencyService};

        let idempotency = IdempotencyService::new();
        let key = idempotency
            .generate_key(
                operation.tenant_id,
                operation.connector_id,
                Some(operation.user_id),
                operation.operation_type.as_str(),
                &operation.payload,
            )
            .map_err(|e| match e {
                IdempotencyError::Serialization(se) => QueueError::Serialization(se),
                IdempotencyError::Database(de) => QueueError::Database(de),
                IdempotencyError::DuplicateOperation { .. } => {
                    // This shouldn't happen in generate_key, but handle it
                    QueueError::Serialization(serde_json::Error::io(std::io::Error::other(
                        e.to_string(),
                    )))
                }
            })?;

        // Check for existing operation with same key
        match idempotency
            .check_duplicate(&self.pool, operation.tenant_id, &key)
            .await
        {
            Ok(Some(existing_id)) => {
                debug!(
                    existing_id = %existing_id,
                    idempotency_key = %key,
                    "Duplicate operation detected"
                );
                return Ok(EnqueueResult::Duplicate { existing_id });
            }
            Ok(None) => {
                // No duplicate, continue with enqueue
            }
            Err(IdempotencyError::Database(de)) => {
                return Err(QueueError::Database(de));
            }
            Err(e) => {
                return Err(QueueError::Serialization(serde_json::Error::io(
                    std::io::Error::other(e.to_string()),
                )));
            }
        }

        // Set the key and enqueue
        operation.idempotency_key = Some(key);
        let id = self.enqueue(operation).await?;
        Ok(EnqueueResult::Enqueued { id })
    }

    /// Dequeue operations ready for processing.
    ///
    /// This atomically selects and locks operations, marking them as `in_progress`.
    #[instrument(skip(self))]
    pub async fn dequeue(
        &self,
        connector_id: Option<Uuid>,
        limit: Option<i32>,
    ) -> QueueResult<Vec<QueuedOperation>> {
        self.dequeue_excluding(connector_id, limit, &[]).await
    }

    /// Dequeue operations ready for processing, excluding offline connectors.
    ///
    /// This atomically selects and locks operations, marking them as `in_progress`.
    /// Operations for connectors in `offline_connectors` are skipped.
    #[instrument(skip(self, offline_connectors))]
    pub async fn dequeue_excluding(
        &self,
        connector_id: Option<Uuid>,
        limit: Option<i32>,
        offline_connectors: &[Uuid],
    ) -> QueueResult<Vec<QueuedOperation>> {
        let limit = limit.unwrap_or(self.config.batch_size);
        let now = Utc::now();

        // Convert offline connectors to a format for SQL
        let offline_ids: Vec<Uuid> = offline_connectors.to_vec();
        let has_offline = !offline_ids.is_empty();

        // Use FOR UPDATE SKIP LOCKED to handle concurrent processors
        // Build query dynamically to handle offline connector exclusion
        let rows = if let Some(cid) = connector_id {
            // Specific connector - just check if it's online
            if offline_ids.contains(&cid) {
                debug!(connector_id = %cid, "Skipping dequeue for offline connector");
                return Ok(Vec::new());
            }

            sqlx::query(
                r"
                UPDATE provisioning_operations
                SET status = 'in_progress',
                    started_at = $1,
                    updated_at = $1
                WHERE id IN (
                    SELECT id FROM provisioning_operations
                    WHERE connector_id = $2
                    AND status IN ('pending', 'failed')
                    AND (next_retry_at IS NULL OR next_retry_at <= $1)
                    ORDER BY priority ASC, created_at ASC
                    LIMIT $3
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING id, tenant_id, connector_id, user_id, operation_type,
                          object_class, target_uid, payload, status,
                          retry_count, max_retries, next_retry_at, error_message,
                          priority, created_at, updated_at, started_at, completed_at, idempotency_key,
                          resolution_notes, resolved_by, resolved_at
                "
            )
            .bind(now)
            .bind(cid)
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await?
        } else if has_offline {
            // Exclude offline connectors using NOT IN clause
            sqlx::query(
                r"
                UPDATE provisioning_operations
                SET status = 'in_progress',
                    started_at = $1,
                    updated_at = $1
                WHERE id IN (
                    SELECT id FROM provisioning_operations
                    WHERE status IN ('pending', 'failed')
                    AND (next_retry_at IS NULL OR next_retry_at <= $1)
                    AND connector_id != ALL($3)
                    ORDER BY priority ASC, created_at ASC
                    LIMIT $2
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING id, tenant_id, connector_id, user_id, operation_type,
                          object_class, target_uid, payload, status,
                          retry_count, max_retries, next_retry_at, error_message,
                          priority, created_at, updated_at, started_at, completed_at, idempotency_key,
                          resolution_notes, resolved_by, resolved_at
                "
            )
            .bind(now)
            .bind(i64::from(limit))
            .bind(&offline_ids)
            .fetch_all(&self.pool)
            .await?
        } else {
            // No filters - get all operations
            sqlx::query(
                r"
                UPDATE provisioning_operations
                SET status = 'in_progress',
                    started_at = $1,
                    updated_at = $1
                WHERE id IN (
                    SELECT id FROM provisioning_operations
                    WHERE status IN ('pending', 'failed')
                    AND (next_retry_at IS NULL OR next_retry_at <= $1)
                    ORDER BY priority ASC, created_at ASC
                    LIMIT $2
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING id, tenant_id, connector_id, user_id, operation_type,
                          object_class, target_uid, payload, status,
                          retry_count, max_retries, next_retry_at, error_message,
                          priority, created_at, updated_at, started_at, completed_at, idempotency_key,
                          resolution_notes, resolved_by, resolved_at
                "
            )
            .bind(now)
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await?
        };

        let operations: Vec<QueuedOperation> = rows
            .into_iter()
            .map(|row| row_to_operation(&row, now))
            .collect();

        debug!(
            count = operations.len(),
            "Dequeued operations for processing"
        );

        Ok(operations)
    }

    /// Dequeue a batch of operations for processing with isolation guarantees (F047).
    ///
    /// This method dequeues operations and groups them by connector for efficient
    /// batch processing. Each connector's operations are returned as a separate group,
    /// allowing for independent processing where one connector's failure doesn't
    /// block others.
    ///
    /// # Returns
    ///
    /// A vector of batches, where each batch contains operations for a single connector.
    /// The batch size per connector is limited by the queue configuration.
    #[instrument(skip(self, offline_connectors))]
    pub async fn dequeue_batch(
        &self,
        batch_size: Option<i32>,
        offline_connectors: &[Uuid],
    ) -> QueueResult<Vec<OperationBatch>> {
        let size = batch_size.unwrap_or(self.config.batch_size);
        let ops = self
            .dequeue_excluding(None, Some(size), offline_connectors)
            .await?;

        // Group operations by connector for batch isolation
        let mut batches: std::collections::HashMap<Uuid, Vec<QueuedOperation>> =
            std::collections::HashMap::new();

        for op in ops {
            batches.entry(op.connector_id).or_default().push(op);
        }

        let result: Vec<OperationBatch> = batches
            .into_iter()
            .map(|(connector_id, operations)| OperationBatch {
                connector_id,
                operations,
            })
            .collect();

        debug!(
            batch_count = result.len(),
            total_ops = result.iter().map(|b| b.operations.len()).sum::<usize>(),
            "Dequeued operation batches for processing"
        );

        Ok(result)
    }

    /// Get an operation by ID.
    #[instrument(skip(self))]
    pub async fn get_operation(&self, id: Uuid) -> QueueResult<Option<QueuedOperation>> {
        let now = Utc::now();
        let row = sqlx::query(
            r"
            SELECT id, tenant_id, connector_id, user_id, operation_type,
                   object_class, target_uid, payload, status,
                   retry_count, max_retries, next_retry_at, error_message,
                   priority, created_at, updated_at, started_at, completed_at, idempotency_key,
                   resolution_notes, resolved_by, resolved_at
            FROM provisioning_operations
            WHERE id = $1
            ",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| row_to_operation(&r, now)))
    }

    /// Mark an operation as completed successfully.
    #[instrument(skip(self), fields(operation_id = %id))]
    pub async fn complete(&self, id: Uuid, target_uid: Option<&str>) -> QueueResult<()> {
        let now = Utc::now();

        let result = sqlx::query(
            r"
            UPDATE provisioning_operations
            SET status = 'completed',
                target_uid = COALESCE($2, target_uid),
                completed_at = $3,
                updated_at = $3,
                error_message = NULL
            WHERE id = $1
            ",
        )
        .bind(id)
        .bind(target_uid)
        .bind(now)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(QueueError::NotFound { id });
        }

        info!(operation_id = %id, "Operation completed successfully");

        Ok(())
    }

    /// Mark an operation as failed and schedule retry.
    #[instrument(skip(self), fields(operation_id = %id))]
    pub async fn fail(&self, id: Uuid, error: &str, is_transient: bool) -> QueueResult<()> {
        let now = Utc::now();

        // Get current retry count
        let row = sqlx::query(
            r"SELECT retry_count, max_retries FROM provisioning_operations WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(QueueError::NotFound { id })?;

        let retry_count: i32 = row.get("retry_count");
        let max_retries: i32 = row.get("max_retries");
        let new_retry_count = retry_count + 1;
        let can_retry = is_transient && new_retry_count < max_retries;

        let (status, next_retry) = if can_retry {
            // Calculate next retry time with exponential backoff + jitter
            let delay = self.calculate_backoff_delay(new_retry_count);
            let next_retry_at = now + Duration::seconds(delay as i64);
            ("failed", Some(next_retry_at))
        } else {
            // Move to dead letter queue
            ("dead_letter", None)
        };

        sqlx::query(
            r"
            UPDATE provisioning_operations
            SET status = $2,
                retry_count = $3,
                next_retry_at = $4,
                error_message = $5,
                updated_at = $6
            WHERE id = $1
            ",
        )
        .bind(id)
        .bind(status)
        .bind(new_retry_count)
        .bind(next_retry)
        .bind(error)
        .bind(now)
        .execute(&self.pool)
        .await?;

        if can_retry {
            info!(
                operation_id = %id,
                retry_count = new_retry_count,
                next_retry_at = ?next_retry,
                "Operation failed, scheduled for retry"
            );
        } else {
            error!(
                operation_id = %id,
                error = error,
                "Operation failed permanently, moved to dead letter queue"
            );
        }

        Ok(())
    }

    /// Cancel a pending operation.
    #[instrument(skip(self), fields(operation_id = %id))]
    pub async fn cancel(&self, id: Uuid) -> QueueResult<()> {
        let now = Utc::now();

        let result = sqlx::query(
            r"
            UPDATE provisioning_operations
            SET status = 'cancelled',
                updated_at = $2
            WHERE id = $1 AND status IN ('pending', 'failed')
            ",
        )
        .bind(id)
        .bind(now)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(QueueError::InvalidState {
                expected: "pending or failed".to_string(),
                actual: "other".to_string(),
            });
        }

        info!(operation_id = %id, "Operation cancelled");

        Ok(())
    }

    /// Retry a dead-lettered operation.
    #[instrument(skip(self), fields(operation_id = %id))]
    pub async fn retry_dead_letter(&self, id: Uuid) -> QueueResult<()> {
        let now = Utc::now();

        let result = sqlx::query(
            r"
            UPDATE provisioning_operations
            SET status = 'pending',
                retry_count = 0,
                next_retry_at = NULL,
                error_message = NULL,
                updated_at = $2
            WHERE id = $1 AND status = 'dead_letter'
            ",
        )
        .bind(id)
        .bind(now)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(QueueError::InvalidState {
                expected: "dead_letter".to_string(),
                actual: "other".to_string(),
            });
        }

        info!(operation_id = %id, "Dead letter operation reset for retry");

        Ok(())
    }

    /// Get operation by ID.
    pub async fn get(&self, id: Uuid) -> QueueResult<Option<QueuedOperation>> {
        let row = sqlx::query(
            r"
            SELECT id, tenant_id, connector_id, user_id, operation_type,
                   object_class, target_uid, payload, status,
                   retry_count, max_retries, next_retry_at, error_message,
                   priority, created_at, updated_at, started_at, completed_at, idempotency_key,
                   resolution_notes, resolved_by, resolved_at
            FROM provisioning_operations
            WHERE id = $1
            ",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| row_to_operation(&r, Utc::now())))
    }

    /// Get queue statistics.
    pub async fn stats(&self, connector_id: Option<Uuid>) -> QueueResult<QueueStats> {
        let query = if connector_id.is_some() {
            r"
            SELECT
                COUNT(*) FILTER (WHERE status = 'pending') as pending,
                COUNT(*) FILTER (WHERE status = 'in_progress') as in_progress,
                COUNT(*) FILTER (WHERE status = 'completed') as completed,
                COUNT(*) FILTER (WHERE status = 'failed') as failed,
                COUNT(*) FILTER (WHERE status = 'dead_letter') as dead_letter,
                COUNT(*) FILTER (WHERE status = 'awaiting_system') as awaiting_system,
                AVG(EXTRACT(EPOCH FROM (completed_at - created_at))) FILTER (WHERE status = 'completed') as avg_processing_time
            FROM provisioning_operations
            WHERE connector_id = $1
            "
        } else {
            r"
            SELECT
                COUNT(*) FILTER (WHERE status = 'pending') as pending,
                COUNT(*) FILTER (WHERE status = 'in_progress') as in_progress,
                COUNT(*) FILTER (WHERE status = 'completed') as completed,
                COUNT(*) FILTER (WHERE status = 'failed') as failed,
                COUNT(*) FILTER (WHERE status = 'dead_letter') as dead_letter,
                COUNT(*) FILTER (WHERE status = 'awaiting_system') as awaiting_system,
                AVG(EXTRACT(EPOCH FROM (completed_at - created_at))) FILTER (WHERE status = 'completed') as avg_processing_time
            FROM provisioning_operations
            "
        };

        let row = if let Some(cid) = connector_id {
            sqlx::query(query).bind(cid).fetch_one(&self.pool).await?
        } else {
            sqlx::query(query).fetch_one(&self.pool).await?
        };

        Ok(QueueStats {
            pending: row.get::<Option<i64>, _>("pending").unwrap_or(0) as u64,
            in_progress: row.get::<Option<i64>, _>("in_progress").unwrap_or(0) as u64,
            completed: row.get::<Option<i64>, _>("completed").unwrap_or(0) as u64,
            failed: row.get::<Option<i64>, _>("failed").unwrap_or(0) as u64,
            dead_letter: row.get::<Option<i64>, _>("dead_letter").unwrap_or(0) as u64,
            awaiting_system: row.get::<Option<i64>, _>("awaiting_system").unwrap_or(0) as u64,
            avg_processing_time_secs: row.get::<Option<f64>, _>("avg_processing_time"),
            batch_size: self.config.batch_size as u64,
            batches_processed: 0, // Not tracked in DB; would need external counter in production
        })
    }

    /// Transition operations to `awaiting_system` status when connector is offline.
    #[instrument(skip(self))]
    pub async fn transition_to_awaiting_system(&self, connector_id: Uuid) -> QueueResult<u64> {
        let now = Utc::now();

        let result = sqlx::query(
            r"
            UPDATE provisioning_operations
            SET status = 'awaiting_system',
                updated_at = $1
            WHERE connector_id = $2
            AND status IN ('pending', 'failed')
            ",
        )
        .bind(now)
        .bind(connector_id)
        .execute(&self.pool)
        .await?;

        let count = result.rows_affected();
        if count > 0 {
            info!(
                connector_id = %connector_id,
                count = count,
                "Transitioned operations to awaiting_system"
            );
        }

        Ok(count)
    }

    /// Resume operations when connector comes back online.
    #[instrument(skip(self))]
    pub async fn resume_awaiting_operations(&self, connector_id: Uuid) -> QueueResult<u64> {
        let now = Utc::now();

        let result = sqlx::query(
            r"
            UPDATE provisioning_operations
            SET status = 'pending',
                updated_at = $1
            WHERE connector_id = $2
            AND status = 'awaiting_system'
            ",
        )
        .bind(now)
        .bind(connector_id)
        .execute(&self.pool)
        .await?;

        let count = result.rows_affected();
        if count > 0 {
            info!(
                connector_id = %connector_id,
                count = count,
                "Resumed awaiting_system operations"
            );
        }

        Ok(count)
    }

    /// Resolve a dead letter operation manually.
    #[instrument(skip(self), fields(operation_id = %id))]
    pub async fn resolve(
        &self,
        id: Uuid,
        resolved_by: Uuid,
        notes: Option<&str>,
    ) -> QueueResult<()> {
        let now = Utc::now();

        let result = sqlx::query(
            r"
            UPDATE provisioning_operations
            SET status = 'resolved',
                resolved_at = $2,
                resolved_by = $3,
                resolution_notes = $4,
                updated_at = $2
            WHERE id = $1
            AND status = 'dead_letter'
            ",
        )
        .bind(id)
        .bind(now)
        .bind(resolved_by)
        .bind(notes)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(QueueError::InvalidState {
                expected: "dead_letter".to_string(),
                actual: "other".to_string(),
            });
        }

        info!(operation_id = %id, resolved_by = %resolved_by, "Dead letter operation resolved");

        Ok(())
    }

    /// List dead letter operations.
    pub async fn list_dead_letter(
        &self,
        connector_id: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> QueueResult<Vec<QueuedOperation>> {
        let now = Utc::now();
        let query = if connector_id.is_some() {
            r"
            SELECT id, tenant_id, connector_id, user_id, operation_type,
                   object_class, target_uid, payload, status,
                   retry_count, max_retries, next_retry_at, error_message,
                   priority, created_at, updated_at, started_at, completed_at, idempotency_key,
                   resolution_notes, resolved_by, resolved_at
            FROM provisioning_operations
            WHERE connector_id = $1 AND status = 'dead_letter'
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "
        } else {
            r"
            SELECT id, tenant_id, connector_id, user_id, operation_type,
                   object_class, target_uid, payload, status,
                   retry_count, max_retries, next_retry_at, error_message,
                   priority, created_at, updated_at, started_at, completed_at, idempotency_key,
                   resolution_notes, resolved_by, resolved_at
            FROM provisioning_operations
            WHERE status = 'dead_letter'
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "
        };

        let rows = if let Some(cid) = connector_id {
            sqlx::query(query)
                .bind(cid)
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?
        } else {
            sqlx::query(query)
                .bind(limit)
                .bind(offset)
                .fetch_all(&self.pool)
                .await?
        };

        Ok(rows
            .into_iter()
            .map(|r| row_to_operation(&r, now))
            .collect())
    }

    /// Calculate backoff delay with jitter.
    fn calculate_backoff_delay(&self, retry_count: i32) -> u64 {
        use rand::Rng;

        let base = self.config.base_delay_secs as f64;
        let exp_delay = base * 2f64.powi(retry_count.saturating_sub(1));
        let capped = exp_delay.min(self.config.max_delay_secs as f64);

        // Add jitter
        let jitter_range = capped * self.config.jitter_factor;
        let mut rng = rand::thread_rng();
        let jitter = rng.gen_range(-jitter_range..jitter_range);

        (capped + jitter).max(0.0) as u64
    }

    /// Release stale in-progress operations.
    ///
    /// This should be called periodically to handle processors that crashed.
    pub async fn release_stale_operations(&self) -> QueueResult<u64> {
        let now = Utc::now();
        let stale_threshold = now - Duration::seconds(self.config.lock_timeout_secs);

        let result = sqlx::query(
            r"
            UPDATE provisioning_operations
            SET status = 'pending',
                started_at = NULL,
                updated_at = $1
            WHERE status = 'in_progress'
            AND started_at < $2
            ",
        )
        .bind(now)
        .bind(stale_threshold)
        .execute(&self.pool)
        .await?;

        let count = result.rows_affected();
        if count > 0 {
            info!(count = count, "Released stale operations");
        }

        Ok(count)
    }
}

/// Convert a database row to a `QueuedOperation`.
fn row_to_operation(row: &sqlx::postgres::PgRow, now: DateTime<Utc>) -> QueuedOperation {
    let operation_type_str: String = row.get("operation_type");
    let status_str: String = row.get("status");

    QueuedOperation {
        id: row.get("id"),
        tenant_id: row.get("tenant_id"),
        connector_id: row.get("connector_id"),
        user_id: row.get("user_id"),
        operation_type: OperationType::from_str(&operation_type_str)
            .unwrap_or(OperationType::Create),
        object_class: row.get("object_class"),
        target_uid: row.get("target_uid"),
        payload: row.get("payload"),
        status: OperationStatus::from_str(&status_str).unwrap_or(OperationStatus::Pending),
        retry_count: row.get("retry_count"),
        max_retries: row.get("max_retries"),
        next_retry_at: row.get("next_retry_at"),
        error_message: row.get("error_message"),
        priority: row.get("priority"),
        created_at: row.get("created_at"),
        updated_at: now,
        started_at: row.get("started_at"),
        completed_at: row.get("completed_at"),
        idempotency_key: row.get("idempotency_key"),
        resolution_notes: row.try_get("resolution_notes").ok().flatten(),
        resolved_by: row.try_get("resolved_by").ok().flatten(),
        resolved_at: row.try_get("resolved_at").ok().flatten(),
    }
}

/// Queue statistics.
#[derive(Debug, Clone, Serialize)]
pub struct QueueStats {
    /// Number of pending operations.
    pub pending: u64,

    /// Number of in-progress operations.
    pub in_progress: u64,

    /// Number of completed operations.
    pub completed: u64,

    /// Number of failed operations awaiting retry.
    pub failed: u64,

    /// Number of operations in dead letter queue.
    pub dead_letter: u64,

    /// Number of operations awaiting system (offline connector).
    pub awaiting_system: u64,

    /// Average processing time in seconds (completed ops only).
    pub avg_processing_time_secs: Option<f64>,

    /// Configured batch size for dequeue operations (F047).
    pub batch_size: u64,

    /// Total number of batches processed since startup (F047).
    pub batches_processed: u64,
}

impl QueueStats {
    /// Total operations in the queue (excluding completed).
    #[must_use] 
    pub fn total_queued(&self) -> u64 {
        self.pending + self.in_progress + self.failed + self.awaiting_system
    }

    /// Calculate success rate as percentage.
    #[must_use] 
    pub fn success_rate(&self) -> f64 {
        let total = self.completed + self.dead_letter;
        if total == 0 {
            100.0
        } else {
            (self.completed as f64 / total as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_queued_operation_new() {
        let op = QueuedOperation::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            OperationType::Create,
            "user".to_string(),
            serde_json::json!({"name": "John"}),
        );

        assert_eq!(op.status, OperationStatus::Pending);
        assert_eq!(op.retry_count, 0);
        assert!(op.can_retry());
        assert!(op.is_ready());
    }

    #[test]
    fn test_queued_operation_with_target() {
        let op = QueuedOperation::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            OperationType::Update,
            "user".to_string(),
            serde_json::json!({}),
        )
        .with_target_uid("cn=john,dc=example,dc=com")
        .with_priority(1);

        assert_eq!(op.target_uid, Some("cn=john,dc=example,dc=com".to_string()));
        assert_eq!(op.priority, 1);
    }

    #[test]
    fn test_can_retry() {
        let mut op = QueuedOperation::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            OperationType::Create,
            "user".to_string(),
            serde_json::json!({}),
        )
        .with_max_retries(3);

        assert!(op.can_retry());

        op.retry_count = 3;
        assert!(!op.can_retry());
    }

    #[test]
    fn test_queue_config_default() {
        let config = QueueConfig::default();
        assert_eq!(config.base_delay_secs, 30); // Updated per spec
        assert_eq!(config.max_delay_secs, 3600);
        assert_eq!(config.default_max_retries, 10); // Updated per spec
        assert_eq!(config.batch_size, 50); // Updated per spec
    }

    #[test]
    fn test_queue_stats() {
        let stats = QueueStats {
            pending: 10,
            in_progress: 5,
            completed: 100,
            failed: 3,
            dead_letter: 2,
            awaiting_system: 4,
            avg_processing_time_secs: Some(1.5),
            batch_size: 50,
            batches_processed: 10,
        };

        assert_eq!(stats.total_queued(), 22); // 10 + 5 + 3 + 4
        assert_eq!(stats.batch_size, 50);
        assert_eq!(stats.batches_processed, 10);
    }

    #[test]
    fn test_queue_stats_success_rate() {
        // 100% success
        let stats = QueueStats {
            pending: 0,
            in_progress: 0,
            completed: 100,
            failed: 0,
            dead_letter: 0,
            awaiting_system: 0,
            avg_processing_time_secs: None,
            batch_size: 50,
            batches_processed: 0,
        };
        assert_eq!(stats.success_rate(), 100.0);

        // 50% success (50 completed, 50 dead letter)
        let stats = QueueStats {
            pending: 0,
            in_progress: 0,
            completed: 50,
            failed: 0,
            dead_letter: 50,
            awaiting_system: 0,
            avg_processing_time_secs: None,
            batch_size: 50,
            batches_processed: 0,
        };
        assert_eq!(stats.success_rate(), 50.0);

        // No completed operations yet (should be 100%)
        let stats = QueueStats {
            pending: 10,
            in_progress: 5,
            completed: 0,
            failed: 0,
            dead_letter: 0,
            awaiting_system: 0,
            avg_processing_time_secs: None,
            batch_size: 50,
            batches_processed: 0,
        };
        assert_eq!(stats.success_rate(), 100.0);
    }

    #[test]
    fn test_enqueue_result() {
        let id = Uuid::new_v4();

        let result = EnqueueResult::Enqueued { id };
        assert!(result.is_new());
        assert!(!result.is_duplicate());
        assert_eq!(result.operation_id(), id);

        let existing_id = Uuid::new_v4();
        let result = EnqueueResult::Duplicate { existing_id };
        assert!(!result.is_new());
        assert!(result.is_duplicate());
        assert_eq!(result.operation_id(), existing_id);
    }

    #[test]
    fn test_queued_operation_with_idempotency_key() {
        let op = QueuedOperation::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            OperationType::Create,
            "user".to_string(),
            serde_json::json!({"name": "John"}),
        )
        .with_idempotency_key("test-key-123");

        assert_eq!(op.idempotency_key, Some("test-key-123".to_string()));
        assert_eq!(op.max_retries, 10); // Updated default
    }
}
