//! Provisioning Operation model.
//!
//! Represents queued provisioning operations with retry support.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "varchar", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum OperationType {
    /// Create a new object in the target system.
    Create,
    /// Update an existing object.
    Update,
    /// Delete an object.
    Delete,
}

impl std::fmt::Display for OperationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperationType::Create => write!(f, "create"),
            OperationType::Update => write!(f, "update"),
            OperationType::Delete => write!(f, "delete"),
        }
    }
}

impl std::str::FromStr for OperationType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "create" => Ok(OperationType::Create),
            "update" => Ok(OperationType::Update),
            "delete" => Ok(OperationType::Delete),
            _ => Err(format!("Unknown operation type: {s}")),
        }
    }
}

/// Operation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    /// Waiting to be processed.
    Pending,
    /// Currently being processed.
    InProgress,
    /// Successfully completed.
    Completed,
    /// Failed (may be retried).
    Failed,
    /// Exceeded max retries, moved to dead letter queue.
    DeadLetter,
    /// Waiting for target system to come online.
    AwaitingSystem,
    /// Manually resolved (acknowledged failure).
    Resolved,
    /// Cancelled before execution.
    Cancelled,
}

impl std::fmt::Display for OperationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OperationStatus::Pending => write!(f, "pending"),
            OperationStatus::InProgress => write!(f, "in_progress"),
            OperationStatus::Completed => write!(f, "completed"),
            OperationStatus::Failed => write!(f, "failed"),
            OperationStatus::DeadLetter => write!(f, "dead_letter"),
            OperationStatus::AwaitingSystem => write!(f, "awaiting_system"),
            OperationStatus::Resolved => write!(f, "resolved"),
            OperationStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::str::FromStr for OperationStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(OperationStatus::Pending),
            "in_progress" => Ok(OperationStatus::InProgress),
            "completed" => Ok(OperationStatus::Completed),
            "failed" => Ok(OperationStatus::Failed),
            "dead_letter" => Ok(OperationStatus::DeadLetter),
            "awaiting_system" => Ok(OperationStatus::AwaitingSystem),
            "resolved" => Ok(OperationStatus::Resolved),
            "cancelled" => Ok(OperationStatus::Cancelled),
            _ => Err(format!("Unknown operation status: {s}")),
        }
    }
}

impl OperationStatus {
    /// Check if the operation is in a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            OperationStatus::Completed
                | OperationStatus::DeadLetter
                | OperationStatus::Resolved
                | OperationStatus::Cancelled
        )
    }

    /// Check if the operation is waiting for external system.
    #[must_use]
    pub fn is_waiting(&self) -> bool {
        matches!(self, OperationStatus::AwaitingSystem)
    }
}

/// A queued provisioning operation.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ProvisioningOperation {
    /// Unique identifier for the operation.
    pub id: Uuid,

    /// The tenant this operation belongs to.
    pub tenant_id: Uuid,

    /// The connector to execute against.
    pub connector_id: Uuid,

    /// The user being provisioned.
    pub user_id: Uuid,

    /// Object class being operated on.
    pub object_class: String,

    /// Type of operation.
    pub operation_type: OperationType,

    /// Target system identifier (if known).
    pub target_uid: Option<String>,

    /// Operation payload (attributes to provision).
    pub payload: serde_json::Value,

    /// Current status.
    pub status: OperationStatus,

    /// Priority (higher = more urgent).
    pub priority: i32,

    /// Number of retry attempts.
    pub retry_count: i32,

    /// Maximum retry attempts.
    pub max_retries: i32,

    /// When to retry next.
    pub next_retry_at: Option<DateTime<Utc>>,

    /// Error message (if failed).
    pub error_message: Option<String>,

    /// Error code (if failed).
    pub error_code: Option<String>,

    /// Whether the error is transient (retryable).
    pub is_transient_error: Option<bool>,

    /// Idempotency key for duplicate detection.
    pub idempotency_key: Option<String>,

    /// Notes about resolution (for resolved operations).
    pub resolution_notes: Option<String>,

    /// Who resolved the operation (user ID).
    pub resolved_by: Option<Uuid>,

    /// When the operation was resolved.
    pub resolved_at: Option<DateTime<Utc>>,

    /// When the operation started processing.
    pub started_at: Option<DateTime<Utc>>,

    /// When the operation was created.
    pub created_at: DateTime<Utc>,

    /// When the operation was last updated.
    pub updated_at: DateTime<Utc>,

    /// When the operation completed.
    pub completed_at: Option<DateTime<Utc>>,

    /// Who cancelled the operation (user ID).
    pub cancelled_by: Option<Uuid>,

    /// When the operation was cancelled.
    pub cancelled_at: Option<DateTime<Utc>>,
}

/// Request to create a provisioning operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateProvisioningOperation {
    pub connector_id: Uuid,
    pub user_id: Uuid,
    pub object_class: String,
    pub operation_type: OperationType,
    pub target_uid: Option<String>,
    pub payload: serde_json::Value,
    pub priority: Option<i32>,
    pub max_retries: Option<i32>,
}

/// Filter for listing operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OperationFilter {
    pub connector_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub status: Option<OperationStatus>,
    pub operation_type: Option<OperationType>,
    /// Filter operations created on or after this date.
    pub from_date: Option<DateTime<Utc>>,
    /// Filter operations created on or before this date.
    pub to_date: Option<DateTime<Utc>>,
}

/// Default max retries.
pub const DEFAULT_MAX_RETRIES: i32 = 5;

/// Default priority.
pub const DEFAULT_PRIORITY: i32 = 0;

impl ProvisioningOperation {
    /// Find an operation by ID.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM provisioning_operations
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List operations with simple filters and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Option<Uuid>,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        if let (Some(cid), Some(s)) = (connector_id, status) {
            sqlx::query_as(
                r"
                SELECT * FROM provisioning_operations
                WHERE tenant_id = $1 AND connector_id = $2 AND status = $3
                ORDER BY priority DESC, created_at ASC
                LIMIT $4 OFFSET $5
                ",
            )
            .bind(tenant_id)
            .bind(cid)
            .bind(s)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await
        } else if let Some(cid) = connector_id {
            sqlx::query_as(
                r"
                SELECT * FROM provisioning_operations
                WHERE tenant_id = $1 AND connector_id = $2
                ORDER BY priority DESC, created_at ASC
                LIMIT $3 OFFSET $4
                ",
            )
            .bind(tenant_id)
            .bind(cid)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await
        } else if let Some(s) = status {
            sqlx::query_as(
                r"
                SELECT * FROM provisioning_operations
                WHERE tenant_id = $1 AND status = $2
                ORDER BY priority DESC, created_at ASC
                LIMIT $3 OFFSET $4
                ",
            )
            .bind(tenant_id)
            .bind(s)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await
        } else {
            sqlx::query_as(
                r"
                SELECT * FROM provisioning_operations
                WHERE tenant_id = $1
                ORDER BY priority DESC, created_at ASC
                LIMIT $2 OFFSET $3
                ",
            )
            .bind(tenant_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await
        }
    }

    /// List operations with `OperationFilter`.
    pub async fn list_with_filter(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &OperationFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM provisioning_operations
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.connector_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND connector_id = ${param_count}"));
        }
        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.operation_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND operation_type = ${param_count}"));
        }
        if filter.from_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${param_count}"));
        }
        if filter.to_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY priority DESC, created_at ASC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, ProvisioningOperation>(&query).bind(tenant_id);

        if let Some(connector_id) = filter.connector_id {
            q = q.bind(connector_id);
        }
        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status.to_string());
        }
        if let Some(operation_type) = filter.operation_type {
            q = q.bind(operation_type.to_string());
        }
        if let Some(from_date) = filter.from_date {
            q = q.bind(from_date);
        }
        if let Some(to_date) = filter.to_date {
            q = q.bind(to_date);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count operations matching the filter.
    pub async fn count_with_filter(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &OperationFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM provisioning_operations
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.connector_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND connector_id = ${param_count}"));
        }
        if filter.user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND user_id = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.operation_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND operation_type = ${param_count}"));
        }
        if filter.from_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${param_count}"));
        }
        if filter.to_date.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(connector_id) = filter.connector_id {
            q = q.bind(connector_id);
        }
        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status.to_string());
        }
        if let Some(operation_type) = filter.operation_type {
            q = q.bind(operation_type.to_string());
        }
        if let Some(from_date) = filter.from_date {
            q = q.bind(from_date);
        }
        if let Some(to_date) = filter.to_date {
            q = q.bind(to_date);
        }

        q.fetch_one(pool).await
    }

    /// Get pending operations ready for processing.
    pub async fn get_pending(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Option<Uuid>,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        if let Some(cid) = connector_id {
            sqlx::query_as(
                r"
                SELECT * FROM provisioning_operations
                WHERE tenant_id = $1 AND connector_id = $2
                    AND status = 'pending'
                    AND (next_retry_at IS NULL OR next_retry_at <= NOW())
                ORDER BY priority DESC, created_at ASC
                LIMIT $3
                ",
            )
            .bind(tenant_id)
            .bind(cid)
            .bind(limit)
            .fetch_all(pool)
            .await
        } else {
            sqlx::query_as(
                r"
                SELECT * FROM provisioning_operations
                WHERE tenant_id = $1 AND status = 'pending'
                    AND (next_retry_at IS NULL OR next_retry_at <= NOW())
                ORDER BY priority DESC, created_at ASC
                LIMIT $2
                ",
            )
            .bind(tenant_id)
            .bind(limit)
            .fetch_all(pool)
            .await
        }
    }

    /// Create a new provisioning operation.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: &CreateProvisioningOperation,
    ) -> Result<Self, sqlx::Error> {
        let id = Uuid::new_v4();
        let priority = input.priority.unwrap_or(DEFAULT_PRIORITY);
        let max_retries = input.max_retries.unwrap_or(DEFAULT_MAX_RETRIES);

        sqlx::query_as(
            r"
            INSERT INTO provisioning_operations (
                id, tenant_id, connector_id, user_id, object_class,
                operation_type, target_uid, payload, priority, max_retries
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(input.connector_id)
        .bind(input.user_id)
        .bind(&input.object_class)
        .bind(input.operation_type.to_string())
        .bind(&input.target_uid)
        .bind(&input.payload)
        .bind(priority)
        .bind(max_retries)
        .fetch_one(pool)
        .await
    }

    /// Claim an operation for processing (atomic update).
    pub async fn claim(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE provisioning_operations
            SET status = 'in_progress', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Mark operation as completed.
    pub async fn complete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        target_uid: Option<&str>,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE provisioning_operations
            SET status = 'completed', target_uid = COALESCE($3, target_uid),
                completed_at = NOW(), updated_at = NOW(),
                error_message = NULL, error_code = NULL
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(target_uid)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Mark operation as failed with retry scheduling.
    pub async fn fail(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        error_message: &str,
        error_code: Option<&str>,
        is_transient: bool,
        retry_delay_seconds: i64,
    ) -> Result<Option<Self>, sqlx::Error> {
        // First get the current operation to check retry count
        let op = Self::find_by_id(pool, tenant_id, id).await?;
        let op = match op {
            Some(o) => o,
            None => return Ok(None),
        };

        let new_retry_count = op.retry_count + 1;
        let (new_status, next_retry) = if !is_transient || new_retry_count >= op.max_retries {
            // Non-transient error or max retries exceeded: move to dead letter
            (OperationStatus::DeadLetter, None)
        } else {
            // Schedule retry with exponential backoff
            let delay_seconds = retry_delay_seconds * (1 << new_retry_count.min(5));
            let retry_at = Utc::now() + chrono::Duration::seconds(delay_seconds);
            (OperationStatus::Pending, Some(retry_at))
        };

        sqlx::query_as(
            r"
            UPDATE provisioning_operations
            SET status = $3, retry_count = $4, next_retry_at = $5,
                error_message = $6, error_code = $7, is_transient_error = $8,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(new_status.to_string())
        .bind(new_retry_count)
        .bind(next_retry)
        .bind(error_message)
        .bind(error_code)
        .bind(is_transient)
        .fetch_optional(pool)
        .await
    }

    /// Retry a dead-letter operation.
    pub async fn retry_dead_letter(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE provisioning_operations
            SET status = 'pending', retry_count = 0, next_retry_at = NULL,
                error_message = NULL, error_code = NULL, is_transient_error = NULL,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'dead_letter'
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Cancel an operation.
    ///
    /// Sets the status to 'cancelled' and records who cancelled it.
    /// Only pending or `in_progress` operations can be cancelled.
    pub async fn cancel(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        cancelled_by: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE provisioning_operations
            SET status = 'cancelled',
                cancelled_by = $3,
                cancelled_at = NOW(),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
                AND status IN ('pending', 'in_progress')
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(cancelled_by)
        .fetch_optional(pool)
        .await
    }

    /// Check if an operation can be cancelled.
    #[must_use]
    pub fn can_cancel(&self) -> bool {
        matches!(
            self.status,
            OperationStatus::Pending | OperationStatus::InProgress
        )
    }

    /// Count operations by status for a connector.
    pub async fn count_by_status(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        status: OperationStatus,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM provisioning_operations
            WHERE tenant_id = $1 AND connector_id = $2 AND status = $3
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(status.to_string())
        .fetch_one(pool)
        .await
    }

    /// Count operations by tenant with optional filters.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Option<Uuid>,
        status: Option<&str>,
    ) -> Result<i64, sqlx::Error> {
        if let (Some(cid), Some(s)) = (connector_id, status) {
            sqlx::query_scalar(
                r"
                SELECT COUNT(*) FROM provisioning_operations
                WHERE tenant_id = $1 AND connector_id = $2 AND status = $3
                ",
            )
            .bind(tenant_id)
            .bind(cid)
            .bind(s)
            .fetch_one(pool)
            .await
        } else if let Some(cid) = connector_id {
            sqlx::query_scalar(
                r"
                SELECT COUNT(*) FROM provisioning_operations
                WHERE tenant_id = $1 AND connector_id = $2
                ",
            )
            .bind(tenant_id)
            .bind(cid)
            .fetch_one(pool)
            .await
        } else if let Some(s) = status {
            sqlx::query_scalar(
                r"
                SELECT COUNT(*) FROM provisioning_operations
                WHERE tenant_id = $1 AND status = $2
                ",
            )
            .bind(tenant_id)
            .bind(s)
            .fetch_one(pool)
            .await
        } else {
            sqlx::query_scalar(
                r"
                SELECT COUNT(*) FROM provisioning_operations
                WHERE tenant_id = $1
                ",
            )
            .bind(tenant_id)
            .fetch_one(pool)
            .await
        }
    }

    /// Check if this operation can be retried.
    #[must_use]
    pub fn can_retry(&self) -> bool {
        matches!(
            self.status,
            OperationStatus::Pending | OperationStatus::Failed
        ) && self.retry_count < self.max_retries
    }

    /// Check if this operation is in dead letter.
    #[must_use]
    pub fn is_dead_letter(&self) -> bool {
        matches!(self.status, OperationStatus::DeadLetter)
    }

    /// Check if this operation is awaiting system.
    #[must_use]
    pub fn is_awaiting_system(&self) -> bool {
        matches!(self.status, OperationStatus::AwaitingSystem)
    }

    /// Mark operation as awaiting system (connector offline).
    pub async fn mark_awaiting_system(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE provisioning_operations
            SET status = 'awaiting_system', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
                AND status IN ('pending', 'failed')
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Resume operations that were awaiting system when connector comes online.
    pub async fn resume_awaiting_operations(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE provisioning_operations
            SET status = 'pending', updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
                AND status = 'awaiting_system'
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Resolve a dead letter operation (acknowledge the failure).
    pub async fn resolve(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        resolved_by: Uuid,
        resolution_notes: Option<&str>,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE provisioning_operations
            SET status = 'resolved',
                resolved_by = $3,
                resolved_at = NOW(),
                resolution_notes = $4,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'dead_letter'
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(resolved_by)
        .bind(resolution_notes)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// List dead letter operations.
    pub async fn list_dead_letter(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        if let Some(cid) = connector_id {
            sqlx::query_as(
                r"
                SELECT * FROM provisioning_operations
                WHERE tenant_id = $1 AND connector_id = $2 AND status = 'dead_letter'
                ORDER BY created_at DESC
                LIMIT $3 OFFSET $4
                ",
            )
            .bind(tenant_id)
            .bind(cid)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await
        } else {
            sqlx::query_as(
                r"
                SELECT * FROM provisioning_operations
                WHERE tenant_id = $1 AND status = 'dead_letter'
                ORDER BY created_at DESC
                LIMIT $2 OFFSET $3
                ",
            )
            .bind(tenant_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await
        }
    }

    /// Count dead letter operations.
    pub async fn count_dead_letter(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Option<Uuid>,
    ) -> Result<i64, sqlx::Error> {
        if let Some(cid) = connector_id {
            sqlx::query_scalar(
                r"
                SELECT COUNT(*) FROM provisioning_operations
                WHERE tenant_id = $1 AND connector_id = $2 AND status = 'dead_letter'
                ",
            )
            .bind(tenant_id)
            .bind(cid)
            .fetch_one(pool)
            .await
        } else {
            sqlx::query_scalar(
                r"
                SELECT COUNT(*) FROM provisioning_operations
                WHERE tenant_id = $1 AND status = 'dead_letter'
                ",
            )
            .bind(tenant_id)
            .fetch_one(pool)
            .await
        }
    }

    /// Count awaiting system operations for a connector.
    pub async fn count_awaiting_system(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM provisioning_operations
            WHERE tenant_id = $1 AND connector_id = $2 AND status = 'awaiting_system'
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_one(pool)
        .await
    }

    /// Find by idempotency key.
    pub async fn find_by_idempotency_key(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        idempotency_key: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM provisioning_operations
            WHERE tenant_id = $1 AND idempotency_key = $2
            ",
        )
        .bind(tenant_id)
        .bind(idempotency_key)
        .fetch_optional(pool)
        .await
    }

    /// Clean up old completed jobs based on retention period.
    ///
    /// - Completed jobs older than `completed_days` are deleted
    /// - Failed jobs older than `failed_days` are deleted
    ///
    /// Returns the number of deleted operations.
    pub async fn cleanup_old_jobs(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        completed_days: i64,
        failed_days: i64,
    ) -> Result<u64, sqlx::Error> {
        // Delete old completed jobs
        let completed_result = sqlx::query(
            r"
            DELETE FROM provisioning_operations
            WHERE tenant_id = $1
                AND status = 'completed'
                AND completed_at < NOW() - INTERVAL '1 day' * $2
            ",
        )
        .bind(tenant_id)
        .bind(completed_days)
        .execute(pool)
        .await?;

        // Delete old failed/cancelled jobs (retain longer for audit)
        let failed_result = sqlx::query(
            r"
            DELETE FROM provisioning_operations
            WHERE tenant_id = $1
                AND status IN ('failed', 'cancelled', 'resolved')
                AND updated_at < NOW() - INTERVAL '1 day' * $2
            ",
        )
        .bind(tenant_id)
        .bind(failed_days)
        .execute(pool)
        .await?;

        Ok(completed_result.rows_affected() + failed_result.rows_affected())
    }

    /// Bulk retry multiple dead letter operations.
    ///
    /// Returns the IDs that were successfully requeued.
    pub async fn bulk_retry_dead_letter(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        ids: &[Uuid],
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        let result: Vec<(Uuid,)> = sqlx::query_as(
            r"
            UPDATE provisioning_operations
            SET status = 'pending',
                retry_count = 0,
                next_retry_at = NULL,
                error_message = NULL,
                error_code = NULL,
                is_transient_error = NULL,
                updated_at = NOW()
            WHERE tenant_id = $1
                AND id = ANY($2)
                AND status = 'dead_letter'
            RETURNING id
            ",
        )
        .bind(tenant_id)
        .bind(ids)
        .fetch_all(pool)
        .await?;

        Ok(result.into_iter().map(|(id,)| id).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_type_display() {
        assert_eq!(OperationType::Create.to_string(), "create");
        assert_eq!(OperationType::Update.to_string(), "update");
        assert_eq!(OperationType::Delete.to_string(), "delete");
    }

    #[test]
    fn test_operation_type_from_str() {
        assert_eq!(
            "create".parse::<OperationType>().unwrap(),
            OperationType::Create
        );
        assert_eq!(
            "UPDATE".parse::<OperationType>().unwrap(),
            OperationType::Update
        );
        assert!("unknown".parse::<OperationType>().is_err());
    }

    #[test]
    fn test_operation_status_display() {
        assert_eq!(OperationStatus::Pending.to_string(), "pending");
        assert_eq!(OperationStatus::InProgress.to_string(), "in_progress");
        assert_eq!(OperationStatus::DeadLetter.to_string(), "dead_letter");
    }

    #[test]
    fn test_operation_status_from_str() {
        assert_eq!(
            "pending".parse::<OperationStatus>().unwrap(),
            OperationStatus::Pending
        );
        assert_eq!(
            "in_progress".parse::<OperationStatus>().unwrap(),
            OperationStatus::InProgress
        );
        assert_eq!(
            "dead_letter".parse::<OperationStatus>().unwrap(),
            OperationStatus::DeadLetter
        );
    }

    #[test]
    fn test_create_operation_request() {
        let request = CreateProvisioningOperation {
            connector_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            object_class: "user".to_string(),
            operation_type: OperationType::Create,
            target_uid: None,
            payload: serde_json::json!({
                "email": "test@example.com",
                "first_name": "Test"
            }),
            priority: Some(10),
            max_retries: Some(3),
        };

        assert_eq!(request.object_class, "user");
        assert_eq!(request.operation_type, OperationType::Create);
        assert_eq!(request.priority, Some(10));
    }

    #[test]
    fn test_operation_filter_default() {
        let filter = OperationFilter::default();
        assert!(filter.connector_id.is_none());
        assert!(filter.user_id.is_none());
        assert!(filter.status.is_none());
    }
}
