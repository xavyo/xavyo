//! Governance Lifecycle Failed Operation model.
//!
//! Represents failed operations in the retry queue for lifecycle transitions.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::{FromRow, Row};
use uuid::Uuid;

use super::gov_lifecycle_config::LifecycleObjectType;

/// Type of failed operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "gov_failed_operation_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum FailedOperationType {
    /// Failed state transition.
    Transition,
    /// Failed entitlement action (pause/revoke/resume).
    EntitlementAction,
    /// Failed object state update.
    StateUpdate,
    /// Failed audit record creation.
    AuditRecord,
}

/// Status of the failed operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailedOperationStatus {
    /// Pending retry.
    Pending,
    /// Currently retrying.
    Retrying,
    /// Successfully completed on retry.
    Succeeded,
    /// Exceeded max retries, moved to dead letter queue.
    DeadLetter,
}

impl std::fmt::Display for FailedOperationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Retrying => write!(f, "retrying"),
            Self::Succeeded => write!(f, "succeeded"),
            Self::DeadLetter => write!(f, "dead_letter"),
        }
    }
}

/// A governance lifecycle failed operation.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovLifecycleFailedOperation {
    /// Unique identifier for the failed operation.
    pub id: Uuid,

    /// The tenant this operation belongs to.
    pub tenant_id: Uuid,

    /// Type of operation that failed.
    pub operation_type: FailedOperationType,

    /// Related transition request ID (if applicable).
    pub related_request_id: Option<Uuid>,

    /// ID of the object involved.
    pub object_id: Uuid,

    /// Type of object involved.
    pub object_type: LifecycleObjectType,

    /// Payload containing operation details for retry.
    pub operation_payload: JsonValue,

    /// Error message from the failure.
    pub error_message: String,

    /// Number of retry attempts made.
    pub retry_count: i32,

    /// Maximum number of retries allowed.
    pub max_retries: i32,

    /// When to next attempt retry.
    pub next_retry_at: DateTime<Utc>,

    /// When the last attempt was made.
    pub last_attempted_at: Option<DateTime<Utc>>,

    /// Current status.
    pub status: String,

    /// When the operation was created.
    pub created_at: DateTime<Utc>,

    /// When the operation was resolved.
    pub resolved_at: Option<DateTime<Utc>>,
}

/// Request to create a new failed operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateFailedOperation {
    pub operation_type: FailedOperationType,
    pub related_request_id: Option<Uuid>,
    pub object_id: Uuid,
    pub object_type: LifecycleObjectType,
    pub operation_payload: JsonValue,
    pub error_message: String,
    pub max_retries: i32,
}

impl GovLifecycleFailedOperation {
    /// Create a new failed operation.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateFailedOperation,
    ) -> Result<Self, sqlx::Error> {
        // Initial retry delay: 1 minute
        let next_retry_at = Utc::now() + Duration::minutes(1);

        sqlx::query_as(
            r#"
            INSERT INTO gov_lifecycle_failed_operations
            (tenant_id, operation_type, related_request_id, object_id, object_type,
             operation_payload, error_message, max_retries, next_retry_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.operation_type)
        .bind(input.related_request_id)
        .bind(input.object_id)
        .bind(input.object_type)
        .bind(&input.operation_payload)
        .bind(&input.error_message)
        .bind(input.max_retries)
        .bind(next_retry_at)
        .fetch_one(pool)
        .await
    }

    /// Find operations due for retry.
    pub async fn find_due_for_retry(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_lifecycle_failed_operations
            WHERE tenant_id = $1
              AND status IN ('pending', 'retrying')
              AND next_retry_at <= NOW()
            ORDER BY next_retry_at ASC
            LIMIT $2
            "#,
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Mark operation as retrying.
    pub async fn mark_retrying(pool: &sqlx::PgPool, id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE gov_lifecycle_failed_operations
            SET status = 'retrying', last_attempted_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Mark operation as succeeded.
    pub async fn mark_succeeded(pool: &sqlx::PgPool, id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE gov_lifecycle_failed_operations
            SET status = 'succeeded', resolved_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Increment retry count and schedule next retry with exponential backoff.
    pub async fn schedule_next_retry(pool: &sqlx::PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
        // Exponential backoff: 1min, 2min, 4min, 8min, 16min
        let result = sqlx::query(
            r#"
            UPDATE gov_lifecycle_failed_operations
            SET
                retry_count = retry_count + 1,
                status = CASE
                    WHEN retry_count + 1 >= max_retries THEN 'dead_letter'
                    ELSE 'pending'
                END,
                next_retry_at = CASE
                    WHEN retry_count + 1 >= max_retries THEN NULL
                    ELSE NOW() + (INTERVAL '1 minute' * POWER(2, retry_count))
                END,
                resolved_at = CASE
                    WHEN retry_count + 1 >= max_retries THEN NOW()
                    ELSE NULL
                END
            WHERE id = $1
            RETURNING status
            "#,
        )
        .bind(id)
        .fetch_one(pool)
        .await?;

        let status: String = result.get("status");
        Ok(status != "dead_letter")
    }

    /// Find dead letter operations for a tenant.
    pub async fn find_dead_letter(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_lifecycle_failed_operations
            WHERE tenant_id = $1 AND status = 'dead_letter'
            ORDER BY resolved_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Count dead letter operations.
    pub async fn count_dead_letter(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        let result: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM gov_lifecycle_failed_operations
            WHERE tenant_id = $1 AND status = 'dead_letter'
            "#,
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

        Ok(result.0)
    }

    /// Get tenants with pending retries.
    pub async fn get_tenants_with_pending_retries(
        pool: &sqlx::PgPool,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            r#"
            SELECT DISTINCT tenant_id
            FROM gov_lifecycle_failed_operations
            WHERE status IN ('pending', 'retrying')
              AND next_retry_at <= NOW()
            "#,
        )
        .fetch_all(pool)
        .await?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }
}
