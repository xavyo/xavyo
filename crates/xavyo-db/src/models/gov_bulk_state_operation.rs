//! Governance Bulk State Operation model.
//!
//! Tracks bulk state transition operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::FromRow;
use uuid::Uuid;

/// Status of a bulk state operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_bulk_operation_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum BulkOperationStatus {
    /// Operation is pending.
    Pending,
    /// Operation is currently running.
    Running,
    /// Operation completed successfully.
    Completed,
    /// Operation failed.
    Failed,
    /// Operation was cancelled.
    Cancelled,
}

/// A governance bulk state operation.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovBulkStateOperation {
    /// Unique identifier for the operation.
    pub id: Uuid,

    /// The tenant this operation belongs to.
    pub tenant_id: Uuid,

    /// The transition to apply to all objects.
    pub transition_id: Uuid,

    /// IDs of objects to transition.
    pub object_ids: Vec<Uuid>,

    /// Current status of the operation.
    pub status: BulkOperationStatus,

    /// Total number of objects.
    pub total_count: i32,

    /// Number of objects processed so far.
    pub processed_count: i32,

    /// Number of successful transitions.
    pub success_count: i32,

    /// Number of failed transitions.
    pub failure_count: i32,

    /// Per-object results including failures.
    pub results: Option<JsonValue>,

    /// User who requested the operation.
    pub requested_by: Uuid,

    /// When the operation was created.
    pub created_at: DateTime<Utc>,

    /// When processing started.
    pub started_at: Option<DateTime<Utc>>,

    /// When processing completed.
    pub completed_at: Option<DateTime<Utc>>,
}

/// Request to create a new bulk state operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovBulkStateOperation {
    pub transition_id: Uuid,
    pub object_ids: Vec<Uuid>,
    pub requested_by: Uuid,
}

/// Request to update a bulk state operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateGovBulkStateOperation {
    pub status: Option<BulkOperationStatus>,
    pub processed_count: Option<i32>,
    pub success_count: Option<i32>,
    pub failure_count: Option<i32>,
    pub results: Option<JsonValue>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Filter options for listing bulk operations.
#[derive(Debug, Clone, Default)]
pub struct BulkOperationFilter {
    pub status: Option<BulkOperationStatus>,
    pub transition_id: Option<Uuid>,
    pub requested_by: Option<Uuid>,
}

/// Result for a single object in a bulk operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkOperationResult {
    pub object_id: Uuid,
    pub success: bool,
    pub transition_request_id: Option<Uuid>,
    pub error_message: Option<String>,
}

/// Progress update for a bulk operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkOperationProgress {
    pub processed_count: i32,
    pub success_count: i32,
    pub failure_count: i32,
    pub progress_percent: u8,
}

/// Maximum number of objects per bulk operation.
pub const MAX_BULK_OPERATION_SIZE: i32 = 1000;

impl GovBulkStateOperation {
    /// Find an operation by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_bulk_state_operations
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find pending or running operations that need processing (background job).
    pub async fn find_pending_or_running(
        pool: &sqlx::PgPool,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_bulk_state_operations
            WHERE status IN ('pending', 'running')
            ORDER BY created_at ASC
            LIMIT $1
            ",
        )
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// List operations for a tenant with optional filters.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &BulkOperationFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_bulk_state_operations
            WHERE tenant_id = $1
            ",
        );

        let mut param_num = 2;

        if filter.status.is_some() {
            query.push_str(&format!(" AND status = ${param_num}"));
            param_num += 1;
        }

        if filter.transition_id.is_some() {
            query.push_str(&format!(" AND transition_id = ${param_num}"));
            param_num += 1;
        }

        if filter.requested_by.is_some() {
            query.push_str(&format!(" AND requested_by = ${param_num}"));
            param_num += 1;
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_num,
            param_num + 1
        ));

        let mut db_query = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(status) = &filter.status {
            db_query = db_query.bind(status);
        }

        if let Some(transition_id) = filter.transition_id {
            db_query = db_query.bind(transition_id);
        }

        if let Some(requested_by) = filter.requested_by {
            db_query = db_query.bind(requested_by);
        }

        db_query.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count operations for a tenant with optional filters.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &BulkOperationFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM gov_bulk_state_operations
            WHERE tenant_id = $1
            ",
        );

        let mut param_num = 2;

        if filter.status.is_some() {
            query.push_str(&format!(" AND status = ${param_num}"));
            param_num += 1;
        }

        if filter.transition_id.is_some() {
            query.push_str(&format!(" AND transition_id = ${param_num}"));
            param_num += 1;
        }

        if filter.requested_by.is_some() {
            query.push_str(&format!(" AND requested_by = ${param_num}"));
        }

        let mut db_query = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(status) = &filter.status {
            db_query = db_query.bind(status);
        }

        if let Some(transition_id) = filter.transition_id {
            db_query = db_query.bind(transition_id);
        }

        if let Some(requested_by) = filter.requested_by {
            db_query = db_query.bind(requested_by);
        }

        db_query.fetch_one(pool).await
    }

    /// Count active (pending or running) operations for a tenant.
    pub async fn count_active(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_bulk_state_operations
            WHERE tenant_id = $1 AND status IN ('pending', 'running')
            ",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await
    }

    /// Create a new bulk state operation.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: &CreateGovBulkStateOperation,
    ) -> Result<Self, sqlx::Error> {
        let total_count = input.object_ids.len() as i32;
        sqlx::query_as(
            r"
            INSERT INTO gov_bulk_state_operations (
                tenant_id, transition_id, object_ids, total_count, requested_by
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.transition_id)
        .bind(&input.object_ids)
        .bind(total_count)
        .bind(input.requested_by)
        .fetch_one(pool)
        .await
    }

    /// Update a bulk state operation.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: &UpdateGovBulkStateOperation,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_bulk_state_operations
            SET
                status = COALESCE($3, status),
                processed_count = COALESCE($4, processed_count),
                success_count = COALESCE($5, success_count),
                failure_count = COALESCE($6, failure_count),
                results = COALESCE($7, results),
                started_at = COALESCE($8, started_at),
                completed_at = COALESCE($9, completed_at)
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(input.status)
        .bind(input.processed_count)
        .bind(input.success_count)
        .bind(input.failure_count)
        .bind(&input.results)
        .bind(input.started_at)
        .bind(input.completed_at)
        .fetch_optional(pool)
        .await
    }

    /// Mark operation as running.
    pub async fn mark_running(pool: &sqlx::PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_bulk_state_operations
            SET status = 'running', started_at = NOW()
            WHERE id = $1 AND status = 'pending'
            ",
        )
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Update progress counters.
    pub async fn update_progress(
        pool: &sqlx::PgPool,
        id: Uuid,
        processed_count: i32,
        success_count: i32,
        failure_count: i32,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_bulk_state_operations
            SET processed_count = $2, success_count = $3, failure_count = $4
            WHERE id = $1 AND status = 'running'
            ",
        )
        .bind(id)
        .bind(processed_count)
        .bind(success_count)
        .bind(failure_count)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Mark operation as completed.
    pub async fn mark_completed(
        pool: &sqlx::PgPool,
        id: Uuid,
        results: JsonValue,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_bulk_state_operations
            SET status = 'completed', results = $2, completed_at = NOW()
            WHERE id = $1 AND status = 'running'
            ",
        )
        .bind(id)
        .bind(&results)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Mark operation as failed.
    pub async fn mark_failed(
        pool: &sqlx::PgPool,
        id: Uuid,
        results: JsonValue,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_bulk_state_operations
            SET status = 'failed', results = $2, completed_at = NOW()
            WHERE id = $1 AND status IN ('pending', 'running')
            ",
        )
        .bind(id)
        .bind(&results)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Cancel a pending operation.
    pub async fn cancel(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_bulk_state_operations
            SET status = 'cancelled', completed_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Get the progress of an operation.
    #[must_use] 
    pub fn get_progress(&self) -> BulkOperationProgress {
        let progress_percent = if self.total_count > 0 {
            ((f64::from(self.processed_count) / f64::from(self.total_count)) * 100.0) as u8
        } else {
            0
        };

        BulkOperationProgress {
            processed_count: self.processed_count,
            success_count: self.success_count,
            failure_count: self.failure_count,
            progress_percent,
        }
    }

    /// Delete a bulk operation (only for cancelled or completed).
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_bulk_state_operations
            WHERE id = $1 AND tenant_id = $2 AND status IN ('cancelled', 'completed', 'failed')
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}
