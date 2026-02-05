//! Governance Reconciliation Run model.
//!
//! Represents a reconciliation job execution for orphan account detection.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Status of a reconciliation run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_reconciliation_status", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationStatus {
    /// Reconciliation is currently running.
    Running,
    /// Reconciliation completed successfully.
    Completed,
    /// Reconciliation failed with error.
    Failed,
    /// Reconciliation partially completed (timeout or cancellation).
    Partial,
}

impl ReconciliationStatus {
    /// Check if this status indicates the run is finished.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        !matches!(self, Self::Running)
    }

    /// Check if this status indicates success.
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

/// A reconciliation run record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovReconciliationRun {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant this run belongs to.
    pub tenant_id: Uuid,

    /// Current status of the run.
    pub status: ReconciliationStatus,

    /// When the run started.
    pub started_at: DateTime<Utc>,

    /// When the run completed (if finished).
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
    pub triggered_by: Option<Uuid>,

    /// Error message if failed.
    pub error_message: Option<String>,

    /// Progress percentage (0-100).
    pub progress_percent: i32,

    /// When the record was created.
    pub created_at: DateTime<Utc>,

    /// When the record was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new reconciliation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovReconciliationRun {
    pub triggered_by: Option<Uuid>,
}

/// Request to update a reconciliation run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateGovReconciliationRun {
    pub status: Option<ReconciliationStatus>,
    pub completed_at: Option<DateTime<Utc>>,
    pub total_accounts: Option<i32>,
    pub orphans_found: Option<i32>,
    pub new_orphans: Option<i32>,
    pub resolved_orphans: Option<i32>,
    pub error_message: Option<String>,
    pub progress_percent: Option<i32>,
}

/// Filter options for listing reconciliation runs.
#[derive(Debug, Clone, Default)]
pub struct ReconciliationRunFilter {
    pub status: Option<ReconciliationStatus>,
    pub triggered_by: Option<Uuid>,
    pub since: Option<DateTime<Utc>>,
}

impl GovReconciliationRun {
    /// Find a run by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_reconciliation_runs
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find the currently running reconciliation for a tenant.
    pub async fn find_running(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_reconciliation_runs
            WHERE tenant_id = $1 AND status = 'running'
            ORDER BY started_at DESC
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List all runs for a tenant with optional filtering.
    pub async fn list(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ReconciliationRunFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM gov_reconciliation_runs
            WHERE tenant_id = $1
            ",
        );

        let mut param_idx = 2;

        if filter.status.is_some() {
            query.push_str(&format!(" AND status = ${param_idx}"));
            param_idx += 1;
        }

        if filter.triggered_by.is_some() {
            query.push_str(&format!(" AND triggered_by = ${param_idx}"));
            param_idx += 1;
        }

        if filter.since.is_some() {
            query.push_str(&format!(" AND started_at >= ${param_idx}"));
            param_idx += 1;
        }

        query.push_str(&format!(
            " ORDER BY started_at DESC LIMIT ${} OFFSET ${}",
            param_idx,
            param_idx + 1
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(status) = &filter.status {
            q = q.bind(status);
        }

        if let Some(triggered_by) = filter.triggered_by {
            q = q.bind(triggered_by);
        }

        if let Some(since) = filter.since {
            q = q.bind(since);
        }

        q = q.bind(limit).bind(offset);

        q.fetch_all(pool).await
    }

    /// Count runs for a tenant with optional filtering.
    pub async fn count(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ReconciliationRunFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) as count FROM gov_reconciliation_runs
            WHERE tenant_id = $1
            ",
        );

        let mut param_idx = 2;

        if filter.status.is_some() {
            query.push_str(&format!(" AND status = ${param_idx}"));
            param_idx += 1;
        }

        if filter.triggered_by.is_some() {
            query.push_str(&format!(" AND triggered_by = ${param_idx}"));
            param_idx += 1;
        }

        if filter.since.is_some() {
            query.push_str(&format!(" AND started_at >= ${param_idx}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(status) = &filter.status {
            q = q.bind(status);
        }

        if let Some(triggered_by) = filter.triggered_by {
            q = q.bind(triggered_by);
        }

        if let Some(since) = filter.since {
            q = q.bind(since);
        }

        q.fetch_one(pool).await
    }

    /// Create a new reconciliation run.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        data: CreateGovReconciliationRun,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_reconciliation_runs (tenant_id, triggered_by)
            VALUES ($1, $2)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(data.triggered_by)
        .fetch_one(pool)
        .await
    }

    /// Update a reconciliation run.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        data: UpdateGovReconciliationRun,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_reconciliation_runs
            SET
                status = COALESCE($3, status),
                completed_at = COALESCE($4, completed_at),
                total_accounts = COALESCE($5, total_accounts),
                orphans_found = COALESCE($6, orphans_found),
                new_orphans = COALESCE($7, new_orphans),
                resolved_orphans = COALESCE($8, resolved_orphans),
                error_message = COALESCE($9, error_message),
                progress_percent = COALESCE($10, progress_percent)
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(data.status)
        .bind(data.completed_at)
        .bind(data.total_accounts)
        .bind(data.orphans_found)
        .bind(data.new_orphans)
        .bind(data.resolved_orphans)
        .bind(data.error_message)
        .bind(data.progress_percent)
        .fetch_optional(pool)
        .await
    }

    /// Mark a run as completed.
    pub async fn mark_completed(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        total_accounts: i32,
        orphans_found: i32,
        new_orphans: i32,
        resolved_orphans: i32,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_reconciliation_runs
            SET
                status = 'completed',
                completed_at = NOW(),
                total_accounts = $3,
                orphans_found = $4,
                new_orphans = $5,
                resolved_orphans = $6,
                progress_percent = 100
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(total_accounts)
        .bind(orphans_found)
        .bind(new_orphans)
        .bind(resolved_orphans)
        .fetch_optional(pool)
        .await
    }

    /// Mark a run as failed.
    pub async fn mark_failed(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        error_message: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_reconciliation_runs
            SET
                status = 'failed',
                completed_at = NOW(),
                error_message = $3
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(error_message)
        .fetch_optional(pool)
        .await
    }

    /// Cancel a running reconciliation.
    pub async fn cancel(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_reconciliation_runs
            SET
                status = 'partial',
                completed_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'running'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Update progress.
    pub async fn update_progress(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        progress_percent: i32,
        total_accounts: i32,
        orphans_found: i32,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_reconciliation_runs
            SET
                progress_percent = $3,
                total_accounts = $4,
                orphans_found = $5
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(progress_percent)
        .bind(total_accounts)
        .bind(orphans_found)
        .fetch_optional(pool)
        .await
    }

    /// Delete a run.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_reconciliation_runs
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reconciliation_status() {
        assert!(!ReconciliationStatus::Running.is_finished());
        assert!(ReconciliationStatus::Completed.is_finished());
        assert!(ReconciliationStatus::Failed.is_finished());
        assert!(ReconciliationStatus::Partial.is_finished());

        assert!(ReconciliationStatus::Completed.is_success());
        assert!(!ReconciliationStatus::Failed.is_success());
    }
}
