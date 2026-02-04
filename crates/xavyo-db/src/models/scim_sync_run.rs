//! SCIM sync run model (F087).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// A SCIM sync run record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ScimSyncRun {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub target_id: Uuid,
    pub run_type: String,
    pub status: String,
    pub triggered_by: Option<Uuid>,
    pub total_resources: i32,
    pub processed_count: i32,
    pub created_count: i32,
    pub updated_count: i32,
    pub skipped_count: i32,
    pub failed_count: i32,
    pub orphan_count: i32,
    pub missing_count: i32,
    pub drift_count: i32,
    pub error_message: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Input for creating a new SCIM sync run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateScimSyncRun {
    pub tenant_id: Uuid,
    pub target_id: Uuid,
    pub run_type: String,
    pub triggered_by: Option<Uuid>,
    pub total_resources: i32,
}

impl ScimSyncRun {
    /// Create a new SCIM sync run.
    pub async fn create(pool: &PgPool, data: CreateScimSyncRun) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO scim_sync_runs (tenant_id, target_id, run_type, triggered_by, total_resources)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
            ",
        )
        .bind(data.tenant_id)
        .bind(data.target_id)
        .bind(&data.run_type)
        .bind(data.triggered_by)
        .bind(data.total_resources)
        .fetch_one(pool)
        .await
    }

    /// Find a sync run by ID within a tenant.
    pub async fn get_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM scim_sync_runs
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List sync runs for a target with optional `run_type` filter.
    /// Returns (items, `total_count`).
    pub async fn list_by_target(
        pool: &PgPool,
        tenant_id: Uuid,
        target_id: Uuid,
        run_type: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<Self>, i64), sqlx::Error> {
        if let Some(rt) = run_type {
            let items: Vec<Self> = sqlx::query_as(
                r"
                SELECT * FROM scim_sync_runs
                WHERE tenant_id = $1 AND target_id = $2 AND run_type = $3
                ORDER BY started_at DESC
                LIMIT $4 OFFSET $5
                ",
            )
            .bind(tenant_id)
            .bind(target_id)
            .bind(rt)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await?;

            let total: i64 = sqlx::query_scalar(
                r"
                SELECT COUNT(*) FROM scim_sync_runs
                WHERE tenant_id = $1 AND target_id = $2 AND run_type = $3
                ",
            )
            .bind(tenant_id)
            .bind(target_id)
            .bind(rt)
            .fetch_one(pool)
            .await?;

            Ok((items, total))
        } else {
            let items: Vec<Self> = sqlx::query_as(
                r"
                SELECT * FROM scim_sync_runs
                WHERE tenant_id = $1 AND target_id = $2
                ORDER BY started_at DESC
                LIMIT $3 OFFSET $4
                ",
            )
            .bind(tenant_id)
            .bind(target_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await?;

            let total: i64 = sqlx::query_scalar(
                r"
                SELECT COUNT(*) FROM scim_sync_runs
                WHERE tenant_id = $1 AND target_id = $2
                ",
            )
            .bind(tenant_id)
            .bind(target_id)
            .fetch_one(pool)
            .await?;

            Ok((items, total))
        }
    }

    /// Update progress counters for a sync run.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_progress(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        processed_count: i32,
        created_count: i32,
        updated_count: i32,
        skipped_count: i32,
        failed_count: i32,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r"
            UPDATE scim_sync_runs
            SET processed_count = $3, created_count = $4, updated_count = $5,
                skipped_count = $6, failed_count = $7
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(processed_count)
        .bind(created_count)
        .bind(updated_count)
        .bind(skipped_count)
        .bind(failed_count)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Mark a sync run as completed.
    pub async fn complete(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE scim_sync_runs
            SET status = 'completed', completed_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Mark a sync run as failed.
    pub async fn fail(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        error_message: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE scim_sync_runs
            SET status = 'failed', error_message = $3, completed_at = NOW()
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

    /// Cancel a running sync run.
    pub async fn cancel(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE scim_sync_runs
            SET status = 'cancelled', completed_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'running'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Check if there is an active (running) sync run for a target.
    pub async fn has_active_run(
        pool: &PgPool,
        tenant_id: Uuid,
        target_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM scim_sync_runs
            WHERE tenant_id = $1 AND target_id = $2 AND status = 'running'
            ",
        )
        .bind(tenant_id)
        .bind(target_id)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }

    /// Atomically create a sync run only if no active run exists for the target.
    ///
    /// Uses a single INSERT ... WHERE NOT EXISTS query to avoid TOCTOU race
    /// conditions between checking for active runs and creating a new one.
    /// Returns `None` if an active run already exists.
    pub async fn create_if_no_active_run(
        pool: &PgPool,
        data: CreateScimSyncRun,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO scim_sync_runs (tenant_id, target_id, run_type, triggered_by, total_resources)
            SELECT $1, $2, $3, $4, $5
            WHERE NOT EXISTS (
                SELECT 1 FROM scim_sync_runs
                WHERE tenant_id = $1 AND target_id = $2 AND status = 'running'
            )
            RETURNING *
            ",
        )
        .bind(data.tenant_id)
        .bind(data.target_id)
        .bind(&data.run_type)
        .bind(data.triggered_by)
        .bind(data.total_resources)
        .fetch_optional(pool)
        .await
    }

    /// Update reconciliation statistics for a sync run.
    pub async fn update_reconciliation_stats(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        orphan_count: i32,
        missing_count: i32,
        drift_count: i32,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r"
            UPDATE scim_sync_runs
            SET orphan_count = $3, missing_count = $4, drift_count = $5
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(orphan_count)
        .bind(missing_count)
        .bind(drift_count)
        .execute(pool)
        .await?;

        Ok(())
    }
}
