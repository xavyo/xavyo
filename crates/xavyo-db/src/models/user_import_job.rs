//! User import job model (F086).
//!
//! Represents a single CSV upload and its processing lifecycle.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// A user import job record.
///
/// Tracks the lifecycle of a CSV bulk user import, including file metadata,
/// processing progress, and final outcome counts.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UserImportJob {
    /// Unique job identifier.
    pub id: Uuid,

    /// Tenant this import belongs to.
    pub tenant_id: Uuid,

    /// Job lifecycle state: pending, processing, completed, failed, cancelled.
    pub status: String,

    /// Original uploaded filename.
    pub file_name: String,

    /// SHA-256 hex hash of uploaded file.
    pub file_hash: String,

    /// Size of uploaded CSV in bytes.
    pub file_size_bytes: i64,

    /// Total data rows (excluding header).
    pub total_rows: i32,

    /// Rows processed so far.
    pub processed_rows: i32,

    /// Successfully created users.
    pub success_count: i32,

    /// Rows with errors.
    pub error_count: i32,

    /// Skipped rows (duplicate email).
    pub skip_count: i32,

    /// Whether to send email invitations.
    pub send_invitations: bool,

    /// Admin who initiated import.
    pub created_by: Option<Uuid>,

    /// When processing began.
    pub started_at: Option<DateTime<Utc>>,

    /// When processing finished.
    pub completed_at: Option<DateTime<Utc>>,

    /// System-level error (for failed status).
    pub error_message: Option<String>,

    /// Record creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Data required to create a new import job.
#[derive(Debug)]
pub struct CreateImportJob {
    pub tenant_id: Uuid,
    pub file_name: String,
    pub file_hash: String,
    pub file_size_bytes: i64,
    pub total_rows: i32,
    pub send_invitations: bool,
    pub created_by: Option<Uuid>,
}

impl UserImportJob {
    /// Create a new import job record.
    pub async fn create(pool: &PgPool, data: CreateImportJob) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO user_import_jobs
                (tenant_id, file_name, file_hash, file_size_bytes, total_rows, send_invitations, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            ",
        )
        .bind(data.tenant_id)
        .bind(&data.file_name)
        .bind(&data.file_hash)
        .bind(data.file_size_bytes)
        .bind(data.total_rows)
        .bind(data.send_invitations)
        .bind(data.created_by)
        .fetch_one(pool)
        .await
    }

    /// Find a job by ID within a specific tenant.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM user_import_jobs
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List import jobs for a tenant with optional status filter and pagination.
    pub async fn list_by_tenant(
        pool: &PgPool,
        tenant_id: Uuid,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<Self>, i64), sqlx::Error> {
        let (jobs, total) = if let Some(s) = status {
            let jobs = sqlx::query_as(
                r"
                SELECT * FROM user_import_jobs
                WHERE tenant_id = $1 AND status = $2
                ORDER BY created_at DESC
                LIMIT $3 OFFSET $4
                ",
            )
            .bind(tenant_id)
            .bind(s)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await?;

            let total: i64 = sqlx::query_scalar(
                r"
                SELECT COUNT(*) FROM user_import_jobs
                WHERE tenant_id = $1 AND status = $2
                ",
            )
            .bind(tenant_id)
            .bind(s)
            .fetch_one(pool)
            .await?;

            (jobs, total)
        } else {
            let jobs = sqlx::query_as(
                r"
                SELECT * FROM user_import_jobs
                WHERE tenant_id = $1
                ORDER BY created_at DESC
                LIMIT $2 OFFSET $3
                ",
            )
            .bind(tenant_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await?;

            let total: i64 = sqlx::query_scalar(
                r"
                SELECT COUNT(*) FROM user_import_jobs
                WHERE tenant_id = $1
                ",
            )
            .bind(tenant_id)
            .fetch_one(pool)
            .await?;

            (jobs, total)
        };

        Ok((jobs, total))
    }

    /// Check if there is a concurrent import running for the tenant.
    /// Returns true if another import is pending or processing.
    pub async fn check_concurrent_import(
        pool: &PgPool,
        tenant_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM user_import_jobs
            WHERE tenant_id = $1 AND status IN ('pending', 'processing')
            ",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }

    /// Update job status.
    pub async fn update_status(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        status: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE user_import_jobs
            SET status = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(status)
        .fetch_optional(pool)
        .await
    }

    /// Update processing progress counters.
    pub async fn update_progress(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        processed_rows: i32,
        success_count: i32,
        error_count: i32,
        skip_count: i32,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r"
            UPDATE user_import_jobs
            SET processed_rows = $3, success_count = $4, error_count = $5, skip_count = $6, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(processed_rows)
        .bind(success_count)
        .bind(error_count)
        .bind(skip_count)
        .execute(pool)
        .await?;
        Ok(())
    }

    /// Mark a job as started (transition from pending to processing).
    pub async fn mark_started(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE user_import_jobs
            SET status = 'processing', started_at = NOW(), updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Mark a job as completed with final counts.
    pub async fn mark_completed(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        success_count: i32,
        error_count: i32,
        skip_count: i32,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE user_import_jobs
            SET status = 'completed',
                completed_at = NOW(),
                processed_rows = $3 + $4 + $5,
                success_count = $3,
                error_count = $4,
                skip_count = $5,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(success_count)
        .bind(error_count)
        .bind(skip_count)
        .fetch_optional(pool)
        .await
    }

    /// Mark a job as failed with an error message.
    pub async fn mark_failed(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        error_message: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE user_import_jobs
            SET status = 'failed', completed_at = NOW(), error_message = $3, updated_at = NOW()
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
}
