//! User import error model (F086).
//!
//! Records per-row errors from CSV import jobs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// A per-row error from a CSV import job.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UserImportError {
    /// Unique error identifier.
    pub id: Uuid,

    /// Tenant this error belongs to.
    pub tenant_id: Uuid,

    /// Parent import job.
    pub job_id: Uuid,

    /// CSV line number (1-based, header = line 1).
    pub line_number: i32,

    /// Email from the row (may be missing/invalid).
    pub email: Option<String>,

    /// Column that caused the error.
    pub column_name: Option<String>,

    /// Error category: validation, `duplicate_in_file`, `duplicate_in_tenant`, `role_not_found`, `group_error`, `attribute_error`, system.
    pub error_type: String,

    /// Human-readable error description.
    pub error_message: String,

    /// Record creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// Data required to create a single import error.
#[derive(Debug, Clone)]
pub struct CreateImportError {
    pub tenant_id: Uuid,
    pub job_id: Uuid,
    pub line_number: i32,
    pub email: Option<String>,
    pub column_name: Option<String>,
    pub error_type: String,
    pub error_message: String,
}

impl UserImportError {
    /// Create a single import error record.
    pub async fn create(pool: &PgPool, data: &CreateImportError) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO user_import_errors
                (tenant_id, job_id, line_number, email, column_name, error_type, error_message)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            ",
        )
        .bind(data.tenant_id)
        .bind(data.job_id)
        .bind(data.line_number)
        .bind(&data.email)
        .bind(&data.column_name)
        .bind(&data.error_type)
        .bind(&data.error_message)
        .fetch_one(pool)
        .await
    }

    /// Create multiple import errors in a batch.
    pub async fn create_batch(
        pool: &PgPool,
        errors: &[CreateImportError],
    ) -> Result<u64, sqlx::Error> {
        if errors.is_empty() {
            return Ok(0);
        }

        let mut count = 0u64;
        for error in errors {
            sqlx::query(
                r"
                INSERT INTO user_import_errors
                    (tenant_id, job_id, line_number, email, column_name, error_type, error_message)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ",
            )
            .bind(error.tenant_id)
            .bind(error.job_id)
            .bind(error.line_number)
            .bind(&error.email)
            .bind(&error.column_name)
            .bind(&error.error_type)
            .bind(&error.error_message)
            .execute(pool)
            .await?;
            count += 1;
        }

        Ok(count)
    }

    /// List errors for a job with pagination.
    pub async fn list_by_job(
        pool: &PgPool,
        tenant_id: Uuid,
        job_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<Self>, i64), sqlx::Error> {
        let items = sqlx::query_as(
            r"
            SELECT * FROM user_import_errors
            WHERE tenant_id = $1 AND job_id = $2
            ORDER BY line_number ASC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(job_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        let total: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM user_import_errors
            WHERE tenant_id = $1 AND job_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(job_id)
        .fetch_one(pool)
        .await?;

        Ok((items, total))
    }

    /// List all errors for a job (for CSV download).
    pub async fn list_all_by_job(
        pool: &PgPool,
        tenant_id: Uuid,
        job_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM user_import_errors
            WHERE tenant_id = $1 AND job_id = $2
            ORDER BY line_number ASC
            ",
        )
        .bind(tenant_id)
        .bind(job_id)
        .fetch_all(pool)
        .await
    }

    /// Count errors for a job.
    pub async fn count_by_job(
        pool: &PgPool,
        tenant_id: Uuid,
        job_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM user_import_errors
            WHERE tenant_id = $1 AND job_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(job_id)
        .fetch_one(pool)
        .await
    }
}
