//! SIEM Batch Export model (F078).
//!
//! Tracks batch export jobs for compliance reporting.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A batch export job.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct SiemBatchExport {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub requested_by: Uuid,
    pub date_range_start: DateTime<Utc>,
    pub date_range_end: DateTime<Utc>,
    /// Event types to include (JSON array of category strings, empty = all).
    pub event_type_filter: serde_json::Value,
    pub output_format: String,
    pub status: String,
    pub total_events: Option<i64>,
    pub file_path: Option<String>,
    pub file_size_bytes: Option<i64>,
    pub error_detail: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Request to create a new batch export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSiemBatchExport {
    pub date_range_start: DateTime<Utc>,
    pub date_range_end: DateTime<Utc>,
    #[serde(default = "default_event_filter")]
    pub event_type_filter: serde_json::Value,
    pub output_format: String,
}

fn default_event_filter() -> serde_json::Value {
    serde_json::json!([])
}

impl SiemBatchExport {
    /// Create a new batch export.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        requested_by: Uuid,
        input: CreateSiemBatchExport,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO siem_batch_exports (
                tenant_id, requested_by, date_range_start, date_range_end,
                event_type_filter, output_format
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(requested_by)
        .bind(input.date_range_start)
        .bind(input.date_range_end)
        .bind(&input.event_type_filter)
        .bind(&input.output_format)
        .fetch_one(pool)
        .await
    }

    /// Find a batch export by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM siem_batch_exports
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List batch exports for a tenant with pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        status_filter: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM siem_batch_exports
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if status_filter.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, SiemBatchExport>(&query).bind(tenant_id);

        if let Some(status) = status_filter {
            q = q.bind(status);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count batch exports for a tenant.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        status_filter: Option<&str>,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM siem_batch_exports
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if status_filter.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(status) = status_filter {
            q = q.bind(status);
        }

        q.fetch_one(pool).await
    }

    /// Claim a pending export for processing (atomically).
    pub async fn claim_pending(pool: &sqlx::PgPool) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE siem_batch_exports
            SET status = 'processing', started_at = NOW()
            WHERE id = (
                SELECT id FROM siem_batch_exports
                WHERE status = 'pending'
                ORDER BY created_at
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING *
            "#,
        )
        .fetch_optional(pool)
        .await
    }

    /// Mark a batch export as completed.
    pub async fn mark_completed(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        total_events: i64,
        file_path: &str,
        file_size_bytes: i64,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE siem_batch_exports
            SET status = 'completed',
                completed_at = NOW(),
                total_events = $3,
                file_path = $4,
                file_size_bytes = $5,
                expires_at = $6
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(total_events)
        .bind(file_path)
        .bind(file_size_bytes)
        .bind(expires_at)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Mark a batch export as failed.
    pub async fn mark_failed(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        error: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE siem_batch_exports
            SET status = 'failed',
                completed_at = NOW(),
                error_detail = $3
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(error)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete expired batch exports.
    pub async fn delete_expired(pool: &sqlx::PgPool) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM siem_batch_exports
            WHERE status = 'completed' AND expires_at < NOW()
            "#,
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_batch_export_request() {
        let request = CreateSiemBatchExport {
            date_range_start: Utc::now() - chrono::Duration::days(7),
            date_range_end: Utc::now(),
            event_type_filter: serde_json::json!(["authentication", "security"]),
            output_format: "json".to_string(),
        };

        assert_eq!(request.output_format, "json");
        assert!(request.date_range_end > request.date_range_start);
    }

    #[test]
    fn test_create_csv_export_request() {
        let request = CreateSiemBatchExport {
            date_range_start: Utc::now() - chrono::Duration::days(30),
            date_range_end: Utc::now(),
            event_type_filter: serde_json::json!([]),
            output_format: "csv".to_string(),
        };

        assert_eq!(request.output_format, "csv");
        assert_eq!(request.event_type_filter, serde_json::json!([]));
    }

    #[test]
    fn test_default_event_filter_via_serde() {
        let json = r#"{"date_range_start":"2024-01-01T00:00:00Z","date_range_end":"2024-01-31T23:59:59Z","output_format":"json"}"#;
        let export: CreateSiemBatchExport = serde_json::from_str(json).unwrap();
        assert_eq!(export.event_type_filter, serde_json::json!([]));
    }
}
