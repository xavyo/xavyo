//! SCIM provisioning log model (F087).
//!
//! Immutable audit log for SCIM provisioning operations against target systems.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// A SCIM provisioning log entry.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ScimProvisioningLog {
    /// Unique identifier for this log entry.
    pub id: Uuid,

    /// The tenant this log belongs to.
    pub tenant_id: Uuid,

    /// The SCIM target (application) this operation was directed at.
    pub target_id: Uuid,

    /// Optional sync run that triggered this operation.
    pub sync_run_id: Option<Uuid>,

    /// The type of provisioning operation (e.g. "create", "update", "delete").
    pub operation_type: String,

    /// The SCIM resource type (e.g. "User", "Group").
    pub resource_type: String,

    /// Internal resource identifier in the IDP.
    pub internal_resource_id: Uuid,

    /// External resource identifier in the target system.
    pub external_resource_id: Option<String>,

    /// HTTP method used (e.g. "POST", "PUT", "PATCH", "DELETE").
    pub http_method: String,

    /// HTTP status code returned by the target.
    pub http_status: Option<i32>,

    /// Summary of the request payload (truncated).
    pub request_summary: Option<String>,

    /// Summary of the response payload (truncated).
    pub response_summary: Option<String>,

    /// Number of retry attempts for this operation.
    pub retry_count: i32,

    /// Duration of the operation in milliseconds.
    pub duration_ms: Option<i32>,

    /// Error message if the operation failed.
    pub error_message: Option<String>,

    /// When the log entry was created.
    pub created_at: DateTime<Utc>,
}

/// Input for creating a SCIM provisioning log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateScimProvisioningLog {
    pub tenant_id: Uuid,
    pub target_id: Uuid,
    pub sync_run_id: Option<Uuid>,
    pub operation_type: String,
    pub resource_type: String,
    pub internal_resource_id: Uuid,
    pub external_resource_id: Option<String>,
    pub http_method: String,
    pub http_status: Option<i32>,
    pub request_summary: Option<String>,
    pub response_summary: Option<String>,
    pub retry_count: i32,
    pub duration_ms: Option<i32>,
    pub error_message: Option<String>,
}

impl ScimProvisioningLog {
    /// Insert a new SCIM provisioning log entry.
    pub async fn insert(
        pool: &PgPool,
        data: CreateScimProvisioningLog,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO scim_provisioning_log (
                tenant_id, target_id, sync_run_id, operation_type, resource_type,
                internal_resource_id, external_resource_id, http_method, http_status,
                request_summary, response_summary, retry_count, duration_ms, error_message
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            RETURNING *
            "#,
        )
        .bind(data.tenant_id)
        .bind(data.target_id)
        .bind(data.sync_run_id)
        .bind(&data.operation_type)
        .bind(&data.resource_type)
        .bind(data.internal_resource_id)
        .bind(&data.external_resource_id)
        .bind(&data.http_method)
        .bind(data.http_status)
        .bind(&data.request_summary)
        .bind(&data.response_summary)
        .bind(data.retry_count)
        .bind(data.duration_ms)
        .bind(&data.error_message)
        .fetch_one(pool)
        .await
    }

    /// Get a single log entry by ID, scoped to tenant.
    pub async fn get_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM scim_provisioning_log
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// List log entries for a target with optional resource_type and operation_type filters.
    ///
    /// Returns `(items, total_count)` for pagination support.
    pub async fn list_by_target(
        pool: &PgPool,
        tenant_id: Uuid,
        target_id: Uuid,
        resource_type: Option<&str>,
        operation_type: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<Self>, i64), sqlx::Error> {
        let (items, count) = match (resource_type, operation_type) {
            // Both filters provided
            (Some(rt), Some(ot)) => {
                let items: Vec<Self> = sqlx::query_as(
                    r#"
                    SELECT * FROM scim_provisioning_log
                    WHERE tenant_id = $1 AND target_id = $2
                      AND resource_type = $3 AND operation_type = $4
                    ORDER BY created_at DESC
                    LIMIT $5 OFFSET $6
                    "#,
                )
                .bind(tenant_id)
                .bind(target_id)
                .bind(rt)
                .bind(ot)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await?;

                let count: (i64,) = sqlx::query_as(
                    r#"
                    SELECT COUNT(*) FROM scim_provisioning_log
                    WHERE tenant_id = $1 AND target_id = $2
                      AND resource_type = $3 AND operation_type = $4
                    "#,
                )
                .bind(tenant_id)
                .bind(target_id)
                .bind(rt)
                .bind(ot)
                .fetch_one(pool)
                .await?;

                (items, count.0)
            }

            // Only resource_type filter
            (Some(rt), None) => {
                let items: Vec<Self> = sqlx::query_as(
                    r#"
                    SELECT * FROM scim_provisioning_log
                    WHERE tenant_id = $1 AND target_id = $2
                      AND resource_type = $3
                    ORDER BY created_at DESC
                    LIMIT $4 OFFSET $5
                    "#,
                )
                .bind(tenant_id)
                .bind(target_id)
                .bind(rt)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await?;

                let count: (i64,) = sqlx::query_as(
                    r#"
                    SELECT COUNT(*) FROM scim_provisioning_log
                    WHERE tenant_id = $1 AND target_id = $2
                      AND resource_type = $3
                    "#,
                )
                .bind(tenant_id)
                .bind(target_id)
                .bind(rt)
                .fetch_one(pool)
                .await?;

                (items, count.0)
            }

            // Only operation_type filter
            (None, Some(ot)) => {
                let items: Vec<Self> = sqlx::query_as(
                    r#"
                    SELECT * FROM scim_provisioning_log
                    WHERE tenant_id = $1 AND target_id = $2
                      AND operation_type = $3
                    ORDER BY created_at DESC
                    LIMIT $4 OFFSET $5
                    "#,
                )
                .bind(tenant_id)
                .bind(target_id)
                .bind(ot)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await?;

                let count: (i64,) = sqlx::query_as(
                    r#"
                    SELECT COUNT(*) FROM scim_provisioning_log
                    WHERE tenant_id = $1 AND target_id = $2
                      AND operation_type = $3
                    "#,
                )
                .bind(tenant_id)
                .bind(target_id)
                .bind(ot)
                .fetch_one(pool)
                .await?;

                (items, count.0)
            }

            // No optional filters
            (None, None) => {
                let items: Vec<Self> = sqlx::query_as(
                    r#"
                    SELECT * FROM scim_provisioning_log
                    WHERE tenant_id = $1 AND target_id = $2
                    ORDER BY created_at DESC
                    LIMIT $3 OFFSET $4
                    "#,
                )
                .bind(tenant_id)
                .bind(target_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await?;

                let count: (i64,) = sqlx::query_as(
                    r#"
                    SELECT COUNT(*) FROM scim_provisioning_log
                    WHERE tenant_id = $1 AND target_id = $2
                    "#,
                )
                .bind(tenant_id)
                .bind(target_id)
                .fetch_one(pool)
                .await?;

                (items, count.0)
            }
        };

        Ok((items, count))
    }

    /// List log entries for a specific sync run.
    pub async fn list_by_sync_run(
        pool: &PgPool,
        tenant_id: Uuid,
        sync_run_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM scim_provisioning_log
            WHERE tenant_id = $1 AND sync_run_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(tenant_id)
        .bind(sync_run_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Delete log entries older than the specified timestamp for a tenant.
    ///
    /// Returns the number of rows deleted.
    pub async fn delete_older_than(
        pool: &PgPool,
        tenant_id: Uuid,
        before: DateTime<Utc>,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM scim_provisioning_log
            WHERE tenant_id = $1 AND created_at < $2
            "#,
        )
        .bind(tenant_id)
        .bind(before)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}
