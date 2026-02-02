//! SCIM target model (F087).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Executor, FromRow, PgPool, Postgres};
use uuid::Uuid;

/// A SCIM target configuration record.
///
/// Represents a downstream SCIM service provider that can be provisioned to.
/// Stores connection details, authentication credentials, and health status.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ScimTarget {
    /// Unique target identifier.
    pub id: Uuid,

    /// Tenant this target belongs to.
    pub tenant_id: Uuid,

    /// Human-readable target name.
    pub name: String,

    /// Base URL of the SCIM service provider.
    pub base_url: String,

    /// Authentication method (e.g. "bearer", "basic", "oauth2").
    pub auth_method: String,

    /// Encrypted authentication credentials. Never exposed in API responses.
    #[serde(skip_serializing)]
    pub credentials_encrypted: Vec<u8>,

    /// Key version used to encrypt credentials.
    pub credentials_key_version: i32,

    /// Strategy for deprovisioning (e.g. "deactivate", "delete").
    pub deprovisioning_strategy: String,

    /// Whether to verify TLS certificates.
    pub tls_verify: bool,

    /// Maximum requests per minute to the target.
    pub rate_limit_per_minute: i32,

    /// Request timeout in seconds.
    pub request_timeout_secs: i32,

    /// Maximum number of retry attempts for failed requests.
    pub max_retries: i32,

    /// Target status (e.g. "active", "inactive", "error").
    pub status: String,

    /// Timestamp of the last health check.
    pub last_health_check_at: Option<DateTime<Utc>>,

    /// Error message from the last health check, if any.
    pub last_health_check_error: Option<String>,

    /// Cached service provider configuration from SCIM discovery.
    pub service_provider_config: Option<serde_json::Value>,

    /// Record creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Data required to create a new SCIM target.
#[derive(Debug)]
pub struct CreateScimTarget {
    pub tenant_id: Uuid,
    pub name: String,
    pub base_url: String,
    pub auth_method: String,
    pub credentials_encrypted: Vec<u8>,
    pub credentials_key_version: i32,
    pub deprovisioning_strategy: String,
    pub tls_verify: bool,
    pub rate_limit_per_minute: i32,
    pub request_timeout_secs: i32,
    pub max_retries: i32,
    pub status: String,
    pub service_provider_config: Option<serde_json::Value>,
}

/// Data for updating an existing SCIM target (partial update).
#[derive(Debug)]
pub struct UpdateScimTarget {
    pub name: Option<String>,
    pub base_url: Option<String>,
    pub auth_method: Option<String>,
    pub credentials_encrypted: Option<Vec<u8>>,
    pub deprovisioning_strategy: Option<String>,
    pub tls_verify: Option<bool>,
    pub rate_limit_per_minute: Option<i32>,
    pub request_timeout_secs: Option<i32>,
    pub max_retries: Option<i32>,
    pub status: Option<String>,
    pub service_provider_config: Option<serde_json::Value>,
}

impl ScimTarget {
    /// Create a new SCIM target record.
    ///
    /// Accepts any executor (PgPool, Transaction, etc.) to support RLS with tenant context.
    pub async fn create<'e, E>(executor: E, data: &CreateScimTarget) -> Result<Self, sqlx::Error>
    where
        E: Executor<'e, Database = Postgres>,
    {
        sqlx::query_as(
            r#"
            INSERT INTO scim_targets
                (tenant_id, name, base_url, auth_method, credentials_encrypted,
                 credentials_key_version, deprovisioning_strategy, tls_verify,
                 rate_limit_per_minute, request_timeout_secs, max_retries,
                 status, service_provider_config)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING *
            "#,
        )
        .bind(data.tenant_id)
        .bind(&data.name)
        .bind(&data.base_url)
        .bind(&data.auth_method)
        .bind(&data.credentials_encrypted)
        .bind(data.credentials_key_version)
        .bind(&data.deprovisioning_strategy)
        .bind(data.tls_verify)
        .bind(data.rate_limit_per_minute)
        .bind(data.request_timeout_secs)
        .bind(data.max_retries)
        .bind(&data.status)
        .bind(&data.service_provider_config)
        .fetch_one(executor)
        .await
    }

    /// Find a SCIM target by ID within a specific tenant.
    pub async fn get_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM scim_targets
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List SCIM targets for a tenant with optional status filter and pagination.
    pub async fn list_by_tenant(
        pool: &PgPool,
        tenant_id: Uuid,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<Self>, i64), sqlx::Error> {
        let (targets, total) = match status {
            Some(s) => {
                let targets = sqlx::query_as(
                    r#"
                    SELECT * FROM scim_targets
                    WHERE tenant_id = $1 AND status = $2
                    ORDER BY created_at DESC
                    LIMIT $3 OFFSET $4
                    "#,
                )
                .bind(tenant_id)
                .bind(s)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await?;

                let total: i64 = sqlx::query_scalar(
                    r#"
                    SELECT COUNT(*) FROM scim_targets
                    WHERE tenant_id = $1 AND status = $2
                    "#,
                )
                .bind(tenant_id)
                .bind(s)
                .fetch_one(pool)
                .await?;

                (targets, total)
            }
            None => {
                let targets = sqlx::query_as(
                    r#"
                    SELECT * FROM scim_targets
                    WHERE tenant_id = $1
                    ORDER BY created_at DESC
                    LIMIT $2 OFFSET $3
                    "#,
                )
                .bind(tenant_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await?;

                let total: i64 = sqlx::query_scalar(
                    r#"
                    SELECT COUNT(*) FROM scim_targets
                    WHERE tenant_id = $1
                    "#,
                )
                .bind(tenant_id)
                .fetch_one(pool)
                .await?;

                (targets, total)
            }
        };

        Ok((targets, total))
    }

    /// Update a SCIM target with partial update semantics.
    ///
    /// Only non-None fields are updated; other fields retain their current values.
    pub async fn update(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        data: &UpdateScimTarget,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE scim_targets
            SET name = COALESCE($3, name),
                base_url = COALESCE($4, base_url),
                auth_method = COALESCE($5, auth_method),
                credentials_encrypted = COALESCE($6, credentials_encrypted),
                deprovisioning_strategy = COALESCE($7, deprovisioning_strategy),
                tls_verify = COALESCE($8, tls_verify),
                rate_limit_per_minute = COALESCE($9, rate_limit_per_minute),
                request_timeout_secs = COALESCE($10, request_timeout_secs),
                max_retries = COALESCE($11, max_retries),
                status = COALESCE($12, status),
                service_provider_config = COALESCE($13, service_provider_config),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&data.name)
        .bind(&data.base_url)
        .bind(&data.auth_method)
        .bind(&data.credentials_encrypted)
        .bind(&data.deprovisioning_strategy)
        .bind(data.tls_verify)
        .bind(data.rate_limit_per_minute)
        .bind(data.request_timeout_secs)
        .bind(data.max_retries)
        .bind(&data.status)
        .bind(&data.service_provider_config)
        .fetch_optional(pool)
        .await
    }

    /// Delete a SCIM target by ID within a specific tenant.
    /// Returns true if a row was deleted.
    pub async fn delete(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM scim_targets
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Find all active SCIM targets for a tenant.
    pub async fn find_active_by_tenant(
        pool: &PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM scim_targets
            WHERE tenant_id = $1 AND status = 'active'
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Update the status of a SCIM target.
    pub async fn update_status(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        status: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE scim_targets
            SET status = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(status)
        .fetch_optional(pool)
        .await
    }

    /// Update health check information for a SCIM target.
    pub async fn update_health_check(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        status: &str,
        error: Option<&str>,
        config: Option<&serde_json::Value>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE scim_targets
            SET status = $3,
                last_health_check_at = NOW(),
                last_health_check_error = $4,
                service_provider_config = COALESCE($5, service_provider_config),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(status)
        .bind(error)
        .bind(config)
        .fetch_optional(pool)
        .await
    }
}
