//! SCIM provisioning state model (F087).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Tracks the provisioning state of SCIM resources to external targets.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ScimProvisioningState {
    /// Unique identifier.
    pub id: Uuid,

    /// The tenant this state belongs to.
    pub tenant_id: Uuid,

    /// The SCIM target (endpoint) this resource is provisioned to.
    pub target_id: Uuid,

    /// The type of resource (e.g. "User", "Group").
    pub resource_type: String,

    /// The internal resource identifier in our system.
    pub internal_resource_id: Uuid,

    /// The resource identifier on the external system.
    pub external_resource_id: Option<String>,

    /// The externalId attribute sent to/from the SCIM target.
    pub external_id: Option<String>,

    /// Current provisioning status.
    pub status: String,

    /// When the resource was last successfully synced.
    pub last_synced_at: Option<DateTime<Utc>>,

    /// Last error message if provisioning failed.
    pub last_error: Option<String>,

    /// Number of consecutive retry attempts.
    pub retry_count: i32,

    /// When the next retry should be attempted.
    pub next_retry_at: Option<DateTime<Utc>>,

    /// When this record was created.
    pub created_at: DateTime<Utc>,

    /// When this record was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Data required to create a new SCIM provisioning state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateScimProvisioningState {
    pub tenant_id: Uuid,
    pub target_id: Uuid,
    pub resource_type: String,
    pub internal_resource_id: Uuid,
    pub external_id: Option<String>,
}

impl ScimProvisioningState {
    /// Insert a new provisioning state, or return the existing one on conflict.
    pub async fn get_or_create(
        pool: &PgPool,
        data: CreateScimProvisioningState,
    ) -> Result<Self, sqlx::Error> {
        // Try INSERT ... ON CONFLICT DO NOTHING RETURNING *
        let maybe = sqlx::query_as::<_, Self>(
            r#"
            INSERT INTO scim_provisioning_states
                (tenant_id, target_id, resource_type, internal_resource_id, external_id)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (target_id, resource_type, internal_resource_id) DO NOTHING
            RETURNING *
            "#,
        )
        .bind(data.tenant_id)
        .bind(data.target_id)
        .bind(&data.resource_type)
        .bind(data.internal_resource_id)
        .bind(&data.external_id)
        .fetch_optional(pool)
        .await?;

        if let Some(state) = maybe {
            return Ok(state);
        }

        // Conflict occurred — fetch the existing row
        let existing = sqlx::query_as::<_, Self>(
            r#"
            SELECT * FROM scim_provisioning_states
            WHERE tenant_id = $1
              AND target_id = $2
              AND resource_type = $3
              AND internal_resource_id = $4
            "#,
        )
        .bind(data.tenant_id)
        .bind(data.target_id)
        .bind(&data.resource_type)
        .bind(data.internal_resource_id)
        .fetch_one(pool)
        .await?;

        Ok(existing)
    }

    /// Find a provisioning state by target, resource type, and internal resource ID.
    pub async fn get_by_target_and_resource(
        pool: &PgPool,
        tenant_id: Uuid,
        target_id: Uuid,
        resource_type: &str,
        internal_resource_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM scim_provisioning_states
            WHERE tenant_id = $1
              AND target_id = $2
              AND resource_type = $3
              AND internal_resource_id = $4
            "#,
        )
        .bind(tenant_id)
        .bind(target_id)
        .bind(resource_type)
        .bind(internal_resource_id)
        .fetch_optional(pool)
        .await
    }

    /// List provisioning states for a target with optional filters and pagination.
    ///
    /// Returns a tuple of (items, total_count).
    pub async fn list_by_target(
        pool: &PgPool,
        tenant_id: Uuid,
        target_id: Uuid,
        resource_type: Option<&str>,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<Self>, i64), sqlx::Error> {
        let (items, count) = match (resource_type, status) {
            (None, None) => {
                let items = sqlx::query_as::<_, Self>(
                    r#"
                    SELECT * FROM scim_provisioning_states
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
                    SELECT COUNT(*) FROM scim_provisioning_states
                    WHERE tenant_id = $1 AND target_id = $2
                    "#,
                )
                .bind(tenant_id)
                .bind(target_id)
                .fetch_one(pool)
                .await?;

                (items, count.0)
            }
            (Some(rt), None) => {
                let items = sqlx::query_as::<_, Self>(
                    r#"
                    SELECT * FROM scim_provisioning_states
                    WHERE tenant_id = $1 AND target_id = $2 AND resource_type = $3
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
                    SELECT COUNT(*) FROM scim_provisioning_states
                    WHERE tenant_id = $1 AND target_id = $2 AND resource_type = $3
                    "#,
                )
                .bind(tenant_id)
                .bind(target_id)
                .bind(rt)
                .fetch_one(pool)
                .await?;

                (items, count.0)
            }
            (None, Some(st)) => {
                let items = sqlx::query_as::<_, Self>(
                    r#"
                    SELECT * FROM scim_provisioning_states
                    WHERE tenant_id = $1 AND target_id = $2 AND status = $3
                    ORDER BY created_at DESC
                    LIMIT $4 OFFSET $5
                    "#,
                )
                .bind(tenant_id)
                .bind(target_id)
                .bind(st)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await?;

                let count: (i64,) = sqlx::query_as(
                    r#"
                    SELECT COUNT(*) FROM scim_provisioning_states
                    WHERE tenant_id = $1 AND target_id = $2 AND status = $3
                    "#,
                )
                .bind(tenant_id)
                .bind(target_id)
                .bind(st)
                .fetch_one(pool)
                .await?;

                (items, count.0)
            }
            (Some(rt), Some(st)) => {
                let items = sqlx::query_as::<_, Self>(
                    r#"
                    SELECT * FROM scim_provisioning_states
                    WHERE tenant_id = $1 AND target_id = $2 AND resource_type = $3 AND status = $4
                    ORDER BY created_at DESC
                    LIMIT $5 OFFSET $6
                    "#,
                )
                .bind(tenant_id)
                .bind(target_id)
                .bind(rt)
                .bind(st)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await?;

                let count: (i64,) = sqlx::query_as(
                    r#"
                    SELECT COUNT(*) FROM scim_provisioning_states
                    WHERE tenant_id = $1 AND target_id = $2 AND resource_type = $3 AND status = $4
                    "#,
                )
                .bind(tenant_id)
                .bind(target_id)
                .bind(rt)
                .bind(st)
                .fetch_one(pool)
                .await?;

                (items, count.0)
            }
        };

        Ok((items, count))
    }

    /// Mark a provisioning state as successfully synced.
    pub async fn update_synced(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        external_resource_id: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE scim_provisioning_states
            SET status = 'synced',
                external_resource_id = $3,
                last_synced_at = NOW(),
                last_error = NULL,
                retry_count = 0,
                next_retry_at = NULL,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(external_resource_id)
        .fetch_optional(pool)
        .await
    }

    /// Mark a provisioning state as errored with retry information.
    pub async fn update_error(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        error: &str,
        retry_count: i32,
        next_retry_at: Option<DateTime<Utc>>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE scim_provisioning_states
            SET status = 'error',
                last_error = $3,
                retry_count = $4,
                next_retry_at = $5,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(error)
        .bind(retry_count)
        .bind(next_retry_at)
        .fetch_optional(pool)
        .await
    }

    /// Update the status of a provisioning state.
    pub async fn update_status(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        status: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE scim_provisioning_states
            SET status = $3,
                updated_at = NOW()
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

    /// Reset an errored provisioning state back to pending for retry.
    pub async fn mark_pending_retry(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE scim_provisioning_states
            SET status = 'pending',
                retry_count = 0,
                next_retry_at = NULL,
                last_error = NULL,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'error'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List all provisioning states that need processing for a given target.
    pub async fn list_pending_for_target(
        pool: &PgPool,
        tenant_id: Uuid,
        target_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM scim_provisioning_states
            WHERE tenant_id = $1
              AND target_id = $2
              AND status IN ('pending', 'pending_update', 'pending_deprovision', 'error')
            ORDER BY created_at
            "#,
        )
        .bind(tenant_id)
        .bind(target_id)
        .fetch_all(pool)
        .await
    }

    /// Find a provisioning state by ID within a tenant.
    pub async fn get_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM scim_provisioning_states
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find provisioning states by internal resource ID across all targets.
    ///
    /// Used by event handlers when the source record has been deleted and
    /// tenant_id is not available from the event payload.  Returns all
    /// provisioning states for the given resource, which implicitly carries
    /// the tenant_id on each row.
    pub async fn find_by_internal_resource_id(
        pool: &PgPool,
        resource_type: &str,
        internal_resource_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM scim_provisioning_states
            WHERE resource_type = $1 AND internal_resource_id = $2
            "#,
        )
        .bind(resource_type)
        .bind(internal_resource_id)
        .fetch_all(pool)
        .await
    }
}
