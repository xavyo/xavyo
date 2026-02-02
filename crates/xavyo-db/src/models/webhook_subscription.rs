//! Webhook subscription database model.
//!
//! Tenant-scoped webhook subscription configuration with CRUD operations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Database entity for a webhook subscription.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct WebhookSubscription {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub url: String,
    pub secret_encrypted: Option<String>,
    pub event_types: Vec<String>,
    pub enabled: bool,
    pub consecutive_failures: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
}

/// Input for creating a new webhook subscription.
#[derive(Debug, Clone)]
pub struct CreateWebhookSubscription {
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub url: String,
    pub secret_encrypted: Option<String>,
    pub event_types: Vec<String>,
    pub created_by: Option<Uuid>,
}

/// Input for updating a webhook subscription.
#[derive(Debug, Clone, Default)]
pub struct UpdateWebhookSubscription {
    pub name: Option<String>,
    pub description: Option<String>,
    pub url: Option<String>,
    pub secret_encrypted: Option<String>,
    pub event_types: Option<Vec<String>>,
    pub enabled: Option<bool>,
}

impl WebhookSubscription {
    /// Create a new webhook subscription.
    pub async fn create(
        pool: &PgPool,
        input: CreateWebhookSubscription,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO webhook_subscriptions (
                tenant_id, name, description, url, secret_encrypted,
                event_types, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(input.tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(&input.url)
        .bind(&input.secret_encrypted)
        .bind(&input.event_types)
        .bind(input.created_by)
        .fetch_one(pool)
        .await
    }

    /// Find a webhook subscription by ID and tenant.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM webhook_subscriptions
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// List webhook subscriptions for a tenant with pagination and optional enabled filter.
    pub async fn list_by_tenant(
        pool: &PgPool,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
        enabled: Option<bool>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        match enabled {
            Some(e) => {
                sqlx::query_as(
                    r#"
                    SELECT * FROM webhook_subscriptions
                    WHERE tenant_id = $1 AND enabled = $2
                    ORDER BY created_at DESC
                    LIMIT $3 OFFSET $4
                    "#,
                )
                .bind(tenant_id)
                .bind(e)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await
            }
            None => {
                sqlx::query_as(
                    r#"
                    SELECT * FROM webhook_subscriptions
                    WHERE tenant_id = $1
                    ORDER BY created_at DESC
                    LIMIT $2 OFFSET $3
                    "#,
                )
                .bind(tenant_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await
            }
        }
    }

    /// Count total webhook subscriptions for a tenant with optional enabled filter.
    pub async fn count_by_tenant(
        pool: &PgPool,
        tenant_id: Uuid,
        enabled: Option<bool>,
    ) -> Result<i64, sqlx::Error> {
        let row: (i64,) = match enabled {
            Some(e) => {
                sqlx::query_as(
                    r#"
                    SELECT COUNT(*) FROM webhook_subscriptions
                    WHERE tenant_id = $1 AND enabled = $2
                    "#,
                )
                .bind(tenant_id)
                .bind(e)
                .fetch_one(pool)
                .await?
            }
            None => {
                sqlx::query_as(
                    r#"
                    SELECT COUNT(*) FROM webhook_subscriptions
                    WHERE tenant_id = $1
                    "#,
                )
                .bind(tenant_id)
                .fetch_one(pool)
                .await?
            }
        };
        Ok(row.0)
    }

    /// Update a webhook subscription. Only non-None fields are updated.
    pub async fn update(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateWebhookSubscription,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE webhook_subscriptions
            SET
                name = COALESCE($3, name),
                description = COALESCE($4, description),
                url = COALESCE($5, url),
                secret_encrypted = COALESCE($6, secret_encrypted),
                event_types = COALESCE($7, event_types),
                enabled = COALESCE($8, enabled)
            WHERE tenant_id = $1 AND id = $2
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(&input.url)
        .bind(&input.secret_encrypted)
        .bind(&input.event_types)
        .bind(input.enabled)
        .fetch_optional(pool)
        .await
    }

    /// Delete a webhook subscription.
    pub async fn delete(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM webhook_subscriptions
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Find all active (enabled) subscriptions for a tenant that subscribe to a given event type.
    /// Uses the GIN index on event_types for efficient array containment check.
    pub async fn find_active_by_event_type(
        pool: &PgPool,
        tenant_id: Uuid,
        event_type: &str,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM webhook_subscriptions
            WHERE tenant_id = $1
              AND enabled = true
              AND event_types @> ARRAY[$2]::text[]
            "#,
        )
        .bind(tenant_id)
        .bind(event_type)
        .fetch_all(pool)
        .await
    }

    /// Increment consecutive failure count for a subscription.
    pub async fn increment_consecutive_failures(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<i32, sqlx::Error> {
        let row: (i32,) = sqlx::query_as(
            r#"
            UPDATE webhook_subscriptions
            SET consecutive_failures = consecutive_failures + 1
            WHERE tenant_id = $1 AND id = $2
            RETURNING consecutive_failures
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }

    /// Reset consecutive failure count to zero (after a successful delivery).
    pub async fn reset_consecutive_failures(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE webhook_subscriptions
            SET consecutive_failures = 0
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(())
    }

    /// Disable a subscription (e.g., after exceeding consecutive failure threshold).
    pub async fn disable(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE webhook_subscriptions
            SET enabled = false
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(())
    }
}
