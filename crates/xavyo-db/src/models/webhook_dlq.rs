//! Dead letter queue model for failed webhooks.
//!
//! Stores webhooks that exhausted all retry attempts for manual
//! investigation and replay.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Dead letter queue entry for a failed webhook.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct WebhookDlqEntry {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub subscription_id: Uuid,
    pub subscription_url: String,
    pub event_id: Uuid,
    pub event_type: String,
    pub request_payload: serde_json::Value,
    pub failure_reason: String,
    pub last_response_code: Option<i16>,
    pub last_response_body: Option<String>,
    pub attempt_history: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub replayed_at: Option<DateTime<Utc>>,
}

/// Input for creating a DLQ entry.
#[derive(Debug, Clone)]
pub struct CreateWebhookDlqEntry {
    pub tenant_id: Uuid,
    pub subscription_id: Uuid,
    pub subscription_url: String,
    pub event_id: Uuid,
    pub event_type: String,
    pub request_payload: serde_json::Value,
    pub failure_reason: String,
    pub last_response_code: Option<i16>,
    pub last_response_body: Option<String>,
    pub attempt_history: serde_json::Value,
}

/// Filter options for querying DLQ entries.
#[derive(Debug, Clone, Default)]
pub struct DlqFilter {
    pub subscription_id: Option<Uuid>,
    pub event_type: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub include_replayed: bool,
}

impl WebhookDlqEntry {
    /// Create a new DLQ entry.
    pub async fn create(pool: &PgPool, input: CreateWebhookDlqEntry) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO webhook_dlq (
                tenant_id, subscription_id, subscription_url, event_id,
                event_type, request_payload, failure_reason,
                last_response_code, last_response_body, attempt_history
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            "#,
        )
        .bind(input.tenant_id)
        .bind(input.subscription_id)
        .bind(&input.subscription_url)
        .bind(input.event_id)
        .bind(&input.event_type)
        .bind(&input.request_payload)
        .bind(&input.failure_reason)
        .bind(input.last_response_code)
        .bind(&input.last_response_body)
        .bind(&input.attempt_history)
        .fetch_one(pool)
        .await
    }

    /// Find a DLQ entry by ID.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM webhook_dlq
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// List DLQ entries with filtering and pagination.
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &DlqFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        // Build dynamic query based on filters
        let mut query = String::from(
            r#"
            SELECT * FROM webhook_dlq
            WHERE tenant_id = $1
            "#,
        );

        let mut param_count = 1;

        if filter.subscription_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND subscription_id = ${param_count}"));
        }

        if filter.event_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND event_type = ${param_count}"));
        }

        if filter.from.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at >= ${param_count}"));
        }

        if filter.to.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND created_at <= ${param_count}"));
        }

        if !filter.include_replayed {
            query.push_str(" AND replayed_at IS NULL");
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        // Build and execute query with dynamic bindings
        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(sub_id) = filter.subscription_id {
            q = q.bind(sub_id);
        }
        if let Some(ref event_type) = filter.event_type {
            q = q.bind(event_type);
        }
        if let Some(from) = filter.from {
            q = q.bind(from);
        }
        if let Some(to) = filter.to {
            q = q.bind(to);
        }

        q = q.bind(limit).bind(offset);
        q.fetch_all(pool).await
    }

    /// Count DLQ entries matching filter.
    pub async fn count(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &DlqFilter,
    ) -> Result<i64, sqlx::Error> {
        // Simplified count query
        let include_replayed = filter.include_replayed;

        let row: (i64,) = if !include_replayed {
            sqlx::query_as(
                r#"
                SELECT COUNT(*) FROM webhook_dlq
                WHERE tenant_id = $1 AND replayed_at IS NULL
                "#,
            )
            .bind(tenant_id)
            .fetch_one(pool)
            .await?
        } else {
            sqlx::query_as(
                r#"
                SELECT COUNT(*) FROM webhook_dlq
                WHERE tenant_id = $1
                "#,
            )
            .bind(tenant_id)
            .fetch_one(pool)
            .await?
        };

        Ok(row.0)
    }

    /// Mark a DLQ entry as replayed.
    pub async fn mark_replayed(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE webhook_dlq
            SET replayed_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// Mark multiple DLQ entries as replayed.
    pub async fn mark_replayed_bulk(
        pool: &PgPool,
        tenant_id: Uuid,
        ids: &[Uuid],
    ) -> Result<i64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE webhook_dlq
            SET replayed_at = NOW()
            WHERE tenant_id = $1 AND id = ANY($2) AND replayed_at IS NULL
            "#,
        )
        .bind(tenant_id)
        .bind(ids)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() as i64)
    }

    /// Delete a DLQ entry.
    pub async fn delete(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM webhook_dlq
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Get unreplayed entries for a subscription (for bulk replay).
    pub async fn find_unreplayed_by_subscription(
        pool: &PgPool,
        tenant_id: Uuid,
        subscription_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM webhook_dlq
            WHERE tenant_id = $1
              AND subscription_id = $2
              AND replayed_at IS NULL
            ORDER BY created_at ASC
            LIMIT $3
            "#,
        )
        .bind(tenant_id)
        .bind(subscription_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dlq_filter_default() {
        let filter = DlqFilter::default();
        assert!(filter.subscription_id.is_none());
        assert!(filter.event_type.is_none());
        assert!(filter.from.is_none());
        assert!(filter.to.is_none());
        assert!(!filter.include_replayed);
    }
}
