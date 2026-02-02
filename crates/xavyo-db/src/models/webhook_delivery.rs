//! Webhook delivery database model.
//!
//! Records individual delivery attempts with status tracking, retry scheduling,
//! and response details.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Database entity for a webhook delivery attempt.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct WebhookDelivery {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub subscription_id: Uuid,
    pub event_id: Uuid,
    pub event_type: String,
    pub status: String,
    pub attempt_number: i32,
    pub max_attempts: i32,
    pub next_attempt_at: Option<DateTime<Utc>>,
    pub request_payload: serde_json::Value,
    pub request_headers: Option<serde_json::Value>,
    pub response_code: Option<i16>,
    pub response_body: Option<String>,
    pub error_message: Option<String>,
    pub latency_ms: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Input for creating a new webhook delivery record.
#[derive(Debug, Clone)]
pub struct CreateWebhookDelivery {
    pub tenant_id: Uuid,
    pub subscription_id: Uuid,
    pub event_id: Uuid,
    pub event_type: String,
    pub request_payload: serde_json::Value,
    pub max_attempts: i32,
    pub next_attempt_at: Option<DateTime<Utc>>,
}

impl WebhookDelivery {
    /// Create a new delivery record.
    pub async fn create(pool: &PgPool, input: CreateWebhookDelivery) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO webhook_deliveries (
                tenant_id, subscription_id, event_id, event_type,
                request_payload, max_attempts, next_attempt_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(input.tenant_id)
        .bind(input.subscription_id)
        .bind(input.event_id)
        .bind(&input.event_type)
        .bind(&input.request_payload)
        .bind(input.max_attempts)
        .bind(input.next_attempt_at)
        .fetch_one(pool)
        .await
    }

    /// Find a delivery by ID, tenant, and subscription.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        subscription_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM webhook_deliveries
            WHERE tenant_id = $1 AND subscription_id = $2 AND id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(subscription_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// List deliveries for a subscription with pagination and optional status filter.
    pub async fn list_by_subscription(
        pool: &PgPool,
        tenant_id: Uuid,
        subscription_id: Uuid,
        limit: i64,
        offset: i64,
        status: Option<&str>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        match status {
            Some(s) => {
                sqlx::query_as(
                    r#"
                    SELECT * FROM webhook_deliveries
                    WHERE tenant_id = $1 AND subscription_id = $2 AND status = $3
                    ORDER BY created_at DESC
                    LIMIT $4 OFFSET $5
                    "#,
                )
                .bind(tenant_id)
                .bind(subscription_id)
                .bind(s)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await
            }
            None => {
                sqlx::query_as(
                    r#"
                    SELECT * FROM webhook_deliveries
                    WHERE tenant_id = $1 AND subscription_id = $2
                    ORDER BY created_at DESC
                    LIMIT $3 OFFSET $4
                    "#,
                )
                .bind(tenant_id)
                .bind(subscription_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await
            }
        }
    }

    /// Count total deliveries for a subscription with optional status filter.
    pub async fn count_by_subscription(
        pool: &PgPool,
        tenant_id: Uuid,
        subscription_id: Uuid,
        status: Option<&str>,
    ) -> Result<i64, sqlx::Error> {
        let row: (i64,) = match status {
            Some(s) => {
                sqlx::query_as(
                    r#"
                    SELECT COUNT(*) FROM webhook_deliveries
                    WHERE tenant_id = $1 AND subscription_id = $2 AND status = $3
                    "#,
                )
                .bind(tenant_id)
                .bind(subscription_id)
                .bind(s)
                .fetch_one(pool)
                .await?
            }
            None => {
                sqlx::query_as(
                    r#"
                    SELECT COUNT(*) FROM webhook_deliveries
                    WHERE tenant_id = $1 AND subscription_id = $2
                    "#,
                )
                .bind(tenant_id)
                .bind(subscription_id)
                .fetch_one(pool)
                .await?
            }
        };
        Ok(row.0)
    }

    /// Find pending deliveries ready for retry (status = 'pending' AND next_attempt_at <= now()).
    pub async fn find_pending_for_retry(
        pool: &PgPool,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM webhook_deliveries
            WHERE status = 'pending'
              AND next_attempt_at IS NOT NULL
              AND next_attempt_at <= NOW()
            ORDER BY next_attempt_at ASC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Update delivery status and related fields after an attempt.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_status(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        status: &str,
        attempt_number: i32,
        next_attempt_at: Option<DateTime<Utc>>,
        response_code: Option<i16>,
        response_body: Option<&str>,
        error_message: Option<&str>,
        latency_ms: Option<i32>,
        request_headers: Option<&serde_json::Value>,
        completed_at: Option<DateTime<Utc>>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE webhook_deliveries
            SET
                status = $3,
                attempt_number = $4,
                next_attempt_at = $5,
                response_code = $6,
                response_body = $7,
                error_message = $8,
                latency_ms = $9,
                request_headers = COALESCE($10, request_headers),
                completed_at = $11
            WHERE tenant_id = $1 AND id = $2
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(status)
        .bind(attempt_number)
        .bind(next_attempt_at)
        .bind(response_code)
        .bind(response_body)
        .bind(error_message)
        .bind(latency_ms)
        .bind(request_headers)
        .bind(completed_at)
        .fetch_optional(pool)
        .await
    }

    /// Mark a delivery as successful.
    pub async fn mark_success(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        response_code: i16,
        response_body: Option<&str>,
        latency_ms: i32,
        request_headers: Option<&serde_json::Value>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE webhook_deliveries
            SET
                status = 'success',
                next_attempt_at = NULL,
                response_code = $3,
                response_body = $4,
                latency_ms = $5,
                request_headers = COALESCE($6, request_headers),
                completed_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(response_code)
        .bind(response_body)
        .bind(latency_ms)
        .bind(request_headers)
        .fetch_optional(pool)
        .await
    }

    /// Mark a delivery as failed with error and schedule next attempt.
    #[allow(clippy::too_many_arguments)]
    pub async fn mark_failed(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        attempt_number: i32,
        error_message: &str,
        response_code: Option<i16>,
        response_body: Option<&str>,
        latency_ms: Option<i32>,
        next_attempt_at: Option<DateTime<Utc>>,
        request_headers: Option<&serde_json::Value>,
    ) -> Result<Option<Self>, sqlx::Error> {
        // If next_attempt_at is None, all retries are exhausted — keep as pending
        // until explicitly abandoned, or mark as failed if no more retries.
        let final_status = if next_attempt_at.is_some() {
            "pending"
        } else {
            "failed"
        };

        sqlx::query_as(
            r#"
            UPDATE webhook_deliveries
            SET
                status = $3,
                attempt_number = $4,
                error_message = $5,
                response_code = $6,
                response_body = $7,
                latency_ms = $8,
                next_attempt_at = $9,
                request_headers = COALESCE($10, request_headers),
                completed_at = CASE WHEN $3 = 'failed' THEN NOW() ELSE completed_at END
            WHERE tenant_id = $1 AND id = $2
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .bind(final_status)
        .bind(attempt_number)
        .bind(error_message)
        .bind(response_code)
        .bind(response_body)
        .bind(latency_ms)
        .bind(next_attempt_at)
        .bind(request_headers)
        .fetch_optional(pool)
        .await
    }

    /// Mark all pending deliveries for a subscription as abandoned (e.g., when subscription is disabled).
    pub async fn mark_abandoned_for_subscription(
        pool: &PgPool,
        tenant_id: Uuid,
        subscription_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE webhook_deliveries
            SET
                status = 'abandoned',
                next_attempt_at = NULL,
                completed_at = NOW()
            WHERE tenant_id = $1
              AND subscription_id = $2
              AND status = 'pending'
            "#,
        )
        .bind(tenant_id)
        .bind(subscription_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}
