//! SIEM Export Event model (F078).
//!
//! Tracks individual event delivery attempts to SIEM destinations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A SIEM export event tracking delivery to a destination.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct SiemExportEvent {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub destination_id: Uuid,
    pub source_event_id: Uuid,
    pub source_event_type: String,
    pub event_timestamp: DateTime<Utc>,
    pub formatted_payload: Option<String>,
    pub delivery_status: String,
    pub retry_count: i16,
    pub next_retry_at: Option<DateTime<Utc>>,
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub error_detail: Option<String>,
    pub delivered_at: Option<DateTime<Utc>>,
    pub delivery_latency_ms: Option<i32>,
    pub created_at: DateTime<Utc>,
}

/// Request to create a new export event record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSiemExportEvent {
    pub destination_id: Uuid,
    pub source_event_id: Uuid,
    pub source_event_type: String,
    pub event_timestamp: DateTime<Utc>,
    pub formatted_payload: Option<String>,
}

impl SiemExportEvent {
    /// Insert a new export event.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateSiemExportEvent,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO siem_export_events (
                tenant_id, destination_id, source_event_id, source_event_type,
                event_timestamp, formatted_payload
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.destination_id)
        .bind(input.source_event_id)
        .bind(&input.source_event_type)
        .bind(input.event_timestamp)
        .bind(&input.formatted_payload)
        .fetch_one(pool)
        .await
    }

    /// Mark an event as delivered.
    pub async fn mark_delivered(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        latency_ms: i32,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE siem_export_events
            SET delivery_status = 'delivered',
                delivered_at = NOW(),
                last_attempt_at = NOW(),
                delivery_latency_ms = $3
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(latency_ms)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Mark an event as failed with retry scheduling.
    pub async fn mark_failed(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        error: &str,
        next_retry_at: Option<DateTime<Utc>>,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE siem_export_events
            SET delivery_status = 'failed',
                last_attempt_at = NOW(),
                retry_count = retry_count + 1,
                error_detail = $3,
                next_retry_at = $4
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(error)
        .bind(next_retry_at)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Move an event to dead letter queue.
    pub async fn mark_dead_letter(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        error: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE siem_export_events
            SET delivery_status = 'dead_letter',
                last_attempt_at = NOW(),
                error_detail = $3,
                next_retry_at = NULL
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(error)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Mark an event as dropped (circuit breaker open / rate limited).
    pub async fn mark_dropped(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        reason: &str,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE siem_export_events
            SET delivery_status = 'dropped',
                error_detail = $3
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(reason)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Re-queue dead letter events for re-delivery.
    pub async fn redeliver_dead_letter(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        destination_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE siem_export_events
            SET delivery_status = 'pending',
                retry_count = 0,
                next_retry_at = NULL,
                error_detail = NULL
            WHERE tenant_id = $1 AND destination_id = $2 AND delivery_status = 'dead_letter'
            ",
        )
        .bind(tenant_id)
        .bind(destination_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// List events needing retry (failed with `next_retry_at` in the past).
    pub async fn list_pending_retries(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM siem_export_events
            WHERE tenant_id = $1
              AND delivery_status = 'failed'
              AND next_retry_at <= NOW()
            ORDER BY next_retry_at
            LIMIT $2
            ",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// List events by destination with pagination.
    pub async fn list_by_destination(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        destination_id: Uuid,
        status_filter: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM siem_export_events
            WHERE tenant_id = $1 AND destination_id = $2
            ",
        );
        let mut param_count = 2;

        if status_filter.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND delivery_status = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, SiemExportEvent>(&query)
            .bind(tenant_id)
            .bind(destination_id);

        if let Some(status) = status_filter {
            q = q.bind(status);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// List dead letter events for a destination.
    pub async fn list_dead_letter(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        destination_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM siem_export_events
            WHERE tenant_id = $1 AND destination_id = $2 AND delivery_status = 'dead_letter'
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            ",
        )
        .bind(tenant_id)
        .bind(destination_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Count events by status for a destination.
    pub async fn count_by_status(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        destination_id: Uuid,
        status: &str,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM siem_export_events
            WHERE tenant_id = $1 AND destination_id = $2 AND delivery_status = $3
            ",
        )
        .bind(tenant_id)
        .bind(destination_id)
        .bind(status)
        .fetch_one(pool)
        .await
    }

    /// Find by source event ID (check if already exported to destination).
    pub async fn find_by_source_event(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        destination_id: Uuid,
        source_event_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM siem_export_events
            WHERE tenant_id = $1 AND destination_id = $2 AND source_event_id = $3
            ",
        )
        .bind(tenant_id)
        .bind(destination_id)
        .bind(source_event_id)
        .fetch_optional(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_export_event_request() {
        let dest_id = Uuid::new_v4();
        let event_id = Uuid::new_v4();

        let request = CreateSiemExportEvent {
            destination_id: dest_id,
            source_event_id: event_id,
            source_event_type: "authentication".to_string(),
            event_timestamp: Utc::now(),
            formatted_payload: Some(
                "CEF:0|Xavyo|IDP|1.0.0|AUTH_LOGIN|Login Success|5|".to_string(),
            ),
        };

        assert_eq!(request.destination_id, dest_id);
        assert_eq!(request.source_event_id, event_id);
        assert_eq!(request.source_event_type, "authentication");
        assert!(request.formatted_payload.is_some());
    }

    #[test]
    fn test_create_event_without_payload() {
        let request = CreateSiemExportEvent {
            destination_id: Uuid::new_v4(),
            source_event_id: Uuid::new_v4(),
            source_event_type: "user_lifecycle".to_string(),
            event_timestamp: Utc::now(),
            formatted_payload: None,
        };

        assert!(request.formatted_payload.is_none());
    }
}
