//! `ProcessedEvent` model for event idempotence tracking.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Record of a processed Kafka event for idempotence.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ProcessedEvent {
    /// Primary key.
    pub id: Uuid,
    /// UUID of the event from the Kafka message envelope.
    pub event_id: Uuid,
    /// Kafka consumer group that processed this event.
    pub consumer_group: String,
    /// Kafka topic the event was consumed from.
    pub topic: String,
    /// Timestamp when the event was successfully processed.
    pub processed_at: DateTime<Utc>,
}

/// Data needed to create a new processed event record.
#[derive(Debug, Clone)]
pub struct CreateProcessedEvent {
    pub event_id: Uuid,
    pub consumer_group: String,
    pub topic: String,
}

impl ProcessedEvent {
    /// Check if an event has been processed by a consumer group.
    ///
    /// Returns true if the event was already processed.
    pub async fn is_processed(
        pool: &sqlx::PgPool,
        event_id: Uuid,
        consumer_group: &str,
    ) -> Result<bool, sqlx::Error> {
        let result: (bool,) = sqlx::query_as(
            r"
            SELECT EXISTS(
                SELECT 1 FROM processed_events
                WHERE event_id = $1 AND consumer_group = $2
            )
            ",
        )
        .bind(event_id)
        .bind(consumer_group)
        .fetch_one(pool)
        .await?;

        Ok(result.0)
    }

    /// Mark an event as processed.
    ///
    /// Uses INSERT with ON CONFLICT DO NOTHING to handle race conditions.
    /// Returns true if the event was marked (first processor), false if already marked.
    pub async fn mark_processed(
        pool: &sqlx::PgPool,
        data: CreateProcessedEvent,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            INSERT INTO processed_events (event_id, consumer_group, topic)
            VALUES ($1, $2, $3)
            ON CONFLICT (event_id, consumer_group) DO NOTHING
            ",
        )
        .bind(data.event_id)
        .bind(&data.consumer_group)
        .bind(&data.topic)
        .execute(pool)
        .await?;

        // rows_affected = 1 means we inserted, 0 means conflict (already exists)
        Ok(result.rows_affected() > 0)
    }

    /// Try to mark an event as processed in a single atomic operation.
    ///
    /// This combines the check and mark into one query for better performance.
    /// Returns true if we successfully marked it (should process), false if already processed.
    pub async fn try_mark_processed(
        pool: &sqlx::PgPool,
        data: CreateProcessedEvent,
    ) -> Result<bool, sqlx::Error> {
        // Use INSERT with ON CONFLICT DO NOTHING
        // If rows_affected is 1, we're the first to process
        // If rows_affected is 0, someone else already processed it
        Self::mark_processed(pool, data).await
    }

    /// Delete processed events older than a given timestamp.
    ///
    /// Used for retention/cleanup of old records.
    pub async fn cleanup_before(
        pool: &sqlx::PgPool,
        before: DateTime<Utc>,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM processed_events
            WHERE processed_at < $1
            ",
        )
        .bind(before)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_processed_event() {
        let data = CreateProcessedEvent {
            event_id: Uuid::new_v4(),
            consumer_group: "test-service".to_string(),
            topic: "xavyo.idp.user.created".to_string(),
        };

        assert!(!data.consumer_group.is_empty());
        assert!(!data.topic.is_empty());
    }
}
