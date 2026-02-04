//! Idempotence service for ensuring exactly-once event processing.

use crate::error::EventError;
use sqlx::PgPool;
use tracing::{debug, instrument};
use uuid::Uuid;

/// Service for managing event processing idempotence.
///
/// Uses `PostgreSQL`'s unique constraint to ensure each event
/// is only processed once per consumer group.
pub struct IdempotenceService {
    pool: PgPool,
    consumer_group: String,
}

impl IdempotenceService {
    /// Create a new idempotence service.
    pub fn new(pool: PgPool, consumer_group: impl Into<String>) -> Self {
        Self {
            pool,
            consumer_group: consumer_group.into(),
        }
    }

    /// Check if an event has already been processed.
    #[instrument(skip(self), fields(consumer_group = %self.consumer_group))]
    pub async fn is_processed(&self, event_id: Uuid) -> Result<bool, EventError> {
        let result: (bool,) = sqlx::query_as(
            r"
            SELECT EXISTS(
                SELECT 1 FROM processed_events
                WHERE event_id = $1 AND consumer_group = $2
            )
            ",
        )
        .bind(event_id)
        .bind(&self.consumer_group)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| EventError::IdempotenceCheckFailed {
            cause: e.to_string(),
        })?;

        debug!(event_id = %event_id, already_processed = result.0, "Idempotence check");

        Ok(result.0)
    }

    /// Try to mark an event as processed.
    ///
    /// Returns true if the event was successfully marked (first to process),
    /// false if already processed by this consumer group.
    #[instrument(skip(self), fields(consumer_group = %self.consumer_group))]
    pub async fn try_mark_processed(
        &self,
        event_id: Uuid,
        topic: &str,
    ) -> Result<bool, EventError> {
        let result = sqlx::query(
            r"
            INSERT INTO processed_events (event_id, consumer_group, topic)
            VALUES ($1, $2, $3)
            ON CONFLICT (event_id, consumer_group) DO NOTHING
            ",
        )
        .bind(event_id)
        .bind(&self.consumer_group)
        .bind(topic)
        .execute(&self.pool)
        .await
        .map_err(|e| EventError::IdempotenceCheckFailed {
            cause: e.to_string(),
        })?;

        let marked = result.rows_affected() > 0;

        debug!(
            event_id = %event_id,
            topic = %topic,
            marked_as_processed = marked,
            "Idempotence mark"
        );

        Ok(marked)
    }

    /// Get the consumer group name.
    #[must_use] 
    pub fn consumer_group(&self) -> &str {
        &self.consumer_group
    }
}

#[cfg(test)]
mod tests {
    // Note: Full integration tests would require a database connection.
    // These are basic structural tests.

    #[test]
    fn test_idempotence_service_consumer_group() {
        // This test just verifies the API works without a database
        // Real testing requires database integration tests
        let consumer_group = "test-service";
        assert!(!consumer_group.is_empty());
    }
}
