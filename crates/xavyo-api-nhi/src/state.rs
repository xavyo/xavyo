//! Application state for the unified NHI API.

use sqlx::PgPool;
#[cfg(feature = "kafka")]
use std::sync::Arc;

/// Application state for the unified NHI API.
///
/// Contains the database pool and will hold service instances
/// as they are implemented in later phases.
#[derive(Clone)]
pub struct NhiState {
    /// Database connection pool.
    pub pool: PgPool,
    /// Kafka event producer for delegation lifecycle events.
    #[cfg(feature = "kafka")]
    pub event_producer: Option<Arc<xavyo_events::EventProducer>>,
}

impl NhiState {
    /// Creates a new `NhiState` with the given database pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            #[cfg(feature = "kafka")]
            event_producer: None,
        }
    }

    /// Creates a new `NhiState` with an event producer for Kafka events.
    #[cfg(feature = "kafka")]
    #[must_use]
    pub fn with_event_producer(
        pool: PgPool,
        producer: Arc<xavyo_events::EventProducer>,
    ) -> Self {
        Self {
            pool,
            event_producer: Some(producer),
        }
    }
}
