//! Application state for the unified NHI API.

use sqlx::PgPool;
#[cfg(feature = "kafka")]
use std::sync::Arc;
use xavyo_api_oauth::services::OAuth2ClientService;

/// Application state for the unified NHI API.
///
/// Contains the database pool and will hold service instances
/// as they are implemented in later phases.
#[derive(Clone)]
pub struct NhiState {
    /// Database connection pool.
    pub pool: PgPool,
    /// OAuth2 client service for provisioning.
    pub oauth_client_service: OAuth2ClientService,
    /// Kafka event producer for delegation lifecycle events.
    #[cfg(feature = "kafka")]
    pub event_producer: Option<Arc<xavyo_events::EventProducer>>,
}

impl NhiState {
    /// Creates a new `NhiState` with the given database pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        let oauth_client_service = OAuth2ClientService::new(pool.clone());
        Self {
            pool,
            oauth_client_service,
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
        let oauth_client_service = OAuth2ClientService::new(pool.clone());
        Self {
            pool,
            oauth_client_service,
            event_producer: Some(producer),
        }
    }
}
