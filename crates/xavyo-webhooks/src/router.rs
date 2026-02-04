//! Axum router setup for webhook endpoints.

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use sqlx::PgPool;

use crate::circuit_breaker::{CircuitBreakerConfig, CircuitBreakerRegistry};
use crate::handlers::{circuit_breakers, deliveries, dlq, subscriptions};
use crate::services::dlq_service::DlqService;
use crate::services::subscription_service::SubscriptionService;

/// Shared state for webhook handlers.
#[derive(Clone)]
pub struct WebhooksState {
    pub subscription_service: Arc<SubscriptionService>,
    pub dlq_service: Arc<DlqService>,
    pub circuit_breaker_registry: Arc<CircuitBreakerRegistry>,
    pool: PgPool,
}

impl WebhooksState {
    /// Create a new webhooks state.
    #[must_use] 
    pub fn new(pool: PgPool, encryption_key: Vec<u8>) -> Self {
        Self {
            subscription_service: Arc::new(SubscriptionService::new(pool.clone(), encryption_key)),
            dlq_service: Arc::new(DlqService::new(pool.clone())),
            circuit_breaker_registry: Arc::new(CircuitBreakerRegistry::new(
                pool.clone(),
                CircuitBreakerConfig::default(),
            )),
            pool,
        }
    }

    /// Create a new webhooks state with custom circuit breaker config.
    #[must_use] 
    pub fn with_circuit_breaker_config(
        pool: PgPool,
        encryption_key: Vec<u8>,
        cb_config: CircuitBreakerConfig,
    ) -> Self {
        Self {
            subscription_service: Arc::new(SubscriptionService::new(pool.clone(), encryption_key)),
            dlq_service: Arc::new(DlqService::new(pool.clone())),
            circuit_breaker_registry: Arc::new(CircuitBreakerRegistry::new(
                pool.clone(),
                cb_config,
            )),
            pool,
        }
    }

    /// Get a reference to the database pool.
    #[must_use] 
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

/// Creates the webhook router with all routes.
pub fn webhooks_router(state: WebhooksState) -> Router {
    Router::new()
        // Subscription CRUD
        .route(
            "/webhooks/subscriptions",
            post(subscriptions::create_subscription_handler)
                .get(subscriptions::list_subscriptions_handler),
        )
        .route(
            "/webhooks/subscriptions/:id",
            get(subscriptions::get_subscription_handler)
                .patch(subscriptions::update_subscription_handler)
                .delete(subscriptions::delete_subscription_handler),
        )
        // Event types
        .route(
            "/webhooks/event-types",
            get(subscriptions::list_event_types_handler),
        )
        // Delivery history
        .route(
            "/webhooks/subscriptions/:id/deliveries",
            get(deliveries::list_deliveries_handler),
        )
        .route(
            "/webhooks/subscriptions/:id/deliveries/:delivery_id",
            get(deliveries::get_delivery_handler),
        )
        // Dead Letter Queue
        .route("/webhooks/dlq", get(dlq::list_dlq_entries_handler))
        .route(
            "/webhooks/dlq/:id",
            get(dlq::get_dlq_entry_handler).delete(dlq::delete_dlq_entry_handler),
        )
        .route("/webhooks/dlq/:id/replay", post(dlq::replay_single_handler))
        .route("/webhooks/dlq/replay", post(dlq::replay_bulk_handler))
        // Circuit Breakers
        .route(
            "/webhooks/circuit-breakers",
            get(circuit_breakers::list_circuit_breakers_handler),
        )
        .route(
            "/webhooks/circuit-breakers/:subscription_id",
            get(circuit_breakers::get_circuit_breaker_handler),
        )
        .with_state(state)
}
