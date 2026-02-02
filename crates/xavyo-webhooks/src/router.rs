//! Axum router setup for webhook endpoints.

use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use sqlx::PgPool;

use crate::handlers::{deliveries, subscriptions};
use crate::services::subscription_service::SubscriptionService;

/// Shared state for webhook handlers.
#[derive(Clone)]
pub struct WebhooksState {
    pub subscription_service: Arc<SubscriptionService>,
    pool: PgPool,
}

impl WebhooksState {
    /// Create a new webhooks state.
    pub fn new(pool: PgPool, encryption_key: Vec<u8>) -> Self {
        Self {
            subscription_service: Arc::new(SubscriptionService::new(pool.clone(), encryption_key)),
            pool,
        }
    }

    /// Get a reference to the database pool.
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
        .with_state(state)
}
