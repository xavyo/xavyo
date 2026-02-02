//! Event publishing trait and implementation using tokio broadcast channel.
//! Implementation in US2 (Phase 4).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A webhook event published by identity operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    pub event_id: Uuid,
    pub event_type: String,
    pub tenant_id: Uuid,
    pub actor_id: Option<Uuid>,
    pub timestamp: DateTime<Utc>,
    pub data: serde_json::Value,
}

/// Publisher that sends webhook events to a broadcast channel.
#[derive(Clone)]
pub struct EventPublisher {
    sender: tokio::sync::broadcast::Sender<WebhookEvent>,
}

impl EventPublisher {
    /// Create a new event publisher with the given channel capacity.
    pub fn new(capacity: usize) -> (Self, tokio::sync::broadcast::Receiver<WebhookEvent>) {
        let (sender, receiver) = tokio::sync::broadcast::channel(capacity);
        (Self { sender }, receiver)
    }

    /// Publish an event to all subscribers. Fire-and-forget — errors are logged but not propagated.
    pub fn publish(&self, event: WebhookEvent) {
        if let Err(e) = self.sender.send(event) {
            tracing::warn!(
                target: "webhook_delivery",
                error = %e,
                "No active webhook subscribers to receive event"
            );
        }
    }

    /// Get a new receiver for the broadcast channel.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<WebhookEvent> {
        self.sender.subscribe()
    }
}
