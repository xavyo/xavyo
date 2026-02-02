//! Example demonstrating how to create custom events.
//!
//! This example shows how to define custom event types using the `Event` trait.
//!
//! Run with: `cargo run --example custom_event -p xavyo-events`

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xavyo_events::{Event, EventEnvelope};

/// Custom event for order creation.
///
/// This demonstrates how to create a domain-specific event type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OrderCreated {
    /// The unique identifier for this order.
    pub order_id: Uuid,
    /// The customer who placed the order.
    pub customer_id: Uuid,
    /// Total order amount in cents.
    pub total_cents: i64,
    /// Number of items in the order.
    pub item_count: u32,
    /// Optional notes from the customer.
    pub notes: Option<String>,
}

impl Event for OrderCreated {
    /// Topic for order events.
    const TOPIC: &'static str = "xavyo.commerce.order.created";
    /// Event type identifier.
    const EVENT_TYPE: &'static str = "xavyo.commerce.order.created";
}

/// Custom event for order cancellation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OrderCancelled {
    pub order_id: Uuid,
    pub reason: CancellationReason,
    pub refund_amount_cents: Option<i64>,
}

/// Reasons for order cancellation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CancellationReason {
    CustomerRequest,
    PaymentFailed,
    OutOfStock,
    FraudSuspected,
}

impl Event for OrderCancelled {
    const TOPIC: &'static str = "xavyo.commerce.order.cancelled";
    const EVENT_TYPE: &'static str = "xavyo.commerce.order.cancelled";
}

fn main() {
    // Create a custom event
    let order_event = OrderCreated {
        order_id: Uuid::new_v4(),
        customer_id: Uuid::new_v4(),
        total_cents: 9999,
        item_count: 3,
        notes: Some("Please gift wrap".to_string()),
    };

    // Wrap in an envelope
    let tenant_id = Uuid::new_v4();
    let actor_id = Some(Uuid::new_v4());
    let envelope = EventEnvelope::new(order_event.clone(), tenant_id, actor_id);

    // Verify the event type and topic
    println!("Event Type: {}", envelope.event_type);
    println!("Topic: {}", envelope.topic());
    println!("Tenant ID: {}", envelope.tenant_id);
    println!("Partition Key: {}", envelope.partition_key());

    // Serialize to JSON
    let json_bytes = envelope.to_json_bytes().expect("Failed to serialize");
    let json_str = String::from_utf8_lossy(&json_bytes);
    println!("\nSerialized JSON:\n{}", json_str);

    // Deserialize back
    let restored: EventEnvelope<OrderCreated> =
        EventEnvelope::from_json_bytes(&json_bytes).expect("Failed to deserialize");

    // Verify round-trip
    assert_eq!(envelope.event_id, restored.event_id);
    assert_eq!(envelope.payload.order_id, restored.payload.order_id);
    assert_eq!(envelope.payload.total_cents, restored.payload.total_cents);

    println!("\n✓ Custom event round-trip successful!");

    // Demonstrate another custom event
    let cancel_event = OrderCancelled {
        order_id: order_event.order_id,
        reason: CancellationReason::CustomerRequest,
        refund_amount_cents: Some(9999),
    };

    let cancel_envelope = EventEnvelope::new(cancel_event, tenant_id, actor_id);
    println!("\nCancellation Event Topic: {}", cancel_envelope.topic());
    println!("Cancellation Event Type: {}", OrderCancelled::EVENT_TYPE);
}
