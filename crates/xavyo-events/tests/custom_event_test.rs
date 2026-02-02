//! Integration test for custom event types.
//!
//! Verifies that custom events can be created, serialized, and deserialized correctly.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xavyo_events::{Event, EventEnvelope, RawEnvelope};

/// Test custom event for integration testing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct TestCustomEvent {
    pub id: Uuid,
    pub name: String,
    pub value: i64,
    pub tags: Vec<String>,
}

impl Event for TestCustomEvent {
    const TOPIC: &'static str = "xavyo.test.custom";
    const EVENT_TYPE: &'static str = "xavyo.test.custom";
}

#[test]
fn test_custom_event_envelope_creation() {
    let event = TestCustomEvent {
        id: Uuid::new_v4(),
        name: "test-event".to_string(),
        value: 42,
        tags: vec!["tag1".to_string(), "tag2".to_string()],
    };

    let tenant_id = Uuid::new_v4();
    let actor_id = Some(Uuid::new_v4());

    let envelope = EventEnvelope::new(event.clone(), tenant_id, actor_id);

    assert_eq!(envelope.event_type, TestCustomEvent::EVENT_TYPE);
    assert_eq!(envelope.tenant_id, tenant_id);
    assert_eq!(envelope.actor_id, actor_id);
    assert_eq!(envelope.payload.id, event.id);
    assert_eq!(envelope.payload.name, event.name);
    assert_eq!(envelope.topic(), TestCustomEvent::TOPIC);
}

#[test]
fn test_custom_event_serialization_roundtrip() {
    let event = TestCustomEvent {
        id: Uuid::new_v4(),
        name: "roundtrip-test".to_string(),
        value: 12345,
        tags: vec!["a".to_string(), "b".to_string(), "c".to_string()],
    };

    let tenant_id = Uuid::new_v4();
    let envelope = EventEnvelope::new(event.clone(), tenant_id, None);

    // Serialize
    let bytes = envelope
        .to_json_bytes()
        .expect("Serialization should succeed");

    // Deserialize
    let restored: EventEnvelope<TestCustomEvent> =
        EventEnvelope::from_json_bytes(&bytes).expect("Deserialization should succeed");

    // Verify all fields match
    assert_eq!(envelope.event_id, restored.event_id);
    assert_eq!(envelope.event_type, restored.event_type);
    assert_eq!(envelope.tenant_id, restored.tenant_id);
    assert_eq!(envelope.actor_id, restored.actor_id);
    assert_eq!(envelope.payload, restored.payload);
}

#[test]
fn test_custom_event_via_raw_envelope() {
    let event = TestCustomEvent {
        id: Uuid::new_v4(),
        name: "raw-envelope-test".to_string(),
        value: -999,
        tags: vec![],
    };

    let tenant_id = Uuid::new_v4();
    let envelope = EventEnvelope::new(event.clone(), tenant_id, None);

    // Serialize to bytes
    let bytes = envelope
        .to_json_bytes()
        .expect("Serialization should succeed");

    // Parse as raw envelope first (simulating consumer that doesn't know the type yet)
    let raw = RawEnvelope::from_bytes(&bytes).expect("Raw parsing should succeed");

    // Validate the raw envelope
    raw.validate().expect("Validation should pass");

    // Verify raw envelope fields
    assert_eq!(raw.event_type, TestCustomEvent::EVENT_TYPE);
    assert_eq!(raw.tenant_id, tenant_id);

    // Convert to typed envelope
    let typed: EventEnvelope<TestCustomEvent> = raw.into_typed().expect("Typing should succeed");

    // Verify the payload
    assert_eq!(typed.payload.id, event.id);
    assert_eq!(typed.payload.name, event.name);
    assert_eq!(typed.payload.value, event.value);
}

#[test]
fn test_custom_event_partition_key() {
    let event = TestCustomEvent {
        id: Uuid::new_v4(),
        name: "partition-test".to_string(),
        value: 0,
        tags: vec![],
    };

    let tenant_id = Uuid::parse_str("12345678-1234-1234-1234-123456789abc").unwrap();
    let envelope = EventEnvelope::new(event, tenant_id, None);

    // Partition key should be the tenant ID as string
    assert_eq!(
        envelope.partition_key(),
        "12345678-1234-1234-1234-123456789abc"
    );
}

#[test]
fn test_custom_event_with_specific_id() {
    let event = TestCustomEvent {
        id: Uuid::new_v4(),
        name: "specific-id-test".to_string(),
        value: 100,
        tags: vec!["test".to_string()],
    };

    let event_id = Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").unwrap();
    let tenant_id = Uuid::new_v4();

    let envelope = EventEnvelope::with_id(event_id, event, tenant_id, None);

    assert_eq!(envelope.event_id, event_id);
}

/// Nested custom event with complex structure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ComplexEvent {
    pub order: OrderInfo,
    pub items: Vec<ItemInfo>,
    pub metadata: Option<Metadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct OrderInfo {
    pub id: Uuid,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ItemInfo {
    pub sku: String,
    pub quantity: u32,
    pub price_cents: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct Metadata {
    pub source: String,
    pub version: u32,
}

impl Event for ComplexEvent {
    const TOPIC: &'static str = "xavyo.test.complex";
    const EVENT_TYPE: &'static str = "xavyo.test.complex";
}

#[test]
fn test_complex_nested_event() {
    let event = ComplexEvent {
        order: OrderInfo {
            id: Uuid::new_v4(),
            status: "pending".to_string(),
        },
        items: vec![
            ItemInfo {
                sku: "SKU-001".to_string(),
                quantity: 2,
                price_cents: 1999,
            },
            ItemInfo {
                sku: "SKU-002".to_string(),
                quantity: 1,
                price_cents: 4999,
            },
        ],
        metadata: Some(Metadata {
            source: "web".to_string(),
            version: 1,
        }),
    };

    let tenant_id = Uuid::new_v4();
    let envelope = EventEnvelope::new(event.clone(), tenant_id, None);

    // Roundtrip test
    let bytes = envelope.to_json_bytes().unwrap();
    let restored: EventEnvelope<ComplexEvent> = EventEnvelope::from_json_bytes(&bytes).unwrap();

    assert_eq!(restored.payload.order.id, event.order.id);
    assert_eq!(restored.payload.items.len(), 2);
    assert_eq!(restored.payload.items[0].sku, "SKU-001");
    assert_eq!(restored.payload.metadata.unwrap().source, "web");
}
