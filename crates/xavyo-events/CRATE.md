# xavyo-events

> Kafka event bus library with type-safe producer/consumer and idempotent processing.

## Purpose

Provides event-driven communication infrastructure for xavyo. Enables publishing domain events to Kafka topics with guaranteed exactly-once processing via PostgreSQL-backed idempotence tracking. All events include tenant context for proper isolation.

## Layer

foundation

## Status

🟢 **stable**

Production-ready with comprehensive test coverage (123+ tests). Kafka event bus with idempotent processing fully implemented.

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId, UserId types

### External (key)
- `rdkafka` - Kafka client (optional, requires `kafka` feature)
- `sqlx` - Idempotence tracking in PostgreSQL
- `tokio` - Async runtime
- `serde` - Event serialization

## Public API

### Types

```rust
/// Event envelope with metadata
pub struct EventEnvelope<E> {
    pub id: Uuid,              // Unique event ID
    pub event_type: String,    // e.g., "user.created"
    pub tenant_id: TenantId,   // Tenant context
    pub actor_id: Option<UserId>, // Who triggered the event
    pub timestamp: DateTime<Utc>,
    pub payload: E,            // The actual event
}

/// Raw envelope for deserialization
pub struct RawEnvelope { ... }

/// Kafka configuration
pub struct KafkaConfig {
    pub brokers: String,
    pub client_id: String,
    pub group_id: String,
}

/// Builder for KafkaConfig
pub struct KafkaConfigBuilder { ... }

/// Health status for monitoring
pub enum HealthStatus { Healthy, Degraded, Unhealthy }

/// Event errors
pub enum EventError { ... }

// Kafka-dependent types (require `kafka` feature)
#[cfg(feature = "kafka")]
pub struct EventProducer { ... }

#[cfg(feature = "kafka")]
pub struct EventConsumer { ... }
```

### Traits

```rust
/// Marker trait for events with topic association
pub trait Event: Serialize + DeserializeOwned {
    /// Kafka topic for this event type
    fn topic() -> &'static str;

    /// Event type identifier (e.g., "user.created")
    fn event_type() -> &'static str;
}

/// Handler for consuming events
#[cfg(feature = "kafka")]
#[async_trait]
pub trait EventHandler<E: Event> {
    async fn handle(&self, envelope: EventEnvelope<E>) -> Result<(), EventError>;
}
```

### Functions

```rust
// Producer methods
#[cfg(feature = "kafka")]
impl EventProducer {
    pub fn new(config: KafkaConfig) -> Result<Self, EventError>;
    pub async fn publish<E: Event>(
        &self,
        event: E,
        tenant_id: TenantId,
        actor_id: Option<UserId>,
    ) -> Result<Uuid, EventError>;
}

// Consumer methods
#[cfg(feature = "kafka")]
impl EventConsumer {
    pub fn new(config: KafkaConfig, pool: PgPool) -> Result<Self, EventError>;
    pub async fn subscribe<E: Event, H: EventHandler<E>>(
        &self,
        handler: H,
    ) -> Result<(), EventError>;
}
```

## Usage Example

```rust
use xavyo_events::{Event, EventEnvelope, EventProducer, KafkaConfig};
use xavyo_core::TenantId;
use serde::{Serialize, Deserialize};

// Define an event
#[derive(Serialize, Deserialize)]
pub struct UserCreated {
    pub user_id: Uuid,
    pub email: String,
}

impl Event for UserCreated {
    fn topic() -> &'static str { "identity.users" }
    fn event_type() -> &'static str { "user.created" }
}

// Publish events
let config = KafkaConfig::from_env()?;
let producer = EventProducer::new(config)?;

let event = UserCreated {
    user_id: Uuid::new_v4(),
    email: "john@example.com".to_string(),
};

let event_id = producer.publish(event, tenant_id, Some(actor_id)).await?;
```

## Integration Points

- **Consumed by**: All domain crates that emit events
- **Requires**: Kafka brokers (when `kafka` feature enabled)
- **Requires**: PostgreSQL for idempotence (when consuming)

## Feature Flags

| Flag | Description | Dependencies Added |
|------|-------------|-------------------|
| `kafka` | Enable Kafka producer/consumer | rdkafka |
| `kafka-static` | Build librdkafka from source | rdkafka/cmake-build |
| `integration` | Enable integration tests | kafka |

## Anti-Patterns

- Never publish events without tenant context
- Never skip idempotence checking when consuming
- Never process events across tenant boundaries
- Never block the event loop with synchronous operations

## Related Crates

- `xavyo-webhooks` - Delivers events via HTTP webhooks
- `xavyo-siem` - Exports audit events to external systems
- `xavyo-provisioning` - Consumes sync events
