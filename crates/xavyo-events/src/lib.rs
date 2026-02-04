//! # xavyo-events
//!
//! Kafka event bus library for xavyo.
//!
//! Provides type-safe producer/consumer abstractions for event-driven
//! communication with guaranteed idempotent processing.
//!
//! ## Features
//!
//! - **Event Publishing**: Publish domain events to Kafka topics
//! - **Idempotent Consuming**: Process events exactly once using `PostgreSQL`
//! - **Type Safety**: Compile-time topic/event type association via Event trait
//! - **Multi-tenant**: All events include tenant context
//!
//! ## Cargo Features
//!
//! - `kafka`: Enable Kafka producer/consumer (requires librdkafka)
//! - `kafka-static`: Build librdkafka from source (requires cmake)
//! - `integration`: Enable integration tests
//!
//! ## Example
//!
//! ```rust,ignore
//! use xavyo_events::{EventProducer, KafkaConfig, events::UserCreated};
//! use uuid::Uuid;
//!
//! let config = KafkaConfig::from_env()?;
//! let producer = EventProducer::new(config)?;
//!
//! let event = UserCreated {
//!     user_id: Uuid::new_v4(),
//!     email: "john@example.com".to_string(),
//!     display_name: Some("John Doe".to_string()),
//!     roles: vec!["user".to_string()],
//!     created_by: None,
//! };
//!
//! producer.publish(event, tenant_id, actor_id).await?;
//! ```

// Core modules (always available)
pub mod config;
pub mod envelope;
pub mod error;
pub mod event;
pub mod events;
pub mod health;
pub mod idempotence;

// Kafka-dependent modules (require `kafka` feature)
#[cfg(feature = "kafka")]
pub mod consumer;
#[cfg(feature = "kafka")]
pub mod producer;

// Re-exports for convenience (core types)
pub use config::{KafkaConfig, KafkaConfigBuilder};
pub use envelope::{EventEnvelope, RawEnvelope};
pub use error::EventError;
pub use event::Event;
pub use health::HealthStatus;

// Re-exports for Kafka types (when feature enabled)
#[cfg(feature = "kafka")]
pub use consumer::{EventConsumer, EventHandler};
#[cfg(feature = "kafka")]
pub use producer::EventProducer;
