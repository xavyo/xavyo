//! Event trait definition for type-safe event publishing/consuming.

use serde::{de::DeserializeOwned, Serialize};

/// Trait for types that can be published and consumed as Kafka events.
///
/// Implementors must define the Kafka topic and event type name.
/// The event type is automatically serialized/deserialized as JSON.
///
/// # Example
///
/// ```rust
/// use serde::{Serialize, Deserialize};
/// use xavyo_events::Event;
/// use uuid::Uuid;
///
/// #[derive(Debug, Serialize, Deserialize)]
/// pub struct UserCreated {
///     pub user_id: Uuid,
///     pub email: String,
/// }
///
/// impl Event for UserCreated {
///     const TOPIC: &'static str = "xavyo.idp.user.created";
///     const EVENT_TYPE: &'static str = "xavyo.idp.user.created";
/// }
/// ```
pub trait Event: Serialize + DeserializeOwned + Send + Sync + 'static {
    /// The Kafka topic for this event type.
    ///
    /// Events of this type will be published to and consumed from this topic.
    const TOPIC: &'static str;

    /// The fully qualified event type name.
    ///
    /// This is stored in the event envelope for routing and deserialization.
    /// Convention: `xavyo.<service>.<entity>.<action>`
    const EVENT_TYPE: &'static str;
}
