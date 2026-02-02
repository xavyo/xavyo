//! Event envelope for wrapping all events with metadata.

use crate::error::EventError;
use crate::event::Event;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Standard envelope wrapping all Xavyo events.
///
/// Contains metadata required for routing, idempotence, and audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope<T> {
    /// Unique identifier for this event instance.
    /// Used for idempotence checking.
    pub event_id: Uuid,

    /// Fully qualified event type name.
    /// E.g., "xavyo.idp.user.created"
    pub event_type: String,

    /// Tenant context for multi-tenant isolation.
    pub tenant_id: Uuid,

    /// User or service that triggered the event.
    /// None for system-generated events.
    pub actor_id: Option<Uuid>,

    /// Timestamp when the event was created.
    pub timestamp: DateTime<Utc>,

    /// The actual event payload.
    pub payload: T,
}

impl<T: Event> EventEnvelope<T> {
    /// Create a new event envelope.
    pub fn new(payload: T, tenant_id: Uuid, actor_id: Option<Uuid>) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            event_type: T::EVENT_TYPE.to_string(),
            tenant_id,
            actor_id,
            timestamp: Utc::now(),
            payload,
        }
    }

    /// Create an envelope with a specific event ID.
    /// Useful for testing or replaying events.
    pub fn with_id(event_id: Uuid, payload: T, tenant_id: Uuid, actor_id: Option<Uuid>) -> Self {
        Self {
            event_id,
            event_type: T::EVENT_TYPE.to_string(),
            tenant_id,
            actor_id,
            timestamp: Utc::now(),
            payload,
        }
    }

    /// Get the Kafka topic for this event.
    pub fn topic(&self) -> &'static str {
        T::TOPIC
    }

    /// Get the partition key (tenant_id as string).
    pub fn partition_key(&self) -> String {
        self.tenant_id.to_string()
    }

    /// Serialize the envelope to JSON bytes.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, EventError>
    where
        T: Serialize,
    {
        serde_json::to_vec(self).map_err(|e| EventError::SerializationFailed {
            event_type: T::EVENT_TYPE.to_string(),
            cause: e.to_string(),
        })
    }

    /// Deserialize an envelope from JSON bytes.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, EventError>
    where
        T: for<'de> Deserialize<'de>,
    {
        serde_json::from_slice(bytes).map_err(|_| EventError::DeserializationFailed {
            event_type: T::EVENT_TYPE.to_string(),
            raw: String::from_utf8_lossy(bytes).to_string(),
        })
    }
}

/// Raw envelope for deserializing when the event type is unknown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEnvelope {
    pub event_id: Uuid,
    pub event_type: String,
    pub tenant_id: Uuid,
    pub actor_id: Option<Uuid>,
    pub timestamp: DateTime<Utc>,
    pub payload: serde_json::Value,
}

impl RawEnvelope {
    /// Parse from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EventError> {
        serde_json::from_slice(bytes).map_err(|e| EventError::InvalidEnvelope {
            reason: e.to_string(),
        })
    }

    /// Validate that required fields are present and valid.
    pub fn validate(&self) -> Result<(), EventError> {
        if self.event_type.is_empty() {
            return Err(EventError::InvalidEnvelope {
                reason: "event_type is empty".to_string(),
            });
        }

        if !self.event_type.starts_with("xavyo.") {
            return Err(EventError::InvalidEnvelope {
                reason: format!(
                    "event_type '{}' does not follow naming convention",
                    self.event_type
                ),
            });
        }

        Ok(())
    }

    /// Try to deserialize the payload into a specific event type.
    pub fn into_typed<T: Event>(self) -> Result<EventEnvelope<T>, EventError> {
        let payload: T = serde_json::from_value(self.payload).map_err(|e| {
            EventError::DeserializationFailed {
                event_type: self.event_type.clone(),
                raw: e.to_string(),
            }
        })?;

        Ok(EventEnvelope {
            event_id: self.event_id,
            event_type: self.event_type,
            tenant_id: self.tenant_id,
            actor_id: self.actor_id,
            timestamp: self.timestamp,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestEvent {
        message: String,
    }

    impl Event for TestEvent {
        const TOPIC: &'static str = "xavyo.test.event";
        const EVENT_TYPE: &'static str = "xavyo.test.event";
    }

    #[test]
    fn test_envelope_creation() {
        let tenant_id = Uuid::new_v4();
        let actor_id = Some(Uuid::new_v4());
        let event = TestEvent {
            message: "Hello".to_string(),
        };

        let envelope = EventEnvelope::new(event.clone(), tenant_id, actor_id);

        assert_eq!(envelope.event_type, "xavyo.test.event");
        assert_eq!(envelope.tenant_id, tenant_id);
        assert_eq!(envelope.actor_id, actor_id);
        assert_eq!(envelope.payload.message, "Hello");
        assert_eq!(envelope.topic(), "xavyo.test.event");
    }

    #[test]
    fn test_envelope_serialization_roundtrip() {
        let tenant_id = Uuid::new_v4();
        let event = TestEvent {
            message: "Test".to_string(),
        };

        let envelope = EventEnvelope::new(event, tenant_id, None);
        let bytes = envelope.to_json_bytes().unwrap();
        let restored: EventEnvelope<TestEvent> = EventEnvelope::from_json_bytes(&bytes).unwrap();

        assert_eq!(envelope.event_id, restored.event_id);
        assert_eq!(envelope.tenant_id, restored.tenant_id);
        assert_eq!(envelope.payload.message, restored.payload.message);
    }

    #[test]
    fn test_partition_key() {
        let tenant_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let event = TestEvent {
            message: "Test".to_string(),
        };

        let envelope = EventEnvelope::new(event, tenant_id, None);

        assert_eq!(
            envelope.partition_key(),
            "550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn test_raw_envelope_validation() {
        let raw = RawEnvelope {
            event_id: Uuid::new_v4(),
            event_type: "xavyo.test.event".to_string(),
            tenant_id: Uuid::new_v4(),
            actor_id: None,
            timestamp: Utc::now(),
            payload: serde_json::json!({"message": "test"}),
        };

        assert!(raw.validate().is_ok());

        let invalid = RawEnvelope {
            event_type: "invalid".to_string(),
            ..raw.clone()
        };

        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_raw_envelope_into_typed() {
        let raw = RawEnvelope {
            event_id: Uuid::new_v4(),
            event_type: "xavyo.test.event".to_string(),
            tenant_id: Uuid::new_v4(),
            actor_id: None,
            timestamp: Utc::now(),
            payload: serde_json::json!({"message": "typed"}),
        };

        let typed: EventEnvelope<TestEvent> = raw.into_typed().unwrap();
        assert_eq!(typed.payload.message, "typed");
    }
}
