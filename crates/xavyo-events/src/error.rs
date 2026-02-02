//! Error types for the xavyo-events crate.

use thiserror::Error;
use uuid::Uuid;

/// Errors that can occur during event operations.
#[derive(Debug, Error)]
pub enum EventError {
    // Configuration errors (permanent, no retry)
    /// Required configuration variable is missing.
    #[error("Configuration missing: {var}")]
    ConfigMissing { var: String },

    /// Configuration value is invalid.
    #[error("Configuration invalid for {var}: {reason}")]
    ConfigInvalid { var: String, reason: String },

    // Connection errors (transient, retry with backoff)
    /// Failed to connect to Kafka broker.
    #[error("Connection to broker {broker} failed: {cause}")]
    ConnectionFailed { broker: String, cause: String },

    /// Connection timed out.
    #[error("Connection timed out")]
    ConnectionTimeout,

    // Publishing errors
    /// Failed to publish event to topic.
    #[error("Failed to publish to topic {topic}: {cause}")]
    PublishFailed { topic: String, cause: String },

    /// Failed to serialize event.
    #[error("Failed to serialize event type {event_type}: {cause}")]
    SerializationFailed { event_type: String, cause: String },

    // Consuming errors
    /// Failed to consume from topic.
    #[error("Failed to consume from topic {topic}: {cause}")]
    ConsumeFailed { topic: String, cause: String },

    /// Failed to deserialize event.
    #[error("Failed to deserialize event type {event_type}: {raw}")]
    DeserializationFailed { event_type: String, raw: String },

    /// Event handler failed.
    #[error("Handler failed for event {event_id}: {cause}")]
    HandlerFailed { event_id: Uuid, cause: String },

    // Idempotence errors
    /// Idempotence check failed.
    #[error("Idempotence check failed: {cause}")]
    IdempotenceCheckFailed { cause: String },

    // Envelope errors
    /// Invalid event envelope.
    #[error("Invalid event envelope: {reason}")]
    InvalidEnvelope { reason: String },

    // Internal Kafka errors
    /// Internal Kafka client error.
    #[cfg(feature = "kafka")]
    #[error("Kafka error: {0}")]
    Kafka(#[from] rdkafka::error::KafkaError),

    // Database errors
    /// Database operation failed.
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl EventError {
    /// Returns true if this error is transient and can be retried.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            EventError::ConnectionFailed { .. }
                | EventError::ConnectionTimeout
                | EventError::PublishFailed { .. }
                | EventError::ConsumeFailed { .. }
                | EventError::IdempotenceCheckFailed { .. }
        )
    }

    /// Returns true if this is a configuration error.
    pub fn is_config_error(&self) -> bool {
        matches!(
            self,
            EventError::ConfigMissing { .. } | EventError::ConfigInvalid { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_is_transient() {
        let transient = EventError::ConnectionTimeout;
        assert!(transient.is_transient());

        let permanent = EventError::ConfigMissing {
            var: "TEST".to_string(),
        };
        assert!(!permanent.is_transient());
    }

    #[test]
    fn test_error_is_config_error() {
        let config_err = EventError::ConfigMissing {
            var: "TEST".to_string(),
        };
        assert!(config_err.is_config_error());

        let other_err = EventError::ConnectionTimeout;
        assert!(!other_err.is_config_error());
    }

    #[test]
    fn test_error_display() {
        let err = EventError::ConfigMissing {
            var: "KAFKA_BOOTSTRAP_SERVERS".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Configuration missing: KAFKA_BOOTSTRAP_SERVERS"
        );
    }
}
