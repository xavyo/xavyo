//! Kafka event producer.

use crate::config::KafkaConfig;
use crate::envelope::EventEnvelope;
use crate::error::EventError;
use crate::event::Event;
use crate::health::HealthStatus;

use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord, Producer};
use std::time::Duration;
use tracing::{debug, info, instrument};
use uuid::Uuid;

/// Kafka event producer for publishing events.
pub struct EventProducer {
    producer: FutureProducer,
    #[allow(dead_code)]
    config: KafkaConfig,
}

impl EventProducer {
    /// Create a new event producer with the given configuration.
    pub fn new(config: KafkaConfig) -> Result<Self, EventError> {
        let mut client_config = ClientConfig::new();

        client_config
            .set("bootstrap.servers", &config.bootstrap_servers)
            .set("client.id", &config.client_id)
            .set("security.protocol", config.security_protocol.as_str())
            .set("message.timeout.ms", "5000")
            .set("acks", "all");

        // Add SASL configuration if present
        if let Some(sasl) = &config.sasl {
            client_config
                .set("sasl.mechanism", sasl.mechanism.as_str())
                .set("sasl.username", &sasl.username)
                .set("sasl.password", &sasl.password);
        }

        let producer: FutureProducer =
            client_config
                .create()
                .map_err(|e| EventError::ConnectionFailed {
                    broker: config.bootstrap_servers.clone(),
                    cause: e.to_string(),
                })?;

        info!(
            bootstrap_servers = %config.bootstrap_servers,
            client_id = %config.client_id,
            "Event producer created"
        );

        Ok(Self { producer, config })
    }

    /// Publish an event to Kafka.
    ///
    /// The event is wrapped in an envelope with metadata and published
    /// to the topic defined by the event type.
    #[instrument(skip(self, event), fields(event_type = %E::EVENT_TYPE, tenant_id = %tenant_id))]
    pub async fn publish<E: Event>(
        &self,
        event: E,
        tenant_id: Uuid,
        actor_id: Option<Uuid>,
    ) -> Result<(), EventError> {
        let envelope = EventEnvelope::new(event, tenant_id, actor_id);
        self.publish_envelope(envelope).await
    }

    /// Publish a pre-constructed envelope.
    #[instrument(skip(self, envelope), fields(
        event_id = %envelope.event_id,
        event_type = %envelope.event_type,
        tenant_id = %envelope.tenant_id
    ))]
    pub async fn publish_envelope<E: Event>(
        &self,
        envelope: EventEnvelope<E>,
    ) -> Result<(), EventError> {
        let topic = E::TOPIC;
        let key = envelope.partition_key();
        let payload = envelope.to_json_bytes()?;

        debug!(
            topic = %topic,
            key = %key,
            payload_size = payload.len(),
            "Publishing event"
        );

        let record = FutureRecord::to(topic).key(&key).payload(&payload);

        let delivery_status = self
            .producer
            .send(record, Duration::from_secs(5))
            .await
            .map_err(|(err, _)| EventError::PublishFailed {
                topic: topic.to_string(),
                cause: err.to_string(),
            })?;

        debug!(
            partition = delivery_status.0,
            offset = delivery_status.1,
            "Event published successfully"
        );

        Ok(())
    }

    /// Check the health of the Kafka connection.
    pub async fn health_check(&self) -> Result<HealthStatus, EventError> {
        let metadata = self
            .producer
            .client()
            .fetch_metadata(None, Duration::from_secs(5))
            .map_err(
                |e: rdkafka::error::KafkaError| EventError::ConnectionFailed {
                    broker: "unknown".to_string(),
                    cause: e.to_string(),
                },
            )?;

        Ok(HealthStatus {
            connected: true,
            brokers: metadata.brokers().len(),
            topics: metadata.topics().len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecurityProtocol;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct TestEvent {
        message: String,
    }

    impl Event for TestEvent {
        const TOPIC: &'static str = "xavyo.test.event";
        const EVENT_TYPE: &'static str = "xavyo.test.event";
    }

    #[test]
    fn test_producer_creation_requires_bootstrap() {
        // Without proper config, creation should work but connection would fail
        let config = KafkaConfig {
            bootstrap_servers: "localhost:9092".to_string(),
            security_protocol: SecurityProtocol::Plaintext,
            sasl: None,
            client_id: "test".to_string(),
        };

        // This creates the producer struct but doesn't actually connect
        let result = EventProducer::new(config);
        // The producer creation itself should succeed (connection is lazy)
        assert!(result.is_ok());
    }
}
