//! Kafka event consumer for SIEM export pipeline.
//!
//! Consumes events from the Kafka event bus and fans out to destination pipelines.
//!
//! This module provides the `SiemEventConsumer` which manages a set of
//! `ExportPipeline` instances (one per active destination) and dispatches
//! incoming `SiemEvent`s to all matching pipelines concurrently.
//!
//! The actual Kafka consumption is wired up in `idp-api` since this crate
//! does not depend on `xavyo-events`. This module provides the fan-out logic.

use std::collections::HashMap;
use std::sync::Arc;

use uuid::Uuid;

use crate::delivery;
use crate::models::{DestinationType, ExportFormat, SiemEvent};
use crate::pipeline::{ExportPipeline, PipelineConfig, PipelineResult};

/// Represents a configured SIEM destination for fan-out.
#[derive(Clone)]
pub struct DestinationConfig {
    pub id: Uuid,
    pub name: String,
    pub destination_type: DestinationType,
    pub export_format: ExportFormat,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub tls_verify_cert: bool,
    pub auth_config: Option<String>,
    pub event_type_filter: Vec<String>,
    pub rate_limit_per_second: u32,
    pub circuit_breaker_threshold: u32,
    pub circuit_breaker_cooldown_secs: u64,
    pub splunk_source: Option<String>,
    pub splunk_sourcetype: Option<String>,
    pub splunk_index: Option<String>,
}

impl std::fmt::Debug for DestinationConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DestinationConfig")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("destination_type", &self.destination_type)
            .field("export_format", &self.export_format)
            .field("endpoint_host", &self.endpoint_host)
            .field("endpoint_port", &self.endpoint_port)
            .field("tls_verify_cert", &self.tls_verify_cert)
            .field(
                "auth_config",
                &self.auth_config.as_ref().map(|_| "[REDACTED]"),
            )
            .field("event_type_filter", &self.event_type_filter)
            .finish()
    }
}

/// Fan-out consumer that dispatches events to multiple SIEM destination pipelines.
///
/// Constructed with a set of active destinations, creates one `ExportPipeline`
/// per destination. When an event arrives, it is sent to all matching pipelines
/// concurrently.
pub struct SiemEventConsumer {
    pipelines: HashMap<Uuid, Arc<ExportPipeline>>,
}

impl SiemEventConsumer {
    /// Create a new consumer from a set of active destination configurations.
    pub fn new(destinations: Vec<DestinationConfig>) -> Self {
        let mut pipelines = HashMap::new();

        for dest in destinations {
            let worker = match delivery::create_worker(
                &dest.destination_type,
                &dest.endpoint_host,
                dest.endpoint_port,
                dest.tls_verify_cert,
                dest.auth_config.as_deref(),
                dest.splunk_source.as_deref(),
                dest.splunk_sourcetype.as_deref(),
                dest.splunk_index.as_deref(),
            ) {
                Ok(w) => w,
                Err(e) => {
                    tracing::error!(
                        "Failed to create delivery worker for destination '{}' ({}): {}",
                        dest.name,
                        dest.id,
                        e
                    );
                    continue;
                }
            };

            let config = PipelineConfig {
                export_format: dest.export_format,
                event_type_filter: dest.event_type_filter,
                rate_limit_per_second: dest.rate_limit_per_second,
                circuit_breaker_threshold: dest.circuit_breaker_threshold,
                circuit_breaker_cooldown_secs: dest.circuit_breaker_cooldown_secs,
            };

            let pipeline = Arc::new(ExportPipeline::new(worker, config));
            pipelines.insert(dest.id, pipeline);

            tracing::info!(
                "Initialized SIEM pipeline for destination '{}' ({})",
                dest.name,
                dest.id
            );
        }

        tracing::info!(
            "SiemEventConsumer initialized with {} destination(s)",
            pipelines.len()
        );

        Self { pipelines }
    }

    /// Dispatch a single event to all configured destination pipelines.
    ///
    /// Returns a map of `destination_id` → `PipelineResult` for each pipeline that
    /// processed the event. Pipelines that filter out the event will return a
    /// result with `delivered: false, dead_lettered: false`.
    pub async fn dispatch(&self, event: &SiemEvent) -> HashMap<Uuid, PipelineResult> {
        let mut results = HashMap::new();

        if self.pipelines.is_empty() {
            return results;
        }

        // Fan out to all pipelines concurrently
        let mut handles = Vec::with_capacity(self.pipelines.len());

        for (&dest_id, pipeline) in &self.pipelines {
            let pipeline = Arc::clone(pipeline);
            let event = event.clone();
            handles.push((
                dest_id,
                tokio::spawn(async move { pipeline.process_event(&event).await }),
            ));
        }

        for (dest_id, handle) in handles {
            match handle.await {
                Ok(result) => {
                    results.insert(dest_id, result);
                }
                Err(e) => {
                    tracing::error!("Pipeline task panicked for destination {}: {}", dest_id, e);
                    results.insert(
                        dest_id,
                        PipelineResult {
                            delivered: false,
                            latency_ms: None,
                            retry_count: 0,
                            dead_lettered: true,
                            error: Some(format!("Pipeline task panicked: {e}")),
                        },
                    );
                }
            }
        }

        results
    }

    /// Get the number of active destination pipelines.
    #[must_use] 
    pub fn destination_count(&self) -> usize {
        self.pipelines.len()
    }

    /// Check if a specific destination pipeline exists.
    #[must_use] 
    pub fn has_destination(&self, id: &Uuid) -> bool {
        self.pipelines.contains_key(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::EventCategory;
    use chrono::Utc;

    fn test_event() -> SiemEvent {
        SiemEvent {
            event_id: Uuid::new_v4(),
            event_type: "AUTH_LOGIN_SUCCESS".to_string(),
            category: EventCategory::Authentication,
            tenant_id: Uuid::new_v4(),
            actor_id: Some(Uuid::new_v4()),
            actor_email: Some("user@example.com".to_string()),
            timestamp: Utc::now(),
            severity: 3,
            event_name: "Login Success".to_string(),
            source_ip: Some("10.0.0.1".to_string()),
            target_user: None,
            target_resource: None,
            action: "login".to_string(),
            outcome: "Success".to_string(),
            reason: None,
            session_id: None,
            request_id: None,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_empty_consumer() {
        let consumer = SiemEventConsumer::new(vec![]);
        assert_eq!(consumer.destination_count(), 0);
    }

    #[tokio::test]
    async fn test_dispatch_with_no_destinations() {
        let consumer = SiemEventConsumer::new(vec![]);
        let event = test_event();
        let results = consumer.dispatch(&event).await;
        assert!(results.is_empty());
    }

    // Note: Full integration tests with real delivery workers require network
    // access and are covered by the integration test suite. Unit tests here
    // verify the fan-out logic and construction.
}
