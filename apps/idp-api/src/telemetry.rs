//! OpenTelemetry telemetry initialization (F072).
//!
//! Provides distributed tracing via OTLP export and W3C Trace Context propagation.
//! When no OTLP endpoint is configured, telemetry is silently disabled and the
//! system operates normally without any collector.
//!
//! SQLx 0.7 already emits `tracing` spans for database queries. With the
//! `tracing-opentelemetry` bridge layer, these automatically become OTel child spans.
//!
//! ## Automatic Database Instrumentation (FR-003)
//!
//! SQLx 0.7 emits `tracing` spans (e.g., `sqlx::query`) for every database
//! operation. Because the `OpenTelemetryLayer` is added to the tracing subscriber
//! stack, these spans are automatically bridged to OpenTelemetry child spans
//! without any additional instrumentation code. Database query traces will appear
//! as children of the HTTP request span when viewed in Jaeger/Tempo.

use crate::config::OtelConfig;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::{Sampler, TracerProvider};
use opentelemetry_sdk::Resource;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::Registry;

/// Guard that holds telemetry providers for shutdown.
///
/// On drop or explicit `shutdown()`, flushes pending telemetry data.
pub struct TelemetryGuard {
    tracer_provider: Option<TracerProvider>,
    meter_provider: Option<SdkMeterProvider>,
}

impl TelemetryGuard {
    /// Shut down telemetry providers, flushing any pending data.
    pub fn shutdown(self) {
        if let Some(provider) = self.tracer_provider {
            if let Err(e) = provider.shutdown() {
                tracing::warn!(error = %e, "Failed to shut down tracer provider");
            }
        }
        if let Some(provider) = self.meter_provider {
            if let Err(e) = provider.shutdown() {
                tracing::warn!(error = %e, "Failed to shut down meter provider");
            }
        }
    }
}

/// Initialize OpenTelemetry telemetry based on configuration.
///
/// Returns a `TelemetryGuard` (for shutdown) and an optional OpenTelemetry
/// tracing layer to add to the subscriber stack.
///
/// When `config.otlp_endpoint` is `None`, returns `(guard_with_none, None)`.
pub fn init_telemetry(
    config: &OtelConfig,
) -> (
    TelemetryGuard,
    Option<OpenTelemetryLayer<Registry, opentelemetry_sdk::trace::Tracer>>,
) {
    // Set W3C TraceContext as the global propagator (FR-002)
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );

    let Some(endpoint) = &config.otlp_endpoint else {
        tracing::info!("OpenTelemetry OTLP export disabled (no OTEL_EXPORTER_OTLP_ENDPOINT set)");
        return (
            TelemetryGuard {
                tracer_provider: None,
                meter_provider: None,
            },
            None,
        );
    };

    // Build resource with service metadata (FR-016)
    let resource = Resource::new(vec![
        KeyValue::new(
            opentelemetry_semantic_conventions::attribute::SERVICE_NAME,
            config.service_name.clone(),
        ),
        KeyValue::new("deployment.environment", config.environment.clone()),
    ]);

    // Build OTLP span exporter
    let exporter = match opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
    {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(error = %e, "Failed to create OTLP span exporter, tracing disabled");
            return (
                TelemetryGuard {
                    tracer_provider: None,
                    meter_provider: None,
                },
                None,
            );
        }
    };

    // Configure sampler (FR-012)
    let sampler = if (config.sampling_rate - 1.0).abs() < f64::EPSILON {
        Sampler::ParentBased(Box::new(Sampler::AlwaysOn))
    } else {
        Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(config.sampling_rate)))
    };

    // Build tracer provider
    let tracer_provider = TracerProvider::builder()
        .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
        .with_resource(resource)
        .with_sampler(sampler)
        .build();

    let tracer = tracer_provider.tracer("idp-api");
    let otel_layer = OpenTelemetryLayer::new(tracer);

    // Build OTLP metrics push export when metrics are enabled (FR-006 / T015).
    // This pushes metrics via OTLP in addition to the pull-based /metrics endpoint.
    let meter_provider = if config.metrics_enabled {
        match opentelemetry_otlp::MetricExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()
        {
            Ok(metric_exporter) => {
                let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(
                    metric_exporter,
                    opentelemetry_sdk::runtime::Tokio,
                )
                .build();

                let meter_provider = SdkMeterProvider::builder()
                    .with_reader(reader)
                    .with_resource(Resource::new(vec![
                        KeyValue::new(
                            opentelemetry_semantic_conventions::attribute::SERVICE_NAME,
                            config.service_name.clone(),
                        ),
                        KeyValue::new("deployment.environment", config.environment.clone()),
                    ]))
                    .build();

                opentelemetry::global::set_meter_provider(meter_provider.clone());
                tracing::info!("OTLP metrics push export enabled");
                Some(meter_provider)
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to create OTLP metric exporter, push metrics disabled");
                None
            }
        }
    } else {
        None
    };

    tracing::info!(
        endpoint = %endpoint,
        service_name = %config.service_name,
        sampling_rate = config.sampling_rate,
        "OpenTelemetry tracing initialized"
    );

    (
        TelemetryGuard {
            tracer_provider: Some(tracer_provider),
            meter_provider,
        },
        Some(otel_layer),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_guard_shutdown_with_none_providers() {
        // FR-010: System operates normally when no collector is configured
        let guard = TelemetryGuard {
            tracer_provider: None,
            meter_provider: None,
        };
        // Should not panic
        guard.shutdown();
    }

    #[test]
    fn test_init_telemetry_disabled_when_no_endpoint() {
        let config = OtelConfig {
            otlp_endpoint: None,
            service_name: "test".to_string(),
            sampling_rate: 1.0,
            metrics_enabled: true,
            environment: "test".to_string(),
        };

        let (guard, layer) = init_telemetry(&config);
        assert!(layer.is_none());
        assert!(guard.tracer_provider.is_none());
        guard.shutdown();
    }
}
