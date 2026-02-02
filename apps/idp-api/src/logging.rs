//! Structured JSON logging setup using tracing.
//!
//! This module initializes the tracing subscriber with JSON output format
//! suitable for log aggregation systems like ELK, Datadog, or CloudWatch.
//!
//! When OpenTelemetry is enabled (F072), an additional layer bridges tracing
//! spans to OTel spans for distributed trace export. Existing JSON log output
//! is preserved unchanged (FR-015).

use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initialize the tracing subscriber with JSON logging and optional OpenTelemetry layer.
///
/// # Arguments
///
/// * `filter` - The log filter directive (e.g., "info,xavyo=debug")
/// * `otel_layer` - Optional OpenTelemetry layer for distributed tracing (F072).
///   When `None`, the subscriber is identical to pre-F072 behavior (FR-015).
///
/// # Panics
///
/// Panics if the subscriber has already been initialized.
pub fn init_logging(
    filter: &str,
    otel_layer: Option<
        tracing_opentelemetry::OpenTelemetryLayer<
            tracing_subscriber::Registry,
            opentelemetry_sdk::trace::Tracer,
        >,
    >,
) {
    let filter_layer =
        match EnvFilter::try_from_default_env().or_else(|_| EnvFilter::try_new(filter)) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("FATAL: Failed to create log filter: {e}");
                std::process::exit(1);
            }
        };

    let fmt_layer = fmt::layer()
        .json()
        .with_target(true)
        .with_thread_ids(false)
        .with_file(true)
        .with_line_number(true)
        .flatten_event(true);

    // Build subscriber with optional OTel layer (FR-015: preserve existing behavior).
    // The OTel layer must be added first (closest to Registry) so its type parameter
    // matches. `Option<Layer>` acts as a no-op when `None`.
    tracing_subscriber::registry()
        .with(otel_layer)
        .with(fmt_layer)
        .with(filter_layer)
        .init();

    tracing::info!(filter = %filter, "Logging initialized");
}

/// Initialize logging for tests (with simpler output).
#[cfg(test)]
pub fn init_test_logging() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("debug")
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_test_logging_does_not_panic() {
        // This should not panic even if called multiple times
        init_test_logging();
        init_test_logging();
    }
}
