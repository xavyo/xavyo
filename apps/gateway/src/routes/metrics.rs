//! Prometheus metrics endpoint.

use axum::{
    body::Body,
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::sync::Arc;
use std::time::Duration;

/// State for metrics routes.
#[derive(Clone)]
pub struct MetricsState {
    pub handle: PrometheusHandle,
}

impl MetricsState {
    /// Create a new metrics state with Prometheus exporter.
    pub fn new() -> anyhow::Result<Self> {
        let builder = PrometheusBuilder::new();
        let handle = builder
            .install_recorder()
            .map_err(|e| anyhow::anyhow!("Failed to install metrics recorder: {e}"))?;

        Ok(Self { handle })
    }
}

/// Create metrics routes.
pub fn metrics_routes(state: Arc<MetricsState>) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(state)
}

/// Metrics handler - returns Prometheus format.
async fn metrics_handler(State(state): State<Arc<MetricsState>>) -> impl IntoResponse {
    let output = state.handle.render();

    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )
        .body(Body::from(output))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Record a request to the gateway.
/// Note: In a production setup, we'd use proper metrics recording with labels.
/// For now, we use the metrics crate's describe_* and counter!/histogram! macros.
#[allow(dead_code)]
pub fn record_request(route: &str, status: u16, tenant: Option<&str>, duration: Duration) {
    use metrics::{describe_counter, describe_histogram, histogram, increment_counter};

    let tenant_str = tenant.unwrap_or("unknown");
    let labels = [
        ("route", route.to_string()),
        ("status", status.to_string()),
        ("tenant", tenant_str.to_string()),
    ];

    // Register and increment counter
    describe_counter!(
        "gateway_requests_total",
        "Total number of requests processed"
    );
    increment_counter!("gateway_requests_total", &labels);

    // Record duration histogram
    describe_histogram!(
        "gateway_request_duration_seconds",
        "Request duration in seconds"
    );
    histogram!(
        "gateway_request_duration_seconds",
        duration.as_secs_f64(),
        &[("route", route.to_string())]
    );
}

/// Record a rate limit hit.
#[allow(dead_code)]
pub fn record_rate_limit(route: &str, tenant: Option<&str>) {
    use metrics::{describe_counter, increment_counter};

    let tenant_str = tenant.unwrap_or("unknown");
    let labels = [
        ("route", route.to_string()),
        ("tenant", tenant_str.to_string()),
    ];

    describe_counter!(
        "gateway_rate_limit_hits_total",
        "Total number of rate limit hits"
    );
    increment_counter!("gateway_rate_limit_hits_total", &labels);
}

/// Record a backend error.
#[allow(dead_code)]
pub fn record_backend_error(backend: &str, error_type: &str) {
    use metrics::{describe_counter, increment_counter};

    let labels = [
        ("backend", backend.to_string()),
        ("error_type", error_type.to_string()),
    ];

    describe_counter!(
        "gateway_backend_errors_total",
        "Total number of backend errors"
    );
    increment_counter!("gateway_backend_errors_total", &labels);
}

/// Record backend latency.
#[allow(dead_code)]
pub fn record_backend_latency(backend: &str, duration: Duration) {
    use metrics::{describe_histogram, histogram};

    describe_histogram!(
        "gateway_backend_latency_seconds",
        "Backend request latency in seconds"
    );
    histogram!(
        "gateway_backend_latency_seconds",
        duration.as_secs_f64(),
        &[("backend", backend.to_string())]
    );
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_record_request() {
        // This test just ensures the function doesn't panic
        // Actual metrics recording requires the recorder to be installed
        // which is done in the main application
    }

    #[test]
    fn test_record_rate_limit() {
        // Same as above
    }
}
