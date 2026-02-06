//! Prometheus metrics collection and exposition (F072).
//!
//! Provides HTTP request metrics (counters, histograms) and a `/metrics`
//! endpoint for Prometheus scraping. Metrics are labeled by HTTP method,
//! route pattern, and status code.
//!
//! Database connection pool gauges are collected on-demand when the `/metrics`
//! endpoint is scraped, using `sqlx::PgPool` stats.

use axum::{
    body::Body,
    extract::{MatchedPath, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family, histogram::Histogram},
    registry::Registry,
};
use std::sync::{Arc, Mutex};

/// Labels for HTTP request metrics: method, route pattern, and status code.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct HttpRequestLabels {
    pub method: String,
    pub route: String,
    pub status: u16,
}

/// HTTP metrics: request counter and duration histogram.
pub struct HttpMetrics {
    /// Total number of HTTP requests, labeled by (method, route, status).
    pub requests_total: Family<HttpRequestLabels, Counter>,
    /// HTTP request duration in seconds, labeled by (method, route, status).
    pub request_duration_seconds: Family<HttpRequestLabels, Histogram>,
}

impl HttpMetrics {
    fn new() -> Self {
        Self {
            requests_total: Family::default(),
            // Histogram buckets aligned with typical HTTP latency distribution
            request_duration_seconds: Family::new_with_constructor(|| {
                Histogram::new(
                    [
                        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
                    ]
                    .into_iter(),
                )
            }),
        }
    }
}

/// Central metrics registry that owns all metric families.
///
/// Wrapped in `Arc` and shared across handlers and middleware.
pub struct MetricsRegistry {
    pub registry: Mutex<Registry>,
    pub http: Arc<HttpMetrics>,
}

impl MetricsRegistry {
    /// Create a new `MetricsRegistry` with all metrics registered.
    pub fn new() -> Self {
        let mut registry = Registry::default();
        let http = Arc::new(HttpMetrics::new());

        registry.register(
            "http_requests",
            "Total number of HTTP requests",
            http.requests_total.clone(),
        );
        registry.register(
            "http_request_duration_seconds",
            "HTTP request duration in seconds",
            http.request_duration_seconds.clone(),
        );

        Self {
            registry: Mutex::new(registry),
            http,
        }
    }
}

/// Axum middleware that records HTTP request metrics (counter + histogram).
///
/// Extracts the matched route pattern for the `route` label to control
/// cardinality (FR-013). Unmatched routes use `"unmatched"` as label value.
pub async fn metrics_middleware(
    State(metrics): State<Arc<MetricsRegistry>>,
    matched_path: Option<MatchedPath>,
    request: axum::http::Request<Body>,
    next: Next,
) -> Response {
    let method = request.method().to_string();
    let route = matched_path
        .as_ref()
        .map_or_else(|| "unmatched".to_string(), |m| m.as_str().to_string());

    let start = std::time::Instant::now();
    let response = next.run(request).await;
    let duration = start.elapsed().as_secs_f64();

    let labels = HttpRequestLabels {
        method,
        route,
        status: response.status().as_u16(),
    };

    metrics.http.requests_total.get_or_create(&labels).inc();
    metrics
        .http
        .request_duration_seconds
        .get_or_create(&labels)
        .observe(duration);

    response
}

/// Handler for `GET /metrics` — returns Prometheus text exposition format.
///
/// Collects database pool stats on-demand and encodes all registered metrics.
pub async fn metrics_handler(State(state): State<crate::state::AppState>) -> impl IntoResponse {
    let mut buf = String::new();

    // Encode registered metrics (http_requests_total, http_request_duration_seconds)
    {
        let registry = state.metrics.registry.lock().unwrap();
        if let Err(e) = prometheus_client::encoding::text::encode(&mut buf, &registry) {
            tracing::error!(error = %e, "Failed to encode metrics");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to encode metrics",
            )
                .into_response();
        }
    }

    // Append database pool gauges (collected on-demand)
    let pool = &state.db;
    let pool_size = i64::from(pool.size());
    let pool_idle = pool.num_idle() as i64;
    let pool_active = pool_size - pool_idle;

    use std::fmt::Write;
    let _ = writeln!(
        buf,
        "# HELP db_pool_connections_active Number of active database connections"
    );
    let _ = writeln!(buf, "# TYPE db_pool_connections_active gauge");
    let _ = writeln!(buf, "db_pool_connections_active {pool_active}");
    let _ = writeln!(
        buf,
        "# HELP db_pool_connections_idle Number of idle database connections"
    );
    let _ = writeln!(buf, "# TYPE db_pool_connections_idle gauge");
    let _ = writeln!(buf, "db_pool_connections_idle {pool_idle}");
    let _ = writeln!(
        buf,
        "# HELP db_pool_connections_max Maximum database connections configured"
    );
    let _ = writeln!(buf, "# TYPE db_pool_connections_max gauge");
    let _ = writeln!(buf, "db_pool_connections_max {pool_size}");

    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        buf,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_registry_creation() {
        let registry = MetricsRegistry::new();
        // Verify http metrics are accessible
        let labels = HttpRequestLabels {
            method: "GET".to_string(),
            route: "/test".to_string(),
            status: 200,
        };
        registry.http.requests_total.get_or_create(&labels).inc();
        // Should not panic
    }

    #[test]
    fn test_histogram_buckets() {
        let registry = MetricsRegistry::new();
        let labels = HttpRequestLabels {
            method: "POST".to_string(),
            route: "/api".to_string(),
            status: 201,
        };
        registry
            .http
            .request_duration_seconds
            .get_or_create(&labels)
            .observe(0.05);
        // Should not panic
    }
}
