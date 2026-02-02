//! Health check endpoint with backend aggregation.

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use serde::Serialize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{info, warn};

use crate::proxy::{BackendRouter, ProxyClient};

/// Application state for health checks.
#[derive(Clone)]
pub struct HealthState {
    pub router: BackendRouter,
    pub client: ProxyClient,
    pub start_time: Instant,
    pub version: String,
}

/// Health check response.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: HealthStatus,
    pub version: String,
    pub uptime_secs: u64,
    pub backends: Vec<BackendHealth>,
}

/// Overall health status.
#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

/// Individual backend health status.
#[derive(Debug, Serialize)]
pub struct BackendHealth {
    pub name: String,
    pub status: BackendStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Backend status.
#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BackendStatus {
    Healthy,
    Unhealthy,
}

/// Create health check routes.
pub fn health_routes(state: Arc<HealthState>) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .with_state(state)
}

/// Health check handler.
async fn health_handler(State(state): State<Arc<HealthState>>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().as_secs();

    // Check all backends in parallel
    let backends = state.router.all_backends();
    let mut health_futures = Vec::with_capacity(backends.len());

    for backend in backends {
        let client = state.client.clone();
        let backend = backend.clone();

        health_futures.push(tokio::spawn(async move {
            let health_timeout = Duration::from_secs(5);

            match timeout(health_timeout, client.health_check(&backend)).await {
                Ok(Ok(latency)) => {
                    info!(backend = %backend.name, latency_ms = %latency.as_millis(), "Backend healthy");
                    BackendHealth {
                        name: backend.name,
                        status: BackendStatus::Healthy,
                        latency_ms: Some(latency.as_millis() as u64),
                        error: None,
                    }
                }
                Ok(Err(e)) => {
                    warn!(backend = %backend.name, error = %e, "Backend unhealthy");
                    BackendHealth {
                        name: backend.name,
                        status: BackendStatus::Unhealthy,
                        latency_ms: None,
                        error: Some(e),
                    }
                }
                Err(_) => {
                    warn!(backend = %backend.name, "Backend health check timed out");
                    BackendHealth {
                        name: backend.name,
                        status: BackendStatus::Unhealthy,
                        latency_ms: None,
                        error: Some("Health check timed out".to_string()),
                    }
                }
            }
        }));
    }

    // Collect results
    let mut backend_healths = Vec::with_capacity(health_futures.len());
    for future in health_futures {
        if let Ok(health) = future.await {
            backend_healths.push(health);
        }
    }

    // Determine overall status
    let unhealthy_count = backend_healths
        .iter()
        .filter(|b| b.status == BackendStatus::Unhealthy)
        .count();

    let overall_status = if unhealthy_count == 0 {
        HealthStatus::Healthy
    } else if unhealthy_count == backend_healths.len() {
        HealthStatus::Unhealthy
    } else {
        HealthStatus::Degraded
    };

    let response = HealthResponse {
        status: overall_status,
        version: state.version.clone(),
        uptime_secs: uptime,
        backends: backend_healths,
    };

    // Return appropriate status code
    let status_code = match overall_status {
        HealthStatus::Healthy => StatusCode::OK,
        HealthStatus::Degraded => StatusCode::OK,
        HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };

    (status_code, Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_serialize() {
        assert_eq!(
            serde_json::to_string(&HealthStatus::Healthy).unwrap(),
            "\"healthy\""
        );
        assert_eq!(
            serde_json::to_string(&HealthStatus::Degraded).unwrap(),
            "\"degraded\""
        );
        assert_eq!(
            serde_json::to_string(&HealthStatus::Unhealthy).unwrap(),
            "\"unhealthy\""
        );
    }

    #[test]
    fn test_backend_status_serialize() {
        assert_eq!(
            serde_json::to_string(&BackendStatus::Healthy).unwrap(),
            "\"healthy\""
        );
        assert_eq!(
            serde_json::to_string(&BackendStatus::Unhealthy).unwrap(),
            "\"unhealthy\""
        );
    }

    #[test]
    fn test_health_response_serialize() {
        let response = HealthResponse {
            status: HealthStatus::Healthy,
            version: "1.0.0".to_string(),
            uptime_secs: 3600,
            backends: vec![BackendHealth {
                name: "idp-api".to_string(),
                status: BackendStatus::Healthy,
                latency_ms: Some(15),
                error: None,
            }],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"healthy\""));
        assert!(json.contains("\"version\":\"1.0.0\""));
        assert!(json.contains("\"uptime_secs\":3600"));
    }
}
