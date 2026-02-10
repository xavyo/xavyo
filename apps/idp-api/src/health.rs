//! Health check endpoints for service monitoring and Kubernetes probes.
//!
//! Provides health endpoints that return service status,
//! version, uptime, and dependency connectivity information.
//!
//! Endpoints:
//! - `GET /health`    — Legacy detailed health (F072)
//! - `GET /livez`     — Liveness probe: process alive, no dependency checks
//! - `GET /readyz`    — Readiness probe: checks DB + Kafka, three-state response
//! - `GET /healthz`   — Alias for readyz
//! - `GET /startupz`  — Startup probe: 503 until initialization complete (F074)

use axum::{extract::State, http::StatusCode, Json};
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;

use crate::state::AppState;

/// Health status response (legacy `/health` endpoint).
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct HealthResponse {
    /// Current service health status.
    pub status: HealthState,

    /// Application version from Cargo.toml.
    pub version: String,

    /// Seconds since service started.
    pub uptime_seconds: u64,

    /// Database connectivity status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,

    /// Response timestamp.
    pub timestamp: DateTime<Utc>,
}

/// Health state enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)] // All variants are part of the API contract
pub enum HealthState {
    /// All systems operational.
    Healthy,
    /// Service running but non-critical dependencies unavailable.
    Degraded,
    /// Critical dependency failed or service shutting down.
    Unhealthy,
}

/// Health check handler (legacy `GET /health`).
///
/// Returns the current service health status including:
/// - Status (healthy, degraded, unhealthy)
/// - Application version
/// - Uptime in seconds
/// - Database connectivity
/// - Current timestamp
#[utoipa::path(
    get,
    path = "/health",
    tag = "Health",
    responses(
        (status = 200, description = "Service health status", body = HealthResponse),
    )
)]
pub async fn health_handler(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let uptime = state.uptime_seconds();

    // Check database connectivity
    let (status, database) = match sqlx::query("SELECT 1").fetch_one(&state.db).await {
        Ok(_) => (HealthState::Healthy, Some("connected".to_string())),
        Err(_) => (HealthState::Unhealthy, Some("disconnected".to_string())),
    };

    let response = HealthResponse {
        status,
        version: state.version.to_string(),
        uptime_seconds: uptime,
        database,
        timestamp: Utc::now(),
    };

    let http_status = match status {
        HealthState::Healthy => StatusCode::OK,
        HealthState::Degraded => StatusCode::OK,
        HealthState::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };

    (http_status, Json(response))
}

// ── Kubernetes Health Probes (F072 US3, enhanced F074) ──────────────────

/// Liveness probe response.
///
/// Indicates the process is alive and not deadlocked. Does not check
/// dependencies — a failing liveness probe restarts the pod.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct LivenessResponse {
    pub status: String,
}

/// Dependency check result included in readiness responses.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DependencyCheck {
    pub status: String,
    pub latency_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Readiness probe response (F074 enhanced).
///
/// Indicates whether the service is ready to accept traffic by checking
/// all critical and non-critical dependencies.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ReadinessResponse {
    pub status: String,
    pub checks: std::collections::HashMap<String, DependencyCheck>,
    /// Application version from Cargo.toml (F074 — FR-004).
    pub version: String,
    /// Seconds since service start (F074 — FR-004).
    pub uptime_seconds: u64,
}

/// Startup probe response (F074 — FR-003).
///
/// Returns 503 during initialization, 200 once startup is complete.
/// This is a one-time gate — once it returns 200, it never reverts.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct StartupResponse {
    pub status: String,
}

/// Liveness probe handler (`GET /livez`).
///
/// Returns 200 immediately — no dependency checks. A failing liveness probe
/// causes Kubernetes to restart the pod, so this only confirms the process
/// is responsive (FR-001).
#[utoipa::path(
    get,
    path = "/livez",
    tag = "Observability",
    responses(
        (status = 200, description = "Process is alive", body = LivenessResponse),
    )
)]
pub async fn livez_handler() -> (StatusCode, Json<LivenessResponse>) {
    (
        StatusCode::OK,
        Json(LivenessResponse {
            status: "ok".to_string(),
        }),
    )
}

/// Readiness probe handler (`GET /readyz`).
///
/// Checks all critical and non-critical dependencies:
/// - **database** (critical): `SELECT 1` with configurable timeout (default 2s)
/// - **kafka** (non-critical): broker connectivity via health callback (default 3s timeout)
///
/// Returns:
/// - 200 with `"healthy"` when all checks pass
/// - 200 with `"degraded"` when non-critical checks fail but critical pass
/// - 503 with `"unhealthy"` when critical checks fail or service is shutting down
///
/// (FR-002, FR-004, FR-005, FR-006, FR-008, FR-009, FR-010, FR-011, FR-012, FR-013)
#[utoipa::path(
    get,
    path = "/readyz",
    tag = "Observability",
    responses(
        (status = 200, description = "Service is ready (healthy or degraded)", body = ReadinessResponse),
        (status = 503, description = "Service is not ready (unhealthy)", body = ReadinessResponse),
    )
)]
pub async fn readyz_handler(
    State(state): State<AppState>,
) -> (StatusCode, Json<ReadinessResponse>) {
    let mut checks = std::collections::HashMap::new();
    let mut critical_ok = true;
    let mut non_critical_ok = true;

    // FR-012: Check graceful shutdown flag first
    if state.is_shutting_down() {
        checks.insert(
            "shutdown".to_string(),
            DependencyCheck {
                status: "fail".to_string(),
                latency_ms: 0,
                error: Some("service is shutting down".to_string()),
            },
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadinessResponse {
                status: "unhealthy".to_string(),
                checks,
                version: state.version.to_string(),
                uptime_seconds: state.uptime_seconds(),
            }),
        );
    }

    // FR-002, FR-009: Check database connectivity (CRITICAL dependency)
    let db_timeout = std::time::Duration::from_secs(state.health_config.db_timeout_secs);
    let db_start = std::time::Instant::now();
    let db_check =
        tokio::time::timeout(db_timeout, sqlx::query("SELECT 1").fetch_one(&state.db)).await;
    let db_latency = db_start.elapsed().as_millis() as u64;

    match db_check {
        Ok(Ok(_)) => {
            checks.insert(
                "database".to_string(),
                DependencyCheck {
                    status: "ok".to_string(),
                    latency_ms: db_latency,
                    error: None,
                },
            );
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "Database health check failed");
            critical_ok = false;
            checks.insert(
                "database".to_string(),
                DependencyCheck {
                    status: "fail".to_string(),
                    latency_ms: db_latency,
                    error: Some("database check failed".to_string()),
                },
            );
        }
        Err(_) => {
            critical_ok = false;
            checks.insert(
                "database".to_string(),
                DependencyCheck {
                    status: "fail".to_string(),
                    latency_ms: db_latency,
                    error: Some(format!(
                        "timeout after {}s",
                        state.health_config.db_timeout_secs
                    )),
                },
            );
        }
    }

    // FR-010: Check Kafka connectivity (NON-CRITICAL dependency, only if configured)
    if let Some(ref kafka_health_fn) = state.kafka_health {
        let kafka_timeout = std::time::Duration::from_secs(state.health_config.kafka_timeout_secs);
        let kafka_fn = kafka_health_fn.clone();
        let kafka_start = std::time::Instant::now();
        let kafka_check: Result<
            Result<crate::state::KafkaHealthInfo, tokio::task::JoinError>,
            tokio::time::error::Elapsed,
        > = tokio::time::timeout(
            kafka_timeout,
            tokio::task::spawn_blocking(move || kafka_fn()),
        )
        .await;
        let kafka_latency = kafka_start.elapsed().as_millis() as u64;

        match kafka_check {
            Ok(Ok(health_status)) if health_status.is_healthy() => {
                checks.insert(
                    "kafka".to_string(),
                    DependencyCheck {
                        status: "ok".to_string(),
                        latency_ms: kafka_latency,
                        error: None,
                    },
                );
            }
            Ok(Ok(health_status)) => {
                non_critical_ok = false;
                checks.insert(
                    "kafka".to_string(),
                    DependencyCheck {
                        status: "fail".to_string(),
                        latency_ms: kafka_latency,
                        error: Some(format!(
                            "connected={}, brokers={}",
                            health_status.connected, health_status.brokers
                        )),
                    },
                );
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "Kafka health check task failed");
                non_critical_ok = false;
                checks.insert(
                    "kafka".to_string(),
                    DependencyCheck {
                        status: "fail".to_string(),
                        latency_ms: kafka_latency,
                        error: Some("kafka health check failed".to_string()),
                    },
                );
            }
            Err(_) => {
                non_critical_ok = false;
                checks.insert(
                    "kafka".to_string(),
                    DependencyCheck {
                        status: "fail".to_string(),
                        latency_ms: kafka_latency,
                        error: Some(format!(
                            "timeout after {}s",
                            state.health_config.kafka_timeout_secs
                        )),
                    },
                );
            }
        }
    }

    // F080: Check secret provider health (NON-CRITICAL dependency, only if configured)
    if let Some(ref secret_provider) = state.secret_provider {
        let sp = secret_provider.clone();
        let sp_start = std::time::Instant::now();
        let sp_timeout = std::time::Duration::from_secs(state.health_config.db_timeout_secs);
        let sp_result = match tokio::time::timeout(sp_timeout, sp.health_check()).await {
            Ok(result) => result,
            Err(_) => Err(xavyo_secrets::SecretError::ProviderUnavailable {
                provider: "secrets".to_string(),
                detail: "Health check timed out".to_string(),
            }),
        };
        let sp_latency = sp_start.elapsed().as_millis() as u64;

        match sp_result {
            Ok(true) => {
                checks.insert(
                    "secrets".to_string(),
                    DependencyCheck {
                        status: "ok".to_string(),
                        latency_ms: sp_latency,
                        error: None,
                    },
                );
            }
            Ok(false) => {
                non_critical_ok = false;
                checks.insert(
                    "secrets".to_string(),
                    DependencyCheck {
                        status: "fail".to_string(),
                        latency_ms: sp_latency,
                        error: Some("secret provider health check returned false".to_string()),
                    },
                );
            }
            Err(e) => {
                non_critical_ok = false;
                checks.insert(
                    "secrets".to_string(),
                    DependencyCheck {
                        status: "fail".to_string(),
                        latency_ms: sp_latency,
                        error: Some(format!("secret provider error: {e}")),
                    },
                );
            }
        }
    }

    // FR-005: Compute three-state health status
    let (status_str, http_status) = if !critical_ok {
        ("unhealthy", StatusCode::SERVICE_UNAVAILABLE)
    } else if !non_critical_ok {
        ("degraded", StatusCode::OK)
    } else {
        ("healthy", StatusCode::OK)
    };

    (
        http_status,
        Json(ReadinessResponse {
            status: status_str.to_string(),
            checks,
            version: state.version.to_string(),
            uptime_seconds: state.uptime_seconds(),
        }),
    )
}

/// Healthz handler (`GET /healthz`).
///
/// Kubernetes naming convention compatibility — delegates to `readyz_handler`
/// for a full dependency check.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "Observability",
    responses(
        (status = 200, description = "Service is healthy", body = ReadinessResponse),
        (status = 503, description = "Service is not healthy", body = ReadinessResponse),
    )
)]
pub async fn healthz_handler(state: State<AppState>) -> (StatusCode, Json<ReadinessResponse>) {
    readyz_handler(state).await
}

/// Startup probe handler (`GET /startupz`).
///
/// Returns 503 during initialization and 200 once startup is complete.
/// This is a one-time gate: once `startup_complete` is set to true, this
/// endpoint always returns 200 (FR-003, FR-014).
#[utoipa::path(
    get,
    path = "/startupz",
    tag = "Observability",
    responses(
        (status = 200, description = "Startup complete", body = StartupResponse),
        (status = 503, description = "Still starting up", body = StartupResponse),
    )
)]
pub async fn startupz_handler(
    State(state): State<AppState>,
) -> (StatusCode, Json<StartupResponse>) {
    if state.is_startup_complete() {
        (
            StatusCode::OK,
            Json(StartupResponse {
                status: "ok".to_string(),
            }),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(StartupResponse {
                status: "starting".to_string(),
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_state_serialization() {
        let state = HealthState::Healthy;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, r#""healthy""#);

        let state = HealthState::Degraded;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, r#""degraded""#);

        let state = HealthState::Unhealthy;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, r#""unhealthy""#);
    }

    #[test]
    fn test_health_response_serialization() {
        let response = HealthResponse {
            status: HealthState::Healthy,
            version: "0.1.0".to_string(),
            uptime_seconds: 3600,
            database: Some("connected".to_string()),
            timestamp: DateTime::parse_from_rfc3339("2026-01-22T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        };

        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["status"], "healthy");
        assert_eq!(json["version"], "0.1.0");
        assert_eq!(json["uptime_seconds"], 3600);
        assert_eq!(json["database"], "connected");
    }

    #[test]
    fn test_health_response_without_database() {
        let response = HealthResponse {
            status: HealthState::Healthy,
            version: "0.1.0".to_string(),
            uptime_seconds: 0,
            database: None,
            timestamp: Utc::now(),
        };

        let json = serde_json::to_value(&response).unwrap();
        assert!(json.get("database").is_none());
    }

    #[test]
    fn test_health_state_unhealthy_serialization() {
        let state = HealthState::Unhealthy;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, r#""unhealthy""#);

        // Verify all three states
        assert_eq!(
            serde_json::to_string(&HealthState::Healthy).unwrap(),
            r#""healthy""#
        );
        assert_eq!(
            serde_json::to_string(&HealthState::Degraded).unwrap(),
            r#""degraded""#
        );
        assert_eq!(
            serde_json::to_string(&HealthState::Unhealthy).unwrap(),
            r#""unhealthy""#
        );
    }

    #[test]
    fn test_readiness_response_with_version_uptime() {
        let mut checks = std::collections::HashMap::new();
        checks.insert(
            "database".to_string(),
            DependencyCheck {
                status: "ok".to_string(),
                latency_ms: 2,
                error: None,
            },
        );

        let response = ReadinessResponse {
            status: "healthy".to_string(),
            checks,
            version: "0.1.0".to_string(),
            uptime_seconds: 3600,
        };

        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["status"], "healthy");
        assert_eq!(json["version"], "0.1.0");
        assert_eq!(json["uptime_seconds"], 3600);
        assert!(json["checks"]["database"]["latency_ms"].is_number());
        assert_eq!(json["checks"]["database"]["status"], "ok");
    }

    #[test]
    fn test_dependency_check_with_error() {
        let check = DependencyCheck {
            status: "fail".to_string(),
            latency_ms: 2000,
            error: Some("timeout after 2s".to_string()),
        };

        let json = serde_json::to_value(&check).unwrap();
        assert_eq!(json["status"], "fail");
        assert_eq!(json["latency_ms"], 2000);
        assert_eq!(json["error"], "timeout after 2s");
    }

    #[test]
    fn test_dependency_check_without_error() {
        let check = DependencyCheck {
            status: "ok".to_string(),
            latency_ms: 1,
            error: None,
        };

        let json = serde_json::to_value(&check).unwrap();
        assert_eq!(json["status"], "ok");
        assert_eq!(json["latency_ms"], 1);
        assert!(json.get("error").is_none());
    }

    #[test]
    fn test_startup_response_serialization() {
        let ok_response = StartupResponse {
            status: "ok".to_string(),
        };
        let json = serde_json::to_value(&ok_response).unwrap();
        assert_eq!(json["status"], "ok");

        let starting_response = StartupResponse {
            status: "starting".to_string(),
        };
        let json = serde_json::to_value(&starting_response).unwrap();
        assert_eq!(json["status"], "starting");
    }

    #[test]
    fn test_liveness_response_serialization() {
        let response = LivenessResponse {
            status: "ok".to_string(),
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["status"], "ok");
    }

    #[test]
    fn test_readiness_response_degraded() {
        let mut checks = std::collections::HashMap::new();
        checks.insert(
            "database".to_string(),
            DependencyCheck {
                status: "ok".to_string(),
                latency_ms: 1,
                error: None,
            },
        );
        checks.insert(
            "kafka".to_string(),
            DependencyCheck {
                status: "fail".to_string(),
                latency_ms: 3000,
                error: Some("timeout after 3s".to_string()),
            },
        );

        let response = ReadinessResponse {
            status: "degraded".to_string(),
            checks,
            version: "0.1.0".to_string(),
            uptime_seconds: 7200,
        };

        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["status"], "degraded");
        assert_eq!(json["checks"]["database"]["status"], "ok");
        assert_eq!(json["checks"]["kafka"]["status"], "fail");
        assert_eq!(json["checks"]["kafka"]["error"], "timeout after 3s");
    }

    #[test]
    fn test_readiness_response_unhealthy() {
        let mut checks = std::collections::HashMap::new();
        checks.insert(
            "database".to_string(),
            DependencyCheck {
                status: "fail".to_string(),
                latency_ms: 2000,
                error: Some("timeout after 2s".to_string()),
            },
        );

        let response = ReadinessResponse {
            status: "unhealthy".to_string(),
            checks,
            version: "0.1.0".to_string(),
            uptime_seconds: 1800,
        };

        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["status"], "unhealthy");
        assert_eq!(json["checks"]["database"]["status"], "fail");
    }
}
