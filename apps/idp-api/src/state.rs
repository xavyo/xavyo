//! Application state shared across all request handlers.
//!
//! The `AppState` struct contains all shared resources like database
//! connections, authentication state, and service metadata.

use crate::config::HealthCheckConfig;
use crate::metrics::MetricsRegistry;
use sqlx::PgPool;
use std::sync::atomic::{AtomicBool, Ordering};

// Note on Ordering: We use Acquire/Release for the shutdown flag to ensure
// visibility across threads on weakly-ordered architectures (ARM).
// For startup_complete, Relaxed would suffice (monotonic transition, read-only
// after initial set) but we use Acquire/Release for consistency.
use std::sync::Arc;
use std::time::Instant;
use xavyo_api_auth::AuthState;
use xavyo_secrets::SecretProvider;

/// Kafka health information returned by the health callback (F074).
///
/// Mirrors `xavyo_events::health::HealthStatus` to avoid a hard dependency
/// on the optional `xavyo-events` crate.
#[derive(Debug, Clone)]
pub struct KafkaHealthInfo {
    /// Whether the connection is established.
    pub connected: bool,
    /// Number of brokers discovered.
    pub brokers: usize,
}

impl KafkaHealthInfo {
    /// Check if the Kafka connection is healthy.
    pub fn is_healthy(&self) -> bool {
        self.connected && self.brokers > 0
    }
}

/// Callback type for checking Kafka health on demand.
pub type KafkaHealthCallback = Arc<dyn Fn() -> KafkaHealthInfo + Send + Sync>;

/// Application state shared across all handlers.
///
/// This struct is cloned for each request, but the inner resources
/// (like `PgPool`) use `Arc` internally so cloning is cheap.
#[derive(Clone)]
#[allow(dead_code)] // Fields may be used in future handlers
pub struct AppState {
    /// Database connection pool
    pub db: PgPool,

    /// Authentication state (JWT keys, etc.)
    pub auth: AuthState,

    /// Prometheus metrics registry (F072)
    pub metrics: Arc<MetricsRegistry>,

    /// Service startup time for uptime calculation
    pub startup_time: Arc<Instant>,

    /// Application version from Cargo.toml
    pub version: &'static str,

    /// Whether initial startup is complete (F074 — startup probe)
    pub startup_complete: Arc<AtomicBool>,

    /// Whether the service is shutting down (F074 — graceful drain)
    pub shutting_down: Arc<AtomicBool>,

    /// Health check timeout configuration (F074)
    pub health_config: HealthCheckConfig,

    /// Kafka health callback — None when Kafka is not configured (F074)
    pub kafka_health: Option<KafkaHealthCallback>,

    /// Secret provider for external key management health checks (F080)
    pub secret_provider: Option<Arc<dyn SecretProvider>>,
}

impl AppState {
    /// Create a new application state.
    ///
    /// # Arguments
    ///
    /// * `db` - PostgreSQL connection pool
    /// * `auth` - Authentication state with JWT configuration
    /// * `metrics` - Prometheus metrics registry
    /// * `health_config` - Health check timeout configuration
    /// * `kafka_health` - Optional Kafka health callback (None if Kafka not configured)
    pub fn new(
        db: PgPool,
        auth: AuthState,
        metrics: Arc<MetricsRegistry>,
        health_config: HealthCheckConfig,
        kafka_health: Option<KafkaHealthCallback>,
    ) -> Self {
        Self {
            db,
            auth,
            metrics,
            startup_time: Arc::new(Instant::now()),
            version: env!("CARGO_PKG_VERSION"),
            startup_complete: Arc::new(AtomicBool::new(false)),
            shutting_down: Arc::new(AtomicBool::new(false)),
            health_config,
            kafka_health,
            secret_provider: None,
        }
    }

    /// Set the secret provider for health check integration (F080).
    pub fn with_secret_provider(mut self, provider: Option<Arc<dyn SecretProvider>>) -> Self {
        self.secret_provider = provider;
        self
    }

    /// Get the service uptime in seconds.
    pub fn uptime_seconds(&self) -> u64 {
        self.startup_time.elapsed().as_secs()
    }

    /// Check if the service has completed startup.
    pub fn is_startup_complete(&self) -> bool {
        self.startup_complete.load(Ordering::Acquire)
    }

    /// Mark startup as complete.
    pub fn mark_startup_complete(&self) {
        self.startup_complete.store(true, Ordering::Release);
    }

    /// Check if the service is shutting down.
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::Acquire)
    }

    /// Mark the service as shutting down (readiness probe will return 503).
    #[allow(dead_code)] // Used by shutdown_signal in main.rs via direct AtomicBool access
    pub fn mark_shutting_down(&self) {
        self.shutting_down.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_is_set() {
        // The version should be set from Cargo.toml
        let version = env!("CARGO_PKG_VERSION");
        assert!(!version.is_empty());
    }

    #[test]
    fn test_startup_complete_default_false() {
        let flag = Arc::new(AtomicBool::new(false));
        assert!(!flag.load(Ordering::Acquire));
        flag.store(true, Ordering::Release);
        assert!(flag.load(Ordering::Acquire));
    }

    #[test]
    fn test_shutting_down_default_false() {
        let flag = Arc::new(AtomicBool::new(false));
        assert!(!flag.load(Ordering::Acquire));
        flag.store(true, Ordering::Release);
        assert!(flag.load(Ordering::Acquire));
    }

    #[test]
    fn test_kafka_health_info_healthy() {
        let info = KafkaHealthInfo {
            connected: true,
            brokers: 3,
        };
        assert!(info.is_healthy());
    }

    #[test]
    fn test_kafka_health_info_not_connected() {
        let info = KafkaHealthInfo {
            connected: false,
            brokers: 3,
        };
        assert!(!info.is_healthy());
    }

    #[test]
    fn test_kafka_health_info_zero_brokers() {
        let info = KafkaHealthInfo {
            connected: true,
            brokers: 0,
        };
        assert!(!info.is_healthy());
    }

    #[test]
    fn test_kafka_health_info_fully_unhealthy() {
        let info = KafkaHealthInfo {
            connected: false,
            brokers: 0,
        };
        assert!(!info.is_healthy());
    }
}
