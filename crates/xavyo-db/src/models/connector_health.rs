//! Connector Health model.
//!
//! Real-time health metrics and circuit breaker state for connectors.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Health status of a connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "varchar", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// Connector is connected and healthy.
    Connected,
    /// Connector is experiencing issues but still functional.
    Degraded,
    /// Connector is not connected.
    Disconnected,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthStatus::Connected => write!(f, "connected"),
            HealthStatus::Degraded => write!(f, "degraded"),
            HealthStatus::Disconnected => write!(f, "disconnected"),
        }
    }
}

impl std::str::FromStr for HealthStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "connected" => Ok(HealthStatus::Connected),
            "degraded" => Ok(HealthStatus::Degraded),
            "disconnected" => Ok(HealthStatus::Disconnected),
            _ => Err(format!("Unknown health status: {s}")),
        }
    }
}

/// Circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "varchar", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum CircuitState {
    /// Circuit is closed, operations flow normally.
    Closed,
    /// Circuit is open, operations are blocked.
    Open,
    /// Circuit is testing with limited operations.
    HalfOpen,
}

impl std::fmt::Display for CircuitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitState::Closed => write!(f, "closed"),
            CircuitState::Open => write!(f, "open"),
            CircuitState::HalfOpen => write!(f, "half_open"),
        }
    }
}

impl std::str::FromStr for CircuitState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "closed" => Ok(CircuitState::Closed),
            "open" => Ok(CircuitState::Open),
            "half_open" => Ok(CircuitState::HalfOpen),
            _ => Err(format!("Unknown circuit state: {s}")),
        }
    }
}

/// Connector health record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ConnectorHealth {
    /// The connector this health record is for.
    pub connector_id: Uuid,

    /// The tenant this health record belongs to.
    pub tenant_id: Uuid,

    /// Current health status.
    pub status: HealthStatus,

    /// When the last health check was performed.
    pub last_check_at: DateTime<Utc>,

    /// Number of consecutive failures.
    pub consecutive_failures: i32,

    /// Current circuit breaker state.
    pub circuit_state: CircuitState,

    /// When the circuit was opened.
    pub circuit_opened_at: Option<DateTime<Utc>>,

    /// Number of pending operations.
    pub operations_pending: i32,

    /// Operations completed in the last 24 hours.
    pub operations_completed_24h: i32,

    /// Operations failed in the last 24 hours.
    pub operations_failed_24h: i32,

    /// Average latency in milliseconds.
    pub avg_latency_ms: Option<i32>,

    /// When the record was last updated.
    pub updated_at: DateTime<Utc>,

    /// When the connector went offline (for offline detection).
    pub offline_since: Option<DateTime<Utc>>,

    /// When the last successful operation was performed.
    pub last_success_at: Option<DateTime<Utc>>,

    /// Last error message from the connector.
    pub last_error: Option<String>,
}

/// Request to update connector health.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConnectorHealth {
    pub status: Option<HealthStatus>,
    pub consecutive_failures: Option<i32>,
    pub circuit_state: Option<CircuitState>,
    pub circuit_opened_at: Option<Option<DateTime<Utc>>>,
    pub operations_pending: Option<i32>,
    pub operations_completed_24h: Option<i32>,
    pub operations_failed_24h: Option<i32>,
    pub avg_latency_ms: Option<Option<i32>>,
}

/// Circuit breaker configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening the circuit.
    pub failure_threshold: i32,
    /// Time in seconds before trying half-open.
    pub reset_timeout_seconds: i64,
    /// Number of successful calls in half-open to close circuit.
    pub success_threshold: i32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            reset_timeout_seconds: 60,
            success_threshold: 3,
        }
    }
}

impl ConnectorHealth {
    /// Find health record by connector ID.
    pub async fn find_by_connector(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM connector_health
            WHERE connector_id = $1 AND tenant_id = $2
            ",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List all health records for a tenant.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        status: Option<HealthStatus>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        if let Some(s) = status {
            sqlx::query_as(
                r"
                SELECT * FROM connector_health
                WHERE tenant_id = $1 AND status = $2
                ORDER BY updated_at DESC
                ",
            )
            .bind(tenant_id)
            .bind(s.to_string())
            .fetch_all(pool)
            .await
        } else {
            sqlx::query_as(
                r"
                SELECT * FROM connector_health
                WHERE tenant_id = $1
                ORDER BY updated_at DESC
                ",
            )
            .bind(tenant_id)
            .fetch_all(pool)
            .await
        }
    }

    /// Update health after a successful health check.
    pub async fn record_success(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE connector_health
            SET status = 'connected',
                last_check_at = NOW(),
                consecutive_failures = 0,
                circuit_state = CASE
                    WHEN circuit_state = 'half_open' THEN 'closed'
                    ELSE circuit_state
                END,
                circuit_opened_at = CASE
                    WHEN circuit_state = 'half_open' THEN NULL
                    ELSE circuit_opened_at
                END,
                updated_at = NOW()
            WHERE connector_id = $1 AND tenant_id = $2
            ",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Update health after a failed health check.
    pub async fn record_failure(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        config: &CircuitBreakerConfig,
    ) -> Result<Option<Self>, sqlx::Error> {
        // Get current state first
        let current = Self::find_by_connector(pool, tenant_id, connector_id).await?;
        let current = match current {
            Some(c) => c,
            None => return Ok(None),
        };

        let new_failures = current.consecutive_failures + 1;
        let (new_status, new_circuit_state, circuit_opened) =
            if new_failures >= config.failure_threshold {
                // Open the circuit
                (
                    HealthStatus::Disconnected,
                    CircuitState::Open,
                    Some(Utc::now()),
                )
            } else if new_failures >= config.failure_threshold / 2 {
                // Degraded
                (
                    HealthStatus::Degraded,
                    current.circuit_state,
                    current.circuit_opened_at,
                )
            } else {
                (
                    current.status,
                    current.circuit_state,
                    current.circuit_opened_at,
                )
            };

        sqlx::query_as(
            r"
            UPDATE connector_health
            SET status = $3,
                last_check_at = NOW(),
                consecutive_failures = $4,
                circuit_state = $5,
                circuit_opened_at = $6,
                updated_at = NOW()
            WHERE connector_id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .bind(new_status.to_string())
        .bind(new_failures)
        .bind(new_circuit_state.to_string())
        .bind(circuit_opened)
        .fetch_optional(pool)
        .await
    }

    /// Try to transition circuit from open to half-open.
    pub async fn try_half_open(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        config: &CircuitBreakerConfig,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE connector_health
            SET circuit_state = 'half_open', updated_at = NOW()
            WHERE connector_id = $1 AND tenant_id = $2
                AND circuit_state = 'open'
                AND circuit_opened_at <= NOW() - ($3 || ' seconds')::interval
            ",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .bind(config.reset_timeout_seconds.to_string())
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Update operation metrics.
    pub async fn update_metrics(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        pending: i32,
        completed_24h: i32,
        failed_24h: i32,
        avg_latency: Option<i32>,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE connector_health
            SET operations_pending = $3,
                operations_completed_24h = $4,
                operations_failed_24h = $5,
                avg_latency_ms = $6,
                updated_at = NOW()
            WHERE connector_id = $1 AND tenant_id = $2
            ",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .bind(pending)
        .bind(completed_24h)
        .bind(failed_24h)
        .bind(avg_latency)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Check if the circuit is open (blocking operations).
    #[must_use]
    pub fn is_circuit_open(&self) -> bool {
        matches!(self.circuit_state, CircuitState::Open)
    }

    /// Check if the circuit allows operations.
    #[must_use]
    pub fn allows_operations(&self) -> bool {
        matches!(
            self.circuit_state,
            CircuitState::Closed | CircuitState::HalfOpen
        )
    }

    /// Check if connector is healthy.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        matches!(self.status, HealthStatus::Connected)
    }

    /// Get failure rate as percentage.
    #[must_use]
    pub fn failure_rate(&self) -> f64 {
        let total = self.operations_completed_24h + self.operations_failed_24h;
        if total == 0 {
            0.0
        } else {
            (f64::from(self.operations_failed_24h) / f64::from(total)) * 100.0
        }
    }

    /// Check if connector is considered offline.
    ///
    /// A connector is offline if:
    /// - Status is disconnected, OR
    /// - Consecutive failures >= 3 (offline threshold)
    #[must_use]
    pub fn is_offline(&self) -> bool {
        self.status == HealthStatus::Disconnected || self.consecutive_failures >= 3
    }

    /// Check if connector is online and accepting operations.
    #[must_use]
    pub fn is_online(&self) -> bool {
        !self.is_offline() && self.allows_operations()
    }

    /// Mark connector as offline.
    pub async fn mark_offline(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
        error: Option<&str>,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE connector_health
            SET status = 'disconnected',
                offline_since = COALESCE(offline_since, NOW()),
                last_error = $3,
                updated_at = NOW()
            WHERE connector_id = $1 AND tenant_id = $2
            ",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .bind(error)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Mark connector as online.
    pub async fn mark_online(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE connector_health
            SET status = 'connected',
                offline_since = NULL,
                consecutive_failures = 0,
                circuit_state = 'closed',
                circuit_opened_at = NULL,
                last_success_at = NOW(),
                last_error = NULL,
                updated_at = NOW()
            WHERE connector_id = $1 AND tenant_id = $2
            ",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Update last success timestamp.
    pub async fn record_success_timestamp(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE connector_health
            SET last_success_at = NOW(),
                consecutive_failures = 0,
                updated_at = NOW()
            WHERE connector_id = $1 AND tenant_id = $2
            ",
        )
        .bind(connector_id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// List offline connectors for a tenant.
    pub async fn list_offline(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM connector_health
            WHERE tenant_id = $1
                AND (status = 'disconnected' OR consecutive_failures >= 3)
            ORDER BY offline_since ASC
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Get duration the connector has been offline.
    #[must_use]
    pub fn offline_duration(&self) -> Option<chrono::Duration> {
        self.offline_since.map(|since| Utc::now() - since)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_display() {
        assert_eq!(HealthStatus::Connected.to_string(), "connected");
        assert_eq!(HealthStatus::Degraded.to_string(), "degraded");
        assert_eq!(HealthStatus::Disconnected.to_string(), "disconnected");
    }

    #[test]
    fn test_health_status_from_str() {
        assert_eq!(
            "connected".parse::<HealthStatus>().unwrap(),
            HealthStatus::Connected
        );
        assert_eq!(
            "DEGRADED".parse::<HealthStatus>().unwrap(),
            HealthStatus::Degraded
        );
        assert!("unknown".parse::<HealthStatus>().is_err());
    }

    #[test]
    fn test_circuit_state_display() {
        assert_eq!(CircuitState::Closed.to_string(), "closed");
        assert_eq!(CircuitState::Open.to_string(), "open");
        assert_eq!(CircuitState::HalfOpen.to_string(), "half_open");
    }

    #[test]
    fn test_circuit_state_from_str() {
        assert_eq!(
            "closed".parse::<CircuitState>().unwrap(),
            CircuitState::Closed
        );
        assert_eq!(
            "half_open".parse::<CircuitState>().unwrap(),
            CircuitState::HalfOpen
        );
        assert!("unknown".parse::<CircuitState>().is_err());
    }

    #[test]
    fn test_circuit_breaker_config_default() {
        let config = CircuitBreakerConfig::default();
        assert_eq!(config.failure_threshold, 5);
        assert_eq!(config.reset_timeout_seconds, 60);
        assert_eq!(config.success_threshold, 3);
    }

    fn create_test_health() -> ConnectorHealth {
        ConnectorHealth {
            connector_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            status: HealthStatus::Connected,
            last_check_at: Utc::now(),
            consecutive_failures: 0,
            circuit_state: CircuitState::Closed,
            circuit_opened_at: None,
            operations_pending: 0,
            operations_completed_24h: 0,
            operations_failed_24h: 0,
            avg_latency_ms: None,
            updated_at: Utc::now(),
            offline_since: None,
            last_success_at: Some(Utc::now()),
            last_error: None,
        }
    }

    #[test]
    fn test_failure_rate_calculation() {
        // No operations
        let health = create_test_health();
        assert_eq!(health.failure_rate(), 0.0);

        // 20% failure rate
        let health = ConnectorHealth {
            operations_completed_24h: 80,
            operations_failed_24h: 20,
            ..health
        };
        assert_eq!(health.failure_rate(), 20.0);
    }

    #[test]
    fn test_allows_operations() {
        let health = create_test_health();
        assert!(health.allows_operations());

        let health = ConnectorHealth {
            circuit_state: CircuitState::HalfOpen,
            ..health
        };
        assert!(health.allows_operations());

        let health = ConnectorHealth {
            circuit_state: CircuitState::Open,
            ..health
        };
        assert!(!health.allows_operations());
    }

    #[test]
    fn test_is_offline() {
        let health = create_test_health();
        assert!(!health.is_offline());
        assert!(health.is_online());

        // Disconnected status
        let health = ConnectorHealth {
            status: HealthStatus::Disconnected,
            ..create_test_health()
        };
        assert!(health.is_offline());
        assert!(!health.is_online());

        // 3+ consecutive failures
        let health = ConnectorHealth {
            consecutive_failures: 3,
            ..create_test_health()
        };
        assert!(health.is_offline());
        assert!(!health.is_online());

        // 2 failures is not offline
        let health = ConnectorHealth {
            consecutive_failures: 2,
            ..create_test_health()
        };
        assert!(!health.is_offline());
    }

    #[test]
    fn test_offline_duration() {
        let health = create_test_health();
        assert!(health.offline_duration().is_none());

        let one_hour_ago = Utc::now() - chrono::Duration::hours(1);
        let health = ConnectorHealth {
            offline_since: Some(one_hour_ago),
            ..create_test_health()
        };
        let duration = health.offline_duration().unwrap();
        // Should be roughly 1 hour (allow some slack for test execution)
        assert!(duration.num_minutes() >= 59);
        assert!(duration.num_minutes() <= 61);
    }
}
