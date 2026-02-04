//! Health monitoring service for connectors.
//!
//! Detects offline connectors and manages operation queueing
//! until systems come back online.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

/// Errors that can occur during health operations.
#[derive(Debug, Error)]
pub enum HealthError {
    /// Database error.
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Connector not found.
    #[error("Connector not found: {id}")]
    ConnectorNotFound { id: Uuid },

    /// Health check failed.
    #[error("Health check failed: {0}")]
    CheckFailed(String),
}

/// Result type for health operations.
pub type HealthResult<T> = Result<T, HealthError>;

/// Configuration for health monitoring.
#[derive(Debug, Clone)]
pub struct HealthConfig {
    /// Number of consecutive failures before marking offline.
    pub offline_threshold: i32,

    /// Interval between health checks (in seconds).
    pub check_interval_secs: u64,

    /// Timeout for health check requests (in seconds).
    pub check_timeout_secs: u64,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            offline_threshold: 3,
            check_interval_secs: 60,
            check_timeout_secs: 30,
        }
    }
}

/// Health status of a connector.
#[derive(Debug, Clone)]
pub struct ConnectorHealthInfo {
    /// Connector ID.
    pub connector_id: Uuid,

    /// Whether the connector is online.
    pub is_online: bool,

    /// Number of consecutive failures.
    pub consecutive_failures: i32,

    /// When the connector went offline (if offline).
    pub offline_since: Option<DateTime<Utc>>,

    /// Last successful operation time.
    pub last_success_at: Option<DateTime<Utc>>,

    /// Last error message (if any).
    pub last_error: Option<String>,

    /// Last health check time.
    pub last_check_at: DateTime<Utc>,
}

/// Service for monitoring connector health.
pub struct HealthService {
    pool: sqlx::PgPool,
    config: HealthConfig,
    /// Cache of connector health status (`connector_id` -> `is_online`).
    cache: Arc<RwLock<std::collections::HashMap<Uuid, bool>>>,
}

impl HealthService {
    /// Create a new health service.
    #[must_use] 
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self {
            pool,
            config: HealthConfig::default(),
            cache: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Create with custom configuration.
    #[must_use] 
    pub fn with_config(pool: sqlx::PgPool, config: HealthConfig) -> Self {
        Self {
            pool,
            config,
            cache: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Check if a connector is online.
    ///
    /// Uses cached value if available, otherwise queries the database.
    pub async fn is_connector_online(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> HealthResult<bool> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(&is_online) = cache.get(&connector_id) {
                return Ok(is_online);
            }
        }

        // Query database
        let health = self.get_health(tenant_id, connector_id).await?;
        let is_online = health.map_or(true, |h| h.is_online); // Assume online if no record

        // Update cache
        {
            let mut cache = self.cache.write().await;
            cache.insert(connector_id, is_online);
        }

        Ok(is_online)
    }

    /// Get detailed health info for a connector.
    pub async fn get_health(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> HealthResult<Option<ConnectorHealthInfo>> {
        let row: Option<HealthRow> = sqlx::query_as(
            r"
            SELECT connector_id, status, consecutive_failures, offline_since,
                   last_success_at, last_error, last_check_at
            FROM connector_health
            WHERE tenant_id = $1 AND connector_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| ConnectorHealthInfo {
            connector_id: r.connector_id,
            is_online: r.status != "disconnected"
                && r.consecutive_failures < self.config.offline_threshold,
            consecutive_failures: r.consecutive_failures,
            offline_since: r.offline_since,
            last_success_at: r.last_success_at,
            last_error: r.last_error,
            last_check_at: r.last_check_at,
        }))
    }

    /// Mark a connector as offline.
    pub async fn mark_connector_offline(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        error: Option<&str>,
    ) -> HealthResult<()> {
        sqlx::query(
            r"
            UPDATE connector_health
            SET status = 'disconnected',
                offline_since = COALESCE(offline_since, NOW()),
                last_error = $3,
                updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(error)
        .execute(&self.pool)
        .await?;

        // Update cache
        {
            let mut cache = self.cache.write().await;
            cache.insert(connector_id, false);
        }

        warn!(
            connector_id = %connector_id,
            error = ?error,
            "Connector marked as offline"
        );

        Ok(())
    }

    /// Mark a connector as online.
    pub async fn mark_connector_online(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> HealthResult<()> {
        sqlx::query(
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
            WHERE tenant_id = $1 AND connector_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .execute(&self.pool)
        .await?;

        // Update cache
        {
            let mut cache = self.cache.write().await;
            cache.insert(connector_id, true);
        }

        info!(connector_id = %connector_id, "Connector marked as online");

        Ok(())
    }

    /// Record a successful operation.
    pub async fn record_success(&self, tenant_id: Uuid, connector_id: Uuid) -> HealthResult<()> {
        sqlx::query(
            r"
            UPDATE connector_health
            SET consecutive_failures = 0,
                last_success_at = NOW(),
                status = CASE
                    WHEN status = 'disconnected' THEN 'connected'
                    ELSE status
                END,
                offline_since = NULL,
                last_error = NULL,
                updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .execute(&self.pool)
        .await?;

        // Update cache
        {
            let mut cache = self.cache.write().await;
            cache.insert(connector_id, true);
        }

        debug!(connector_id = %connector_id, "Recorded successful operation");

        Ok(())
    }

    /// Record a failed operation and check if connector should be marked offline.
    pub async fn record_failure(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        error: &str,
    ) -> HealthResult<bool> {
        // Increment failure count
        let row: (i32,) = sqlx::query_as(
            r"
            UPDATE connector_health
            SET consecutive_failures = consecutive_failures + 1,
                last_error = $3,
                last_check_at = NOW(),
                updated_at = NOW()
            WHERE tenant_id = $1 AND connector_id = $2
            RETURNING consecutive_failures
            ",
        )
        .bind(tenant_id)
        .bind(connector_id)
        .bind(error)
        .fetch_one(&self.pool)
        .await?;

        let failures = row.0;
        let should_mark_offline = failures >= self.config.offline_threshold;

        if should_mark_offline {
            self.mark_connector_offline(tenant_id, connector_id, Some(error))
                .await?;
        }

        Ok(should_mark_offline)
    }

    /// List offline connectors for a tenant.
    pub async fn list_offline_connectors(
        &self,
        tenant_id: Uuid,
    ) -> HealthResult<Vec<ConnectorHealthInfo>> {
        let rows: Vec<HealthRow> = sqlx::query_as(
            r"
            SELECT connector_id, status, consecutive_failures, offline_since,
                   last_success_at, last_error, last_check_at
            FROM connector_health
            WHERE tenant_id = $1
                AND (status = 'disconnected' OR consecutive_failures >= $2)
            ORDER BY offline_since ASC
            ",
        )
        .bind(tenant_id)
        .bind(self.config.offline_threshold)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| ConnectorHealthInfo {
                connector_id: r.connector_id,
                is_online: false,
                consecutive_failures: r.consecutive_failures,
                offline_since: r.offline_since,
                last_success_at: r.last_success_at,
                last_error: r.last_error,
                last_check_at: r.last_check_at,
            })
            .collect())
    }

    /// Clear the health cache (useful for testing or manual refresh).
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    /// Get check interval as Duration.
    #[must_use] 
    pub fn check_interval(&self) -> Duration {
        Duration::from_secs(self.config.check_interval_secs)
    }

    /// Get check timeout as Duration.
    #[must_use] 
    pub fn check_timeout(&self) -> Duration {
        Duration::from_secs(self.config.check_timeout_secs)
    }

    /// Get the database pool.
    #[must_use] 
    pub fn pool(&self) -> &sqlx::PgPool {
        &self.pool
    }

    /// Get the configuration.
    #[must_use] 
    pub fn config(&self) -> &HealthConfig {
        &self.config
    }
}

/// Background health monitor that periodically checks connector health.
///
/// This task runs in the background and:
/// - Checks offline connectors to see if they're back online
/// - Resumes operations that were waiting for connectors to come online
pub struct HealthMonitor {
    health_service: Arc<HealthService>,
    queue: Arc<crate::queue::OperationQueue>,
    running: Arc<RwLock<bool>>,
}

impl HealthMonitor {
    /// Create a new health monitor.
    #[must_use] 
    pub fn new(
        health_service: Arc<HealthService>,
        queue: Arc<crate::queue::OperationQueue>,
    ) -> Self {
        Self {
            health_service,
            queue,
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Start the health monitoring loop.
    ///
    /// This runs indefinitely until `stop()` is called.
    pub async fn start(&self, tenant_id: Uuid) -> HealthResult<()> {
        *self.running.write().await = true;
        let interval = self.health_service.check_interval();

        info!(interval_secs = interval.as_secs(), "Health monitor started");

        while *self.running.read().await {
            // Sleep first, then check
            tokio::time::sleep(interval).await;

            if !*self.running.read().await {
                break;
            }

            // Check offline connectors
            match self.check_offline_connectors(tenant_id).await {
                Ok(resumed) => {
                    if resumed > 0 {
                        info!(
                            resumed = resumed,
                            "Resumed operations for recovered connectors"
                        );
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Error checking offline connectors");
                }
            }
        }

        info!("Health monitor stopped");
        Ok(())
    }

    /// Stop the health monitoring loop.
    pub async fn stop(&self) {
        *self.running.write().await = false;
    }

    /// Check if the monitor is running.
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Check offline connectors and resume operations if they're back online.
    ///
    /// Returns the number of operations resumed.
    async fn check_offline_connectors(&self, tenant_id: Uuid) -> HealthResult<u64> {
        let offline = self
            .health_service
            .list_offline_connectors(tenant_id)
            .await?;

        let mut resumed_count: u64 = 0;

        for health_info in offline {
            // Try to check if connector is back online
            // For now, we just check if enough time has passed since going offline
            // In a real implementation, this would actually ping the connector
            if let Some(offline_since) = health_info.offline_since {
                let offline_duration = Utc::now() - offline_since;

                // Minimum recovery check interval: 5 minutes
                if offline_duration.num_seconds() < 300 {
                    continue;
                }

                // Mark connector as potentially online (will be verified on next operation)
                debug!(
                    connector_id = %health_info.connector_id,
                    offline_since = %offline_since,
                    "Attempting to recover connector"
                );

                // Try to mark online - the next operation will verify
                if let Err(e) = self
                    .health_service
                    .mark_connector_online(tenant_id, health_info.connector_id)
                    .await
                {
                    warn!(
                        connector_id = %health_info.connector_id,
                        error = %e,
                        "Failed to mark connector online"
                    );
                    continue;
                }

                // Resume awaiting operations for this connector
                match self
                    .queue
                    .resume_awaiting_operations(health_info.connector_id)
                    .await
                {
                    Ok(count) => {
                        if count > 0 {
                            info!(
                                connector_id = %health_info.connector_id,
                                count = count,
                                "Resumed awaiting operations"
                            );
                            resumed_count += count;
                        }
                    }
                    Err(e) => {
                        warn!(
                            connector_id = %health_info.connector_id,
                            error = %e,
                            "Failed to resume awaiting operations"
                        );
                    }
                }
            }
        }

        Ok(resumed_count)
    }
}

/// Internal row type for health queries.
#[derive(Debug, sqlx::FromRow)]
struct HealthRow {
    connector_id: Uuid,
    status: String,
    consecutive_failures: i32,
    offline_since: Option<DateTime<Utc>>,
    last_success_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    last_check_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_config_default() {
        let config = HealthConfig::default();
        assert_eq!(config.offline_threshold, 3);
        assert_eq!(config.check_interval_secs, 60);
        assert_eq!(config.check_timeout_secs, 30);
    }

    #[test]
    fn test_connector_health_info() {
        let info = ConnectorHealthInfo {
            connector_id: Uuid::new_v4(),
            is_online: true,
            consecutive_failures: 0,
            offline_since: None,
            last_success_at: Some(Utc::now()),
            last_error: None,
            last_check_at: Utc::now(),
        };

        assert!(info.is_online);
        assert_eq!(info.consecutive_failures, 0);
        assert!(info.offline_since.is_none());
    }

    #[test]
    fn test_health_config_intervals() {
        let config = HealthConfig {
            offline_threshold: 5,
            check_interval_secs: 120,
            check_timeout_secs: 60,
        };

        // Create a mock pool - we can't test actual service without DB
        // but we can verify the config is applied
        assert_eq!(config.offline_threshold, 5);
        assert_eq!(config.check_interval_secs, 120);
    }
}
