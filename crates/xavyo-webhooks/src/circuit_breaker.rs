//! Circuit breaker pattern implementation for webhook delivery.
//!
//! Provides protection against failing webhook destinations by tracking failures
//! and temporarily blocking requests to endpoints that have exceeded the failure
//! threshold. Supports state persistence for recovery after service restarts.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::sync::RwLock;
use uuid::Uuid;

use xavyo_db::models::{
    CircuitState as DbCircuitState, UpsertCircuitBreakerState, WebhookCircuitBreakerState,
};

// Note: We define our own CircuitState here for the webhook domain to provide
// better ergonomics and doc comments specific to webhook circuit breaking.
// The database model uses the shared CircuitState from connector_health.

/// Circuit breaker states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CircuitState {
    /// Normal operation - deliveries proceed.
    #[default]
    Closed,
    /// Circuit tripped - deliveries rejected immediately.
    Open,
    /// Testing recovery - allows one probe request.
    HalfOpen,
}

impl CircuitState {
    /// Convert to database string representation.
    #[must_use] 
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::HalfOpen => "half_open",
        }
    }

    /// Parse from database string representation.
    #[must_use] 
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "closed" => Some(Self::Closed),
            "open" => Some(Self::Open),
            "half_open" => Some(Self::HalfOpen),
            _ => None,
        }
    }

    /// Convert from database `CircuitState`.
    #[must_use] 
    pub fn from_db(db_state: DbCircuitState) -> Self {
        match db_state {
            DbCircuitState::Closed => Self::Closed,
            DbCircuitState::Open => Self::Open,
            DbCircuitState::HalfOpen => Self::HalfOpen,
        }
    }

    /// Convert to database `CircuitState`.
    #[must_use] 
    pub fn to_db(self) -> DbCircuitState {
        match self {
            Self::Closed => DbCircuitState::Closed,
            Self::Open => DbCircuitState::Open,
            Self::HalfOpen => DbCircuitState::HalfOpen,
        }
    }
}

/// Configuration for circuit breaker behavior.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening the circuit.
    pub failure_threshold: u32,
    /// Duration in seconds before transitioning from Open to `HalfOpen`.
    pub recovery_timeout_secs: u64,
    /// Maximum number of recent failures to track for diagnostics.
    pub max_failure_history: usize,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            recovery_timeout_secs: 30,
            max_failure_history: 10,
        }
    }
}

impl CircuitBreakerConfig {
    /// Create a new configuration with custom failure threshold.
    #[must_use] 
    pub fn with_failure_threshold(mut self, threshold: u32) -> Self {
        self.failure_threshold = threshold;
        self
    }

    /// Create a new configuration with custom recovery timeout.
    #[must_use] 
    pub fn with_recovery_timeout(mut self, secs: u64) -> Self {
        self.recovery_timeout_secs = secs;
        self
    }

    /// Create a new configuration with custom failure history size.
    #[must_use] 
    pub fn with_max_failure_history(mut self, size: usize) -> Self {
        self.max_failure_history = size;
        self
    }
}

/// Record of a single delivery failure for diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailureRecord {
    /// Timestamp of the failure.
    pub timestamp: DateTime<Utc>,
    /// Error message describing the failure.
    pub error: String,
    /// HTTP response code if available.
    pub response_code: Option<i16>,
    /// Response latency in milliseconds if available.
    pub latency_ms: Option<i32>,
}

impl FailureRecord {
    /// Create a new failure record.
    #[must_use] 
    pub fn new(error: String, response_code: Option<i16>, latency_ms: Option<i32>) -> Self {
        Self {
            timestamp: Utc::now(),
            error,
            response_code,
            latency_ms,
        }
    }
}

/// Circuit breaker for a single webhook subscription.
#[derive(Debug)]
pub struct CircuitBreaker {
    subscription_id: Uuid,
    tenant_id: Uuid,
    config: CircuitBreakerConfig,
    state: CircuitState,
    failure_count: u32,
    recent_failures: Vec<FailureRecord>,
    last_failure_at: Option<DateTime<Utc>>,
    last_success_at: Option<DateTime<Utc>>,
    opened_at: Option<DateTime<Utc>>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with default closed state.
    #[must_use] 
    pub fn new(subscription_id: Uuid, tenant_id: Uuid, config: CircuitBreakerConfig) -> Self {
        Self {
            subscription_id,
            tenant_id,
            config,
            state: CircuitState::Closed,
            failure_count: 0,
            recent_failures: Vec::new(),
            last_failure_at: None,
            last_success_at: None,
            opened_at: None,
        }
    }

    /// Create a circuit breaker from persisted state.
    #[must_use] 
    pub fn from_persisted(
        state: &WebhookCircuitBreakerState,
        config: CircuitBreakerConfig,
    ) -> Self {
        let circuit_state = CircuitState::parse(&state.state).unwrap_or_default();
        let recent_failures: Vec<FailureRecord> =
            serde_json::from_value(state.recent_failures.clone()).unwrap_or_default();

        Self {
            subscription_id: state.subscription_id,
            tenant_id: state.tenant_id,
            config,
            state: circuit_state,
            failure_count: state.failure_count as u32,
            recent_failures,
            last_failure_at: state.last_failure_at,
            last_success_at: state.last_success_at,
            opened_at: state.opened_at,
        }
    }

    /// Get the subscription ID this circuit breaker is for.
    #[must_use] 
    pub fn subscription_id(&self) -> Uuid {
        self.subscription_id
    }

    /// Get the tenant ID.
    #[must_use] 
    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    /// Get the current circuit state.
    #[must_use] 
    pub fn state(&self) -> CircuitState {
        self.state
    }

    /// Get the current failure count.
    #[must_use] 
    pub fn failure_count(&self) -> u32 {
        self.failure_count
    }

    /// Get recent failure records.
    #[must_use] 
    pub fn recent_failures(&self) -> &[FailureRecord] {
        &self.recent_failures
    }

    /// Get the last failure timestamp.
    #[must_use] 
    pub fn last_failure_at(&self) -> Option<DateTime<Utc>> {
        self.last_failure_at
    }

    /// Get the last success timestamp.
    #[must_use] 
    pub fn last_success_at(&self) -> Option<DateTime<Utc>> {
        self.last_success_at
    }

    /// Get the timestamp when the circuit was opened.
    #[must_use] 
    pub fn opened_at(&self) -> Option<DateTime<Utc>> {
        self.opened_at
    }

    /// Check if a delivery can be executed.
    ///
    /// Returns `true` if the circuit allows the request to proceed.
    /// Handles automatic state transitions from Open to `HalfOpen`.
    pub fn can_execute(&mut self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if recovery timeout has elapsed
                if let Some(opened_at) = self.opened_at {
                    let elapsed = Utc::now().signed_duration_since(opened_at);
                    if elapsed.num_seconds() >= self.config.recovery_timeout_secs as i64 {
                        // Transition to half-open for probe
                        self.state = CircuitState::HalfOpen;
                        tracing::info!(
                            target: "circuit_breaker",
                            subscription_id = %self.subscription_id,
                            "Circuit breaker transitioning to half-open for probe"
                        );
                        return true;
                    }
                }
                false
            }
            CircuitState::HalfOpen => {
                // Allow one probe request
                true
            }
        }
    }

    /// Record a successful delivery.
    ///
    /// Resets failure count and closes the circuit if in half-open state.
    pub fn record_success(&mut self) {
        self.last_success_at = Some(Utc::now());

        match self.state {
            CircuitState::HalfOpen => {
                // Successful probe - close the circuit
                self.state = CircuitState::Closed;
                self.failure_count = 0;
                self.recent_failures.clear();
                self.opened_at = None;
                tracing::info!(
                    target: "circuit_breaker",
                    subscription_id = %self.subscription_id,
                    "Circuit breaker closed after successful probe"
                );
            }
            CircuitState::Closed => {
                // Reset consecutive failure count on success
                self.failure_count = 0;
            }
            CircuitState::Open => {
                // Shouldn't happen - log warning
                tracing::warn!(
                    target: "circuit_breaker",
                    subscription_id = %self.subscription_id,
                    "Unexpected success recorded while circuit is open"
                );
            }
        }
    }

    /// Record a delivery failure.
    ///
    /// Increments failure count and opens the circuit if threshold is reached.
    pub fn record_failure(&mut self, failure: FailureRecord) {
        self.last_failure_at = Some(Utc::now());
        self.failure_count += 1;

        // Add to recent failures, keeping bounded
        self.recent_failures.push(failure);
        while self.recent_failures.len() > self.config.max_failure_history {
            self.recent_failures.remove(0);
        }

        match self.state {
            CircuitState::Closed => {
                if self.failure_count >= self.config.failure_threshold {
                    // Open the circuit
                    self.state = CircuitState::Open;
                    self.opened_at = Some(Utc::now());
                    tracing::warn!(
                        target: "circuit_breaker",
                        subscription_id = %self.subscription_id,
                        failure_count = self.failure_count,
                        threshold = self.config.failure_threshold,
                        "Circuit breaker opened due to consecutive failures"
                    );
                }
            }
            CircuitState::HalfOpen => {
                // Failed probe - reopen the circuit
                self.state = CircuitState::Open;
                self.opened_at = Some(Utc::now());
                tracing::warn!(
                    target: "circuit_breaker",
                    subscription_id = %self.subscription_id,
                    "Circuit breaker reopened after failed probe"
                );
            }
            CircuitState::Open => {
                // Already open - just track the failure
            }
        }
    }

    /// Save the circuit breaker state to the database.
    pub async fn save(&self, pool: &PgPool) -> Result<(), sqlx::Error> {
        let recent_failures_json = serde_json::to_value(&self.recent_failures)
            .unwrap_or_else(|_| serde_json::Value::Array(vec![]));

        WebhookCircuitBreakerState::upsert(
            pool,
            UpsertCircuitBreakerState {
                subscription_id: self.subscription_id,
                tenant_id: self.tenant_id,
                state: self.state.to_db(),
                failure_count: self.failure_count as i32,
                last_failure_at: self.last_failure_at,
                last_success_at: self.last_success_at,
                opened_at: self.opened_at,
                recent_failures: recent_failures_json,
            },
        )
        .await?;

        Ok(())
    }

    /// Load circuit breaker state from the database.
    pub async fn load(
        pool: &PgPool,
        tenant_id: Uuid,
        subscription_id: Uuid,
        config: CircuitBreakerConfig,
    ) -> Result<Option<Self>, sqlx::Error> {
        let state =
            WebhookCircuitBreakerState::find_by_subscription(pool, tenant_id, subscription_id)
                .await?;

        Ok(state.map(|s| Self::from_persisted(&s, config)))
    }
}

/// Status information for a circuit breaker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerStatus {
    pub subscription_id: Uuid,
    pub state: CircuitState,
    pub failure_count: u32,
    pub last_failure_at: Option<DateTime<Utc>>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub opened_at: Option<DateTime<Utc>>,
    pub recent_failures: Vec<FailureRecord>,
}

impl From<&CircuitBreaker> for CircuitBreakerStatus {
    fn from(cb: &CircuitBreaker) -> Self {
        Self {
            subscription_id: cb.subscription_id,
            state: cb.state,
            failure_count: cb.failure_count,
            last_failure_at: cb.last_failure_at,
            last_success_at: cb.last_success_at,
            opened_at: cb.opened_at,
            recent_failures: cb.recent_failures.clone(),
        }
    }
}

/// Registry for managing circuit breakers across all subscriptions.
#[derive(Clone)]
pub struct CircuitBreakerRegistry {
    breakers: Arc<RwLock<HashMap<Uuid, CircuitBreaker>>>,
    config: CircuitBreakerConfig,
    pool: PgPool,
}

impl CircuitBreakerRegistry {
    /// Create a new registry with the given configuration.
    #[must_use] 
    pub fn new(pool: PgPool, config: CircuitBreakerConfig) -> Self {
        Self {
            breakers: Arc::new(RwLock::new(HashMap::new())),
            config,
            pool,
        }
    }

    /// Get or create a circuit breaker for a subscription.
    ///
    /// Loads from database if not in memory, creates new if not found.
    pub async fn get_or_create(
        &self,
        tenant_id: Uuid,
        subscription_id: Uuid,
    ) -> Result<CircuitBreakerStatus, sqlx::Error> {
        // Check in-memory cache first
        {
            let breakers = self.breakers.read().await;
            if let Some(cb) = breakers.get(&subscription_id) {
                return Ok(CircuitBreakerStatus::from(cb));
            }
        }

        // Try to load from database
        let mut breakers = self.breakers.write().await;

        // Double-check after acquiring write lock
        if let Some(cb) = breakers.get(&subscription_id) {
            return Ok(CircuitBreakerStatus::from(cb));
        }

        // Load from database or create new
        let cb =
            match CircuitBreaker::load(&self.pool, tenant_id, subscription_id, self.config.clone())
                .await?
            {
                Some(cb) => cb,
                None => CircuitBreaker::new(subscription_id, tenant_id, self.config.clone()),
            };

        let status = CircuitBreakerStatus::from(&cb);
        breakers.insert(subscription_id, cb);

        Ok(status)
    }

    /// Check if a delivery can proceed for a subscription.
    pub async fn can_execute(
        &self,
        tenant_id: Uuid,
        subscription_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        // Ensure circuit breaker exists
        self.get_or_create(tenant_id, subscription_id).await?;

        let mut breakers = self.breakers.write().await;
        if let Some(cb) = breakers.get_mut(&subscription_id) {
            Ok(cb.can_execute())
        } else {
            // Should not happen after get_or_create
            Ok(true)
        }
    }

    /// Record a successful delivery.
    pub async fn record_success(
        &self,
        tenant_id: Uuid,
        subscription_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        self.get_or_create(tenant_id, subscription_id).await?;

        let mut breakers = self.breakers.write().await;
        if let Some(cb) = breakers.get_mut(&subscription_id) {
            cb.record_success();
            cb.save(&self.pool).await?;
        }

        Ok(())
    }

    /// Record a delivery failure.
    pub async fn record_failure(
        &self,
        tenant_id: Uuid,
        subscription_id: Uuid,
        failure: FailureRecord,
    ) -> Result<(), sqlx::Error> {
        self.get_or_create(tenant_id, subscription_id).await?;

        let mut breakers = self.breakers.write().await;
        if let Some(cb) = breakers.get_mut(&subscription_id) {
            cb.record_failure(failure);
            cb.save(&self.pool).await?;
        }

        Ok(())
    }

    /// Get status for a specific subscription's circuit breaker.
    pub async fn get_status(
        &self,
        tenant_id: Uuid,
        subscription_id: Uuid,
    ) -> Result<Option<CircuitBreakerStatus>, sqlx::Error> {
        // Check in-memory first
        {
            let breakers = self.breakers.read().await;
            if let Some(cb) = breakers.get(&subscription_id) {
                if cb.tenant_id() == tenant_id {
                    return Ok(Some(CircuitBreakerStatus::from(cb)));
                }
            }
        }

        // Try loading from database
        let cb = CircuitBreaker::load(&self.pool, tenant_id, subscription_id, self.config.clone())
            .await?;

        Ok(cb.map(|c| CircuitBreakerStatus::from(&c)))
    }

    /// Get status for all circuit breakers for a tenant.
    pub async fn get_all_status(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<CircuitBreakerStatus>, sqlx::Error> {
        let db_states = WebhookCircuitBreakerState::list_by_tenant(&self.pool, tenant_id).await?;

        let statuses: Vec<CircuitBreakerStatus> = db_states
            .iter()
            .map(|s| {
                let cb = CircuitBreaker::from_persisted(s, self.config.clone());
                CircuitBreakerStatus::from(&cb)
            })
            .collect();

        Ok(statuses)
    }

    /// Remove a circuit breaker from the registry (e.g., when subscription is deleted).
    pub async fn remove(&self, subscription_id: Uuid) {
        let mut breakers = self.breakers.write().await;
        breakers.remove(&subscription_id);
    }

    /// Clear all in-memory circuit breakers.
    pub async fn clear(&self) {
        let mut breakers = self.breakers.write().await;
        breakers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_state_default() {
        assert_eq!(CircuitState::default(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_state_round_trip() {
        for state in [
            CircuitState::Closed,
            CircuitState::Open,
            CircuitState::HalfOpen,
        ] {
            let s = state.as_str();
            let parsed = CircuitState::parse(s);
            assert_eq!(parsed, Some(state));
        }
    }

    #[test]
    fn test_circuit_state_invalid() {
        assert_eq!(CircuitState::parse("invalid"), None);
    }

    #[test]
    fn test_circuit_breaker_config_default() {
        let config = CircuitBreakerConfig::default();
        assert_eq!(config.failure_threshold, 5);
        assert_eq!(config.recovery_timeout_secs, 30);
        assert_eq!(config.max_failure_history, 10);
    }

    #[test]
    fn test_circuit_breaker_config_builder() {
        let config = CircuitBreakerConfig::default()
            .with_failure_threshold(10)
            .with_recovery_timeout(60)
            .with_max_failure_history(20);

        assert_eq!(config.failure_threshold, 10);
        assert_eq!(config.recovery_timeout_secs, 60);
        assert_eq!(config.max_failure_history, 20);
    }

    #[test]
    fn test_failure_record_new() {
        let record = FailureRecord::new("Test error".to_string(), Some(500), Some(100));
        assert_eq!(record.error, "Test error");
        assert_eq!(record.response_code, Some(500));
        assert_eq!(record.latency_ms, Some(100));
    }

    #[test]
    fn test_circuit_breaker_new() {
        let sub_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let cb = CircuitBreaker::new(sub_id, tenant_id, CircuitBreakerConfig::default());

        assert_eq!(cb.subscription_id(), sub_id);
        assert_eq!(cb.tenant_id(), tenant_id);
        assert_eq!(cb.state(), CircuitState::Closed);
        assert_eq!(cb.failure_count(), 0);
        assert!(cb.recent_failures().is_empty());
    }

    #[test]
    fn test_circuit_breaker_can_execute_closed() {
        let mut cb = CircuitBreaker::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            CircuitBreakerConfig::default(),
        );

        assert!(cb.can_execute());
    }

    #[test]
    fn test_circuit_breaker_opens_after_threshold() {
        let config = CircuitBreakerConfig::default().with_failure_threshold(3);
        let mut cb = CircuitBreaker::new(Uuid::new_v4(), Uuid::new_v4(), config);

        for i in 0..3 {
            cb.record_failure(FailureRecord::new(format!("Error {i}"), None, None));
        }

        assert_eq!(cb.state(), CircuitState::Open);
        assert_eq!(cb.failure_count(), 3);
        assert!(!cb.can_execute());
    }

    #[test]
    fn test_circuit_breaker_success_resets_count() {
        let config = CircuitBreakerConfig::default().with_failure_threshold(5);
        let mut cb = CircuitBreaker::new(Uuid::new_v4(), Uuid::new_v4(), config);

        cb.record_failure(FailureRecord::new("Error 1".to_string(), None, None));
        cb.record_failure(FailureRecord::new("Error 2".to_string(), None, None));
        assert_eq!(cb.failure_count(), 2);

        cb.record_success();
        assert_eq!(cb.failure_count(), 0);
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_breaker_half_open_success_closes() {
        let config = CircuitBreakerConfig::default().with_failure_threshold(1);
        let mut cb = CircuitBreaker::new(Uuid::new_v4(), Uuid::new_v4(), config);

        // Open the circuit
        cb.record_failure(FailureRecord::new("Error".to_string(), None, None));
        assert_eq!(cb.state(), CircuitState::Open);

        // Manually set to half-open (simulating timeout)
        cb.state = CircuitState::HalfOpen;

        // Successful probe should close
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert_eq!(cb.failure_count(), 0);
    }

    #[test]
    fn test_circuit_breaker_half_open_failure_reopens() {
        let config = CircuitBreakerConfig::default().with_failure_threshold(1);
        let mut cb = CircuitBreaker::new(Uuid::new_v4(), Uuid::new_v4(), config);

        // Open the circuit
        cb.record_failure(FailureRecord::new("Error".to_string(), None, None));
        assert_eq!(cb.state(), CircuitState::Open);

        // Manually set to half-open (simulating timeout)
        cb.state = CircuitState::HalfOpen;

        // Failed probe should reopen
        cb.record_failure(FailureRecord::new("Error 2".to_string(), None, None));
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn test_circuit_breaker_tracks_consecutive_failures() {
        let config = CircuitBreakerConfig::default().with_failure_threshold(5);
        let mut cb = CircuitBreaker::new(Uuid::new_v4(), Uuid::new_v4(), config);

        // Record 3 failures
        for _ in 0..3 {
            cb.record_failure(FailureRecord::new("Error".to_string(), None, None));
        }
        assert_eq!(cb.failure_count(), 3);
        assert_eq!(cb.state(), CircuitState::Closed);

        // Success resets
        cb.record_success();
        assert_eq!(cb.failure_count(), 0);

        // Record 2 more failures - still under threshold
        for _ in 0..2 {
            cb.record_failure(FailureRecord::new("Error".to_string(), None, None));
        }
        assert_eq!(cb.failure_count(), 2);
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_failure_history_bounded() {
        let config = CircuitBreakerConfig::default()
            .with_failure_threshold(100)
            .with_max_failure_history(3);
        let mut cb = CircuitBreaker::new(Uuid::new_v4(), Uuid::new_v4(), config);

        for i in 0..10 {
            cb.record_failure(FailureRecord::new(format!("Error {i}"), None, None));
        }

        assert_eq!(cb.recent_failures().len(), 3);
        assert_eq!(cb.recent_failures()[0].error, "Error 7");
        assert_eq!(cb.recent_failures()[2].error, "Error 9");
    }

    #[test]
    fn test_circuit_breaker_status_from() {
        let mut cb = CircuitBreaker::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            CircuitBreakerConfig::default(),
        );
        cb.record_failure(FailureRecord::new("Test".to_string(), Some(500), Some(100)));

        let status = CircuitBreakerStatus::from(&cb);
        assert_eq!(status.subscription_id, cb.subscription_id());
        assert_eq!(status.state, cb.state());
        assert_eq!(status.failure_count, cb.failure_count());
        assert_eq!(status.recent_failures.len(), 1);
    }
}
