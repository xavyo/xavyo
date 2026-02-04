//! Resilience patterns for connector operations.
//!
//! Provides circuit breaker and retry logic with exponential backoff.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::error::{ConnectorError, ConnectorResult};
use crate::ids::ConnectorId;
use crate::types::CircuitState;

/// Configuration for circuit breaker behavior.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening the circuit.
    pub failure_threshold: u32,
    /// Duration the circuit stays open before transitioning to half-open.
    pub open_duration: Duration,
    /// Number of successful probes required to close the circuit.
    pub success_threshold: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_duration: Duration::from_secs(30),
            success_threshold: 2,
        }
    }
}

/// Circuit breaker for protecting connector operations.
///
/// Implements the circuit breaker pattern to prevent cascading failures
/// when a connector's target system is unavailable.
#[derive(Debug)]
pub struct CircuitBreaker {
    connector_id: ConnectorId,
    config: CircuitBreakerConfig,
    state: RwLock<CircuitState>,
    failure_count: AtomicU32,
    success_count: AtomicU32,
    last_failure_time: AtomicU64,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given configuration.
    #[must_use] 
    pub fn new(connector_id: ConnectorId, config: CircuitBreakerConfig) -> Self {
        Self {
            connector_id,
            config,
            state: RwLock::new(CircuitState::Closed),
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            last_failure_time: AtomicU64::new(0),
        }
    }

    /// Create a new circuit breaker with default configuration.
    #[must_use] 
    pub fn with_defaults(connector_id: ConnectorId) -> Self {
        Self::new(connector_id, CircuitBreakerConfig::default())
    }

    /// Get the connector ID this circuit breaker is protecting.
    pub fn connector_id(&self) -> ConnectorId {
        self.connector_id
    }

    /// Get the current circuit state.
    pub async fn state(&self) -> CircuitState {
        self.maybe_transition_to_half_open().await;
        *self.state.read().await
    }

    /// Check if operations are currently allowed.
    pub async fn is_allowed(&self) -> bool {
        self.state().await.allows_operations()
    }

    /// Record a successful operation.
    pub async fn record_success(&self) {
        let mut state = self.state.write().await;

        match *state {
            CircuitState::Closed => {
                // Reset failure count on success
                self.failure_count.store(0, Ordering::SeqCst);
            }
            CircuitState::HalfOpen => {
                let count = self.success_count.fetch_add(1, Ordering::SeqCst) + 1;
                if count >= self.config.success_threshold {
                    debug!(
                        "Circuit breaker transitioning to CLOSED after {} successes",
                        count
                    );
                    *state = CircuitState::Closed;
                    self.failure_count.store(0, Ordering::SeqCst);
                    self.success_count.store(0, Ordering::SeqCst);
                }
            }
            CircuitState::Open => {
                // Shouldn't happen, but reset if it does
            }
        }
    }

    /// Record a failed operation.
    pub async fn record_failure(&self) {
        let mut state = self.state.write().await;

        match *state {
            CircuitState::Closed => {
                let count = self.failure_count.fetch_add(1, Ordering::SeqCst) + 1;
                if count >= self.config.failure_threshold {
                    warn!(
                        "Circuit breaker transitioning to OPEN after {} failures",
                        count
                    );
                    *state = CircuitState::Open;
                    self.last_failure_time
                        .store(Instant::now().elapsed().as_secs(), Ordering::SeqCst);
                    // Store current time as Unix timestamp approximation
                    self.last_failure_time.store(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        Ordering::SeqCst,
                    );
                }
            }
            CircuitState::HalfOpen => {
                warn!("Circuit breaker transitioning back to OPEN after probe failure");
                *state = CircuitState::Open;
                self.success_count.store(0, Ordering::SeqCst);
                self.last_failure_time.store(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    Ordering::SeqCst,
                );
            }
            CircuitState::Open => {
                // Already open, update timestamp
                self.last_failure_time.store(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    Ordering::SeqCst,
                );
            }
        }
    }

    /// Check if we should transition from Open to `HalfOpen`.
    async fn maybe_transition_to_half_open(&self) {
        let state = *self.state.read().await;
        if state != CircuitState::Open {
            return;
        }

        let last_failure = self.last_failure_time.load(Ordering::SeqCst);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now.saturating_sub(last_failure) >= self.config.open_duration.as_secs() {
            let mut state = self.state.write().await;
            if *state == CircuitState::Open {
                debug!("Circuit breaker transitioning to HALF_OPEN");
                *state = CircuitState::HalfOpen;
                self.success_count.store(0, Ordering::SeqCst);
            }
        }
    }

    /// Execute an operation with circuit breaker protection.
    pub async fn execute<F, Fut, T>(&self, operation: F) -> ConnectorResult<T>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = ConnectorResult<T>>,
    {
        if !self.is_allowed().await {
            return Err(ConnectorError::CircuitOpen {
                connector_id: self.connector_id,
            });
        }

        match operation().await {
            Ok(result) => {
                self.record_success().await;
                Ok(result)
            }
            Err(e) => {
                if e.is_transient() {
                    self.record_failure().await;
                }
                Err(e)
            }
        }
    }

    /// Reset the circuit breaker to closed state.
    pub async fn reset(&self) {
        let mut state = self.state.write().await;
        *state = CircuitState::Closed;
        self.failure_count.store(0, Ordering::SeqCst);
        self.success_count.store(0, Ordering::SeqCst);
    }
}

/// Configuration for retry behavior.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts.
    pub max_retries: u32,
    /// Initial delay before first retry.
    pub initial_delay: Duration,
    /// Maximum delay between retries.
    pub max_delay: Duration,
    /// Multiplier for exponential backoff.
    pub backoff_multiplier: f64,
    /// Whether to add jitter to delays.
    pub jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            backoff_multiplier: 2.0,
            jitter: true,
        }
    }
}

/// Retry executor with exponential backoff.
#[derive(Debug, Clone)]
pub struct RetryExecutor {
    config: RetryConfig,
}

impl RetryExecutor {
    /// Create a new retry executor with the given configuration.
    #[must_use] 
    pub fn new(config: RetryConfig) -> Self {
        Self { config }
    }

    /// Create a new retry executor with default configuration.
    #[must_use] 
    pub fn with_defaults() -> Self {
        Self::new(RetryConfig::default())
    }

    /// Calculate delay for a given attempt (0-indexed).
    fn calculate_delay(&self, attempt: u32) -> Duration {
        let base_delay = self.config.initial_delay.as_millis() as f64
            * self.config.backoff_multiplier.powi(attempt as i32);

        let delay_ms = base_delay.min(self.config.max_delay.as_millis() as f64);

        let final_delay = if self.config.jitter {
            // Add up to 25% jitter
            let jitter_factor = 1.0 + (rand_simple() * 0.25);
            delay_ms * jitter_factor
        } else {
            delay_ms
        };

        Duration::from_millis(final_delay as u64)
    }

    /// Execute an operation with retries.
    pub async fn execute<F, Fut, T>(&self, mut operation: F) -> ConnectorResult<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = ConnectorResult<T>>,
    {
        let mut last_error = None;

        for attempt in 0..=self.config.max_retries {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if !e.is_transient() || attempt == self.config.max_retries {
                        return Err(e);
                    }

                    let delay = self.calculate_delay(attempt);
                    debug!(
                        attempt = attempt + 1,
                        max_retries = self.config.max_retries,
                        delay_ms = delay.as_millis(),
                        error = %e,
                        "Retrying after transient error"
                    );

                    tokio::time::sleep(delay).await;
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| ConnectorError::operation_failed("Max retries exceeded")))
    }

    /// Execute an operation with retries and circuit breaker protection.
    pub async fn execute_with_circuit_breaker<F, Fut, T>(
        &self,
        circuit_breaker: &CircuitBreaker,
        mut operation: F,
    ) -> ConnectorResult<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = ConnectorResult<T>>,
    {
        let mut last_error = None;

        for attempt in 0..=self.config.max_retries {
            match circuit_breaker.execute(&mut operation).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    // Don't retry if circuit is open
                    if matches!(e, ConnectorError::CircuitOpen { .. }) {
                        return Err(e);
                    }

                    if !e.is_transient() || attempt == self.config.max_retries {
                        return Err(e);
                    }

                    let delay = self.calculate_delay(attempt);
                    debug!(
                        attempt = attempt + 1,
                        max_retries = self.config.max_retries,
                        delay_ms = delay.as_millis(),
                        error = %e,
                        "Retrying after transient error"
                    );

                    tokio::time::sleep(delay).await;
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| ConnectorError::operation_failed("Max retries exceeded")))
    }
}

/// Simple pseudo-random number generator for jitter.
/// Not cryptographically secure, but sufficient for jitter.
fn rand_simple() -> f64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let state = RandomState::new();
    let mut hasher = state.build_hasher();
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64,
    );
    (hasher.finish() as f64) / (u64::MAX as f64)
}

/// Resilient connector wrapper that adds circuit breaker and retry logic.
#[derive(Debug)]
pub struct ResilientConnector<C> {
    inner: C,
    circuit_breaker: Arc<CircuitBreaker>,
    retry_executor: RetryExecutor,
}

impl<C> ResilientConnector<C> {
    /// Create a new resilient connector wrapper.
    pub fn new(connector_id: ConnectorId, connector: C) -> Self {
        Self {
            inner: connector,
            circuit_breaker: Arc::new(CircuitBreaker::with_defaults(connector_id)),
            retry_executor: RetryExecutor::with_defaults(),
        }
    }

    /// Create with custom configuration.
    pub fn with_config(
        connector_id: ConnectorId,
        connector: C,
        circuit_config: CircuitBreakerConfig,
        retry_config: RetryConfig,
    ) -> Self {
        Self {
            inner: connector,
            circuit_breaker: Arc::new(CircuitBreaker::new(connector_id, circuit_config)),
            retry_executor: RetryExecutor::new(retry_config),
        }
    }

    /// Get a reference to the inner connector.
    pub fn inner(&self) -> &C {
        &self.inner
    }

    /// Get the circuit breaker.
    pub fn circuit_breaker(&self) -> &CircuitBreaker {
        &self.circuit_breaker
    }

    /// Get the retry executor.
    pub fn retry_executor(&self) -> &RetryExecutor {
        &self.retry_executor
    }

    /// Execute an operation with resilience (retry + circuit breaker).
    pub async fn execute<F, Fut, T>(&self, operation: F) -> ConnectorResult<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = ConnectorResult<T>>,
    {
        self.retry_executor
            .execute_with_circuit_breaker(&self.circuit_breaker, operation)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[tokio::test]
    async fn test_circuit_breaker_starts_closed() {
        let cb = CircuitBreaker::with_defaults(ConnectorId::new());
        assert_eq!(cb.state().await, CircuitState::Closed);
        assert!(cb.is_allowed().await);
    }

    #[tokio::test]
    async fn test_circuit_breaker_opens_after_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            open_duration: Duration::from_secs(1),
            success_threshold: 1,
        };
        let cb = CircuitBreaker::new(ConnectorId::new(), config);

        // Record failures
        cb.record_failure().await;
        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Closed);

        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Open);
        assert!(!cb.is_allowed().await);
    }

    #[tokio::test]
    async fn test_circuit_breaker_success_resets_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            open_duration: Duration::from_secs(1),
            success_threshold: 1,
        };
        let cb = CircuitBreaker::new(ConnectorId::new(), config);

        cb.record_failure().await;
        cb.record_failure().await;
        cb.record_success().await;

        // Success should reset failure count
        cb.record_failure().await;
        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_circuit_breaker_reset() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_secs(60),
            success_threshold: 1,
        };
        let cb = CircuitBreaker::new(ConnectorId::new(), config);

        cb.record_failure().await;
        assert_eq!(cb.state().await, CircuitState::Open);

        cb.reset().await;
        assert_eq!(cb.state().await, CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_retry_executor_succeeds_first_try() {
        let executor = RetryExecutor::with_defaults();
        let call_count = AtomicUsize::new(0);

        let result = executor
            .execute(|| {
                call_count.fetch_add(1, Ordering::SeqCst);
                async { Ok::<_, ConnectorError>(42) }
            })
            .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_retry_executor_retries_on_transient_error() {
        let config = RetryConfig {
            max_retries: 3,
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(10),
            backoff_multiplier: 2.0,
            jitter: false,
        };
        let executor = RetryExecutor::new(config);
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        let result = executor
            .execute(move || {
                let count = call_count_clone.fetch_add(1, Ordering::SeqCst);
                async move {
                    if count < 2 {
                        Err(ConnectorError::TargetUnavailable {
                            message: "temporarily unavailable".to_string(),
                        })
                    } else {
                        Ok(42)
                    }
                }
            })
            .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_retry_executor_fails_on_permanent_error() {
        let executor = RetryExecutor::with_defaults();
        let call_count = AtomicUsize::new(0);

        let result: ConnectorResult<i32> = executor
            .execute(|| {
                call_count.fetch_add(1, Ordering::SeqCst);
                async {
                    Err(ConnectorError::InvalidConfiguration {
                        message: "permanent error".to_string(),
                    })
                }
            })
            .await;

        assert!(result.is_err());
        // Should not retry permanent errors
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_calculate_delay_exponential_backoff() {
        let config = RetryConfig {
            max_retries: 5,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            backoff_multiplier: 2.0,
            jitter: false,
        };
        let executor = RetryExecutor::new(config);

        assert_eq!(executor.calculate_delay(0), Duration::from_millis(100));
        assert_eq!(executor.calculate_delay(1), Duration::from_millis(200));
        assert_eq!(executor.calculate_delay(2), Duration::from_millis(400));
        assert_eq!(executor.calculate_delay(3), Duration::from_millis(800));
    }

    #[tokio::test]
    async fn test_calculate_delay_respects_max() {
        let config = RetryConfig {
            max_retries: 10,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(500),
            backoff_multiplier: 2.0,
            jitter: false,
        };
        let executor = RetryExecutor::new(config);

        // 100 * 2^5 = 3200, should be capped at 500
        assert_eq!(executor.calculate_delay(5), Duration::from_millis(500));
    }

    #[tokio::test]
    async fn test_circuit_breaker_execute() {
        let cb = CircuitBreaker::with_defaults(ConnectorId::new());

        let result = cb.execute(|| async { Ok::<_, ConnectorError>(42) }).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_circuit_breaker_rejects_when_open() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_secs(60),
            success_threshold: 1,
        };
        let cb = CircuitBreaker::new(ConnectorId::new(), config);

        // Open the circuit
        let _ = cb
            .execute(|| async {
                Err::<(), _>(ConnectorError::TargetUnavailable {
                    message: "down".to_string(),
                })
            })
            .await;

        // Next call should be rejected
        let result = cb.execute(|| async { Ok::<_, ConnectorError>(42) }).await;

        assert!(matches!(result, Err(ConnectorError::CircuitOpen { .. })));
    }
}
