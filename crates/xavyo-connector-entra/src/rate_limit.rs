//! Rate limiting for Microsoft Graph API requests.
//!
//! This module provides rate limit handling with exponential backoff, jitter,
//! and request queuing for the Microsoft Graph API.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerState};
use crate::metrics::RateLimitMetrics;
use crate::EntraError;

/// Configuration for rate limit handling.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Base delay for exponential backoff in milliseconds (default: 1000ms).
    pub base_delay_ms: u64,
    /// Maximum delay cap in milliseconds (default: 300000ms = 5 minutes).
    pub max_delay_ms: u64,
    /// Jitter factor as a fraction of delay (default: 0.25 = 25%).
    pub jitter_factor: f64,
    /// Maximum retry attempts for rate limited requests (default: 10).
    pub max_retries: u32,
    /// Failures required to open circuit breaker (default: 10).
    pub circuit_failure_threshold: u32,
    /// Window in seconds for counting failures (default: 300 = 5 minutes).
    pub circuit_failure_window_secs: u64,
    /// Duration in seconds circuit stays open (default: 30).
    pub circuit_open_duration_secs: u64,
    /// Maximum pending requests in queue (default: 100).
    pub queue_max_depth: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            base_delay_ms: 1000,
            max_delay_ms: 300_000, // 5 minutes
            jitter_factor: 0.25,
            max_retries: 10,
            circuit_failure_threshold: 10,
            circuit_failure_window_secs: 300, // 5 minutes
            circuit_open_duration_secs: 30,
            queue_max_depth: 100,
        }
    }
}

impl RateLimitConfig {
    /// Creates a new configuration with all defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a configuration optimized for testing (shorter delays).
    #[must_use]
    pub fn for_testing() -> Self {
        Self {
            base_delay_ms: 10,
            max_delay_ms: 100,
            jitter_factor: 0.25,
            max_retries: 3,
            circuit_failure_threshold: 3,
            circuit_failure_window_secs: 60,
            circuit_open_duration_secs: 1,
            queue_max_depth: 10,
        }
    }

    /// Validates the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.base_delay_ms == 0 {
            return Err("base_delay_ms must be > 0".to_string());
        }
        if self.max_delay_ms < self.base_delay_ms {
            return Err("max_delay_ms must be >= base_delay_ms".to_string());
        }
        if !(0.0..=1.0).contains(&self.jitter_factor) {
            return Err("jitter_factor must be in range [0.0, 1.0]".to_string());
        }
        Ok(())
    }
}

/// Internal state for rate limiting.
#[derive(Debug, Default)]
pub struct RateLimitState {
    /// Whether currently rate-limited.
    pub is_throttled: bool,
    /// Time until rate limit clears (from Retry-After header).
    pub retry_after_until: Option<Instant>,
    /// Count of consecutive 429 responses.
    pub consecutive_failures: u32,
    /// When the last 429 was received.
    pub last_failure_time: Option<Instant>,
}

impl RateLimitState {
    /// Records a rate limit failure (429 response).
    pub fn record_failure(&mut self) {
        self.is_throttled = true;
        self.consecutive_failures += 1;
        self.last_failure_time = Some(Instant::now());
    }

    /// Records a successful request, clearing throttle state.
    pub fn record_success(&mut self) {
        self.is_throttled = false;
        self.retry_after_until = None;
        self.consecutive_failures = 0;
    }

    /// Sets the retry-after time.
    pub fn set_retry_after(&mut self, seconds: u64) {
        self.retry_after_until = Some(Instant::now() + Duration::from_secs(seconds));
    }

    /// Checks if still within retry-after period.
    #[must_use]
    pub fn is_within_retry_after(&self) -> bool {
        self.retry_after_until
            .is_some_and(|until| Instant::now() < until)
    }
}

/// Rate limiter for Microsoft Graph API requests.
///
/// Provides:
/// - Retry-After header handling
/// - Exponential backoff with jitter
/// - Circuit breaker for sustained failures
/// - Request queuing during throttle periods
/// - Metrics exposure
#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    state: Arc<RwLock<RateLimitState>>,
    circuit_breaker: Arc<RwLock<CircuitBreaker>>,
    metrics: Arc<RwLock<RateLimitMetrics>>,
}

impl RateLimiter {
    /// Creates a new rate limiter with the given configuration.
    pub fn new(config: RateLimitConfig) -> Result<Self, String> {
        config.validate()?;

        let circuit_breaker = CircuitBreaker::new(
            config.circuit_failure_threshold,
            Duration::from_secs(config.circuit_failure_window_secs),
            Duration::from_secs(config.circuit_open_duration_secs),
        );

        Ok(Self {
            config,
            state: Arc::new(RwLock::new(RateLimitState::default())),
            circuit_breaker: Arc::new(RwLock::new(circuit_breaker)),
            metrics: Arc::new(RwLock::new(RateLimitMetrics::default())),
        })
    }

    /// Creates a rate limiter with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(RateLimitConfig::default()).expect("default config should be valid")
    }

    /// Returns the current configuration.
    #[must_use]
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }

    /// Checks if requests should be allowed through.
    pub async fn should_allow_request(&self) -> Result<(), EntraError> {
        // Check circuit breaker first
        let mut cb = self.circuit_breaker.write().await;
        if !cb.should_allow_request() {
            let mut metrics = self.metrics.write().await;
            metrics.increment_circuit_rejects();
            return Err(EntraError::CircuitOpen);
        }

        // Check if within retry-after period
        let state = self.state.read().await;
        if state.is_within_retry_after() {
            // Still throttled, but circuit allows - will queue
            debug!("Within retry-after period, request will wait");
        }

        Ok(())
    }

    /// Parses the Retry-After header value.
    #[must_use]
    pub fn parse_retry_after(header_value: &str) -> Option<u64> {
        // Retry-After can be either seconds or HTTP-date
        // We only support seconds format for simplicity
        header_value.trim().parse::<u64>().ok()
    }

    /// Calculates backoff delay with exponential growth.
    #[must_use]
    pub fn calculate_backoff_delay(&self, attempt: u32) -> Duration {
        let base = self.config.base_delay_ms as f64;
        let max = self.config.max_delay_ms as f64;

        // Calculate exponential delay: base * 2^attempt
        let delay_ms = (base * 2_f64.powi(attempt as i32)).min(max);

        Duration::from_millis(delay_ms as u64)
    }

    /// Adds jitter to a delay using the configured factor.
    #[must_use]
    pub fn add_jitter(&self, delay: Duration) -> Duration {
        use rand::Rng;

        let delay_ms = delay.as_millis() as f64;
        let jitter_range = delay_ms * self.config.jitter_factor;
        let jitter = rand::thread_rng().gen_range(0.0..=jitter_range);

        Duration::from_millis((delay_ms + jitter) as u64)
    }

    /// Waits for the retry period to elapse.
    pub async fn wait_for_retry(&self, retry_after_secs: Option<u64>, attempt: u32) {
        let delay = if let Some(secs) = retry_after_secs {
            // Use Retry-After header, but cap at max_delay
            let capped_secs = secs.min(self.config.max_delay_ms / 1000);
            if secs > capped_secs {
                warn!(
                    "Retry-After {} seconds exceeds max, capping at {} seconds",
                    secs, capped_secs
                );
            }
            Duration::from_secs(capped_secs)
        } else {
            // No header - use exponential backoff
            self.calculate_backoff_delay(attempt)
        };

        let delay_with_jitter = self.add_jitter(delay);
        info!(
            "Rate limited, waiting {:?} (attempt {})",
            delay_with_jitter, attempt
        );
        tokio::time::sleep(delay_with_jitter).await;
    }

    /// Handles a rate limit response (429).
    ///
    /// Returns the retry-after value in seconds if present, and whether to continue retrying.
    pub async fn handle_rate_limit_response(
        &self,
        retry_after_header: Option<&str>,
        attempt: u32,
    ) -> Result<bool, EntraError> {
        // Update state
        {
            let mut state = self.state.write().await;
            state.record_failure();
            if let Some(header) = retry_after_header {
                if let Some(secs) = Self::parse_retry_after(header) {
                    state.set_retry_after(secs);
                }
            }
        }

        // Update metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.increment_rate_limited();
        }

        // Record failure in circuit breaker
        {
            let mut cb = self.circuit_breaker.write().await;
            cb.record_failure();
            if cb.state() == CircuitBreakerState::Open {
                let mut metrics = self.metrics.write().await;
                metrics.increment_circuit_opens();
                return Err(EntraError::CircuitOpen);
            }
        }

        // Check if we've exceeded max retries
        if attempt >= self.config.max_retries {
            return Err(EntraError::MaxRetriesExceeded { attempts: attempt });
        }

        // Wait for retry period
        let retry_after_secs = retry_after_header.and_then(Self::parse_retry_after);
        self.wait_for_retry(retry_after_secs, attempt).await;

        // Update retry metrics
        {
            let mut metrics = self.metrics.write().await;
            metrics.increment_retries();
        }

        Ok(true) // Continue retrying
    }

    /// Records a successful request.
    pub async fn record_success(&self) {
        {
            let mut state = self.state.write().await;
            state.record_success();
        }
        {
            let mut cb = self.circuit_breaker.write().await;
            cb.record_success();
        }
        {
            let mut metrics = self.metrics.write().await;
            metrics.increment_total_requests();
        }
    }

    /// Returns whether currently throttled.
    pub async fn is_throttled(&self) -> bool {
        let state = self.state.read().await;
        state.is_throttled
    }

    /// Returns the current circuit breaker state.
    pub async fn circuit_state(&self) -> CircuitBreakerState {
        let cb = self.circuit_breaker.read().await;
        cb.state()
    }

    /// Returns a snapshot of current metrics.
    pub async fn get_metrics(&self) -> RateLimitMetrics {
        let metrics = self.metrics.read().await;
        metrics.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = RateLimitConfig::default();
        assert_eq!(config.base_delay_ms, 1000);
        assert_eq!(config.max_delay_ms, 300_000);
        assert_eq!(config.jitter_factor, 0.25);
        assert_eq!(config.max_retries, 10);
    }

    #[test]
    fn test_config_validation() {
        let mut config = RateLimitConfig::default();
        assert!(config.validate().is_ok());

        config.base_delay_ms = 0;
        assert!(config.validate().is_err());

        config.base_delay_ms = 1000;
        config.max_delay_ms = 500;
        assert!(config.validate().is_err());

        config.max_delay_ms = 300_000;
        config.jitter_factor = 1.5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_parse_retry_after() {
        assert_eq!(RateLimiter::parse_retry_after("60"), Some(60));
        assert_eq!(RateLimiter::parse_retry_after("  120  "), Some(120));
        assert_eq!(RateLimiter::parse_retry_after("invalid"), None);
        assert_eq!(RateLimiter::parse_retry_after(""), None);
    }

    #[test]
    fn test_calculate_backoff_delay() {
        let config = RateLimitConfig {
            base_delay_ms: 1000,
            max_delay_ms: 300_000,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config).unwrap();

        // Base delay for attempt 0
        assert_eq!(
            limiter.calculate_backoff_delay(0),
            Duration::from_millis(1000)
        );
        // 2x for attempt 1
        assert_eq!(
            limiter.calculate_backoff_delay(1),
            Duration::from_millis(2000)
        );
        // 4x for attempt 2
        assert_eq!(
            limiter.calculate_backoff_delay(2),
            Duration::from_millis(4000)
        );
        // 8x for attempt 3
        assert_eq!(
            limiter.calculate_backoff_delay(3),
            Duration::from_millis(8000)
        );
    }

    #[test]
    fn test_backoff_delay_capped() {
        let config = RateLimitConfig {
            base_delay_ms: 1000,
            max_delay_ms: 5000, // Cap at 5 seconds
            ..Default::default()
        };
        let limiter = RateLimiter::new(config).unwrap();

        // Attempt 10 would be 1024 seconds, but capped at 5 seconds
        assert_eq!(
            limiter.calculate_backoff_delay(10),
            Duration::from_millis(5000)
        );
    }

    #[test]
    fn test_jitter_adds_variance() {
        let config = RateLimitConfig::for_testing();
        let limiter = RateLimiter::new(config.clone()).unwrap();

        let base_delay = Duration::from_millis(1000);
        let max_jitter = (1000.0 * config.jitter_factor) as u64;

        // Run multiple times and verify delays are in expected range
        let mut delays = Vec::new();
        for _ in 0..100 {
            let delay = limiter.add_jitter(base_delay);
            let delay_ms = delay.as_millis() as u64;
            // Should be in range [base, base + max_jitter]
            assert!(delay_ms >= 1000, "delay {delay_ms} should be >= 1000");
            assert!(
                delay_ms <= 1000 + max_jitter,
                "delay {} should be <= {}",
                delay_ms,
                1000 + max_jitter
            );
            delays.push(delay_ms);
        }

        // Verify there's some variance (not all identical)
        let first = delays[0];
        let has_variance = delays.iter().any(|&d| d != first);
        assert!(has_variance, "jitter should produce varying delays");
    }

    #[test]
    fn test_state_failure_tracking() {
        let mut state = RateLimitState::default();
        assert!(!state.is_throttled);
        assert_eq!(state.consecutive_failures, 0);

        state.record_failure();
        assert!(state.is_throttled);
        assert_eq!(state.consecutive_failures, 1);

        state.record_failure();
        assert_eq!(state.consecutive_failures, 2);

        state.record_success();
        assert!(!state.is_throttled);
        assert_eq!(state.consecutive_failures, 0);
    }

    #[test]
    fn test_state_retry_after() {
        let mut state = RateLimitState::default();
        assert!(!state.is_within_retry_after());

        state.set_retry_after(1);
        assert!(state.is_within_retry_after());
    }

    #[tokio::test]
    async fn test_retry_after_header_honored() {
        let config = RateLimitConfig {
            base_delay_ms: 10,
            max_delay_ms: 1000,
            jitter_factor: 0.0, // No jitter for predictable timing
            max_retries: 10,
            circuit_failure_threshold: 100, // High threshold to avoid circuit opening
            circuit_failure_window_secs: 300,
            circuit_open_duration_secs: 1,
            queue_max_depth: 10,
        };
        let limiter = RateLimiter::new(config).unwrap();

        // Simulate rate limit with Retry-After: 0 (minimal wait)
        let start = Instant::now();
        let result = limiter.handle_rate_limit_response(Some("0"), 0).await;
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        // Should complete quickly with Retry-After: 0
        assert!(elapsed < Duration::from_millis(100), "elapsed {elapsed:?}");
    }

    #[tokio::test]
    async fn test_retry_succeeds_after_wait() {
        let config = RateLimitConfig::for_testing();
        let limiter = RateLimiter::new(config).unwrap();

        // First request hits rate limit
        let result = limiter.handle_rate_limit_response(Some("0"), 0).await;
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should continue retrying

        // Simulate successful retry
        limiter.record_success().await;

        // State should be cleared
        assert!(!limiter.is_throttled().await);
    }

    #[tokio::test]
    async fn test_base_delay_used_when_no_header() {
        let config = RateLimitConfig {
            base_delay_ms: 50, // Very short for testing
            max_delay_ms: 1000,
            jitter_factor: 0.0, // No jitter for predictable timing
            ..RateLimitConfig::for_testing()
        };
        let limiter = RateLimiter::new(config).unwrap();

        let start = Instant::now();
        let result = limiter.handle_rate_limit_response(None, 0).await;
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        // Should have waited approximately base_delay (50ms)
        assert!(elapsed >= Duration::from_millis(45), "elapsed {elapsed:?}");
        assert!(elapsed < Duration::from_millis(200), "elapsed {elapsed:?}");
    }

    #[tokio::test]
    async fn test_delay_doubles_on_consecutive_failures() {
        let config = RateLimitConfig {
            base_delay_ms: 20,
            max_delay_ms: 1000,
            jitter_factor: 0.0,
            max_retries: 10,
            circuit_failure_threshold: 100, // High threshold to avoid circuit opening
            circuit_failure_window_secs: 300,
            circuit_open_duration_secs: 1,
            queue_max_depth: 10,
        };
        let limiter = RateLimiter::new(config).unwrap();

        // First failure - 20ms (attempt 0: 20 * 2^0 = 20ms)
        let start = Instant::now();
        let _ = limiter.handle_rate_limit_response(None, 0).await;
        let elapsed1 = start.elapsed();

        // Second failure - 40ms (attempt 1: 20 * 2^1 = 40ms)
        let start = Instant::now();
        let _ = limiter.handle_rate_limit_response(None, 1).await;
        let elapsed2 = start.elapsed();

        // Third failure - 80ms (attempt 2: 20 * 2^2 = 80ms)
        let start = Instant::now();
        let _ = limiter.handle_rate_limit_response(None, 2).await;
        let elapsed3 = start.elapsed();

        // Verify exponential growth pattern
        assert!(elapsed1 >= Duration::from_millis(15), "e1: {elapsed1:?}");
        assert!(elapsed2 >= Duration::from_millis(35), "e2: {elapsed2:?}");
        assert!(elapsed3 >= Duration::from_millis(70), "e3: {elapsed3:?}");
        assert!(elapsed2 > elapsed1, "e2 should > e1");
        assert!(elapsed3 > elapsed2, "e3 should > e2");
    }

    #[tokio::test]
    async fn test_max_retries_exceeded() {
        let config = RateLimitConfig {
            base_delay_ms: 1,
            max_delay_ms: 10,
            max_retries: 3,
            jitter_factor: 0.0,
            circuit_failure_threshold: 100, // High threshold to avoid circuit opening
            circuit_failure_window_secs: 300,
            circuit_open_duration_secs: 1,
            queue_max_depth: 10,
        };
        let limiter = RateLimiter::new(config).unwrap();

        // Attempt 3 should fail (max_retries = 3, attempts start at 0)
        let result = limiter.handle_rate_limit_response(None, 3).await;
        assert!(matches!(
            result,
            Err(EntraError::MaxRetriesExceeded { attempts: 3 })
        ));
    }

    #[tokio::test]
    async fn test_metrics_track_rate_limited_count() {
        let config = RateLimitConfig::for_testing();
        let limiter = RateLimiter::new(config).unwrap();

        let metrics_before = limiter.get_metrics().await;
        assert_eq!(metrics_before.rate_limited_count, 0);

        // Hit rate limit
        let _ = limiter.handle_rate_limit_response(Some("0"), 0).await;

        let metrics_after = limiter.get_metrics().await;
        assert_eq!(metrics_after.rate_limited_count, 1);
    }

    #[tokio::test]
    async fn test_metrics_track_retry_count() {
        let config = RateLimitConfig::for_testing();
        let limiter = RateLimiter::new(config).unwrap();

        // Hit rate limit and retry
        let _ = limiter.handle_rate_limit_response(Some("0"), 0).await;
        let _ = limiter.handle_rate_limit_response(Some("0"), 1).await;

        let metrics = limiter.get_metrics().await;
        assert_eq!(metrics.retry_count, 2);
    }
}
