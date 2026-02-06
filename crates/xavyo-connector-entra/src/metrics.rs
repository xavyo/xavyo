//! Rate limiting metrics for observability.
//!
//! Exposes metrics for monitoring rate limit state, retry counts,
//! and circuit breaker status.

use std::time::Instant;

use crate::circuit_breaker::CircuitBreakerState;

/// Metrics exposed by the rate limiter.
#[derive(Debug, Clone)]
pub struct RateLimitMetrics {
    /// Total requests processed.
    pub total_requests: u64,
    /// Count of 429 responses received.
    pub rate_limited_count: u64,
    /// Total retry attempts made.
    pub retry_count: u64,
    /// Times circuit breaker has opened.
    pub circuit_opens: u64,
    /// Current circuit breaker state.
    pub current_circuit_state: CircuitBreakerState,
    /// Requests rejected by circuit breaker.
    pub circuit_rejects: u64,
    /// Current queue depth.
    pub current_queue_depth: usize,
    /// Sum of all retry delays in milliseconds (for average calculation).
    total_retry_delay_ms: u64,
    /// When the last rate limit occurred.
    pub last_rate_limit_time: Option<Instant>,
}

impl Default for RateLimitMetrics {
    fn default() -> Self {
        Self {
            total_requests: 0,
            rate_limited_count: 0,
            retry_count: 0,
            circuit_opens: 0,
            current_circuit_state: CircuitBreakerState::Closed,
            circuit_rejects: 0,
            current_queue_depth: 0,
            total_retry_delay_ms: 0,
            last_rate_limit_time: None,
        }
    }
}

impl RateLimitMetrics {
    /// Creates new metrics with default values.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Increments the total request counter.
    pub fn increment_total_requests(&mut self) {
        self.total_requests += 1;
    }

    /// Increments the rate limited counter.
    pub fn increment_rate_limited(&mut self) {
        self.rate_limited_count += 1;
        self.last_rate_limit_time = Some(Instant::now());
    }

    /// Increments the retry counter.
    pub fn increment_retries(&mut self) {
        self.retry_count += 1;
    }

    /// Increments the circuit opens counter.
    pub fn increment_circuit_opens(&mut self) {
        self.circuit_opens += 1;
    }

    /// Increments the circuit rejects counter.
    pub fn increment_circuit_rejects(&mut self) {
        self.circuit_rejects += 1;
    }

    /// Records a retry delay for average calculation.
    pub fn record_retry_delay(&mut self, delay_ms: u64) {
        self.total_retry_delay_ms += delay_ms;
    }

    /// Sets the current circuit state.
    pub fn set_circuit_state(&mut self, state: CircuitBreakerState) {
        self.current_circuit_state = state;
    }

    /// Sets the current queue depth.
    pub fn set_queue_depth(&mut self, depth: usize) {
        self.current_queue_depth = depth;
    }

    /// Returns the average retry delay in milliseconds.
    #[must_use]
    pub fn average_retry_delay_ms(&self) -> f64 {
        if self.retry_count == 0 {
            0.0
        } else {
            self.total_retry_delay_ms as f64 / self.retry_count as f64
        }
    }

    /// Returns the rate limit ratio (`rate_limited` / total).
    #[must_use]
    pub fn rate_limit_ratio(&self) -> f64 {
        if self.total_requests == 0 {
            0.0
        } else {
            self.rate_limited_count as f64 / self.total_requests as f64
        }
    }

    /// Returns time since last rate limit, if any.
    #[must_use]
    pub fn time_since_last_rate_limit(&self) -> Option<std::time::Duration> {
        self.last_rate_limit_time.map(|t| t.elapsed())
    }

    /// Resets all metrics to zero.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_metrics() {
        let metrics = RateLimitMetrics::default();
        assert_eq!(metrics.total_requests, 0);
        assert_eq!(metrics.rate_limited_count, 0);
        assert_eq!(metrics.retry_count, 0);
        assert_eq!(metrics.circuit_opens, 0);
        assert_eq!(metrics.current_circuit_state, CircuitBreakerState::Closed);
    }

    #[test]
    fn test_metrics_track_rate_limited_count() {
        let mut metrics = RateLimitMetrics::new();
        assert_eq!(metrics.rate_limited_count, 0);

        metrics.increment_rate_limited();
        assert_eq!(metrics.rate_limited_count, 1);

        metrics.increment_rate_limited();
        metrics.increment_rate_limited();
        assert_eq!(metrics.rate_limited_count, 3);
    }

    #[test]
    fn test_metrics_track_retry_count() {
        let mut metrics = RateLimitMetrics::new();
        assert_eq!(metrics.retry_count, 0);

        metrics.increment_retries();
        assert_eq!(metrics.retry_count, 1);

        metrics.increment_retries();
        assert_eq!(metrics.retry_count, 2);
    }

    #[test]
    fn test_metrics_expose_circuit_state() {
        let mut metrics = RateLimitMetrics::new();
        assert_eq!(metrics.current_circuit_state, CircuitBreakerState::Closed);

        metrics.set_circuit_state(CircuitBreakerState::Open);
        assert_eq!(metrics.current_circuit_state, CircuitBreakerState::Open);

        metrics.set_circuit_state(CircuitBreakerState::HalfOpen);
        assert_eq!(metrics.current_circuit_state, CircuitBreakerState::HalfOpen);
    }

    #[test]
    fn test_average_retry_delay() {
        let mut metrics = RateLimitMetrics::new();

        // No retries yet
        assert_eq!(metrics.average_retry_delay_ms(), 0.0);

        // Record some delays
        metrics.increment_retries();
        metrics.record_retry_delay(100);
        metrics.increment_retries();
        metrics.record_retry_delay(200);
        metrics.increment_retries();
        metrics.record_retry_delay(300);

        // Average of 100, 200, 300 = 200
        assert_eq!(metrics.average_retry_delay_ms(), 200.0);
    }

    #[test]
    fn test_rate_limit_ratio() {
        let mut metrics = RateLimitMetrics::new();

        // No requests yet
        assert_eq!(metrics.rate_limit_ratio(), 0.0);

        // 10 requests, 2 rate limited
        for _ in 0..10 {
            metrics.increment_total_requests();
        }
        metrics.increment_rate_limited();
        metrics.increment_rate_limited();

        assert_eq!(metrics.rate_limit_ratio(), 0.2);
    }

    #[test]
    fn test_last_rate_limit_time() {
        let mut metrics = RateLimitMetrics::new();
        assert!(metrics.last_rate_limit_time.is_none());
        assert!(metrics.time_since_last_rate_limit().is_none());

        metrics.increment_rate_limited();
        assert!(metrics.last_rate_limit_time.is_some());
        assert!(metrics.time_since_last_rate_limit().is_some());
    }

    #[test]
    fn test_circuit_opens_tracking() {
        let mut metrics = RateLimitMetrics::new();
        assert_eq!(metrics.circuit_opens, 0);

        metrics.increment_circuit_opens();
        assert_eq!(metrics.circuit_opens, 1);

        metrics.increment_circuit_opens();
        assert_eq!(metrics.circuit_opens, 2);
    }

    #[test]
    fn test_circuit_rejects_tracking() {
        let mut metrics = RateLimitMetrics::new();
        assert_eq!(metrics.circuit_rejects, 0);

        metrics.increment_circuit_rejects();
        metrics.increment_circuit_rejects();
        metrics.increment_circuit_rejects();
        assert_eq!(metrics.circuit_rejects, 3);
    }

    #[test]
    fn test_queue_depth_tracking() {
        let mut metrics = RateLimitMetrics::new();
        assert_eq!(metrics.current_queue_depth, 0);

        metrics.set_queue_depth(5);
        assert_eq!(metrics.current_queue_depth, 5);

        metrics.set_queue_depth(10);
        assert_eq!(metrics.current_queue_depth, 10);
    }

    #[test]
    fn test_reset() {
        let mut metrics = RateLimitMetrics::new();
        metrics.increment_total_requests();
        metrics.increment_rate_limited();
        metrics.increment_retries();
        metrics.increment_circuit_opens();

        metrics.reset();

        assert_eq!(metrics.total_requests, 0);
        assert_eq!(metrics.rate_limited_count, 0);
        assert_eq!(metrics.retry_count, 0);
        assert_eq!(metrics.circuit_opens, 0);
    }
}
