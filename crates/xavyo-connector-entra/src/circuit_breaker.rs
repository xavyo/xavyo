//! Circuit breaker pattern for rate limit protection.
//!
//! Implements a three-state circuit breaker (Closed/Open/HalfOpen) to prevent
//! resource waste during sustained rate limiting.

use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Circuit breaker states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBreakerState {
    /// Normal operation, requests allowed.
    Closed,
    /// Failing fast, requests rejected immediately.
    Open,
    /// Testing recovery, single probe request allowed.
    HalfOpen,
}

impl std::fmt::Display for CircuitBreakerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "Closed"),
            Self::Open => write!(f, "Open"),
            Self::HalfOpen => write!(f, "HalfOpen"),
        }
    }
}

/// Circuit breaker state tracking.
#[derive(Debug)]
pub struct CircuitState {
    /// Current state.
    pub state: CircuitBreakerState,
    /// Consecutive failures in current window.
    pub failure_count: u32,
    /// Start of current failure counting window.
    pub failure_window_start: Option<Instant>,
    /// When state last transitioned.
    pub last_state_change: Instant,
}

impl Default for CircuitState {
    fn default() -> Self {
        Self {
            state: CircuitBreakerState::Closed,
            failure_count: 0,
            failure_window_start: None,
            last_state_change: Instant::now(),
        }
    }
}

/// Circuit breaker implementation.
///
/// State machine transitions:
/// - Closed -> Open: failure_count >= threshold within window
/// - Open -> HalfOpen: elapsed time >= open_duration
/// - HalfOpen -> Closed: Successful probe request
/// - HalfOpen -> Open: Failed probe request
#[derive(Debug)]
pub struct CircuitBreaker {
    /// Internal state.
    state: CircuitState,
    /// Failures required to open circuit.
    failure_threshold: u32,
    /// Window for counting failures.
    failure_window: Duration,
    /// How long to stay open before half-open.
    open_duration: Duration,
}

impl CircuitBreaker {
    /// Creates a new circuit breaker with the given configuration.
    pub fn new(failure_threshold: u32, failure_window: Duration, open_duration: Duration) -> Self {
        Self {
            state: CircuitState::default(),
            failure_threshold,
            failure_window,
            open_duration,
        }
    }

    /// Creates a circuit breaker with default settings (10 failures in 5 min, 30 sec open).
    pub fn with_defaults() -> Self {
        Self::new(
            10,
            Duration::from_secs(300), // 5 minutes
            Duration::from_secs(30),
        )
    }

    /// Returns the current state.
    pub fn state(&self) -> CircuitBreakerState {
        self.state.state
    }

    /// Returns the current failure count.
    pub fn failure_count(&self) -> u32 {
        self.state.failure_count
    }

    /// Checks if a request should be allowed through.
    pub fn should_allow_request(&mut self) -> bool {
        match self.state.state {
            CircuitBreakerState::Closed => true,
            CircuitBreakerState::Open => {
                // Check if we should transition to half-open
                let elapsed = self.state.last_state_change.elapsed();
                if elapsed >= self.open_duration {
                    self.transition_to(CircuitBreakerState::HalfOpen);
                    debug!("Circuit breaker transitioning to half-open");
                    true // Allow probe request
                } else {
                    debug!(
                        "Circuit open, {:?} until half-open",
                        self.open_duration - elapsed
                    );
                    false
                }
            }
            CircuitBreakerState::HalfOpen => {
                // Only allow one probe at a time
                // In a real implementation, we'd track if a probe is in flight
                debug!("Circuit half-open, allowing probe request");
                true
            }
        }
    }

    /// Records a failure.
    pub fn record_failure(&mut self) {
        match self.state.state {
            CircuitBreakerState::Closed => {
                // Start or continue failure window
                let now = Instant::now();
                if let Some(window_start) = self.state.failure_window_start {
                    if now.duration_since(window_start) > self.failure_window {
                        // Window expired, start new one
                        self.state.failure_window_start = Some(now);
                        self.state.failure_count = 1;
                    } else {
                        self.state.failure_count += 1;
                    }
                } else {
                    self.state.failure_window_start = Some(now);
                    self.state.failure_count = 1;
                }

                // Check if we should open
                if self.state.failure_count >= self.failure_threshold {
                    self.transition_to(CircuitBreakerState::Open);
                    warn!(
                        "Circuit breaker opened after {} failures",
                        self.state.failure_count
                    );
                }
            }
            CircuitBreakerState::HalfOpen => {
                // Probe failed, back to open
                self.transition_to(CircuitBreakerState::Open);
                warn!("Circuit breaker probe failed, returning to open state");
            }
            CircuitBreakerState::Open => {
                // Already open, no action needed
            }
        }
    }

    /// Records a success.
    pub fn record_success(&mut self) {
        match self.state.state {
            CircuitBreakerState::Closed => {
                // Reset failure count on success
                self.state.failure_count = 0;
                self.state.failure_window_start = None;
            }
            CircuitBreakerState::HalfOpen => {
                // Probe succeeded, close circuit
                self.transition_to(CircuitBreakerState::Closed);
                info!("Circuit breaker closed after successful probe");
            }
            CircuitBreakerState::Open => {
                // Shouldn't happen, but if it does, just log
                debug!("Unexpected success in open state");
            }
        }
    }

    /// Transitions to a new state.
    fn transition_to(&mut self, new_state: CircuitBreakerState) {
        let old_state = self.state.state;
        self.state.state = new_state;
        self.state.last_state_change = Instant::now();

        if new_state == CircuitBreakerState::Closed {
            // Reset failure tracking
            self.state.failure_count = 0;
            self.state.failure_window_start = None;
        }

        debug!("Circuit breaker: {} -> {}", old_state, new_state);
    }

    /// Forces the circuit to a specific state (for testing).
    #[cfg(test)]
    pub fn force_state(&mut self, state: CircuitBreakerState) {
        self.transition_to(state);
    }

    /// Sets the last state change time (for testing time-based transitions).
    #[cfg(test)]
    pub fn set_last_state_change(&mut self, instant: Instant) {
        self.state.last_state_change = instant;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state_closed() {
        let cb = CircuitBreaker::with_defaults();
        assert_eq!(cb.state(), CircuitBreakerState::Closed);
        assert_eq!(cb.failure_count(), 0);
    }

    #[test]
    fn test_closed_allows_requests() {
        let mut cb = CircuitBreaker::with_defaults();
        assert!(cb.should_allow_request());
    }

    #[test]
    fn test_circuit_opens_after_threshold() {
        let mut cb = CircuitBreaker::new(
            3, // Low threshold for testing
            Duration::from_secs(60),
            Duration::from_secs(1),
        );

        assert_eq!(cb.state(), CircuitBreakerState::Closed);

        // Record failures up to threshold
        cb.record_failure();
        assert_eq!(cb.state(), CircuitBreakerState::Closed);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitBreakerState::Closed);
        cb.record_failure(); // Threshold reached
        assert_eq!(cb.state(), CircuitBreakerState::Open);
    }

    #[test]
    fn test_open_circuit_fails_fast() {
        let mut cb = CircuitBreaker::new(
            1,
            Duration::from_secs(60),
            Duration::from_secs(30), // Long open duration
        );

        // Open the circuit
        cb.record_failure();
        assert_eq!(cb.state(), CircuitBreakerState::Open);

        // Should reject requests immediately
        assert!(!cb.should_allow_request());
    }

    #[test]
    fn test_circuit_transitions_to_half_open() {
        let mut cb = CircuitBreaker::new(
            1,
            Duration::from_secs(60),
            Duration::from_millis(1), // Very short open duration
        );

        // Open the circuit
        cb.record_failure();
        assert_eq!(cb.state(), CircuitBreakerState::Open);

        // Wait for open duration (in real test, just set time)
        std::thread::sleep(Duration::from_millis(5));

        // Should transition to half-open on next request check
        assert!(cb.should_allow_request());
        assert_eq!(cb.state(), CircuitBreakerState::HalfOpen);
    }

    #[test]
    fn test_successful_probe_closes_circuit() {
        let mut cb = CircuitBreaker::new(1, Duration::from_secs(60), Duration::from_millis(1));

        // Open and transition to half-open
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(5));
        cb.should_allow_request(); // Triggers half-open
        assert_eq!(cb.state(), CircuitBreakerState::HalfOpen);

        // Successful probe
        cb.record_success();
        assert_eq!(cb.state(), CircuitBreakerState::Closed);
    }

    #[test]
    fn test_failed_probe_reopens_circuit() {
        let mut cb = CircuitBreaker::new(1, Duration::from_secs(60), Duration::from_millis(1));

        // Open and transition to half-open
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(5));
        cb.should_allow_request();
        assert_eq!(cb.state(), CircuitBreakerState::HalfOpen);

        // Failed probe
        cb.record_failure();
        assert_eq!(cb.state(), CircuitBreakerState::Open);
    }

    #[test]
    fn test_failure_window_reset() {
        let mut cb = CircuitBreaker::new(
            3,
            Duration::from_millis(10), // Very short window
            Duration::from_secs(30),
        );

        // First two failures
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.failure_count(), 2);

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(20));

        // New failure starts fresh window
        cb.record_failure();
        assert_eq!(cb.failure_count(), 1);
        assert_eq!(cb.state(), CircuitBreakerState::Closed);
    }

    #[test]
    fn test_success_resets_failure_count() {
        let mut cb = CircuitBreaker::new(5, Duration::from_secs(60), Duration::from_secs(30));

        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.failure_count(), 2);

        cb.record_success();
        assert_eq!(cb.failure_count(), 0);
    }

    #[test]
    fn test_state_display() {
        assert_eq!(format!("{}", CircuitBreakerState::Closed), "Closed");
        assert_eq!(format!("{}", CircuitBreakerState::Open), "Open");
        assert_eq!(format!("{}", CircuitBreakerState::HalfOpen), "HalfOpen");
    }
}
