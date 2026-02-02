//! Circuit breaker state machine for delivery resilience.

use crate::models::CircuitState;
use std::time::{Duration, Instant};

/// Circuit breaker for a SIEM destination.
pub struct CircuitBreaker {
    state: CircuitState,
    failure_count: u32,
    threshold: u32,
    cooldown: Duration,
    last_failure_at: Option<Instant>,
    last_state_change: Instant,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with configurable threshold and cooldown.
    pub fn new(threshold: u32, cooldown_secs: u64) -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            threshold,
            cooldown: Duration::from_secs(cooldown_secs),
            last_failure_at: None,
            last_state_change: Instant::now(),
        }
    }

    /// Check if a delivery attempt is allowed.
    pub fn can_attempt(&mut self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if cooldown has elapsed → transition to HalfOpen
                if let Some(last_failure) = self.last_failure_at {
                    if last_failure.elapsed() >= self.cooldown {
                        self.state = CircuitState::HalfOpen;
                        self.last_state_change = Instant::now();
                        tracing::info!("Circuit breaker transitioning from Open to HalfOpen");
                        return true;
                    }
                }
                false
            }
            CircuitState::HalfOpen => true,
        }
    }

    /// Record a successful delivery.
    pub fn record_success(&mut self) {
        match self.state {
            CircuitState::HalfOpen => {
                self.state = CircuitState::Closed;
                self.failure_count = 0;
                self.last_state_change = Instant::now();
                tracing::info!("Circuit breaker transitioning from HalfOpen to Closed");
            }
            CircuitState::Closed => {
                self.failure_count = 0;
            }
            CircuitState::Open => {
                // Shouldn't happen, but reset on success
                self.state = CircuitState::Closed;
                self.failure_count = 0;
                self.last_state_change = Instant::now();
            }
        }
    }

    /// Record a failed delivery.
    pub fn record_failure(&mut self) {
        self.last_failure_at = Some(Instant::now());

        match self.state {
            CircuitState::Closed => {
                self.failure_count += 1;
                if self.failure_count >= self.threshold {
                    self.state = CircuitState::Open;
                    self.last_state_change = Instant::now();
                    tracing::warn!(
                        "Circuit breaker OPEN after {} consecutive failures (threshold: {})",
                        self.failure_count,
                        self.threshold
                    );
                }
            }
            CircuitState::HalfOpen => {
                // Probe failed → back to Open
                self.state = CircuitState::Open;
                self.last_state_change = Instant::now();
                tracing::warn!("Circuit breaker probe failed, returning to Open");
            }
            CircuitState::Open => {
                // Already open, just update failure time
            }
        }
    }

    /// Get the current circuit state.
    pub fn state(&self) -> CircuitState {
        self.state
    }

    /// Get the consecutive failure count.
    pub fn failure_count(&self) -> u32 {
        self.failure_count
    }

    /// Reset the circuit breaker to closed state.
    pub fn reset(&mut self) {
        self.state = CircuitState::Closed;
        self.failure_count = 0;
        self.last_failure_at = None;
        self.last_state_change = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state_is_closed() {
        let cb = CircuitBreaker::new(5, 60);
        assert_eq!(cb.state(), CircuitState::Closed);
        assert_eq!(cb.failure_count(), 0);
    }

    #[test]
    fn test_closed_allows_attempts() {
        let mut cb = CircuitBreaker::new(5, 60);
        assert!(cb.can_attempt());
    }

    #[test]
    fn test_closed_to_open_after_threshold() {
        let mut cb = CircuitBreaker::new(3, 60);

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn test_open_blocks_attempts() {
        let mut cb = CircuitBreaker::new(1, 60);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.can_attempt());
    }

    #[test]
    fn test_open_to_half_open_after_cooldown() {
        let mut cb = CircuitBreaker::new(1, 0); // 0 second cooldown for test
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // After cooldown (0 seconds), should transition to HalfOpen
        std::thread::sleep(Duration::from_millis(10));
        assert!(cb.can_attempt());
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn test_half_open_to_closed_on_success() {
        let mut cb = CircuitBreaker::new(1, 0);
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(10));
        cb.can_attempt(); // Transitions to HalfOpen

        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert_eq!(cb.failure_count(), 0);
    }

    #[test]
    fn test_half_open_to_open_on_failure() {
        let mut cb = CircuitBreaker::new(1, 0);
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(10));
        cb.can_attempt(); // Transitions to HalfOpen

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn test_success_resets_failure_count() {
        let mut cb = CircuitBreaker::new(5, 60);
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.failure_count(), 2);

        cb.record_success();
        assert_eq!(cb.failure_count(), 0);
    }

    #[test]
    fn test_reset() {
        let mut cb = CircuitBreaker::new(1, 60);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        cb.reset();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert_eq!(cb.failure_count(), 0);
        assert!(cb.can_attempt());
    }

    #[test]
    fn test_configurable_threshold() {
        let mut cb = CircuitBreaker::new(10, 60);
        for _ in 0..9 {
            cb.record_failure();
            assert_eq!(cb.state(), CircuitState::Closed);
        }
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }
}
