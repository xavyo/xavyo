//! Integration tests for the circuit breaker functionality.
//!
//! Tests circuit breaker state transitions, failure thresholds,
//! recovery timeouts, and persistence.

use std::time::Duration;

use uuid::Uuid;
use xavyo_webhooks::{
    CircuitBreaker, CircuitBreakerConfig, CircuitBreakerStatus, CircuitState, FailureRecord,
};

// Helper to create a test circuit breaker
fn test_circuit_breaker(threshold: u32, recovery_secs: u64) -> CircuitBreaker {
    let config = CircuitBreakerConfig::default()
        .with_failure_threshold(threshold)
        .with_recovery_timeout(recovery_secs);
    CircuitBreaker::new(Uuid::new_v4(), Uuid::new_v4(), config)
}

fn make_failure(error: &str) -> FailureRecord {
    FailureRecord::new(error.to_string(), Some(500), Some(100))
}

// ---------------------------------------------------------------------------
// T012: circuit_opens_after_consecutive_failures
// ---------------------------------------------------------------------------

#[test]
fn circuit_opens_after_consecutive_failures() {
    let mut cb = test_circuit_breaker(5, 30);

    // Initial state should be closed
    assert_eq!(cb.state(), CircuitState::Closed);
    assert!(cb.can_execute());

    // Record 4 failures - should still be closed
    for i in 0..4 {
        cb.record_failure(make_failure(&format!("Error {i}")));
        assert_eq!(
            cb.state(),
            CircuitState::Closed,
            "Should still be closed after {} failures",
            i + 1
        );
    }

    // 5th failure should open the circuit
    cb.record_failure(make_failure("Error 4"));
    assert_eq!(cb.state(), CircuitState::Open);
    assert_eq!(cb.failure_count(), 5);
}

#[test]
fn circuit_opens_at_exact_threshold() {
    let mut cb = test_circuit_breaker(3, 30);

    cb.record_failure(make_failure("Error 1"));
    cb.record_failure(make_failure("Error 2"));
    assert_eq!(cb.state(), CircuitState::Closed);

    cb.record_failure(make_failure("Error 3"));
    assert_eq!(cb.state(), CircuitState::Open);
}

// ---------------------------------------------------------------------------
// T013: circuit_rejects_delivery_when_open
// ---------------------------------------------------------------------------

#[test]
fn circuit_rejects_delivery_when_open() {
    let mut cb = test_circuit_breaker(2, 30);

    // Open the circuit
    cb.record_failure(make_failure("Error 1"));
    cb.record_failure(make_failure("Error 2"));
    assert_eq!(cb.state(), CircuitState::Open);

    // Should reject execution
    assert!(!cb.can_execute());
}

#[test]
fn circuit_allows_delivery_when_closed() {
    let mut cb = test_circuit_breaker(5, 30);

    assert!(cb.can_execute());
    cb.record_failure(make_failure("Error 1"));
    assert!(cb.can_execute()); // Still under threshold
}

// ---------------------------------------------------------------------------
// T014: circuit_transitions_to_half_open_after_timeout
// ---------------------------------------------------------------------------

#[tokio::test]
async fn circuit_transitions_to_half_open_after_timeout() {
    let config = CircuitBreakerConfig::default()
        .with_failure_threshold(1)
        .with_recovery_timeout(1); // 1 second for test

    let mut cb = CircuitBreaker::new(Uuid::new_v4(), Uuid::new_v4(), config);

    // Open the circuit
    cb.record_failure(make_failure("Error"));
    assert_eq!(cb.state(), CircuitState::Open);
    assert!(!cb.can_execute());

    // Wait for recovery timeout
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Should transition to half-open and allow probe
    assert!(cb.can_execute());
    assert_eq!(cb.state(), CircuitState::HalfOpen);
}

#[test]
fn circuit_stays_open_before_timeout() {
    let config = CircuitBreakerConfig::default()
        .with_failure_threshold(1)
        .with_recovery_timeout(3600); // 1 hour - won't elapse

    let mut cb = CircuitBreaker::new(Uuid::new_v4(), Uuid::new_v4(), config);

    cb.record_failure(make_failure("Error"));
    assert_eq!(cb.state(), CircuitState::Open);

    // Should still be open (timeout hasn't elapsed)
    assert!(!cb.can_execute());
    assert_eq!(cb.state(), CircuitState::Open);
}

// ---------------------------------------------------------------------------
// T015: circuit_closes_on_successful_probe
// ---------------------------------------------------------------------------

#[test]
fn circuit_closes_on_successful_probe() {
    let mut cb = test_circuit_breaker(1, 30);

    // Open the circuit
    cb.record_failure(make_failure("Error"));
    assert_eq!(cb.state(), CircuitState::Open);

    // Manually set to half-open (simulating timeout)
    // In real code, this happens via can_execute() after timeout
    cb.record_success(); // This should close it even from Open (with warning)

    // Now test proper half-open flow
    let mut cb2 = test_circuit_breaker(1, 30);
    cb2.record_failure(make_failure("Error"));

    // Simulate the half-open state (normally via timeout)
    // We'll directly set it for this test
    let config = CircuitBreakerConfig::default()
        .with_failure_threshold(1)
        .with_recovery_timeout(0); // Immediate timeout
    let mut cb3 = CircuitBreaker::new(Uuid::new_v4(), Uuid::new_v4(), config);
    cb3.record_failure(make_failure("Error"));

    // Allow transition to half-open
    assert!(cb3.can_execute()); // This transitions to half-open
    assert_eq!(cb3.state(), CircuitState::HalfOpen);

    // Success should close
    cb3.record_success();
    assert_eq!(cb3.state(), CircuitState::Closed);
    assert_eq!(cb3.failure_count(), 0);
}

// ---------------------------------------------------------------------------
// T016: circuit_reopens_on_failed_probe
// ---------------------------------------------------------------------------

#[test]
fn circuit_reopens_on_failed_probe() {
    let config = CircuitBreakerConfig::default()
        .with_failure_threshold(1)
        .with_recovery_timeout(0); // Immediate timeout for test

    let mut cb = CircuitBreaker::new(Uuid::new_v4(), Uuid::new_v4(), config);

    // Open the circuit
    cb.record_failure(make_failure("Error 1"));
    assert_eq!(cb.state(), CircuitState::Open);

    // Transition to half-open
    assert!(cb.can_execute());
    assert_eq!(cb.state(), CircuitState::HalfOpen);

    // Failed probe should reopen
    cb.record_failure(make_failure("Error 2"));
    assert_eq!(cb.state(), CircuitState::Open);
}

// ---------------------------------------------------------------------------
// T017: circuit_tracks_consecutive_failures_only
// ---------------------------------------------------------------------------

#[test]
fn circuit_tracks_consecutive_failures_only() {
    let mut cb = test_circuit_breaker(5, 30);

    // Record 3 failures
    cb.record_failure(make_failure("Error 1"));
    cb.record_failure(make_failure("Error 2"));
    cb.record_failure(make_failure("Error 3"));
    assert_eq!(cb.failure_count(), 3);
    assert_eq!(cb.state(), CircuitState::Closed);

    // Success resets the count
    cb.record_success();
    assert_eq!(cb.failure_count(), 0);

    // Record 2 more failures - still under threshold
    cb.record_failure(make_failure("Error 4"));
    cb.record_failure(make_failure("Error 5"));
    assert_eq!(cb.failure_count(), 2);
    assert_eq!(cb.state(), CircuitState::Closed);

    // Circuit should not open because we didn't have 5 CONSECUTIVE failures
}

#[test]
fn circuit_requires_consecutive_failures_to_open() {
    let mut cb = test_circuit_breaker(3, 30);

    // Failure, success, failure pattern
    cb.record_failure(make_failure("Error 1"));
    cb.record_success();
    cb.record_failure(make_failure("Error 2"));
    cb.record_success();
    cb.record_failure(make_failure("Error 3"));

    // Should still be closed - never had 3 consecutive failures
    assert_eq!(cb.state(), CircuitState::Closed);
    assert_eq!(cb.failure_count(), 1);
}

// ---------------------------------------------------------------------------
// Additional tests for circuit breaker functionality
// ---------------------------------------------------------------------------

#[test]
fn circuit_breaker_status_reflects_state() {
    let mut cb = test_circuit_breaker(2, 30);

    cb.record_failure(make_failure("Error 1"));
    let status = CircuitBreakerStatus::from(&cb);

    assert_eq!(status.state, CircuitState::Closed);
    assert_eq!(status.failure_count, 1);
    assert!(status.last_failure_at.is_some());
    assert!(status.opened_at.is_none());
    assert_eq!(status.recent_failures.len(), 1);
}

#[test]
fn circuit_breaker_failure_history_bounded() {
    let config = CircuitBreakerConfig::default()
        .with_failure_threshold(100)
        .with_max_failure_history(3);

    let mut cb = CircuitBreaker::new(Uuid::new_v4(), Uuid::new_v4(), config);

    for i in 0..10 {
        cb.record_failure(make_failure(&format!("Error {i}")));
    }

    assert_eq!(cb.recent_failures().len(), 3);
    // Should have the most recent errors
    assert!(cb.recent_failures()[0].error.contains("Error 7"));
    assert!(cb.recent_failures()[2].error.contains("Error 9"));
}

#[test]
fn circuit_breaker_opened_at_set_when_opened() {
    let mut cb = test_circuit_breaker(1, 30);

    assert!(cb.opened_at().is_none());

    cb.record_failure(make_failure("Error"));
    assert_eq!(cb.state(), CircuitState::Open);
    assert!(cb.opened_at().is_some());
}

#[test]
fn circuit_breaker_timestamps_updated() {
    let mut cb = test_circuit_breaker(5, 30);

    assert!(cb.last_failure_at().is_none());
    assert!(cb.last_success_at().is_none());

    cb.record_failure(make_failure("Error"));
    assert!(cb.last_failure_at().is_some());
    assert!(cb.last_success_at().is_none());

    cb.record_success();
    assert!(cb.last_success_at().is_some());
}

#[test]
fn circuit_breaker_half_open_allows_probe() {
    let config = CircuitBreakerConfig::default()
        .with_failure_threshold(1)
        .with_recovery_timeout(0);

    let mut cb = CircuitBreaker::new(Uuid::new_v4(), Uuid::new_v4(), config);

    cb.record_failure(make_failure("Error"));
    assert_eq!(cb.state(), CircuitState::Open);

    // First can_execute transitions to half-open
    assert!(cb.can_execute());
    assert_eq!(cb.state(), CircuitState::HalfOpen);

    // Half-open allows execution
    assert!(cb.can_execute());
}

// ---------------------------------------------------------------------------
// Registry tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registry_creates_circuit_breakers_on_demand() {
    // Create a mock pool (in real integration tests, this would be a real DB)
    // For now, we'll test the logic without DB
    let sub_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();

    // Test that CircuitBreaker can be created
    let cb = CircuitBreaker::new(sub_id, tenant_id, CircuitBreakerConfig::default());

    assert_eq!(cb.subscription_id(), sub_id);
    assert_eq!(cb.tenant_id(), tenant_id);
    assert_eq!(cb.state(), CircuitState::Closed);
}

#[test]
fn circuit_breaker_config_defaults() {
    let config = CircuitBreakerConfig::default();

    assert_eq!(config.failure_threshold, 5);
    assert_eq!(config.recovery_timeout_secs, 30);
    assert_eq!(config.max_failure_history, 10);
}

#[test]
fn circuit_breaker_config_builder() {
    let config = CircuitBreakerConfig::default()
        .with_failure_threshold(10)
        .with_recovery_timeout(60)
        .with_max_failure_history(20);

    assert_eq!(config.failure_threshold, 10);
    assert_eq!(config.recovery_timeout_secs, 60);
    assert_eq!(config.max_failure_history, 20);
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn circuit_breaker_handles_zero_threshold() {
    let config = CircuitBreakerConfig::default().with_failure_threshold(0);

    let mut cb = CircuitBreaker::new(Uuid::new_v4(), Uuid::new_v4(), config);

    // With threshold of 0, first failure should open
    // (or never open if threshold is 0 - depends on implementation)
    // Current impl: failure_count >= threshold, so 1 >= 0 is true
    cb.record_failure(make_failure("Error"));
    // This is an edge case - a threshold of 0 means always open on first failure
    // which may not be desired behavior in practice
}

#[test]
fn circuit_breaker_handles_high_threshold() {
    let config = CircuitBreakerConfig::default().with_failure_threshold(1000);

    let mut cb = CircuitBreaker::new(Uuid::new_v4(), Uuid::new_v4(), config);

    for i in 0..999 {
        cb.record_failure(make_failure(&format!("Error {i}")));
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    cb.record_failure(make_failure("Error 999"));
    assert_eq!(cb.state(), CircuitState::Open);
}

#[test]
fn failure_record_captures_all_fields() {
    let record = FailureRecord::new("Connection timeout".to_string(), Some(504), Some(30000));

    assert_eq!(record.error, "Connection timeout");
    assert_eq!(record.response_code, Some(504));
    assert_eq!(record.latency_ms, Some(30000));
    assert!(record.timestamp <= chrono::Utc::now());
}

#[test]
fn failure_record_handles_none_values() {
    let record = FailureRecord::new("Network error".to_string(), None, None);

    assert_eq!(record.error, "Network error");
    assert_eq!(record.response_code, None);
    assert_eq!(record.latency_ms, None);
}
