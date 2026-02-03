//! Circuit breaker integration tests.
//!
//! Tests User Story 7 (Circuit Breaker and Health Monitoring).

#![cfg(feature = "integration")]

mod helpers;

use std::time::Duration;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};
use xavyo_siem::models::CircuitState;
use xavyo_siem::pipeline::circuit_breaker::CircuitBreaker;

// =============================================================================
// Circuit Breaker State Transition Tests
// =============================================================================

/// Test circuit breaker opens after consecutive failures.
#[tokio::test]
async fn test_circuit_breaker_opens_after_failures() {
    let server = MockServer::start().await;

    // Server always fails
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let mut circuit = CircuitBreaker::new(5, 60); // threshold=5, cooldown=60s
    let client = reqwest::Client::new();

    // Make 5 failing requests
    for i in 0..5 {
        assert!(circuit.can_attempt(), "Attempt {} should be allowed", i);

        let response = client.post(&server.uri()).body("{}").send().await.unwrap();

        if response.status().is_server_error() {
            circuit.record_failure();
        }
    }

    // Circuit should now be open
    assert_eq!(
        circuit.state(),
        CircuitState::Open,
        "Circuit should be open after 5 failures"
    );
}

/// Test circuit breaker rejects requests when open.
#[tokio::test]
async fn test_circuit_breaker_rejects_when_open() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let mut circuit = CircuitBreaker::new(3, 60);
    let client = reqwest::Client::new();

    // Trip the circuit
    for _ in 0..3 {
        assert!(circuit.can_attempt());
        let response = client.post(&server.uri()).body("{}").send().await.unwrap();
        if response.status().is_server_error() {
            circuit.record_failure();
        }
    }

    assert_eq!(circuit.state(), CircuitState::Open);

    // Reset server to track new requests
    server.reset().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    // Try to make requests while circuit is open
    let mut blocked_count = 0;
    for _ in 0..5 {
        if !circuit.can_attempt() {
            blocked_count += 1;
            continue;
        }
        // If we get here, circuit allowed attempt (shouldn't happen while open)
        let _ = client.post(&server.uri()).body("{}").send().await;
    }

    // Verify requests were blocked
    let received = server.received_requests().await.unwrap();
    assert_eq!(
        received.len(),
        0,
        "No requests should reach server while circuit is open"
    );
    assert_eq!(blocked_count, 5, "All 5 attempts should be blocked");
}

/// Test circuit breaker recovery after timeout.
#[tokio::test]
async fn test_circuit_breaker_recovery() {
    let server = MockServer::start().await;

    // First return failures, then success
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(3)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    // Use 0 second cooldown for fast testing
    let mut circuit = CircuitBreaker::new(3, 0);
    let client = reqwest::Client::new();

    // Trip the circuit
    for _ in 0..3 {
        if circuit.can_attempt() {
            let response = client.post(&server.uri()).body("{}").send().await.unwrap();
            if response.status().is_server_error() {
                circuit.record_failure();
            }
        }
    }

    assert_eq!(circuit.state(), CircuitState::Open);

    // Wait for cooldown (0 seconds + small buffer)
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Circuit should transition to half-open
    assert!(circuit.can_attempt(), "Should allow probe attempt");
    assert_eq!(circuit.state(), CircuitState::HalfOpen);

    // Make successful probe request
    let response = client.post(&server.uri()).body("{}").send().await.unwrap();
    if response.status().is_success() {
        circuit.record_success();
    }

    // Circuit should now be closed
    assert_eq!(
        circuit.state(),
        CircuitState::Closed,
        "Circuit should be closed after successful probe"
    );
}

/// Test half-open circuit allows probe request.
#[tokio::test]
async fn test_circuit_breaker_half_open_probe() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let mut circuit = CircuitBreaker::new(1, 0); // threshold=1, cooldown=0

    // Trip the circuit
    circuit.record_failure();
    assert_eq!(circuit.state(), CircuitState::Open);

    // Wait for cooldown
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Should transition to half-open on probe attempt
    assert!(circuit.can_attempt());
    assert_eq!(circuit.state(), CircuitState::HalfOpen);

    // Probe request
    let client = reqwest::Client::new();
    let response = client.post(&server.uri()).body("{}").send().await.unwrap();
    assert!(response.status().is_success());

    circuit.record_success();
    assert_eq!(circuit.state(), CircuitState::Closed);
}

/// Test circuit breaker reopens on probe failure.
#[tokio::test]
async fn test_circuit_breaker_reopens_on_probe_failure() {
    let server = MockServer::start().await;

    // Server always fails
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let mut circuit = CircuitBreaker::new(1, 0);
    let client = reqwest::Client::new();

    // Trip the circuit
    circuit.record_failure();
    assert_eq!(circuit.state(), CircuitState::Open);

    // Wait for cooldown
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Transition to half-open
    assert!(circuit.can_attempt());
    assert_eq!(circuit.state(), CircuitState::HalfOpen);

    // Probe fails
    let response = client.post(&server.uri()).body("{}").send().await.unwrap();
    if response.status().is_server_error() {
        circuit.record_failure();
    }

    // Should be back to open
    assert_eq!(
        circuit.state(),
        CircuitState::Open,
        "Circuit should reopen after probe failure"
    );
}

// =============================================================================
// Circuit Breaker Configuration Tests
// =============================================================================

/// Test configurable failure threshold.
#[test]
fn test_configurable_failure_threshold() {
    // Different thresholds
    for threshold in [1, 3, 5, 10] {
        let mut circuit = CircuitBreaker::new(threshold, 60);

        // Record threshold-1 failures (shouldn't open)
        for _ in 0..(threshold - 1) {
            circuit.record_failure();
            assert_eq!(circuit.state(), CircuitState::Closed);
        }

        // One more failure should open
        circuit.record_failure();
        assert_eq!(
            circuit.state(),
            CircuitState::Open,
            "Circuit should open at threshold {}",
            threshold
        );
    }
}

/// Test success resets failure count.
#[test]
fn test_success_resets_failure_count() {
    let mut circuit = CircuitBreaker::new(5, 60);

    // Record some failures
    circuit.record_failure();
    circuit.record_failure();
    assert_eq!(circuit.failure_count(), 2);

    // Success resets count
    circuit.record_success();
    assert_eq!(circuit.failure_count(), 0);
    assert_eq!(circuit.state(), CircuitState::Closed);

    // Need full threshold failures again
    for _ in 0..4 {
        circuit.record_failure();
        assert_eq!(circuit.state(), CircuitState::Closed);
    }
    circuit.record_failure();
    assert_eq!(circuit.state(), CircuitState::Open);
}

/// Test circuit breaker reset.
#[test]
fn test_circuit_breaker_reset() {
    let mut circuit = CircuitBreaker::new(1, 60);

    // Trip the circuit
    circuit.record_failure();
    assert_eq!(circuit.state(), CircuitState::Open);

    // Reset
    circuit.reset();
    assert_eq!(circuit.state(), CircuitState::Closed);
    assert_eq!(circuit.failure_count(), 0);
    assert!(circuit.can_attempt());
}

// =============================================================================
// Integration with Delivery Tests
// =============================================================================

/// Test circuit breaker integration with HTTP delivery.
#[tokio::test]
async fn test_circuit_breaker_http_integration() {
    let server = MockServer::start().await;

    // First 5 requests fail, then succeed
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(5)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    // Use 1 second cooldown to ensure blocking happens
    let mut circuit = CircuitBreaker::new(5, 1);
    let client = reqwest::Client::new();

    let mut delivered = 0u32;
    let mut blocked = 0u32;
    let mut failures = 0u32;

    // First, trigger 5 failures to open the circuit
    for _ in 0..5 {
        if circuit.can_attempt() {
            let response = client.post(&server.uri()).body("{}").send().await.unwrap();
            if response.status().is_server_error() {
                circuit.record_failure();
                failures += 1;
            }
        }
    }

    assert_eq!(failures, 5, "Should have recorded 5 failures");
    assert_eq!(
        circuit.state(),
        CircuitState::Open,
        "Circuit should be open"
    );

    // Now try some requests while circuit is open - these should be blocked
    for _ in 0..5 {
        if !circuit.can_attempt() {
            blocked += 1;
        }
    }

    assert!(
        blocked > 0,
        "Some requests should have been blocked by circuit breaker"
    );

    // Wait for cooldown to pass
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // Circuit should transition to half-open, then closed after success
    if circuit.can_attempt() {
        let response = client.post(&server.uri()).body("{}").send().await.unwrap();
        if response.status().is_success() {
            circuit.record_success();
            delivered += 1;
        }
    }

    assert!(
        delivered > 0,
        "Some requests should have been delivered after recovery"
    );
    assert_eq!(
        circuit.state(),
        CircuitState::Closed,
        "Circuit should be closed after success"
    );
}
