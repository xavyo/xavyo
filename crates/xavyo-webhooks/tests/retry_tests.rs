//! Integration tests for webhook retry logic (User Story 2).
//!
//! Tests verify exponential backoff, eventual success after failures,
//! and proper abandonment after max retries.

#![cfg(feature = "integration")]

mod common;

use common::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer};
use xavyo_webhooks::services::delivery_service::calculate_next_attempt_at;

/// Test: Retry is scheduled after 5xx error.
#[tokio::test]
async fn test_retry_on_5xx_error() {
    let mock_server = MockServer::start().await;
    let capture = CaptureResponder::with_status(500);

    Mock::given(method("POST"))
        .and(path("/webhook"))
        .respond_with(capture.clone())
        .mount(&mock_server)
        .await;

    let client = TestWebhookClient::new();
    let payload = user_created_payload(TENANT_A, USER_1);
    let url = format!("{}/webhook", mock_server.uri());

    let response = client.deliver(&url, &payload, None).await.unwrap();

    // Server returned 500
    assert_eq!(response.status().as_u16(), 500);
    assert_eq!(capture.request_count(), 1);

    // In a real system, the delivery would be scheduled for retry
    // Here we verify the retry calculation logic
    let next_attempt = calculate_next_attempt_at(1, 6);
    assert!(
        next_attempt.is_some(),
        "First failure should schedule retry"
    );
}

/// Test: Exponential backoff schedule follows 60s, 5min, 30min, 2hr, 24hr.
#[tokio::test]
async fn test_exponential_backoff_schedule() {
    // Expected delays in seconds: 60, 300, 1800, 7200, 86400
    let expected_delays = vec![60i64, 300, 1800, 7200, 86400];

    for (attempt, expected_delay) in expected_delays.iter().enumerate() {
        let next = calculate_next_attempt_at((attempt + 1) as i32, 6);
        assert!(
            next.is_some(),
            "Attempt {} should have a retry",
            attempt + 1
        );

        let delay = next.unwrap() - chrono::Utc::now();
        let delay_secs = delay.num_seconds();

        // Allow 2 second tolerance for timing
        assert!(
            (delay_secs - expected_delay).abs() <= 2,
            "Attempt {} delay should be ~{} seconds, got {}",
            attempt + 1,
            expected_delay,
            delay_secs
        );
    }
}

/// Test: Successful delivery after failures stops retry loop.
#[tokio::test]
async fn test_eventual_success_stops_retries() {
    let mock_server = MockServer::start().await;
    let failing = FailingResponder::fail_times(2);

    Mock::given(method("POST"))
        .and(path("/webhook"))
        .respond_with(failing.clone())
        .mount(&mock_server)
        .await;

    let client = TestWebhookClient::new();
    let payload = user_created_payload(TENANT_A, USER_1);
    let url = format!("{}/webhook", mock_server.uri());

    // First attempt: fails (500)
    let response1 = client.deliver(&url, &payload, None).await.unwrap();
    assert_eq!(response1.status().as_u16(), 500);

    // Second attempt: fails (500)
    let response2 = client.deliver(&url, &payload, None).await.unwrap();
    assert_eq!(response2.status().as_u16(), 500);

    // Third attempt: succeeds (200)
    let response3 = client.deliver(&url, &payload, None).await.unwrap();
    assert!(response3.status().is_success());

    // Total of 3 attempts
    assert_eq!(failing.attempt_count(), 3);
}

/// Test: Delivery is abandoned after max retry attempts.
#[tokio::test]
async fn test_max_retries_abandons_delivery() {
    // Verify that attempt 6 (max) returns None for next_attempt_at
    let next_6 = calculate_next_attempt_at(6, 6);
    assert!(
        next_6.is_none(),
        "Attempt 6 (max) should not schedule more retries"
    );

    let next_7 = calculate_next_attempt_at(7, 6);
    assert!(
        next_7.is_none(),
        "Attempt 7 (over max) should not schedule more retries"
    );

    // Verify that attempt 5 still allows one more retry
    let next_5 = calculate_next_attempt_at(5, 6);
    assert!(next_5.is_some(), "Attempt 5 should still allow retry");
}

/// Test: Custom max_attempts configuration is respected.
#[tokio::test]
async fn test_retry_respects_max_attempts_config() {
    // With max_attempts = 3
    let max_attempts = 3;

    // Attempt 3 should be the last (no more retries)
    let next_3 = calculate_next_attempt_at(3, max_attempts);
    assert!(
        next_3.is_none(),
        "Attempt 3 (max=3) should not schedule more retries"
    );

    // Attempt 2 should still allow one more retry
    let next_2 = calculate_next_attempt_at(2, max_attempts);
    assert!(next_2.is_some(), "Attempt 2 (max=3) should allow retry");

    // Attempt 1 should also allow retry
    let next_1 = calculate_next_attempt_at(1, max_attempts);
    assert!(next_1.is_some(), "Attempt 1 (max=3) should allow retry");
}

/// Test: Verify actual backoff interval values.
#[tokio::test]
async fn test_backoff_schedule_values() {
    // These are the exact values from the BACKOFF_SCHEDULE_SECS constant
    let tests = vec![
        (1, 60),    // 1 minute
        (2, 300),   // 5 minutes
        (3, 1800),  // 30 minutes
        (4, 7200),  // 2 hours
        (5, 86400), // 24 hours
    ];

    for (attempt, expected_secs) in tests {
        let next = calculate_next_attempt_at(attempt, 6).unwrap();
        let delay = (next - chrono::Utc::now()).num_seconds();

        // Allow small tolerance for test execution time
        let min_delay = expected_secs - 2;
        let max_delay = expected_secs + 2;

        assert!(
            delay >= min_delay && delay <= max_delay,
            "Attempt {}: expected delay ~{} seconds, got {}",
            attempt,
            expected_secs,
            delay
        );
    }
}
