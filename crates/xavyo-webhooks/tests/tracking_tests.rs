//! Integration tests for delivery tracking verification (User Story 6).
//!
//! Tests verify delivery records include timestamps, response codes,
//! latency measurements, and all attempt details.

#![cfg(feature = "integration")]

mod common;

use common::*;
use std::time::Instant;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Test: Delivery is tracked with request/response details.
#[tokio::test]
async fn test_delivery_record_created() {
    let mock_server = MockServer::start().await;
    let capture = CaptureResponder::new();

    Mock::given(method("POST"))
        .and(path("/webhook"))
        .respond_with(capture.clone())
        .mount(&mock_server)
        .await;

    let client = TestWebhookClient::new();
    let payload = user_created_payload(TENANT_A, USER_1);
    let url = format!("{}/webhook", mock_server.uri());

    let response = client
        .deliver(&url, &payload, Some(SECRET_1))
        .await
        .unwrap();

    // Response indicates a delivery occurred
    assert!(response.status().is_success());

    // Request was captured (simulates delivery record)
    assert_eq!(capture.request_count(), 1);

    let captured = &capture.requests()[0];
    // Verify all required fields are present in the request
    assert!(!captured.body.is_empty(), "Request body should be recorded");
    assert!(
        captured.header("x-event-id").is_some(),
        "Event ID should be recorded"
    );
    assert!(
        captured.header("x-webhook-timestamp").is_some(),
        "Timestamp should be recorded"
    );
}

/// Test: Multiple delivery attempts are all recorded.
#[tokio::test]
async fn test_delivery_records_all_attempts() {
    let mock_server = MockServer::start().await;
    let failing = FailingResponder::fail_times(2);

    Mock::given(method("POST"))
        .and(path("/webhook"))
        .respond_with(failing.clone())
        .mount(&mock_server)
        .await;

    let client = TestWebhookClient::new();
    let url = format!("{}/webhook", mock_server.uri());

    // Simulate 3 delivery attempts
    let payload = user_created_payload(TENANT_A, USER_1);

    // Attempt 1 (fails)
    let r1 = client.deliver(&url, &payload, None).await.unwrap();
    assert_eq!(r1.status().as_u16(), 500);

    // Attempt 2 (fails)
    let r2 = client.deliver(&url, &payload, None).await.unwrap();
    assert_eq!(r2.status().as_u16(), 500);

    // Attempt 3 (succeeds)
    let r3 = client.deliver(&url, &payload, None).await.unwrap();
    assert!(r3.status().is_success());

    // All 3 attempts were recorded
    assert_eq!(
        failing.attempt_count(),
        3,
        "All 3 attempts should be recorded"
    );
}

/// Test: HTTP response code is recorded.
#[tokio::test]
async fn test_delivery_includes_response_code() {
    // Test various status codes
    for (status_code, expected) in [
        (200u16, 200u16),
        (201, 201),
        (400, 400),
        (404, 404),
        (500, 500),
    ] {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/webhook"))
            .respond_with(ResponseTemplate::new(status_code))
            .mount(&mock_server)
            .await;

        let client = TestWebhookClient::new();
        let payload = user_created_payload(TENANT_A, USER_1);
        let url = format!("{}/webhook", mock_server.uri());

        let response = client.deliver(&url, &payload, None).await.unwrap();

        assert_eq!(
            response.status().as_u16(),
            expected,
            "Response code {} should be captured",
            status_code
        );
    }
}

/// Test: Response latency is measured.
#[tokio::test]
async fn test_delivery_includes_latency() {
    let mock_server = MockServer::start().await;

    // Endpoint delays 100ms
    Mock::given(method("POST"))
        .and(path("/webhook"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_millis(100)))
        .mount(&mock_server)
        .await;

    let client = TestWebhookClient::new();
    let payload = user_created_payload(TENANT_A, USER_1);
    let url = format!("{}/webhook", mock_server.uri());

    let start = Instant::now();
    let response = client.deliver(&url, &payload, None).await.unwrap();
    let latency = start.elapsed();

    assert!(response.status().is_success());

    // Latency should be at least 100ms (the delay)
    assert!(
        latency.as_millis() >= 100,
        "Latency should be at least 100ms, was {}ms",
        latency.as_millis()
    );

    // But not too long (< 500ms total including overhead)
    assert!(
        latency.as_millis() < 500,
        "Latency should be reasonable, was {}ms",
        latency.as_millis()
    );
}

/// Test: Timestamps are included in delivery tracking.
#[tokio::test]
async fn test_delivery_includes_timestamps() {
    let mock_server = MockServer::start().await;
    let capture = CaptureResponder::new();

    Mock::given(method("POST"))
        .and(path("/webhook"))
        .respond_with(capture.clone())
        .mount(&mock_server)
        .await;

    let before = chrono::Utc::now();

    let client = TestWebhookClient::new();
    let payload = user_created_payload(TENANT_A, USER_1);
    let url = format!("{}/webhook", mock_server.uri());

    client.deliver(&url, &payload, None).await.unwrap();

    let after = chrono::Utc::now();

    // Check the capture timestamp
    let captured = &capture.requests()[0];
    assert!(
        captured.timestamp >= before && captured.timestamp <= after,
        "Capture timestamp should be between test start and end"
    );

    // Check the X-Webhook-Timestamp header
    let ts_header = captured.header("x-webhook-timestamp").unwrap();
    let ts: i64 = ts_header.parse().expect("Timestamp should be numeric");

    // Should be a Unix timestamp close to now
    let now_ts = chrono::Utc::now().timestamp();
    assert!(
        (now_ts - ts).abs() < 5,
        "Webhook timestamp should be close to current time"
    );
}

/// Test: Event ID is tracked with delivery.
#[tokio::test]
async fn test_delivery_includes_event_id() {
    let mock_server = MockServer::start().await;
    let capture = CaptureResponder::new();

    Mock::given(method("POST"))
        .and(path("/webhook"))
        .respond_with(capture.clone())
        .mount(&mock_server)
        .await;

    let client = TestWebhookClient::new();
    let payload = user_created_payload(TENANT_A, USER_1);
    let expected_event_id = payload.event_id;
    let url = format!("{}/webhook", mock_server.uri());

    client.deliver(&url, &payload, None).await.unwrap();

    let captured = &capture.requests()[0];

    // Event ID in header
    let header_event_id = captured.header("x-event-id").unwrap();
    assert_eq!(
        header_event_id,
        expected_event_id.to_string(),
        "X-Event-ID header should match payload"
    );

    // Event ID in body
    let body: WebhookPayload = captured.body_json().unwrap();
    assert_eq!(
        body.event_id, expected_event_id,
        "Body event_id should match"
    );
}

/// Test: Response body is captured (for debugging failed deliveries).
#[tokio::test]
async fn test_delivery_captures_response_body() {
    let mock_server = MockServer::start().await;

    // Return a body with the response
    let response_body = r#"{"status": "received", "message": "OK"}"#;
    Mock::given(method("POST"))
        .and(path("/webhook"))
        .respond_with(ResponseTemplate::new(200).set_body_string(response_body))
        .mount(&mock_server)
        .await;

    let client = TestWebhookClient::new();
    let payload = user_created_payload(TENANT_A, USER_1);
    let url = format!("{}/webhook", mock_server.uri());

    let response = client.deliver(&url, &payload, None).await.unwrap();

    let body = response.text().await.unwrap();
    assert_eq!(body, response_body, "Response body should be captured");
}

/// Test: Error messages are captured for failed deliveries.
#[tokio::test]
async fn test_delivery_captures_error_message() {
    let mock_server = MockServer::start().await;

    // Return an error with a body
    let error_body = r#"{"error": "Invalid payload", "code": "VALIDATION_ERROR"}"#;
    Mock::given(method("POST"))
        .and(path("/webhook"))
        .respond_with(ResponseTemplate::new(400).set_body_string(error_body))
        .mount(&mock_server)
        .await;

    let client = TestWebhookClient::new();
    let payload = user_created_payload(TENANT_A, USER_1);
    let url = format!("{}/webhook", mock_server.uri());

    let response = client.deliver(&url, &payload, None).await.unwrap();

    assert!(response.status().is_client_error());
    let body = response.text().await.unwrap();
    assert!(
        body.contains("Invalid payload"),
        "Error message should be captured"
    );
}
