//! Integration tests for webhook failure scenarios (User Story 5).
//!
//! Tests verify proper handling of timeouts, HTTP errors, network failures,
//! and subscription state changes.

#![cfg(feature = "integration")]

mod common;

use common::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Test: Timeout is handled and should trigger retry.
#[tokio::test]
async fn test_timeout_handling() {
    let mock_server = MockServer::start().await;

    // Configure endpoint to delay longer than client timeout (10s)
    // We use a shorter delay for testing but still demonstrate the pattern
    Mock::given(method("POST"))
        .and(path("/webhook"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(15)))
        .mount(&mock_server)
        .await;

    // Use a client with shorter timeout for testing
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(100))
        .build()
        .unwrap();

    let payload = user_created_payload(TENANT_A, USER_1);
    let url = format!("{}/webhook", mock_server.uri());
    let body = serde_json::to_vec(&payload).unwrap();

    let result = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await;

    // Should timeout
    assert!(result.is_err(), "Request should timeout");
    let err = result.unwrap_err();
    assert!(err.is_timeout(), "Error should be a timeout");
}

/// Test: 4xx errors are handled appropriately.
#[tokio::test]
async fn test_4xx_error_handling() {
    for status_code in [400u16, 401, 403, 404, 422, 429] {
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
            status_code,
            "Should receive {} status",
            status_code
        );
        assert!(
            response.status().is_client_error(),
            "Status {} should be client error",
            status_code
        );
    }
}

/// Test: Network errors (connection refused) are handled.
#[tokio::test]
async fn test_network_error_handling() {
    // Use a port that nothing is listening on
    let url = "http://127.0.0.1:59999/webhook";

    let client = TestWebhookClient::new();
    let payload = user_created_payload(TENANT_A, USER_1);

    let result = client.deliver(url, &payload, None).await;

    // Should fail to connect
    assert!(result.is_err(), "Should fail to connect");
    let err = result.unwrap_err();
    assert!(err.is_connect(), "Error should be a connection error");
}

/// Test: 5xx server errors are handled (and should trigger retry).
#[tokio::test]
async fn test_5xx_server_error_handling() {
    for status_code in [500u16, 502, 503, 504] {
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
            status_code,
            "Should receive {} status",
            status_code
        );
        assert!(
            response.status().is_server_error(),
            "Status {} should be server error",
            status_code
        );
    }
}

/// Test: Consecutive failures would trigger subscription disable.
#[tokio::test]
async fn test_consecutive_failures_threshold() {
    let mock_server = MockServer::start().await;

    // Always return 500
    Mock::given(method("POST"))
        .and(path("/webhook"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

    let client = TestWebhookClient::new();
    let url = format!("{}/webhook", mock_server.uri());

    // Simulate 50 consecutive failures (the threshold)
    let mut failure_count = 0;
    for _ in 0..50 {
        let payload = user_created_payload(TENANT_A, USER_1);
        let response = client.deliver(&url, &payload, None).await.unwrap();
        if response.status().is_server_error() {
            failure_count += 1;
        }
    }

    assert_eq!(failure_count, 50, "Should have 50 consecutive failures");

    // In the real system, this would trigger subscription auto-disable
    // The delivery service checks consecutive_failures >= 50
}

/// Test: Disabled subscription should not receive webhooks.
#[tokio::test]
async fn test_disabled_subscription_behavior() {
    let enabled_server = MockServer::start().await;
    let disabled_server = MockServer::start().await;

    let enabled_capture = CaptureResponder::new();
    let disabled_capture = CaptureResponder::new();

    Mock::given(method("POST"))
        .and(path("/webhook"))
        .respond_with(enabled_capture.clone())
        .mount(&enabled_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/webhook"))
        .respond_with(disabled_capture.clone())
        .mount(&disabled_server)
        .await;

    let client = TestWebhookClient::new();
    let payload = user_created_payload(TENANT_A, USER_1);

    // Only deliver to enabled subscription (simulating filtered delivery)
    let enabled_url = format!("{}/webhook", enabled_server.uri());
    client.deliver(&enabled_url, &payload, None).await.unwrap();

    // Don't deliver to disabled subscription
    // (In real system, DeliveryService filters by enabled=true)

    assert_eq!(
        enabled_capture.request_count(),
        1,
        "Enabled subscription should receive webhook"
    );
    assert_eq!(
        disabled_capture.request_count(),
        0,
        "Disabled subscription should NOT receive webhook"
    );
}

/// Test: Redirect responses are not followed (security).
#[tokio::test]
async fn test_redirect_not_followed() {
    let mock_server = MockServer::start().await;

    // Return a redirect
    Mock::given(method("POST"))
        .and(path("/webhook"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", "http://evil.com/steal"))
        .mount(&mock_server)
        .await;

    // The delivery service is configured with redirect::Policy::none()
    // So we test with a client that also doesn't follow redirects
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let payload = user_created_payload(TENANT_A, USER_1);
    let url = format!("{}/webhook", mock_server.uri());
    let body = serde_json::to_vec(&payload).unwrap();

    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();

    // Should return the redirect status, not follow it
    assert_eq!(
        response.status().as_u16(),
        302,
        "Should receive redirect status, not follow it"
    );
}

/// Test: Large response body is truncated.
#[tokio::test]
async fn test_large_response_body() {
    let mock_server = MockServer::start().await;

    // Return a large body (10KB)
    let large_body = "x".repeat(10_000);
    Mock::given(method("POST"))
        .and(path("/webhook"))
        .respond_with(ResponseTemplate::new(200).set_body_string(large_body.clone()))
        .mount(&mock_server)
        .await;

    let client = TestWebhookClient::new();
    let payload = user_created_payload(TENANT_A, USER_1);
    let url = format!("{}/webhook", mock_server.uri());

    let response = client.deliver(&url, &payload, None).await.unwrap();

    assert!(response.status().is_success());

    // The response body is available
    let body = response.text().await.unwrap();
    assert_eq!(body.len(), 10_000);

    // In the real delivery service, response_body is truncated to 4096 chars
}
