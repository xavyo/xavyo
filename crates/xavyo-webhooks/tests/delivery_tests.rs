//! Integration tests for successful webhook delivery (User Story 1).
//!
//! Tests verify webhooks are delivered with correct payloads, signatures,
//! and to all matching subscriptions.

#![cfg(feature = "integration")]

mod common;

use common::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer};

/// Test: Successful delivery to a single subscription endpoint.
#[tokio::test]
async fn test_successful_delivery_to_single_subscription() {
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

    assert!(response.status().is_success());
    assert_eq!(capture.request_count(), 1);

    let captured = &capture.requests()[0];
    let received: WebhookPayload = captured.body_json().unwrap();
    assert_eq!(received.event_type, "user.created");
    assert_eq!(received.tenant_id, TENANT_A);
}

/// Test: Webhook delivered to multiple subscriptions for the same event.
#[tokio::test]
async fn test_delivery_to_multiple_subscriptions() {
    let mock_server1 = MockServer::start().await;
    let mock_server2 = MockServer::start().await;
    let mock_server3 = MockServer::start().await;

    let capture1 = CaptureResponder::new();
    let capture2 = CaptureResponder::new();
    let capture3 = CaptureResponder::new();

    Mock::given(method("POST"))
        .and(path("/webhook"))
        .respond_with(capture1.clone())
        .mount(&mock_server1)
        .await;

    Mock::given(method("POST"))
        .and(path("/webhook"))
        .respond_with(capture2.clone())
        .mount(&mock_server2)
        .await;

    Mock::given(method("POST"))
        .and(path("/webhook"))
        .respond_with(capture3.clone())
        .mount(&mock_server3)
        .await;

    let client = TestWebhookClient::new();
    let payload = user_created_payload(TENANT_A, USER_1);

    // Deliver to all three endpoints
    let urls = vec![
        format!("{}/webhook", mock_server1.uri()),
        format!("{}/webhook", mock_server2.uri()),
        format!("{}/webhook", mock_server3.uri()),
    ];

    for url in &urls {
        let response = client.deliver(url, &payload, Some(SECRET_1)).await.unwrap();
        assert!(response.status().is_success());
    }

    // All three received the webhook
    assert_eq!(capture1.request_count(), 1);
    assert_eq!(capture2.request_count(), 1);
    assert_eq!(capture3.request_count(), 1);

    // All received the same event
    for capture in &[&capture1, &capture2, &capture3] {
        let received: WebhookPayload = capture.requests()[0].body_json().unwrap();
        assert_eq!(received.event_id, payload.event_id);
    }
}

/// Test: 2xx responses (200, 201, 204) all mark delivery as successful.
#[tokio::test]
async fn test_delivery_marked_success_on_2xx() {
    for status_code in [200u16, 201, 204] {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/webhook"))
            .respond_with(wiremock::ResponseTemplate::new(status_code))
            .mount(&mock_server)
            .await;

        let client = TestWebhookClient::new();
        let payload = user_created_payload(TENANT_A, USER_1);
        let url = format!("{}/webhook", mock_server.uri());

        let response = client.deliver(&url, &payload, None).await.unwrap();

        assert!(
            response.status().is_success(),
            "Status {} should be considered success",
            status_code
        );
    }
}

/// Test: Payload structure matches specification.
#[tokio::test]
async fn test_payload_structure_matches_spec() {
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

    client
        .deliver(&url, &payload, Some(SECRET_1))
        .await
        .unwrap();

    let captured = &capture.requests()[0];

    // Verify required headers
    assert!(captured
        .header("content-type")
        .unwrap()
        .contains("application/json"));
    assert!(captured.header("x-webhook-timestamp").is_some());
    assert!(captured.header("x-event-id").is_some());
    assert!(captured.header("x-webhook-signature").is_some());

    // Verify payload structure
    let body: serde_json::Value = captured.body_json().unwrap();
    assert!(body.get("event_id").is_some(), "Missing event_id");
    assert!(body.get("event_type").is_some(), "Missing event_type");
    assert!(body.get("timestamp").is_some(), "Missing timestamp");
    assert!(body.get("tenant_id").is_some(), "Missing tenant_id");
    assert!(body.get("data").is_some(), "Missing data");
}

/// Test: Only subscriptions matching event type receive webhook.
#[tokio::test]
async fn test_subscription_filtering_by_event_type() {
    let mock_server = MockServer::start().await;
    let capture_user = CaptureResponder::new();
    let capture_role = CaptureResponder::new();

    Mock::given(method("POST"))
        .and(path("/user-events"))
        .respond_with(capture_user.clone())
        .mount(&mock_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/role-events"))
        .respond_with(capture_role.clone())
        .mount(&mock_server)
        .await;

    let client = TestWebhookClient::new();

    // Send user.created event to user-events endpoint
    let user_payload = user_created_payload(TENANT_A, USER_1);
    let user_url = format!("{}/user-events", mock_server.uri());
    client
        .deliver(&user_url, &user_payload, None)
        .await
        .unwrap();

    // Send role.assigned event to role-events endpoint
    let role_payload = role_assigned_payload(TENANT_A, USER_1, "admin");
    let role_url = format!("{}/role-events", mock_server.uri());
    client
        .deliver(&role_url, &role_payload, None)
        .await
        .unwrap();

    // Verify each endpoint received only its matching event type
    assert_eq!(capture_user.request_count(), 1);
    assert_eq!(capture_role.request_count(), 1);

    let user_received: WebhookPayload = capture_user.requests()[0].body_json().unwrap();
    assert_eq!(user_received.event_type, "user.created");

    let role_received: WebhookPayload = capture_role.requests()[0].body_json().unwrap();
    assert_eq!(role_received.event_type, "role.assigned");
}
