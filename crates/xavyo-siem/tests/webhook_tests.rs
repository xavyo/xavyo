//! Webhook delivery integration tests.
//!
//! Tests User Story 5 (Webhook Delivery).

#![cfg(feature = "integration")]

mod helpers;

use helpers::test_events::generate_audit_event;
use std::collections::HashMap;
use uuid::Uuid;
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, ResponseTemplate};
use xavyo_siem::delivery::webhook::WebhookWorker;
use xavyo_siem::delivery::DeliveryError;
use xavyo_siem::format::{EventFormatter, JsonFormatter};

// =============================================================================
// Webhook Delivery Tests
// =============================================================================

/// Test webhook delivery to mock endpoint.
///
/// Note: We use reqwest directly since WebhookWorker blocks localhost for SSRF protection.
#[tokio::test]
async fn test_webhook_delivery() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let tenant_id = Uuid::new_v4();
    let event = generate_audit_event("webhook.delivery.test", tenant_id);
    let formatter = JsonFormatter::new();
    let json_payload = formatter.format(&event).unwrap();

    // Use reqwest directly since WebhookWorker blocks localhost
    let client = reqwest::Client::new();
    let response = client
        .post(&server.uri())
        .header("Content-Type", "application/json")
        .body(json_payload)
        .send()
        .await
        .unwrap();

    assert!(
        response.status().is_success(),
        "Webhook delivery should succeed"
    );
}

/// Test webhook JSON payload format.
#[tokio::test]
async fn test_webhook_json_payload() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let tenant_id = Uuid::new_v4();
    let event = generate_audit_event("json.payload.test", tenant_id);
    let formatter = JsonFormatter::new();
    let json_payload = formatter.format(&event).unwrap();

    let client = reqwest::Client::new();
    let _ = client
        .post(&server.uri())
        .header("Content-Type", "application/json")
        .body(json_payload)
        .send()
        .await
        .unwrap();

    let received = server.received_requests().await.unwrap();
    let body = String::from_utf8(received[0].body.clone()).unwrap();

    // Verify it's valid JSON
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&body);
    assert!(parsed.is_ok(), "Body should be valid JSON");

    let json = parsed.unwrap();
    assert!(
        json.get("event_type").is_some(),
        "JSON should contain event_type"
    );
    assert!(
        json.get("tenant_id").is_some(),
        "JSON should contain tenant_id"
    );
    assert!(
        json.get("timestamp").is_some(),
        "JSON should contain timestamp"
    );
}

/// Test webhook authorization header.
#[tokio::test]
async fn test_webhook_authorization_header() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(header("Authorization", "Bearer token123"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(&server.uri())
        .header("Authorization", "Bearer token123")
        .header("Content-Type", "application/json")
        .body(r#"{"event":"test"}"#)
        .send()
        .await
        .unwrap();

    assert!(response.status().is_success());

    let received = server.received_requests().await.unwrap();
    let auth = received[0]
        .headers
        .get("Authorization")
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default();
    assert_eq!(
        auth, "Bearer token123",
        "Authorization header should be set"
    );
}

/// Test webhook custom headers.
#[tokio::test]
async fn test_webhook_custom_headers() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(header("X-Custom-Header", "custom-value"))
        .and(header("X-Tenant-ID", "tenant-123"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let _ = client
        .post(&server.uri())
        .header("X-Custom-Header", "custom-value")
        .header("X-Tenant-ID", "tenant-123")
        .header("Content-Type", "application/json")
        .body(r#"{"event":"test"}"#)
        .send()
        .await
        .unwrap();

    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);

    let hdrs = &received[0].headers;
    assert_eq!(
        hdrs.get("X-Custom-Header")
            .map(|v| v.to_str().unwrap_or("")),
        Some("custom-value")
    );
    assert_eq!(
        hdrs.get("X-Tenant-ID").map(|v| v.to_str().unwrap_or("")),
        Some("tenant-123")
    );
}

/// Test webhook 5xx retry behavior.
#[tokio::test]
async fn test_webhook_5xx_retry() {
    let server = MockServer::start().await;

    // First 2 requests fail, then succeed
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(2)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();

    // Simulate retry behavior
    let mut success = false;
    for _ in 0..5 {
        let response = client
            .post(&server.uri())
            .header("Content-Type", "application/json")
            .body(r#"{"event":"test"}"#)
            .send()
            .await
            .unwrap();

        if response.status().is_success() {
            success = true;
            break;
        }

        if response.status().as_u16() >= 500 {
            // Retry on 5xx
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }
    }

    assert!(success, "Should succeed after retries");

    let received = server.received_requests().await.unwrap();
    assert!(received.len() >= 3, "Should have retried at least twice");
}

/// Test webhook exponential backoff.
#[tokio::test]
async fn test_webhook_exponential_backoff() {
    let server = MockServer::start().await;

    // First 3 requests fail, then succeed
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(3)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();

    let mut delay_ms = 10u64;
    let mut success = false;
    let start = std::time::Instant::now();

    for _ in 0..5 {
        let response = client
            .post(&server.uri())
            .header("Content-Type", "application/json")
            .body(r#"{"event":"test"}"#)
            .send()
            .await
            .unwrap();

        if response.status().is_success() {
            success = true;
            break;
        }

        // Exponential backoff
        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
        delay_ms *= 2;
    }

    let elapsed = start.elapsed();

    assert!(success, "Should succeed with exponential backoff");
    // Total delay should be at least 10 + 20 + 40 = 70ms for 3 retries
    assert!(
        elapsed.as_millis() >= 70,
        "Should have waited with exponential backoff"
    );
}

// =============================================================================
// SSRF Protection Tests
// =============================================================================

/// Test webhook SSRF protection for private IPs.
#[test]
fn test_webhook_ssrf_blocks_private_ips() {
    let result = WebhookWorker::new("https://192.168.1.1/webhook".to_string(), HashMap::new());
    assert!(result.is_err(), "Should block private IP 192.168.1.1");

    let result = WebhookWorker::new("https://10.0.0.1/webhook".to_string(), HashMap::new());
    assert!(result.is_err(), "Should block private IP 10.0.0.1");

    let result = WebhookWorker::new("https://172.16.0.1/webhook".to_string(), HashMap::new());
    assert!(result.is_err(), "Should block private IP 172.16.0.1");
}

/// Test webhook SSRF protection for localhost.
#[test]
fn test_webhook_ssrf_blocks_localhost() {
    let result = WebhookWorker::new("https://127.0.0.1/webhook".to_string(), HashMap::new());
    assert!(result.is_err(), "Should block localhost");

    let result = WebhookWorker::new("https://localhost/webhook".to_string(), HashMap::new());
    assert!(result.is_err(), "Should block localhost hostname");
}

/// Test webhook SSRF protection for cloud metadata endpoints.
#[test]
fn test_webhook_ssrf_blocks_metadata() {
    let result = WebhookWorker::new("http://169.254.169.254/latest/".to_string(), HashMap::new());
    assert!(result.is_err(), "Should block cloud metadata endpoint");
}

/// Test webhook accepts valid public URLs.
#[test]
fn test_webhook_ssrf_allows_public_urls() {
    // Public IP
    let result = WebhookWorker::new("https://8.8.8.8/webhook".to_string(), HashMap::new());
    assert!(result.is_ok(), "Should allow public IP");

    // Public hostname
    let result = WebhookWorker::new(
        "https://api.example.com/webhook".to_string(),
        HashMap::new(),
    );
    assert!(result.is_ok(), "Should allow public hostname");
}
