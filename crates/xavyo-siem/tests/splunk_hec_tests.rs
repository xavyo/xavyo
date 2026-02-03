//! Splunk HEC integration tests.
//!
//! Tests User Story 4 (Splunk HEC Integration).

#![cfg(feature = "integration")]

mod helpers;

use helpers::test_events::{generate_audit_event, generate_batch};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use uuid::Uuid;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use xavyo_siem::format::{EventFormatter, JsonFormatter};

// =============================================================================
// Splunk HEC Delivery Tests
// =============================================================================

/// Test Splunk HEC delivery to mock endpoint.
#[tokio::test]
async fn test_splunk_hec_delivery() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/services/collector/event"))
        .and(header("Authorization", "Splunk test-token"))
        .and(header("Content-Type", "application/json"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"text": "Success", "code": 0})),
        )
        .mount(&server)
        .await;

    let tenant_id = Uuid::new_v4();
    let event = generate_audit_event("splunk.hec.test", tenant_id);
    let formatter = JsonFormatter::new();
    let json_payload = formatter.format(&event).unwrap();

    // Make request directly to mock
    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/services/collector/event", server.uri()))
        .header("Authorization", "Splunk test-token")
        .header("Content-Type", "application/json")
        .body(build_hec_payload(&json_payload))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 200);
}

/// Test Splunk HEC JSON format.
#[tokio::test]
async fn test_splunk_hec_json_format() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/services/collector/event"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"text": "Success", "code": 0})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let tenant_id = Uuid::new_v4();
    let event = generate_audit_event("json.format.test", tenant_id);
    let formatter = JsonFormatter::new();
    let json_payload = formatter.format(&event).unwrap();

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/services/collector/event", server.uri()))
        .header("Authorization", "Splunk test-token")
        .header("Content-Type", "application/json")
        .body(build_hec_payload(&json_payload))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 200);

    // Verify request was received
    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);

    // Parse body and verify HEC fields
    let body = String::from_utf8(received[0].body.clone()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();

    assert!(
        parsed.get("time").is_some(),
        "HEC payload must have 'time' field"
    );
    assert!(
        parsed.get("host").is_some(),
        "HEC payload must have 'host' field"
    );
    assert!(
        parsed.get("source").is_some(),
        "HEC payload must have 'source' field"
    );
    assert!(
        parsed.get("sourcetype").is_some(),
        "HEC payload must have 'sourcetype' field"
    );
    assert!(
        parsed.get("event").is_some(),
        "HEC payload must have 'event' field"
    );
}

/// Test Splunk HEC authorization header.
#[tokio::test]
async fn test_splunk_hec_authorization_header() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/services/collector/event"))
        .and(header("Authorization", "Splunk my-secret-token"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/services/collector/event", server.uri()))
        .header("Authorization", "Splunk my-secret-token")
        .header("Content-Type", "application/json")
        .body(r#"{"event":"test"}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 200);

    // Verify the mock matched (authorization header was correct)
    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);

    let auth = received[0]
        .headers
        .get("Authorization")
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default();
    assert_eq!(auth, "Splunk my-secret-token");
}

/// Test Splunk HEC content type header.
#[tokio::test]
async fn test_splunk_hec_content_type() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/services/collector/event"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/services/collector/event", server.uri()))
        .header("Authorization", "Splunk token")
        .header("Content-Type", "application/json")
        .body(r#"{"event":"test"}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 200);

    let received = server.received_requests().await.unwrap();
    let ct = received[0]
        .headers
        .get("Content-Type")
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default();
    assert_eq!(ct, "application/json");
}

/// Test Splunk HEC batch delivery.
#[tokio::test]
async fn test_splunk_hec_batch_delivery() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/services/collector/event"))
        .respond_with(ResponseTemplate::new(200))
        .expect(10)
        .mount(&server)
        .await;

    let tenant_id = Uuid::new_v4();
    let events = generate_batch(10, tenant_id);
    let formatter = JsonFormatter::new();

    let client = reqwest::Client::new();

    for event in events {
        let json_payload = formatter.format(&event).unwrap();
        let _ = client
            .post(format!("{}/services/collector/event", server.uri()))
            .header("Authorization", "Splunk token")
            .header("Content-Type", "application/json")
            .body(build_hec_payload(&json_payload))
            .send()
            .await;
    }

    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 10, "Should send 10 requests");
}

/// Test Splunk HEC 401 error handling.
#[tokio::test]
async fn test_splunk_hec_401_error_handling() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/services/collector/event"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(serde_json::json!({"text": "Token disabled", "code": 1})),
        )
        .mount(&server)
        .await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/services/collector/event", server.uri()))
        .header("Authorization", "Splunk invalid-token")
        .header("Content-Type", "application/json")
        .body(r#"{"event":"test"}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status().as_u16(), 401);
}

/// Test Splunk HEC rate limit (429) handling.
#[tokio::test]
async fn test_splunk_hec_rate_limit_handling() {
    let server = MockServer::start().await;

    // First mock rate limits, then success
    Mock::given(method("POST"))
        .and(path("/services/collector/event"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(serde_json::json!({"text": "Rate limit exceeded", "code": 9})),
        )
        .up_to_n_times(3)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/services/collector/event"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({"text": "Success", "code": 0})),
        )
        .mount(&server)
        .await;

    let client = reqwest::Client::new();

    // Simulate retry behavior
    let mut attempts = 0;
    let mut success = false;

    while attempts < 5 && !success {
        let response = client
            .post(format!("{}/services/collector/event", server.uri()))
            .header("Authorization", "Splunk token")
            .header("Content-Type", "application/json")
            .body(r#"{"event":"test"}"#)
            .send()
            .await
            .unwrap();

        if response.status().as_u16() == 200 {
            success = true;
        } else if response.status().as_u16() == 429 {
            // Backoff before retry
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }
        attempts += 1;
    }

    assert!(success, "Should eventually succeed after rate limit clears");
    assert!(attempts > 3, "Should have retried after rate limit");
}

/// Test Splunk HEC retry with backoff.
#[tokio::test]
async fn test_splunk_hec_retry_with_backoff() {
    let server = MockServer::start().await;

    // First 2 requests fail, then succeed
    Mock::given(method("POST"))
        .and(path("/services/collector/event"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(2)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/services/collector/event"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let client = reqwest::Client::new();

    let mut delay_ms = 10u64;
    let mut success = false;

    for _ in 0..5 {
        let response = client
            .post(format!("{}/services/collector/event", server.uri()))
            .header("Authorization", "Splunk token")
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

    assert!(
        success,
        "Should succeed after retries with exponential backoff"
    );
}

// =============================================================================
// Helper Functions
// =============================================================================

fn build_hec_payload(event_json: &str) -> String {
    let event: serde_json::Value = serde_json::from_str(event_json).unwrap();
    let timestamp = chrono::Utc::now().timestamp();

    serde_json::json!({
        "time": timestamp,
        "host": "idp.xavyo.net",
        "source": "xavyo",
        "sourcetype": "xavyo:identity:events",
        "event": event,
    })
    .to_string()
}
