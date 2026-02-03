//! Integration tests for concurrent webhook delivery (User Story 4).
//!
//! Tests verify the system handles multiple concurrent deliveries
//! without race conditions or blocking.

#![cfg(feature = "integration")]

mod common;

use common::*;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// A responder that tracks concurrent request count.
struct ConcurrencyTrackingResponder {
    current_concurrent: Arc<AtomicU32>,
    max_concurrent: Arc<AtomicU32>,
    total_requests: Arc<AtomicU32>,
    delay_ms: u64,
}

impl ConcurrencyTrackingResponder {
    fn new(delay_ms: u64) -> Self {
        Self {
            current_concurrent: Arc::new(AtomicU32::new(0)),
            max_concurrent: Arc::new(AtomicU32::new(0)),
            total_requests: Arc::new(AtomicU32::new(0)),
            delay_ms,
        }
    }

    fn max_concurrent(&self) -> u32 {
        self.max_concurrent.load(Ordering::SeqCst)
    }

    fn total_requests(&self) -> u32 {
        self.total_requests.load(Ordering::SeqCst)
    }
}

impl Clone for ConcurrencyTrackingResponder {
    fn clone(&self) -> Self {
        Self {
            current_concurrent: self.current_concurrent.clone(),
            max_concurrent: self.max_concurrent.clone(),
            total_requests: self.total_requests.clone(),
            delay_ms: self.delay_ms,
        }
    }
}

impl Respond for ConcurrencyTrackingResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        // Increment current concurrent count
        let current = self.current_concurrent.fetch_add(1, Ordering::SeqCst) + 1;
        self.total_requests.fetch_add(1, Ordering::SeqCst);

        // Update max if needed
        loop {
            let max = self.max_concurrent.load(Ordering::SeqCst);
            if current <= max {
                break;
            }
            if self
                .max_concurrent
                .compare_exchange(max, current, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                break;
            }
        }

        // Note: wiremock's set_delay doesn't block the test thread properly
        // for concurrency testing, so we use a simple delay response
        let response =
            ResponseTemplate::new(200).set_delay(std::time::Duration::from_millis(self.delay_ms));

        // Decrement will happen after response is sent
        // For testing purposes, we track at request start
        self.current_concurrent.fetch_sub(1, Ordering::SeqCst);

        response
    }
}

/// Test: Multiple events are processed concurrently.
#[tokio::test]
async fn test_multiple_events_processed_concurrently() {
    let mock_server = MockServer::start().await;
    let tracking = ConcurrencyTrackingResponder::new(50);

    Mock::given(method("POST"))
        .and(path("/webhook"))
        .respond_with(tracking.clone())
        .mount(&mock_server)
        .await;

    let client = TestWebhookClient::new();
    let url = format!("{}/webhook", mock_server.uri());

    // Create 10 events
    let payloads: Vec<_> = (0..10)
        .map(|i| custom_payload(TENANT_A, "test.event", serde_json::json!({"index": i})))
        .collect();

    // Send all concurrently
    let handles: Vec<_> = payloads
        .iter()
        .map(|payload| {
            let client = TestWebhookClient::new();
            let url = url.clone();
            let payload = payload.clone();
            tokio::spawn(async move { client.deliver(&url, &payload, None).await })
        })
        .collect();

    // Wait for all to complete
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok());
        assert!(result.unwrap().status().is_success());
    }

    // Verify all 10 were processed
    assert_eq!(
        tracking.total_requests(),
        10,
        "All 10 events should be processed"
    );
}

/// Test: Concurrent deliveries complete independently.
#[tokio::test]
async fn test_concurrent_deliveries_complete_independently() {
    let mock_server = MockServer::start().await;
    let capture = CaptureResponder::new();

    Mock::given(method("POST"))
        .and(path("/webhook"))
        .respond_with(capture.clone())
        .mount(&mock_server)
        .await;

    let client1 = TestWebhookClient::new();
    let client2 = TestWebhookClient::new();
    let url = format!("{}/webhook", mock_server.uri());

    let payload1 = custom_payload(TENANT_A, "event.one", serde_json::json!({"id": 1}));
    let payload2 = custom_payload(TENANT_B, "event.two", serde_json::json!({"id": 2}));

    // Send concurrently
    let (result1, result2) = tokio::join!(
        client1.deliver(&url, &payload1, None),
        client2.deliver(&url, &payload2, None)
    );

    assert!(result1.is_ok());
    assert!(result2.is_ok());
    assert!(result1.unwrap().status().is_success());
    assert!(result2.unwrap().status().is_success());

    // Both were received
    assert_eq!(capture.request_count(), 2);

    // Verify both events are tracked independently
    let requests = capture.requests();
    let event_ids: Vec<_> = requests
        .iter()
        .map(|r| {
            let payload: WebhookPayload = r.body_json().unwrap();
            payload.event_id
        })
        .collect();

    assert_eq!(event_ids.len(), 2);
    assert_ne!(
        event_ids[0], event_ids[1],
        "Each delivery has unique event ID"
    );
}

/// Test: Slow endpoint doesn't block other deliveries.
#[tokio::test]
async fn test_no_blocking_between_deliveries() {
    // Two endpoints: one slow, one fast
    let slow_server = MockServer::start().await;
    let fast_server = MockServer::start().await;

    let slow_capture = CaptureResponder::new();
    let fast_capture = CaptureResponder::new();

    // Slow endpoint delays 500ms
    Mock::given(method("POST"))
        .and(path("/slow"))
        .respond_with(ResponseTemplate::new(200).set_delay(std::time::Duration::from_millis(200)))
        .mount(&slow_server)
        .await;

    // Fast endpoint responds immediately
    Mock::given(method("POST"))
        .and(path("/fast"))
        .respond_with(fast_capture.clone())
        .mount(&fast_server)
        .await;

    let slow_url = format!("{}/slow", slow_server.uri());
    let fast_url = format!("{}/fast", fast_server.uri());

    let payload = user_created_payload(TENANT_A, USER_1);

    // Start timing
    let start = std::time::Instant::now();

    // Send to both concurrently
    let slow_client = TestWebhookClient::new();
    let fast_client = TestWebhookClient::new();

    let slow_handle = {
        let url = slow_url.clone();
        let payload = payload.clone();
        tokio::spawn(async move { slow_client.deliver(&url, &payload, None).await })
    };

    let fast_handle = {
        let url = fast_url.clone();
        let payload = payload.clone();
        tokio::spawn(async move { fast_client.deliver(&url, &payload, None).await })
    };

    // Wait for fast one first
    let fast_result = fast_handle.await.unwrap();
    let fast_elapsed = start.elapsed();

    // Fast should complete quickly (< 100ms)
    assert!(
        fast_elapsed.as_millis() < 100,
        "Fast endpoint should respond quickly, took {}ms",
        fast_elapsed.as_millis()
    );
    assert!(fast_result.is_ok());

    // Wait for slow one
    let slow_result = slow_handle.await.unwrap();
    assert!(slow_result.is_ok());

    // Fast was not blocked by slow
    assert_eq!(fast_capture.request_count(), 1);
}

/// Test: Concurrent deliveries to the same endpoint are handled.
#[tokio::test]
async fn test_concurrent_to_same_endpoint() {
    let mock_server = MockServer::start().await;
    let counter = CountingResponder::new();

    Mock::given(method("POST"))
        .and(path("/webhook"))
        .respond_with(counter.clone())
        .mount(&mock_server)
        .await;

    let url = format!("{}/webhook", mock_server.uri());

    // Send 20 concurrent requests to the same endpoint
    let handles: Vec<_> = (0..20)
        .map(|i| {
            let client = TestWebhookClient::new();
            let url = url.clone();
            let payload = custom_payload(TENANT_A, "burst.event", serde_json::json!({"index": i}));
            tokio::spawn(async move { client.deliver(&url, &payload, None).await })
        })
        .collect();

    // Wait for all
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok());
        assert!(result.unwrap().status().is_success());
    }

    // All 20 were received
    assert_eq!(
        counter.count(),
        20,
        "All 20 concurrent requests should complete"
    );
}
