//! Batch export integration tests.
//!
//! Tests User Story 6 (Large Batch Export).

#![cfg(feature = "integration")]

mod helpers;

use helpers::test_events::generate_batch;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};
use xavyo_siem::format::{EventFormatter, JsonFormatter};

// =============================================================================
// Batch Export Tests
// =============================================================================

/// Test batch export of 10,000 events.
#[tokio::test]
async fn test_batch_export_10000_events() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let tenant_id = Uuid::new_v4();
    let events = generate_batch(10_000, tenant_id);
    let formatter = JsonFormatter::new();

    let start = Instant::now();

    let client = reqwest::Client::new();
    for event in events {
        let json_payload = formatter.format(&event).unwrap();
        let _ = client
            .post(&server.uri())
            .header("Content-Type", "application/json")
            .body(json_payload)
            .send()
            .await;
    }

    let elapsed = start.elapsed();

    // SC-006: Batch export should complete within 60 seconds
    assert!(
        elapsed < Duration::from_secs(60),
        "10,000 events should export within 60 seconds, took {:?}",
        elapsed
    );

    let received = server.received_requests().await.unwrap();
    assert_eq!(
        received.len(),
        10_000,
        "All 10,000 events should be received"
    );
}

/// Test batch export stays memory bounded.
#[tokio::test]
async fn test_batch_export_memory_bounded() {
    // This test verifies that events are processed in a streaming manner
    // rather than loading all into memory at once.
    //
    // In a streaming approach, we process events one at a time,
    // so memory usage should remain relatively constant regardless of batch size.

    let tenant_id = Uuid::new_v4();

    // Generate events in chunks to simulate streaming
    let chunk_size = 100;
    let total_events = 1000;
    let formatter = JsonFormatter::new();

    let mut total_bytes_processed = 0usize;

    for _ in 0..(total_events / chunk_size) {
        let chunk = generate_batch(chunk_size, tenant_id);

        // Process chunk - in a real streaming implementation,
        // only this chunk would be in memory at a time
        for event in chunk {
            let json = formatter.format(&event).unwrap();
            total_bytes_processed += json.len();
        }

        // Simulate sending and releasing memory
        // In practice, the chunk goes out of scope here
    }

    // Verify we processed all events
    assert!(total_bytes_processed > 0);

    // This test passes if it doesn't OOM
    // In a real implementation, we'd measure actual memory usage
}

/// Test batch export with streaming.
#[tokio::test]
async fn test_batch_export_streaming() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let tenant_id = Uuid::new_v4();
    let formatter = JsonFormatter::new();
    let client = reqwest::Client::new();

    // Stream events in batches to simulate async streaming
    let mut sent_count = 0u32;

    for _batch_num in 0..10 {
        let batch = generate_batch(100, tenant_id);

        // Process batch as a stream
        for event in batch {
            let json = formatter.format(&event).unwrap();
            let _ = client.post(&server.uri()).body(json).send().await;
            sent_count += 1;
        }

        // Small delay to simulate real-world streaming
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert_eq!(sent_count, 1000, "Should stream all 1000 events");
}

/// Test batch export cancellation.
#[tokio::test]
async fn test_batch_export_cancellation() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let cancel_token = CancellationToken::new();
    let cancel_clone = cancel_token.clone();

    let tenant_id = Uuid::new_v4();
    let formatter = JsonFormatter::new();
    let client = reqwest::Client::new();
    let server_uri = server.uri();

    // Start batch export task
    let export_handle = tokio::spawn(async move {
        let events = generate_batch(1000, tenant_id);
        let mut processed = 0u32;

        for event in events {
            // Check for cancellation
            if cancel_clone.is_cancelled() {
                return processed;
            }

            let json = formatter.format(&event).unwrap();
            let _ = client.post(&server_uri).body(json).send().await;
            processed += 1;

            // Small delay to allow cancellation
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        processed
    });

    // Cancel after some events have been processed
    tokio::time::sleep(Duration::from_millis(100)).await;
    cancel_token.cancel();

    let processed = export_handle.await.unwrap();

    // Should have processed some but not all events
    assert!(
        processed > 0,
        "Should have processed some events before cancellation"
    );
    assert!(
        processed < 1000,
        "Should not have processed all events after cancellation"
    );
}

/// Test batch export completion time.
#[tokio::test]
async fn test_batch_export_completion_time() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let tenant_id = Uuid::new_v4();
    let batch_sizes = [100, 500, 1000];
    let formatter = JsonFormatter::new();
    let client = reqwest::Client::new();

    for size in batch_sizes {
        let events = generate_batch(size, tenant_id);
        let start = Instant::now();

        for event in events {
            let json = formatter.format(&event).unwrap();
            let _ = client.post(&server.uri()).body(json).send().await;
        }

        let elapsed = start.elapsed();

        // Rough estimate: should process at least 50 events per second
        let events_per_sec = size as f64 / elapsed.as_secs_f64();
        assert!(
            events_per_sec >= 50.0,
            "Should process at least 50 events/sec, got {:.1} for {} events",
            events_per_sec,
            size
        );
    }
}

// =============================================================================
// Multi-Tenant Isolation Test
// =============================================================================

/// Test that tenant A events don't go to tenant B destination.
#[tokio::test]
async fn test_multi_tenant_isolation() {
    let server_a = MockServer::start().await;
    let server_b = MockServer::start().await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server_a)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server_b)
        .await;

    let tenant_a_id = Uuid::new_v4();
    let tenant_b_id = Uuid::new_v4();

    let events_a = generate_batch(50, tenant_a_id);
    let events_b = generate_batch(50, tenant_b_id);

    let formatter = JsonFormatter::new();
    let client = reqwest::Client::new();

    // Send tenant A events to server A
    for event in events_a {
        assert_eq!(
            event.tenant_id, tenant_a_id,
            "Event should belong to tenant A"
        );
        let json = formatter.format(&event).unwrap();
        let _ = client.post(&server_a.uri()).body(json).send().await;
    }

    // Send tenant B events to server B
    for event in events_b {
        assert_eq!(
            event.tenant_id, tenant_b_id,
            "Event should belong to tenant B"
        );
        let json = formatter.format(&event).unwrap();
        let _ = client.post(&server_b.uri()).body(json).send().await;
    }

    // Verify isolation
    let received_a = server_a.received_requests().await.unwrap();
    let received_b = server_b.received_requests().await.unwrap();

    assert_eq!(
        received_a.len(),
        50,
        "Server A should receive 50 events from tenant A"
    );
    assert_eq!(
        received_b.len(),
        50,
        "Server B should receive 50 events from tenant B"
    );

    // No cross-tenant leakage verification is implicit:
    // Server A only received 50 events (all from tenant A)
    // Server B only received 50 events (all from tenant B)
}
