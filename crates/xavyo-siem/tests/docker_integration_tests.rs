//! Docker-based integration tests for SIEM functionality.
//!
//! These tests require Docker containers to be running:
//! ```bash
//! cd crates/xavyo-siem/scripts
//! ./start-test-infra.sh --wait
//! ```
//!
//! Run tests with:
//! ```bash
//! cargo test -p xavyo-siem --features docker-tests -- --ignored
//! ```

#![cfg(feature = "docker-tests")]

mod helpers;

use helpers::docker_infra::DockerTestInfra;
use std::io::Write;
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;
use tokio::time::sleep;

/// Skip test if Docker infrastructure is not available.
async fn skip_if_unavailable(infra: &DockerTestInfra) -> bool {
    if !infra.is_available().await {
        eprintln!("Docker infrastructure not available, skipping test");
        return true;
    }
    false
}

/// Test Splunk HEC event delivery via Docker container.
#[tokio::test]
#[ignore = "requires Docker infrastructure"]
async fn test_splunk_hec_delivery_with_docker() {
    let infra = DockerTestInfra::from_env();
    if skip_if_unavailable(&infra).await {
        return;
    }

    // Clear any existing events
    infra.clear_hec_events().await.unwrap();

    // Send test event via HEC
    let client = reqwest::Client::new();
    let event = serde_json::json!({
        "time": 1234567890.123,
        "host": "test-host",
        "source": "docker-test",
        "sourcetype": "_json",
        "event": {
            "action": "test_splunk_hec_delivery_with_docker",
            "user": "test-user",
            "resource": "test-resource"
        }
    });

    let response = client
        .post(format!("{}/services/collector/event", infra.hec_url))
        .header("Authorization", format!("Splunk {}", infra.hec_token))
        .header("Content-Type", "application/json")
        .json(&event)
        .send()
        .await
        .unwrap();

    assert!(response.status().is_success(), "HEC request should succeed");

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["code"], 0, "HEC should return success code");
    assert_eq!(body["text"], "Success");

    // Verify event was received
    let events = infra.get_hec_events().await.unwrap();
    assert_eq!(events.len(), 1, "Should have received exactly one event");
    assert_eq!(events[0].payload["host"], "test-host");
    assert_eq!(events[0].payload["source"], "docker-test");
}

/// Test HEC token validation via Docker container.
#[tokio::test]
#[ignore = "requires Docker infrastructure"]
async fn test_hec_token_validation() {
    let infra = DockerTestInfra::from_env();
    if skip_if_unavailable(&infra).await {
        return;
    }

    let client = reqwest::Client::new();
    let event = serde_json::json!({
        "event": {"test": "data"}
    });

    // Test with invalid token
    let response = client
        .post(format!("{}/services/collector/event", infra.hec_url))
        .header("Authorization", "Splunk invalid-token")
        .header("Content-Type", "application/json")
        .json(&event)
        .send()
        .await
        .unwrap();

    assert_eq!(
        response.status().as_u16(),
        401,
        "Invalid token should return 401"
    );

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["code"], 4, "Should return error code 4");

    // Test without token
    let response = client
        .post(format!("{}/services/collector/event", infra.hec_url))
        .header("Content-Type", "application/json")
        .json(&event)
        .send()
        .await
        .unwrap();

    assert_eq!(
        response.status().as_u16(),
        401,
        "Missing token should return 401"
    );

    // Test with valid token
    let response = client
        .post(format!("{}/services/collector/event", infra.hec_url))
        .header("Authorization", format!("Splunk {}", infra.hec_token))
        .header("Content-Type", "application/json")
        .json(&event)
        .send()
        .await
        .unwrap();

    assert!(
        response.status().is_success(),
        "Valid token should be accepted"
    );
}

/// Test syslog TCP delivery via Docker container.
#[tokio::test]
#[ignore = "requires Docker infrastructure"]
async fn test_syslog_tcp_delivery_with_docker() {
    let infra = DockerTestInfra::from_env();
    if skip_if_unavailable(&infra).await {
        return;
    }

    // Clear existing messages
    infra.clear_syslog_messages().await.unwrap();

    // Send RFC 5424 syslog message over TCP
    let message = "<134>1 2024-01-15T10:30:00Z test-host xavyo-test - - - TCP test message\n";

    let mut stream =
        TcpStream::connect(infra.syslog_tcp_addr).expect("Failed to connect to syslog TCP");
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .write_all(message.as_bytes())
        .expect("Failed to send TCP message");
    drop(stream); // Close connection

    // Wait for message to be processed
    sleep(Duration::from_millis(500)).await;

    // Verify message was received
    let messages = infra.get_syslog_messages_by_protocol("tcp").await.unwrap();
    assert!(
        !messages.is_empty(),
        "Should have received at least one TCP message"
    );

    let last_msg = &messages[messages.len() - 1];
    assert_eq!(last_msg.protocol, "tcp");
    assert!(last_msg.raw.contains("TCP test message"));

    // Verify parsing
    if let Some(parsed) = &last_msg.parsed {
        assert_eq!(parsed.priority, 134);
        assert_eq!(parsed.facility, 16); // local0
        assert_eq!(parsed.severity, 6); // info
        assert_eq!(parsed.hostname.as_deref(), Some("test-host"));
        assert_eq!(parsed.app_name.as_deref(), Some("xavyo-test"));
    }
}

/// Test syslog UDP delivery via Docker container.
#[tokio::test]
#[ignore = "requires Docker infrastructure"]
async fn test_syslog_udp_delivery_with_docker() {
    let infra = DockerTestInfra::from_env();
    if skip_if_unavailable(&infra).await {
        return;
    }

    // Clear existing messages
    infra.clear_syslog_messages().await.unwrap();

    // Send RFC 5424 syslog message over UDP
    let message = "<165>1 2024-01-15T10:30:00Z test-host xavyo-test - - - UDP test message";

    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind UDP socket");
    socket
        .send_to(message.as_bytes(), infra.syslog_udp_addr)
        .expect("Failed to send UDP message");

    // Wait for message to be processed
    sleep(Duration::from_millis(500)).await;

    // Verify message was received
    let messages = infra.get_syslog_messages_by_protocol("udp").await.unwrap();
    assert!(
        !messages.is_empty(),
        "Should have received at least one UDP message"
    );

    let last_msg = &messages[messages.len() - 1];
    assert_eq!(last_msg.protocol, "udp");
    assert!(last_msg.raw.contains("UDP test message"));

    // Verify parsing
    if let Some(parsed) = &last_msg.parsed {
        assert_eq!(parsed.priority, 165);
        assert_eq!(parsed.facility, 20); // local4
        assert_eq!(parsed.severity, 5); // notice
        assert_eq!(parsed.hostname.as_deref(), Some("test-host"));
    }
}

/// Test high-volume event delivery (100+ events/sec).
#[tokio::test]
#[ignore = "requires Docker infrastructure"]
async fn test_high_volume_delivery() {
    let infra = DockerTestInfra::from_env();
    if skip_if_unavailable(&infra).await {
        return;
    }

    // Clear existing events
    infra.clear_hec_events().await.unwrap();
    infra.clear_syslog_messages().await.unwrap();

    let client = reqwest::Client::new();
    let num_events = 150;
    let start = std::time::Instant::now();

    // Send events in parallel
    let mut handles = Vec::new();
    for i in 0..num_events {
        let client = client.clone();
        let hec_url = infra.hec_url.clone();
        let token = infra.hec_token.clone();

        let handle = tokio::spawn(async move {
            let event = serde_json::json!({
                "time": chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
                "host": "load-test-host",
                "source": "high-volume-test",
                "event": {
                    "sequence": i,
                    "action": "high_volume_test"
                }
            });

            client
                .post(format!("{}/services/collector/event", hec_url))
                .header("Authorization", format!("Splunk {}", token))
                .header("Content-Type", "application/json")
                .json(&event)
                .send()
                .await
        });
        handles.push(handle);
    }

    // Wait for all requests to complete
    let mut success_count = 0;
    for handle in handles {
        if let Ok(Ok(response)) = handle.await {
            if response.status().is_success() {
                success_count += 1;
            }
        }
    }

    let elapsed = start.elapsed();
    let events_per_sec = num_events as f64 / elapsed.as_secs_f64();

    println!(
        "High-volume test: {} events in {:?} ({:.1} events/sec)",
        success_count, elapsed, events_per_sec
    );

    // Verify throughput target
    assert!(
        events_per_sec >= 100.0,
        "Should achieve at least 100 events/sec, got {:.1}",
        events_per_sec
    );

    // Verify all events were received
    let received_count = infra.get_hec_event_count().await.unwrap();
    assert_eq!(
        received_count, success_count,
        "All sent events should be received"
    );
}

/// Test concurrent TCP and UDP syslog delivery.
#[tokio::test]
#[ignore = "requires Docker infrastructure"]
async fn test_concurrent_syslog_protocols() {
    let infra = DockerTestInfra::from_env();
    if skip_if_unavailable(&infra).await {
        return;
    }

    infra.clear_syslog_messages().await.unwrap();

    let tcp_addr = infra.syslog_tcp_addr;
    let udp_addr = infra.syslog_udp_addr;

    // Send messages concurrently via both protocols
    let tcp_handle = tokio::spawn(async move {
        for i in 0..10 {
            let message = format!(
                "<134>1 2024-01-15T10:30:00Z host-tcp app - - - TCP message {}\n",
                i
            );
            if let Ok(mut stream) = TcpStream::connect(tcp_addr) {
                let _ = stream.write_all(message.as_bytes());
            }
        }
    });

    let udp_handle = tokio::spawn(async move {
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        for i in 0..10 {
            let message = format!(
                "<165>1 2024-01-15T10:30:00Z host-udp app - - - UDP message {}",
                i
            );
            let _ = socket.send_to(message.as_bytes(), udp_addr);
        }
    });

    tcp_handle.await.unwrap();
    udp_handle.await.unwrap();

    // Wait for processing
    sleep(Duration::from_secs(1)).await;

    // Verify both protocols received messages
    let tcp_messages = infra.get_syslog_messages_by_protocol("tcp").await.unwrap();
    let udp_messages = infra.get_syslog_messages_by_protocol("udp").await.unwrap();

    assert!(
        !tcp_messages.is_empty(),
        "Should have received TCP messages"
    );
    assert!(
        !udp_messages.is_empty(),
        "Should have received UDP messages"
    );

    println!(
        "Received {} TCP messages and {} UDP messages",
        tcp_messages.len(),
        udp_messages.len()
    );
}
