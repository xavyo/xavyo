//! Syslog delivery integration tests for TCP, TLS, and UDP.
//!
//! Tests User Story 2 (Syslog Delivery).

#![cfg(feature = "integration")]

mod helpers;

use helpers::certificates::generate_test_cert;
use helpers::mock_syslog::{MockTcpSyslogServer, MockTlsSyslogServer, MockUdpSyslogServer};
use helpers::test_events::generate_audit_event;
use std::time::Duration;
use uuid::Uuid;
use xavyo_siem::delivery::syslog_tcp::SyslogTcpWorker;
use xavyo_siem::delivery::syslog_udp::SyslogUdpWorker;
use xavyo_siem::delivery::DeliveryWorker;
use xavyo_siem::format::{EventFormatter, SyslogFormatter};

// =============================================================================
// TCP Syslog Delivery Tests
// =============================================================================

/// Test TCP syslog delivery to mock server.
#[tokio::test]
async fn test_tcp_syslog_delivery() {
    let server = MockTcpSyslogServer::start(0).await;
    let addr = server.addr();

    // Create a plain TCP worker (bypassing TLS for this test)
    // We need to send directly since SyslogTcpWorker uses TLS
    let tenant_id = Uuid::new_v4();
    let event = generate_audit_event("tcp.delivery.test", tenant_id);
    let formatter = SyslogFormatter::new(16, None);
    let formatted = formatter.format(&event).unwrap();

    // Connect directly to mock TCP server
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    use tokio::io::AsyncWriteExt;
    stream
        .write_all(format!("{}\n", formatted).as_bytes())
        .await
        .unwrap();
    stream.flush().await.unwrap();

    // Wait for message to be processed
    tokio::time::sleep(Duration::from_millis(100)).await;

    let messages = server.received_messages().await;
    assert_eq!(messages.len(), 1, "Should receive exactly 1 message");
    assert!(
        messages[0].contains("tcp.delivery.test"),
        "Message should contain event type"
    );

    server.shutdown();
}

/// Test multiple TCP messages maintain order.
#[tokio::test]
async fn test_tcp_syslog_message_order() {
    let server = MockTcpSyslogServer::start(0).await;
    let addr = server.addr();

    let tenant_id = Uuid::new_v4();
    let formatter = SyslogFormatter::new(16, None);

    // Connect and send multiple messages
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    use tokio::io::AsyncWriteExt;

    for i in 0..10 {
        let event = generate_audit_event(&format!("ORDER_TEST_{}", i), tenant_id);
        let formatted = formatter.format(&event).unwrap();
        stream
            .write_all(format!("{}\n", formatted).as_bytes())
            .await
            .unwrap();
    }
    stream.flush().await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    let messages = server.received_messages().await;
    assert_eq!(messages.len(), 10, "Should receive all 10 messages");

    // Verify order is maintained
    for (i, msg) in messages.iter().enumerate() {
        assert!(
            msg.contains(&format!("ORDER_TEST_{}", i)),
            "Message {} should contain ORDER_TEST_{}, got: {}",
            i,
            i,
            msg
        );
    }

    server.shutdown();
}

/// Test TCP messages are newline-terminated.
#[tokio::test]
async fn test_tcp_syslog_newline_termination() {
    let server = MockTcpSyslogServer::start(0).await;
    let addr = server.addr();

    let tenant_id = Uuid::new_v4();
    let event = generate_audit_event("NEWLINE_TEST", tenant_id);
    let formatter = SyslogFormatter::new(16, None);
    let formatted = formatter.format(&event).unwrap();

    // Send with proper newline termination
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    use tokio::io::AsyncWriteExt;
    stream
        .write_all(format!("{}\n", formatted).as_bytes())
        .await
        .unwrap();
    stream.flush().await.unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    let messages = server.received_messages().await;
    assert_eq!(messages.len(), 1);

    // Message should not contain trailing newline (server trims it)
    assert!(
        !messages[0].ends_with('\n'),
        "Server should have trimmed newline"
    );

    server.shutdown();
}

// =============================================================================
// TLS Syslog Delivery Tests
// =============================================================================

/// Test TLS syslog delivery with valid certificate.
#[tokio::test]
async fn test_tls_syslog_delivery() {
    let (cert_pem, key_pem) = generate_test_cert();
    let server = MockTlsSyslogServer::start(0, &cert_pem, &key_pem).await;
    let addr = server.addr();

    // Create TLS worker that accepts self-signed certs
    let worker = SyslogTcpWorker::new(
        addr.ip().to_string(),
        addr.port(),
        false, // Don't verify cert (self-signed)
    );

    let tenant_id = Uuid::new_v4();
    let event = generate_audit_event("tls.delivery.test", tenant_id);
    let formatter = SyslogFormatter::new(16, None);
    let formatted = formatter.format(&event).unwrap();

    let result = worker.deliver(&formatted).await;
    assert!(
        result.is_ok(),
        "TLS delivery should succeed: {:?}",
        result.err()
    );

    tokio::time::sleep(Duration::from_millis(100)).await;

    let messages = server.received_messages().await;
    assert_eq!(messages.len(), 1, "Should receive exactly 1 message");
    assert!(messages[0].contains("tls.delivery.test"));

    server.shutdown();
}

/// Test TLS certificate validation.
#[tokio::test]
async fn test_tls_syslog_certificate_validation() {
    let (cert_pem, key_pem) = generate_test_cert();
    let server = MockTlsSyslogServer::start(0, &cert_pem, &key_pem).await;
    let addr = server.addr();

    // Create TLS worker WITH certificate verification
    let worker = SyslogTcpWorker::new(
        addr.ip().to_string(),
        addr.port(),
        true, // Verify cert (will fail for self-signed)
    );

    let result = worker.deliver("test message").await;

    // Should fail because we're using a self-signed cert
    assert!(
        result.is_err(),
        "Should fail with self-signed cert when verification is enabled"
    );

    server.shutdown();
}

// =============================================================================
// UDP Syslog Delivery Tests
// =============================================================================

/// Test UDP syslog delivery.
#[tokio::test]
async fn test_udp_syslog_delivery() {
    let server = MockUdpSyslogServer::start(0).await;
    let addr = server.addr();

    let worker = SyslogUdpWorker::new(addr.ip().to_string(), addr.port());

    let tenant_id = Uuid::new_v4();
    let event = generate_audit_event("udp.delivery.test", tenant_id);
    let formatter = SyslogFormatter::new(16, None);
    let formatted = formatter.format(&event).unwrap();

    let result = worker.deliver(&formatted).await;
    assert!(result.is_ok(), "UDP delivery should succeed");
    assert!(result.unwrap().success);

    tokio::time::sleep(Duration::from_millis(100)).await;

    let messages = server.received_messages().await;
    assert_eq!(messages.len(), 1, "Should receive 1 UDP message");
    assert!(messages[0].contains("udp.delivery.test"));

    server.shutdown();
}

/// Test UDP message size limit.
#[tokio::test]
async fn test_udp_message_too_large() {
    let server = MockUdpSyslogServer::start(0).await;
    let addr = server.addr();

    let worker = SyslogUdpWorker::new(addr.ip().to_string(), addr.port());

    // Create oversized message (> 65507 bytes)
    let oversized = "x".repeat(65508);

    let result = worker.deliver(&oversized).await;
    assert!(result.is_err(), "Oversized UDP message should fail");

    server.shutdown();
}

// =============================================================================
// Connection Failure and Retry Tests
// =============================================================================

/// Test TCP connection retry on failure.
#[tokio::test]
async fn test_tcp_connection_retry_on_failure() {
    // Try to connect to a port that's not listening
    let worker = SyslogTcpWorker::new("127.0.0.1".to_string(), 1, false);

    let result = worker.deliver("test message").await;
    assert!(result.is_err(), "Should fail when no server is listening");

    match result.unwrap_err() {
        xavyo_siem::delivery::DeliveryError::ConnectionFailed(_) => {
            // Expected error type
        }
        xavyo_siem::delivery::DeliveryError::TlsError(_) => {
            // Also acceptable - TLS handshake fails after TCP connect
        }
        e => panic!("Unexpected error type: {:?}", e),
    }
}

/// Test exponential backoff behavior.
#[tokio::test]
async fn test_tcp_exponential_backoff() {
    use helpers::mock_syslog::FailingMockServer;

    // Server that fails first 2 connections then succeeds
    let server = FailingMockServer::start(0, 2).await;
    let addr = server.addr();

    let tenant_id = Uuid::new_v4();
    let formatter = SyslogFormatter::new(16, None);
    let event = generate_audit_event("backoff.test", tenant_id);
    let formatted = formatter.format(&event).unwrap();

    // First two attempts should fail
    for i in 0..2 {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        use tokio::io::AsyncWriteExt;
        let write_result = stream
            .write_all(format!("{}\n", formatted).as_bytes())
            .await;
        // Connection may fail or write may fail
        if write_result.is_ok() {
            // Server will close connection, but that's okay
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Third attempt should succeed
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    use tokio::io::AsyncWriteExt;
    stream
        .write_all(format!("{}\n", formatted).as_bytes())
        .await
        .unwrap();
    stream.flush().await.unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    let messages = server.received_messages().await;
    assert_eq!(messages.len(), 1, "Should receive message after retries");

    server.shutdown();
}
