//! Integration tests for HMAC-SHA256 signature verification (User Story 3).
//!
//! Tests verify signatures are correctly generated, included in headers,
//! and can be verified by recipients.

#![cfg(feature = "integration")]

mod common;

use common::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer};
use xavyo_webhooks::crypto::{compute_hmac_signature, verify_hmac_signature};

/// Test: HMAC signature header is present when secret is configured.
#[tokio::test]
async fn test_hmac_signature_header_present() {
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
    let signature = captured.header("x-webhook-signature");

    assert!(
        signature.is_some(),
        "X-Webhook-Signature header should be present"
    );
    assert!(
        signature.unwrap().starts_with("sha256="),
        "Signature should start with 'sha256='"
    );
}

/// Test: Signature format is sha256={64 hex characters}.
#[tokio::test]
async fn test_signature_format_sha256_hex() {
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
    let signature = captured.header("x-webhook-signature").unwrap();

    // Format: sha256={64 hex chars}
    assert!(
        signature.starts_with("sha256="),
        "Should start with 'sha256='"
    );

    let hex_part = &signature[7..]; // Skip "sha256="
    assert_eq!(
        hex_part.len(),
        64,
        "SHA256 should produce 64 hex characters"
    );
    assert!(
        hex_part.chars().all(|c| c.is_ascii_hexdigit()),
        "Signature should be valid hex"
    );
}

/// Test: Computed signature matches the header value.
#[tokio::test]
async fn test_signature_verification_succeeds() {
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

    // Verify using our test helper
    assert!(
        verify_captured_signature(captured, SECRET_1),
        "Signature verification should succeed with correct secret"
    );

    // Verify using the crypto module directly
    let signature_header = captured.header("x-webhook-signature").unwrap();
    let timestamp = captured.header("x-webhook-timestamp").unwrap();
    let hex_signature = &signature_header[7..]; // Skip "sha256="

    let is_valid = verify_hmac_signature(hex_signature, SECRET_1, timestamp, &captured.body);
    assert!(is_valid, "Crypto module verification should succeed");
}

/// Test: Different payloads produce different signatures.
#[tokio::test]
async fn test_different_payloads_different_signatures() {
    let mock_server = MockServer::start().await;
    let capture = CaptureResponder::new();

    Mock::given(method("POST"))
        .and(path("/webhook"))
        .respond_with(capture.clone())
        .mount(&mock_server)
        .await;

    let client = TestWebhookClient::new();
    let url = format!("{}/webhook", mock_server.uri());

    // Send two different payloads
    let payload1 = user_created_payload(TENANT_A, USER_1);
    let payload2 = user_updated_payload(TENANT_A, USER_2);

    client
        .deliver(&url, &payload1, Some(SECRET_1))
        .await
        .unwrap();
    client
        .deliver(&url, &payload2, Some(SECRET_1))
        .await
        .unwrap();

    let requests = capture.requests();
    let sig1 = requests[0].header("x-webhook-signature").unwrap();
    let sig2 = requests[1].header("x-webhook-signature").unwrap();

    assert_ne!(
        sig1, sig2,
        "Different payloads should produce different signatures"
    );
}

/// Test: No signature header when secret is not configured.
#[tokio::test]
async fn test_delivery_without_secret_no_signature() {
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

    // Deliver without a secret
    client.deliver(&url, &payload, None).await.unwrap();

    let captured = &capture.requests()[0];

    // Should NOT have a signature header
    assert!(
        captured.header("x-webhook-signature").is_none(),
        "X-Webhook-Signature should NOT be present without a secret"
    );

    // But timestamp should still be present
    assert!(
        captured.header("x-webhook-timestamp").is_some(),
        "X-Webhook-Timestamp should still be present"
    );
}

/// Test: Signature verification fails with wrong secret.
#[tokio::test]
async fn test_signature_verification_fails_with_wrong_secret() {
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

    // Sign with SECRET_1
    client
        .deliver(&url, &payload, Some(SECRET_1))
        .await
        .unwrap();

    let captured = &capture.requests()[0];

    // Verify with wrong secret should fail
    assert!(
        !verify_captured_signature(captured, SECRET_2),
        "Signature verification should fail with wrong secret"
    );

    // Verify with correct secret should succeed
    assert!(
        verify_captured_signature(captured, SECRET_1),
        "Signature verification should succeed with correct secret"
    );
}

/// Test: Signature uses timestamp to prevent replay attacks.
#[tokio::test]
async fn test_signature_includes_timestamp() {
    // The signature is computed as HMAC(secret, timestamp + "." + body)
    // This test verifies the timestamp is used in signature computation

    let secret = "test-secret";
    let body = b"test-body";

    // Same body, different timestamps should produce different signatures
    let sig1 = compute_hmac_signature(secret, "1706400000", body);
    let sig2 = compute_hmac_signature(secret, "1706400001", body);

    assert_ne!(
        sig1, sig2,
        "Different timestamps should produce different signatures"
    );

    // Same timestamp, same body should be deterministic
    let sig3 = compute_hmac_signature(secret, "1706400000", body);
    assert_eq!(sig1, sig3, "Same inputs should produce same signature");
}
