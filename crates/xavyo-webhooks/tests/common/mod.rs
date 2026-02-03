//! Common test utilities for xavyo-webhooks integration tests.
//!
//! Provides mock servers, helper structs, and test fixtures for verifying
//! webhook delivery behavior without requiring a real database.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use wiremock::{Request, Respond, ResponseTemplate};

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

/// Standard test tenant IDs
pub const TENANT_A: Uuid = Uuid::from_bytes([
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
]);

pub const TENANT_B: Uuid = Uuid::from_bytes([
    0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
]);

/// Standard test user IDs
pub const USER_1: Uuid = Uuid::from_bytes([
    0xaa, 0xaa, 0x11, 0x11, 0xaa, 0xaa, 0x11, 0x11, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
]);

pub const USER_2: Uuid = Uuid::from_bytes([
    0xbb, 0xbb, 0x22, 0x22, 0xbb, 0xbb, 0x22, 0x22, 0xbb, 0xbb, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
]);

/// Standard test secrets
pub const SECRET_1: &str = "whsec_test_secret_key_12345";
pub const SECRET_2: &str = "whsec_another_secret_67890";

// ---------------------------------------------------------------------------
// CapturedRequest - for inspecting webhook requests
// ---------------------------------------------------------------------------

/// A captured HTTP request with body and headers.
#[derive(Debug, Clone)]
pub struct CapturedRequest {
    pub body: Vec<u8>,
    pub headers: HashMap<String, String>,
    pub timestamp: DateTime<Utc>,
}

impl CapturedRequest {
    /// Parse the body as JSON.
    pub fn body_json<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }

    /// Get a header value by name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == name_lower)
            .map(|(_, v)| v.as_str())
    }
}

// ---------------------------------------------------------------------------
// CaptureResponder - captures requests and returns success
// ---------------------------------------------------------------------------

/// A wiremock responder that captures incoming requests.
#[derive(Clone)]
pub struct CaptureResponder {
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    response_code: u16,
}

impl CaptureResponder {
    /// Create a new capture responder that returns 200 OK.
    pub fn new() -> Self {
        Self {
            requests: Arc::new(Mutex::new(Vec::new())),
            response_code: 200,
        }
    }

    /// Create a capture responder that returns a custom status code.
    pub fn with_status(status: u16) -> Self {
        Self {
            requests: Arc::new(Mutex::new(Vec::new())),
            response_code: status,
        }
    }

    /// Get all captured requests.
    pub fn requests(&self) -> Vec<CapturedRequest> {
        self.requests.lock().unwrap().clone()
    }

    /// Get the number of captured requests.
    pub fn request_count(&self) -> usize {
        self.requests.lock().unwrap().len()
    }
}

impl Default for CaptureResponder {
    fn default() -> Self {
        Self::new()
    }
}

impl Respond for CaptureResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let captured = CapturedRequest {
            body: request.body.clone(),
            headers: request
                .headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect(),
            timestamp: Utc::now(),
        };
        self.requests.lock().unwrap().push(captured);
        ResponseTemplate::new(self.response_code)
    }
}

// ---------------------------------------------------------------------------
// CountingResponder - counts requests
// ---------------------------------------------------------------------------

/// A wiremock responder that counts incoming requests.
#[derive(Clone)]
pub struct CountingResponder {
    count: Arc<AtomicU32>,
    response_code: u16,
}

impl CountingResponder {
    /// Create a new counting responder that returns 200 OK.
    pub fn new() -> Self {
        Self {
            count: Arc::new(AtomicU32::new(0)),
            response_code: 200,
        }
    }

    /// Create a counting responder that returns a custom status code.
    pub fn with_status(status: u16) -> Self {
        Self {
            count: Arc::new(AtomicU32::new(0)),
            response_code: status,
        }
    }

    /// Get the current request count.
    pub fn count(&self) -> u32 {
        self.count.load(Ordering::SeqCst)
    }
}

impl Default for CountingResponder {
    fn default() -> Self {
        Self::new()
    }
}

impl Respond for CountingResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        self.count.fetch_add(1, Ordering::SeqCst);
        ResponseTemplate::new(self.response_code)
    }
}

// ---------------------------------------------------------------------------
// FailingResponder - fails N times then succeeds
// ---------------------------------------------------------------------------

/// A wiremock responder that fails a specified number of times before succeeding.
#[derive(Clone)]
pub struct FailingResponder {
    attempt_count: Arc<AtomicU32>,
    failures_before_success: u32,
    failure_code: u16,
    success_code: u16,
}

impl FailingResponder {
    /// Create a responder that fails `n` times with 500, then returns 200.
    pub fn fail_times(n: u32) -> Self {
        Self {
            attempt_count: Arc::new(AtomicU32::new(0)),
            failures_before_success: n,
            failure_code: 500,
            success_code: 200,
        }
    }

    /// Create a responder that fails with a custom status code.
    pub fn fail_with_status(n: u32, failure_code: u16) -> Self {
        Self {
            attempt_count: Arc::new(AtomicU32::new(0)),
            failures_before_success: n,
            failure_code,
            success_code: 200,
        }
    }

    /// Get the current attempt count.
    pub fn attempt_count(&self) -> u32 {
        self.attempt_count.load(Ordering::SeqCst)
    }
}

impl Respond for FailingResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let n = self.attempt_count.fetch_add(1, Ordering::SeqCst);
        if n < self.failures_before_success {
            ResponseTemplate::new(self.failure_code)
        } else {
            ResponseTemplate::new(self.success_code)
        }
    }
}

// ---------------------------------------------------------------------------
// DelayedResponder - adds response delay
// ---------------------------------------------------------------------------

/// A wiremock responder that adds a delay before responding.
#[derive(Clone)]
pub struct DelayedResponder {
    delay_ms: u64,
    response_code: u16,
}

impl DelayedResponder {
    /// Create a responder that delays for `ms` milliseconds.
    pub fn new(delay_ms: u64) -> Self {
        Self {
            delay_ms,
            response_code: 200,
        }
    }

    /// Create a delayed responder with custom status code.
    pub fn with_status(delay_ms: u64, response_code: u16) -> Self {
        Self {
            delay_ms,
            response_code,
        }
    }
}

impl Respond for DelayedResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        ResponseTemplate::new(self.response_code)
            .set_delay(std::time::Duration::from_millis(self.delay_ms))
    }
}

// ---------------------------------------------------------------------------
// WebhookPayload - matches the expected webhook structure
// ---------------------------------------------------------------------------

/// JSON payload delivered to webhook endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    pub event_id: Uuid,
    pub event_type: String,
    pub timestamp: DateTime<Utc>,
    pub tenant_id: Uuid,
    pub data: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Helper functions for signature verification
// ---------------------------------------------------------------------------

/// Compute HMAC-SHA256 signature for verification (same as crypto module).
pub fn compute_test_signature(secret: &str, timestamp: &str, body: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");

    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);

    hex::encode(mac.finalize().into_bytes())
}

/// Verify a webhook signature from a captured request.
pub fn verify_captured_signature(request: &CapturedRequest, secret: &str) -> bool {
    let signature_header = match request.header("x-webhook-signature") {
        Some(h) => h,
        None => return false,
    };

    let timestamp = match request.header("x-webhook-timestamp") {
        Some(t) => t,
        None => return false,
    };

    // Expected format: "sha256={hex}"
    let expected = format!(
        "sha256={}",
        compute_test_signature(secret, timestamp, &request.body)
    );

    signature_header == expected
}

// ---------------------------------------------------------------------------
// Test HTTP client for direct delivery testing
// ---------------------------------------------------------------------------

/// Simple HTTP client for testing webhook delivery.
pub struct TestWebhookClient {
    client: reqwest::Client,
}

impl TestWebhookClient {
    /// Create a new test client.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("Failed to build HTTP client"),
        }
    }

    /// Deliver a webhook payload to a URL with optional signature.
    pub async fn deliver(
        &self,
        url: &str,
        payload: &WebhookPayload,
        secret: Option<&str>,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let body = serde_json::to_vec(payload).expect("Failed to serialize payload");
        let timestamp = Utc::now().timestamp().to_string();

        let mut request = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .header("X-Webhook-Timestamp", &timestamp)
            .header("X-Event-ID", payload.event_id.to_string());

        if let Some(secret) = secret {
            let signature = compute_test_signature(secret, &timestamp, &body);
            request = request.header("X-Webhook-Signature", format!("sha256={}", signature));
        }

        request.body(body).send().await
    }
}

impl Default for TestWebhookClient {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helper to create test payloads
// ---------------------------------------------------------------------------

/// Create a test webhook payload for user.created event.
pub fn user_created_payload(tenant_id: Uuid, user_id: Uuid) -> WebhookPayload {
    WebhookPayload {
        event_id: Uuid::new_v4(),
        event_type: "user.created".to_string(),
        timestamp: Utc::now(),
        tenant_id,
        data: serde_json::json!({
            "user_id": user_id.to_string(),
            "email": "test@example.com",
            "display_name": "Test User"
        }),
    }
}

/// Create a test webhook payload for user.updated event.
pub fn user_updated_payload(tenant_id: Uuid, user_id: Uuid) -> WebhookPayload {
    WebhookPayload {
        event_id: Uuid::new_v4(),
        event_type: "user.updated".to_string(),
        timestamp: Utc::now(),
        tenant_id,
        data: serde_json::json!({
            "user_id": user_id.to_string(),
            "changes": ["email", "display_name"]
        }),
    }
}

/// Create a test webhook payload for role.assigned event.
pub fn role_assigned_payload(tenant_id: Uuid, user_id: Uuid, role: &str) -> WebhookPayload {
    WebhookPayload {
        event_id: Uuid::new_v4(),
        event_type: "role.assigned".to_string(),
        timestamp: Utc::now(),
        tenant_id,
        data: serde_json::json!({
            "user_id": user_id.to_string(),
            "role": role
        }),
    }
}

/// Create a custom test webhook payload.
pub fn custom_payload(
    tenant_id: Uuid,
    event_type: &str,
    data: serde_json::Value,
) -> WebhookPayload {
    WebhookPayload {
        event_id: Uuid::new_v4(),
        event_type: event_type.to_string(),
        timestamp: Utc::now(),
        tenant_id,
        data,
    }
}
