//! HTTP webhook delivery worker.

use super::{DeliveryError, DeliveryResult, DeliveryWorker};
use crate::validation::validate_webhook_url;
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Default webhook timeout.
const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);

/// HTTP POST webhook delivery worker.
pub struct WebhookWorker {
    url: String,
    headers: HashMap<String, String>,
    client: reqwest::Client,
}

impl WebhookWorker {
    /// Create a new webhook worker.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL fails SSRF validation (e.g., targets internal services).
    ///
    /// # Security
    ///
    /// This constructor validates the URL against SSRF attacks to prevent:
    /// - Requests to private IP ranges (10.x, 172.16.x, 192.168.x)
    /// - Requests to loopback addresses (127.0.0.1, localhost)
    /// - Requests to cloud metadata endpoints (169.254.169.254)
    pub fn new(url: String, headers: HashMap<String, String>) -> Result<Self, DeliveryError> {
        // SECURITY: Validate URL to prevent SSRF attacks
        validate_webhook_url(&url)
            .map_err(|e| DeliveryError::SendFailed(format!("SSRF validation failed: {}", e)))?;

        let client = reqwest::Client::builder()
            .timeout(WEBHOOK_TIMEOUT)
            .build()
            .unwrap_or_default();

        Ok(Self {
            url,
            headers,
            client,
        })
    }

    /// Create a new webhook worker without SSRF validation.
    ///
    /// **WARNING**: This method bypasses SSRF protection. Only use for internal/trusted URLs.
    #[cfg(test)]
    pub fn new_unchecked(url: String, headers: HashMap<String, String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(WEBHOOK_TIMEOUT)
            .build()
            .unwrap_or_default();

        Self {
            url,
            headers,
            client,
        }
    }
}

#[async_trait]
impl DeliveryWorker for WebhookWorker {
    async fn deliver(&self, payload: &str) -> Result<DeliveryResult, DeliveryError> {
        let start = Instant::now();

        let mut request = self
            .client
            .post(&self.url)
            .header("Content-Type", "application/json")
            .body(payload.to_string());

        for (key, value) in &self.headers {
            request = request.header(key.as_str(), value.as_str());
        }

        let response = request.send().await.map_err(|e| {
            if e.is_timeout() {
                DeliveryError::Timeout(format!("Webhook timeout after {:?}", WEBHOOK_TIMEOUT))
            } else if e.is_connect() {
                DeliveryError::ConnectionFailed(format!(
                    "Webhook connect to {} failed: {}",
                    self.url, e
                ))
            } else {
                DeliveryError::SendFailed(e.to_string())
            }
        })?;

        let latency = start.elapsed().as_millis() as u64;
        let status = response.status().as_u16();

        if (200..300).contains(&status) {
            Ok(DeliveryResult::success(latency))
        } else {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "Unable to read response body".to_string());
            Err(DeliveryError::HttpError { status, body })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_worker_creation_valid_url() {
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer token123".to_string());

        let worker =
            WebhookWorker::new("https://siem.example.com/webhook".to_string(), headers).unwrap();
        assert_eq!(worker.url, "https://siem.example.com/webhook");
        assert_eq!(worker.headers.len(), 1);
    }

    #[test]
    fn test_webhook_worker_rejects_private_ip() {
        let result = WebhookWorker::new("https://127.0.0.1/webhook".to_string(), HashMap::new());
        assert!(result.is_err());

        let result = WebhookWorker::new("https://10.0.0.1/webhook".to_string(), HashMap::new());
        assert!(result.is_err());

        let result = WebhookWorker::new("https://192.168.1.1/webhook".to_string(), HashMap::new());
        assert!(result.is_err());
    }

    #[test]
    fn test_webhook_worker_rejects_metadata_endpoint() {
        let result =
            WebhookWorker::new("http://169.254.169.254/latest/".to_string(), HashMap::new());
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_webhook_success_with_mock() {
        use wiremock::matchers::{header, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(header("Content-Type", "application/json"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer test-token".to_string());

        // Use new_unchecked for mock server (127.0.0.1 would fail SSRF validation)
        let worker = WebhookWorker::new_unchecked(server.uri(), headers);
        let result = worker.deliver(r#"{"event": "test"}"#).await;

        assert!(result.is_ok());
        let delivery = result.unwrap();
        assert!(delivery.success);
    }

    #[tokio::test]
    async fn test_webhook_http_error() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
            .mount(&server)
            .await;

        // Use new_unchecked for mock server (127.0.0.1 would fail SSRF validation)
        let worker = WebhookWorker::new_unchecked(server.uri(), HashMap::new());
        let result = worker.deliver("{}").await;

        assert!(result.is_err());
        match result.unwrap_err() {
            DeliveryError::HttpError { status, body } => {
                assert_eq!(status, 403);
                assert_eq!(body, "Forbidden");
            }
            e => panic!("Expected HttpError, got: {:?}", e),
        }
    }
}
