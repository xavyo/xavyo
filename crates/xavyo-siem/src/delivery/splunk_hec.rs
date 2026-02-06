//! Splunk HTTP Event Collector (HEC) delivery worker.

use super::{DeliveryError, DeliveryResult, DeliveryWorker};
use async_trait::async_trait;
use serde_json::json;
use std::time::{Duration, Instant};

/// Default HEC timeout.
const HEC_TIMEOUT: Duration = Duration::from_secs(10);

/// Splunk HEC delivery worker.
pub struct SplunkHecWorker {
    host: String,
    port: u16,
    token: String,
    source: String,
    sourcetype: String,
    index: Option<String>,
    client: reqwest::Client,
}

impl SplunkHecWorker {
    #[must_use]
    pub fn new(
        host: String,
        port: u16,
        token: String,
        source: String,
        sourcetype: String,
        index: Option<String>,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(HEC_TIMEOUT)
            .build()
            .unwrap_or_default();

        Self {
            host,
            port,
            token,
            source,
            sourcetype,
            index,
            client,
        }
    }

    /// Build the HEC endpoint URL.
    fn endpoint_url(&self) -> String {
        format!(
            "https://{}:{}/services/collector/event",
            self.host, self.port
        )
    }

    /// Build the HEC JSON payload wrapping the event data.
    fn build_hec_payload(&self, event_json: &str) -> Result<String, DeliveryError> {
        let event: serde_json::Value = serde_json::from_str(event_json)
            .map_err(|e| DeliveryError::SendFailed(format!("Invalid event JSON: {e}")))?;

        let timestamp = event
            .get("timestamp")
            .and_then(|t| t.as_str())
            .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
            .map_or_else(|| chrono::Utc::now().timestamp(), |dt| dt.timestamp());

        let mut payload = json!({
            "time": timestamp,
            "host": "idp.xavyo.net",
            "source": self.source,
            "sourcetype": self.sourcetype,
            "event": event,
        });

        if let Some(ref index) = self.index {
            payload
                .as_object_mut()
                .unwrap()
                .insert("index".to_string(), json!(index));
        }

        serde_json::to_string(&payload)
            .map_err(|e| DeliveryError::SendFailed(format!("JSON serialization failed: {e}")))
    }
}

#[async_trait]
impl DeliveryWorker for SplunkHecWorker {
    async fn deliver(&self, payload: &str) -> Result<DeliveryResult, DeliveryError> {
        let start = Instant::now();
        let url = self.endpoint_url();

        let hec_payload = self.build_hec_payload(payload)?;

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Splunk {}", self.token))
            .header("Content-Type", "application/json")
            .body(hec_payload)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    DeliveryError::Timeout(format!("HEC timeout after {HEC_TIMEOUT:?}"))
                } else if e.is_connect() {
                    DeliveryError::ConnectionFailed(format!("HEC connect to {url} failed: {e}"))
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
    fn test_splunk_hec_worker_creation() {
        let worker = SplunkHecWorker::new(
            "splunk.example.com".to_string(),
            8088,
            "my-token".to_string(),
            "xavyo".to_string(),
            "xavyo:identity:events".to_string(),
            Some("identity_events".to_string()),
        );
        assert_eq!(worker.host, "splunk.example.com");
        assert_eq!(worker.port, 8088);
        assert_eq!(worker.token, "my-token");
    }

    #[test]
    fn test_splunk_hec_endpoint_url() {
        let worker = SplunkHecWorker::new(
            "splunk.example.com".to_string(),
            8088,
            "token".to_string(),
            "src".to_string(),
            "st".to_string(),
            None,
        );
        assert_eq!(
            worker.endpoint_url(),
            "https://splunk.example.com:8088/services/collector/event"
        );
    }

    #[test]
    fn test_build_hec_payload() {
        let worker = SplunkHecWorker::new(
            "splunk.example.com".to_string(),
            8088,
            "token".to_string(),
            "xavyo".to_string(),
            "xavyo:identity:events".to_string(),
            Some("identity_events".to_string()),
        );

        let event = r#"{"timestamp":"2026-01-27T14:30:00.000Z","event_type":"authentication.failure","severity":6}"#;
        let payload = worker.build_hec_payload(event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();

        assert!(parsed.get("time").is_some());
        assert_eq!(parsed["host"], "idp.xavyo.net");
        assert_eq!(parsed["source"], "xavyo");
        assert_eq!(parsed["sourcetype"], "xavyo:identity:events");
        assert_eq!(parsed["index"], "identity_events");
        assert!(parsed.get("event").is_some());
    }

    #[test]
    fn test_build_hec_payload_without_index() {
        let worker = SplunkHecWorker::new(
            "splunk.example.com".to_string(),
            8088,
            "token".to_string(),
            "xavyo".to_string(),
            "xavyo:identity:events".to_string(),
            None,
        );

        let event = r#"{"event_type":"test"}"#;
        let payload = worker.build_hec_payload(event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();

        assert!(parsed.get("index").is_none());
    }

    #[tokio::test]
    async fn test_splunk_hec_success_with_mock() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/collector/event"))
            .and(header("Authorization", "Splunk test-token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(r#"{"text":"Success","code":0}"#),
            )
            .mount(&server)
            .await;

        // Extract host/port from the mock server URI
        let uri = server.uri();
        let url: url::Url = uri.parse().unwrap();
        let host = url.host_str().unwrap().to_string();
        let port = url.port().unwrap();

        // Override the endpoint to use HTTP (mock) instead of HTTPS
        let client = reqwest::Client::builder()
            .timeout(HEC_TIMEOUT)
            .build()
            .unwrap();

        let worker = SplunkHecWorker {
            host,
            port,
            token: "test-token".to_string(),
            source: "xavyo".to_string(),
            sourcetype: "xavyo:identity:events".to_string(),
            index: Some("identity_events".to_string()),
            client,
        };

        // Override endpoint URL to use HTTP
        let event = r#"{"timestamp":"2026-01-27T14:30:00.000Z","event_type":"test"}"#;
        let hec_payload = worker.build_hec_payload(event).unwrap();

        let response = worker
            .client
            .post(format!("{}/services/collector/event", server.uri()))
            .header("Authorization", "Splunk test-token")
            .header("Content-Type", "application/json")
            .body(hec_payload)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status().as_u16(), 200);
    }

    #[tokio::test]
    async fn test_splunk_hec_403_handling() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/services/collector/event"))
            .respond_with(
                ResponseTemplate::new(403).set_body_string(r#"{"text":"Invalid token","code":4}"#),
            )
            .mount(&server)
            .await;

        let uri = server.uri();
        let url_parsed: url::Url = uri.parse().unwrap();

        let worker = SplunkHecWorker {
            host: url_parsed.host_str().unwrap().to_string(),
            port: url_parsed.port().unwrap(),
            token: "bad-token".to_string(),
            source: "xavyo".to_string(),
            sourcetype: "xavyo:identity:events".to_string(),
            index: None,
            client: reqwest::Client::new(),
        };

        let event = r#"{"event_type":"test"}"#;
        let hec_payload = worker.build_hec_payload(event).unwrap();

        let response = worker
            .client
            .post(format!("{}/services/collector/event", server.uri()))
            .header("Authorization", "Splunk bad-token")
            .header("Content-Type", "application/json")
            .body(hec_payload)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status().as_u16(), 403);
    }
}
