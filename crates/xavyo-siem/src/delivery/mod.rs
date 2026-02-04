//! Delivery workers for SIEM export.
//!
//! Supported delivery mechanisms:
//! - Syslog TCP/TLS
//! - Syslog UDP
//! - HTTP webhook
//! - Splunk HEC

pub mod splunk_hec;
pub mod syslog_tcp;
pub mod syslog_udp;
pub mod webhook;

use std::collections::HashMap;
use std::net::IpAddr;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from delivery operations.
#[derive(Debug, Error)]
pub enum DeliveryError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Send failed: {0}")]
    SendFailed(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("TLS error: {0}")]
    TlsError(String),

    #[error("HTTP error: status {status}, body: {body}")]
    HttpError { status: u16, body: String },

    #[error("Message too large: {size} bytes (max {max})")]
    MessageTooLarge { size: usize, max: usize },
}

/// Result of a delivery attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryResult {
    /// Whether delivery succeeded.
    pub success: bool,
    /// Delivery latency in milliseconds.
    pub latency_ms: u64,
    /// Error message if delivery failed.
    pub error: Option<String>,
}

impl DeliveryResult {
    #[must_use] 
    pub fn success(latency_ms: u64) -> Self {
        Self {
            success: true,
            latency_ms,
            error: None,
        }
    }

    #[must_use] 
    pub fn failure(latency_ms: u64, error: String) -> Self {
        Self {
            success: false,
            latency_ms,
            error: Some(error),
        }
    }
}

/// Trait for delivering formatted payloads to SIEM destinations.
#[async_trait]
pub trait DeliveryWorker: Send + Sync {
    /// Deliver a formatted payload string to the destination.
    async fn deliver(&self, payload: &str) -> Result<DeliveryResult, DeliveryError>;

    /// Send a test event to verify connectivity.
    async fn test_connectivity(&self) -> Result<DeliveryResult, DeliveryError> {
        self.deliver("CEF:0|Xavyo|IDP|1.0.0|TEST|Test Connectivity|0|msg=Test event from xavyo SIEM integration")
            .await
    }
}

/// HTTP headers that must not be overridden by tenant-provided `auth_config`.
const DENIED_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "upgrade",
    "te",
    "trailer",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "forwarded",
];

/// Validate that a destination host is not a private/internal address.
///
/// Blocks SSRF attempts targeting internal networks, link-local,
/// loopback, and cloud metadata endpoints.
fn validate_host_not_internal(host: &str) -> Result<(), DeliveryError> {
    // Check if host is a raw IP address
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_internal_ip(&ip) {
            return Err(DeliveryError::ConnectionFailed(format!(
                "Destination host {host} is a private/internal address"
            )));
        }
    }

    // Block common internal hostnames
    let lower = host.to_ascii_lowercase();
    if lower == "localhost"
        || lower == "metadata.google.internal"
        || lower.ends_with(".internal")
        || lower.ends_with(".local")
    {
        return Err(DeliveryError::ConnectionFailed(format!(
            "Destination host {host} is a restricted internal hostname"
        )));
    }

    Ok(())
}

fn is_internal_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()                     // 127.0.0.0/8
                || v4.is_private()               // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || v4.is_link_local()            // 169.254.0.0/16 (AWS/Azure metadata)
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64 // 100.64.0.0/10 (CGNAT)
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

/// Filter tenant-provided headers, removing any from the denylist.
fn sanitize_headers(headers: HashMap<String, String>) -> HashMap<String, String> {
    headers
        .into_iter()
        .filter(|(k, _)| !DENIED_HEADERS.contains(&k.to_ascii_lowercase().as_str()))
        .collect()
}

/// Factory function to create a delivery worker based on destination configuration.
///
/// Validates the destination host against SSRF protections before creating
/// the worker. Returns a `DeliveryError` if the host is an internal address.
#[allow(clippy::too_many_arguments)]
pub fn create_worker(
    destination_type: &crate::models::DestinationType,
    host: &str,
    port: u16,
    tls_verify_cert: bool,
    auth_config: Option<&str>,
    splunk_source: Option<&str>,
    splunk_sourcetype: Option<&str>,
    splunk_index: Option<&str>,
) -> Result<Box<dyn DeliveryWorker>, DeliveryError> {
    // SSRF protection: block internal/private addresses
    validate_host_not_internal(host)?;

    match destination_type {
        crate::models::DestinationType::SyslogTcpTls => Ok(Box::new(
            syslog_tcp::SyslogTcpWorker::new(host.to_string(), port, tls_verify_cert),
        )),
        crate::models::DestinationType::SyslogUdp => Ok(Box::new(
            syslog_udp::SyslogUdpWorker::new(host.to_string(), port),
        )),
        crate::models::DestinationType::Webhook => {
            let raw_headers: HashMap<String, String> = auth_config
                .and_then(|c| serde_json::from_str(c).ok())
                .unwrap_or_default();
            let headers = sanitize_headers(raw_headers);
            // SECURITY: WebhookWorker::new validates URL against SSRF attacks
            let worker =
                webhook::WebhookWorker::new(format!("https://{host}:{port}"), headers)?;
            Ok(Box::new(worker))
        }
        crate::models::DestinationType::SplunkHec => {
            let token = auth_config
                .and_then(|c| {
                    serde_json::from_str::<serde_json::Value>(c)
                        .ok()
                        .and_then(|v| {
                            v.get("hec_token")
                                .and_then(|t| t.as_str().map(String::from))
                        })
                })
                .unwrap_or_default();
            Ok(Box::new(splunk_hec::SplunkHecWorker::new(
                host.to_string(),
                port,
                token,
                splunk_source.unwrap_or("xavyo").to_string(),
                splunk_sourcetype
                    .unwrap_or("xavyo:identity:events")
                    .to_string(),
                splunk_index.map(String::from),
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::DestinationType;

    #[test]
    fn test_ssrf_blocks_loopback() {
        assert!(validate_host_not_internal("127.0.0.1").is_err());
    }

    #[test]
    fn test_ssrf_blocks_private_networks() {
        assert!(validate_host_not_internal("10.0.0.1").is_err());
        assert!(validate_host_not_internal("172.16.0.1").is_err());
        assert!(validate_host_not_internal("192.168.1.1").is_err());
    }

    #[test]
    fn test_ssrf_blocks_link_local() {
        assert!(validate_host_not_internal("169.254.169.254").is_err());
    }

    #[test]
    fn test_ssrf_blocks_localhost() {
        assert!(validate_host_not_internal("localhost").is_err());
    }

    #[test]
    fn test_ssrf_blocks_internal_hostnames() {
        assert!(validate_host_not_internal("metadata.google.internal").is_err());
        assert!(validate_host_not_internal("service.internal").is_err());
        assert!(validate_host_not_internal("myhost.local").is_err());
    }

    #[test]
    fn test_ssrf_allows_public_hosts() {
        assert!(validate_host_not_internal("siem.company.com").is_ok());
        assert!(validate_host_not_internal("8.8.8.8").is_ok());
        assert!(validate_host_not_internal("splunk.example.com").is_ok());
    }

    #[test]
    fn test_ssrf_blocks_in_create_worker() {
        let result = create_worker(
            &DestinationType::Webhook,
            "169.254.169.254",
            80,
            true,
            None,
            None,
            None,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_sanitize_headers_removes_forbidden() {
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer token".to_string());
        headers.insert("Host".to_string(), "evil.com".to_string());
        headers.insert("Transfer-Encoding".to_string(), "chunked".to_string());
        headers.insert("X-Custom".to_string(), "value".to_string());

        let sanitized = sanitize_headers(headers);
        assert_eq!(sanitized.len(), 2);
        assert!(sanitized.contains_key("Authorization"));
        assert!(sanitized.contains_key("X-Custom"));
        assert!(!sanitized.contains_key("Host"));
        assert!(!sanitized.contains_key("Transfer-Encoding"));
    }
}
