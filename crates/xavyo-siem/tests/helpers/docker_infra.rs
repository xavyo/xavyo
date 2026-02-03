//! Docker test infrastructure helper.
//!
//! This module provides utilities for running integration tests against
//! Docker-based mock SIEM services (Splunk HEC and syslog).
//!
//! # Usage
//!
//! ```ignore
//! let infra = DockerTestInfra::from_env();
//! infra.wait_ready(Duration::from_secs(60)).await?;
//!
//! // Run tests...
//!
//! let events = infra.get_hec_events().await;
//! let messages = infra.get_syslog_messages().await;
//! ```

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;

/// Errors from Docker infrastructure operations.
#[derive(Error, Debug)]
pub enum DockerInfraError {
    #[error("Service not ready after {0} seconds")]
    Timeout(u64),

    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Failed to parse response: {0}")]
    ParseError(String),

    #[error("Service unhealthy: {0}")]
    Unhealthy(String),
}

/// Docker test infrastructure manager.
///
/// Manages connections to Docker-based mock SIEM services for integration testing.
pub struct DockerTestInfra {
    /// Base URL for Splunk HEC mock (e.g., "http://localhost:8088")
    pub hec_url: String,

    /// Base URL for syslog mock HTTP API (e.g., "http://localhost:8089")
    pub syslog_api_url: String,

    /// Syslog TCP address (e.g., "127.0.0.1:1514")
    pub syslog_tcp_addr: SocketAddr,

    /// Syslog UDP address (e.g., "127.0.0.1:1514")
    pub syslog_udp_addr: SocketAddr,

    /// HEC authentication token
    pub hec_token: String,

    /// HTTP client for API calls
    client: Client,
}

/// Health check response from mock services.
#[derive(Debug, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub service: String,
    pub version: String,
    pub uptime_seconds: f64,
}

/// HEC event record from mock server.
#[derive(Debug, Deserialize, Serialize)]
pub struct HecEventRecord {
    pub received_at: String,
    pub payload: serde_json::Value,
    pub source_ip: String,
}

/// Syslog message record from mock server.
#[derive(Debug, Deserialize, Serialize)]
pub struct SyslogMessageRecord {
    pub received_at: String,
    pub protocol: String,
    pub source_ip: String,
    pub raw: String,
    #[serde(default)]
    pub parsed: Option<ParsedSyslog>,
}

/// Parsed RFC 5424 syslog fields.
#[derive(Debug, Deserialize, Serialize)]
pub struct ParsedSyslog {
    pub priority: i32,
    pub facility: i32,
    pub severity: i32,
    pub version: Option<String>,
    pub timestamp: Option<String>,
    pub hostname: Option<String>,
    pub app_name: Option<String>,
    pub proc_id: Option<String>,
    pub msg_id: Option<String>,
    pub message: Option<String>,
}

impl DockerTestInfra {
    /// Create infrastructure manager from environment variables.
    ///
    /// Environment variables (with defaults):
    /// - `HEC_PORT`: Splunk HEC port (default: 8088)
    /// - `HEC_TOKEN`: HEC authentication token (default: test-token-12345)
    /// - `SYSLOG_TCP_PORT`: Syslog TCP port (default: 1514)
    /// - `SYSLOG_UDP_PORT`: Syslog UDP port (default: 1514)
    /// - `SYSLOG_API_PORT`: Syslog HTTP API port (default: 8089)
    /// - `DOCKER_HOST_IP`: Host IP for containers (default: 127.0.0.1)
    pub fn from_env() -> Self {
        let host = env::var("DOCKER_HOST_IP").unwrap_or_else(|_| "127.0.0.1".to_string());
        let hec_port = env::var("HEC_PORT").unwrap_or_else(|_| "8088".to_string());
        let hec_token = env::var("HEC_TOKEN").unwrap_or_else(|_| "test-token-12345".to_string());
        let syslog_tcp_port = env::var("SYSLOG_TCP_PORT").unwrap_or_else(|_| "1514".to_string());
        let syslog_udp_port = env::var("SYSLOG_UDP_PORT").unwrap_or_else(|_| "1514".to_string());
        let syslog_api_port = env::var("SYSLOG_API_PORT").unwrap_or_else(|_| "8089".to_string());

        let hec_url = format!("http://{}:{}", host, hec_port);
        let syslog_api_url = format!("http://{}:{}", host, syslog_api_port);
        let syslog_tcp_addr: SocketAddr = format!("{}:{}", host, syslog_tcp_port).parse().unwrap();
        let syslog_udp_addr: SocketAddr = format!("{}:{}", host, syslog_udp_port).parse().unwrap();

        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap();

        Self {
            hec_url,
            syslog_api_url,
            syslog_tcp_addr,
            syslog_udp_addr,
            hec_token,
            client,
        }
    }

    /// Wait for all services to be healthy.
    ///
    /// Polls health endpoints until both services report healthy status
    /// or the timeout is exceeded.
    pub async fn wait_ready(&self, timeout: Duration) -> Result<(), DockerInfraError> {
        let start = std::time::Instant::now();
        let poll_interval = Duration::from_millis(500);

        loop {
            if start.elapsed() > timeout {
                return Err(DockerInfraError::Timeout(timeout.as_secs()));
            }

            // Check HEC mock health
            let hec_healthy = self.check_hec_health().await.is_ok();
            let syslog_healthy = self.check_syslog_health().await.is_ok();

            if hec_healthy && syslog_healthy {
                return Ok(());
            }

            tokio::time::sleep(poll_interval).await;
        }
    }

    /// Check if Splunk HEC mock is healthy.
    pub async fn check_hec_health(&self) -> Result<HealthResponse, DockerInfraError> {
        let url = format!("{}/health", self.hec_url);
        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(DockerInfraError::Unhealthy(format!(
                "HEC health check returned {}",
                response.status()
            )));
        }

        let health: HealthResponse = response.json().await?;
        if health.status != "healthy" {
            return Err(DockerInfraError::Unhealthy(format!(
                "HEC status: {}",
                health.status
            )));
        }

        Ok(health)
    }

    /// Check if syslog mock is healthy.
    pub async fn check_syslog_health(&self) -> Result<HealthResponse, DockerInfraError> {
        let url = format!("{}/health", self.syslog_api_url);
        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(DockerInfraError::Unhealthy(format!(
                "Syslog health check returned {}",
                response.status()
            )));
        }

        let health: HealthResponse = response.json().await?;
        if health.status != "healthy" {
            return Err(DockerInfraError::Unhealthy(format!(
                "Syslog status: {}",
                health.status
            )));
        }

        Ok(health)
    }

    /// Get all received HEC events from the mock server.
    pub async fn get_hec_events(&self) -> Result<Vec<HecEventRecord>, DockerInfraError> {
        let url = format!("{}/events", self.hec_url);
        let response = self.client.get(&url).send().await?;
        let events: Vec<HecEventRecord> = response.json().await?;
        Ok(events)
    }

    /// Get HEC event count.
    pub async fn get_hec_event_count(&self) -> Result<usize, DockerInfraError> {
        let url = format!("{}/events/count", self.hec_url);
        let response = self.client.get(&url).send().await?;
        let body: serde_json::Value = response.json().await?;
        let count = body["count"]
            .as_u64()
            .ok_or_else(|| DockerInfraError::ParseError("Missing count field".to_string()))?;
        Ok(count as usize)
    }

    /// Clear all HEC events from the mock server.
    pub async fn clear_hec_events(&self) -> Result<(), DockerInfraError> {
        let url = format!("{}/events/clear", self.hec_url);
        self.client.post(&url).send().await?;
        Ok(())
    }

    /// Get all received syslog messages from the mock server.
    pub async fn get_syslog_messages(&self) -> Result<Vec<SyslogMessageRecord>, DockerInfraError> {
        let url = format!("{}/messages", self.syslog_api_url);
        let response = self.client.get(&url).send().await?;
        let messages: Vec<SyslogMessageRecord> = response.json().await?;
        Ok(messages)
    }

    /// Get syslog messages filtered by protocol (tcp or udp).
    pub async fn get_syslog_messages_by_protocol(
        &self,
        protocol: &str,
    ) -> Result<Vec<SyslogMessageRecord>, DockerInfraError> {
        let url = format!("{}/messages?protocol={}", self.syslog_api_url, protocol);
        let response = self.client.get(&url).send().await?;
        let messages: Vec<SyslogMessageRecord> = response.json().await?;
        Ok(messages)
    }

    /// Get syslog message count.
    pub async fn get_syslog_message_count(&self) -> Result<usize, DockerInfraError> {
        let url = format!("{}/messages/count", self.syslog_api_url);
        let response = self.client.get(&url).send().await?;
        let body: serde_json::Value = response.json().await?;
        let count = body["count"]
            .as_u64()
            .ok_or_else(|| DockerInfraError::ParseError("Missing count field".to_string()))?;
        Ok(count as usize)
    }

    /// Clear all syslog messages from the mock server.
    pub async fn clear_syslog_messages(&self) -> Result<(), DockerInfraError> {
        let url = format!("{}/messages/clear", self.syslog_api_url);
        self.client.post(&url).send().await?;
        Ok(())
    }

    /// Clear all events and messages from both mock servers.
    pub async fn clear_all(&self) -> Result<(), DockerInfraError> {
        self.clear_hec_events().await?;
        self.clear_syslog_messages().await?;
        Ok(())
    }

    /// Check if Docker infrastructure is available.
    ///
    /// Returns true if both services respond to health checks within 5 seconds.
    pub async fn is_available(&self) -> bool {
        self.wait_ready(Duration::from_secs(5)).await.is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_env_defaults() {
        // Clear any existing env vars that might affect test
        env::remove_var("HEC_PORT");
        env::remove_var("DOCKER_HOST_IP");

        let infra = DockerTestInfra::from_env();

        assert!(infra.hec_url.contains("8088"));
        assert!(infra.syslog_api_url.contains("8089"));
        assert_eq!(infra.hec_token, "test-token-12345");
    }

    #[test]
    fn test_from_env_custom() {
        env::set_var("HEC_PORT", "18088");
        env::set_var("SYSLOG_API_PORT", "18089");
        env::set_var("HEC_TOKEN", "custom-token");

        let infra = DockerTestInfra::from_env();

        assert!(infra.hec_url.contains("18088"));
        assert!(infra.syslog_api_url.contains("18089"));
        assert_eq!(infra.hec_token, "custom-token");

        // Cleanup
        env::remove_var("HEC_PORT");
        env::remove_var("SYSLOG_API_PORT");
        env::remove_var("HEC_TOKEN");
    }
}
