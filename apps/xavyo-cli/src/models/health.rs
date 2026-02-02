//! Health check response model

use serde::{Deserialize, Serialize};

/// Response from health check endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Health status
    pub status: HealthStatus,

    /// API version (optional)
    pub version: Option<String>,

    /// Timestamp (optional)
    pub timestamp: Option<String>,
}

/// Health status enum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// Service is fully operational
    Healthy,

    /// Service is operational but with degraded performance
    Degraded,

    /// Service is not operational
    Unhealthy,
}

impl HealthStatus {
    /// Get a display symbol for the status
    pub fn symbol(&self) -> &'static str {
        match self {
            HealthStatus::Healthy => "✓",
            HealthStatus::Degraded => "⚠",
            HealthStatus::Unhealthy => "✗",
        }
    }

    /// Get a display string for the status
    pub fn display(&self) -> &'static str {
        match self {
            HealthStatus::Healthy => "Healthy",
            HealthStatus::Degraded => "Degraded",
            HealthStatus::Unhealthy => "Unhealthy",
        }
    }

    /// Check if the status is operational (healthy or degraded)
    pub fn is_operational(&self) -> bool {
        matches!(self, HealthStatus::Healthy | HealthStatus::Degraded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_response_deserialization() {
        let json = r#"{
            "status": "healthy",
            "version": "1.0.0",
            "timestamp": "2026-01-29T12:00:00Z"
        }"#;

        let response: HealthResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.status, HealthStatus::Healthy);
        assert_eq!(response.version.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn test_health_status_variants() {
        let healthy: HealthStatus = serde_json::from_str(r#""healthy""#).unwrap();
        assert_eq!(healthy, HealthStatus::Healthy);
        assert!(healthy.is_operational());

        let degraded: HealthStatus = serde_json::from_str(r#""degraded""#).unwrap();
        assert_eq!(degraded, HealthStatus::Degraded);
        assert!(degraded.is_operational());

        let unhealthy: HealthStatus = serde_json::from_str(r#""unhealthy""#).unwrap();
        assert_eq!(unhealthy, HealthStatus::Unhealthy);
        assert!(!unhealthy.is_operational());
    }

    #[test]
    fn test_health_status_display() {
        assert_eq!(HealthStatus::Healthy.display(), "Healthy");
        assert_eq!(HealthStatus::Healthy.symbol(), "✓");

        assert_eq!(HealthStatus::Degraded.display(), "Degraded");
        assert_eq!(HealthStatus::Degraded.symbol(), "⚠");

        assert_eq!(HealthStatus::Unhealthy.display(), "Unhealthy");
        assert_eq!(HealthStatus::Unhealthy.symbol(), "✗");
    }
}
