//! Health check types.

use serde::{Deserialize, Serialize};

/// Health status of the Kafka connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Whether the connection is established.
    pub connected: bool,
    /// Number of brokers discovered.
    pub brokers: usize,
    /// Number of topics discovered.
    pub topics: usize,
}

impl HealthStatus {
    /// Check if the connection is healthy.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.connected && self.brokers > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status_healthy() {
        let status = HealthStatus {
            connected: true,
            brokers: 3,
            topics: 10,
        };

        assert!(status.is_healthy());
    }

    #[test]
    fn test_health_status_no_brokers() {
        let status = HealthStatus {
            connected: true,
            brokers: 0,
            topics: 0,
        };

        assert!(!status.is_healthy());
    }

    #[test]
    fn test_health_status_disconnected() {
        let status = HealthStatus {
            connected: false,
            brokers: 0,
            topics: 0,
        };

        assert!(!status.is_healthy());
    }
}
