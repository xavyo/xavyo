//! SLA Monitoring Job for F064 Semi-manual Resources.
//!
//! Monitors manual tasks for SLA warnings and breaches.
//! This job runs periodically (default: every minute) to check SLA statuses.

use std::sync::Arc;

use tracing::{debug, info, instrument};

use crate::services::SlaMonitoringService;

/// Default polling interval in seconds (1 minute).
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 60;

/// Default batch size for processing.
pub const DEFAULT_BATCH_SIZE: i64 = 100;

/// Job for monitoring SLA compliance on manual tasks.
///
/// This job polls for tasks approaching SLA deadline (warnings)
/// and tasks that have breached SLA (breaches).
pub struct SlaMonitoringJob {
    monitoring_service: Arc<SlaMonitoringService>,
    batch_size: i64,
}

/// Statistics from processing SLA monitoring.
#[derive(Debug, Clone, Default)]
pub struct SlaMonitoringStats {
    /// Total tasks checked.
    pub checked: usize,
    /// Warning notifications sent.
    pub warnings_sent: usize,
    /// Breach notifications sent.
    pub breaches_detected: usize,
    /// Failed operations.
    pub failed: usize,
}

impl SlaMonitoringStats {
    /// Merge stats from another instance.
    pub fn merge(&mut self, other: &SlaMonitoringStats) {
        self.checked += other.checked;
        self.warnings_sent += other.warnings_sent;
        self.breaches_detected += other.breaches_detected;
        self.failed += other.failed;
    }
}

/// Errors that can occur during SLA monitoring.
#[derive(Debug, thiserror::Error)]
pub enum SlaMonitoringJobError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Service error: {0}")]
    Service(String),
}

impl SlaMonitoringJob {
    /// Create a new SLA monitoring job.
    #[must_use] 
    pub fn new(monitoring_service: SlaMonitoringService) -> Self {
        Self {
            monitoring_service: Arc::new(monitoring_service),
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }

    /// Create with custom batch size.
    #[must_use]
    pub fn with_batch_size(mut self, batch_size: i64) -> Self {
        self.batch_size = batch_size.max(1);
        self
    }

    /// Run a single poll cycle - check all tasks for SLA status.
    ///
    /// Returns statistics about the processing.
    #[instrument(skip(self))]
    pub async fn poll(&self) -> Result<SlaMonitoringStats, SlaMonitoringJobError> {
        info!("Starting SLA monitoring poll cycle");

        let mut stats = SlaMonitoringStats::default();

        // Process warnings first
        let warning_stats = self.process_warnings().await?;
        stats.merge(&warning_stats);

        // Then process breaches
        let breach_stats = self.process_breaches().await?;
        stats.merge(&breach_stats);

        info!(
            checked = stats.checked,
            warnings_sent = stats.warnings_sent,
            breaches_detected = stats.breaches_detected,
            failed = stats.failed,
            "SLA monitoring poll cycle complete"
        );

        Ok(stats)
    }

    /// Process tasks approaching SLA warning threshold.
    async fn process_warnings(&self) -> Result<SlaMonitoringStats, SlaMonitoringJobError> {
        let mut stats = SlaMonitoringStats::default();

        loop {
            let result = self
                .monitoring_service
                .process_sla_warnings(self.batch_size)
                .await
                .map_err(|e| SlaMonitoringJobError::Service(e.to_string()))?;

            stats.checked += result.checked;
            stats.warnings_sent += result.warnings_sent;
            stats.failed += result.failed;

            // If we processed less than batch_size, we're done
            if result.checked < self.batch_size as usize {
                break;
            }
        }

        debug!(
            warnings_sent = stats.warnings_sent,
            "Finished processing SLA warnings"
        );

        Ok(stats)
    }

    /// Process tasks that have breached SLA.
    async fn process_breaches(&self) -> Result<SlaMonitoringStats, SlaMonitoringJobError> {
        let mut stats = SlaMonitoringStats::default();

        loop {
            let result = self
                .monitoring_service
                .process_sla_breaches(self.batch_size)
                .await
                .map_err(|e| SlaMonitoringJobError::Service(e.to_string()))?;

            stats.checked += result.checked;
            stats.breaches_detected += result.breaches_detected;
            stats.failed += result.failed;

            // If we processed less than batch_size, we're done
            if result.checked < self.batch_size as usize {
                break;
            }
        }

        debug!(
            breaches_detected = stats.breaches_detected,
            "Finished processing SLA breaches"
        );

        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_merge() {
        let mut stats1 = SlaMonitoringStats {
            checked: 10,
            warnings_sent: 3,
            breaches_detected: 1,
            failed: 1,
        };

        let stats2 = SlaMonitoringStats {
            checked: 5,
            warnings_sent: 2,
            breaches_detected: 1,
            failed: 0,
        };

        stats1.merge(&stats2);

        assert_eq!(stats1.checked, 15);
        assert_eq!(stats1.warnings_sent, 5);
        assert_eq!(stats1.breaches_detected, 2);
        assert_eq!(stats1.failed, 1);
    }

    #[test]
    fn test_stats_default() {
        let stats = SlaMonitoringStats::default();
        assert_eq!(stats.checked, 0);
        assert_eq!(stats.warnings_sent, 0);
        assert_eq!(stats.breaches_detected, 0);
        assert_eq!(stats.failed, 0);
    }
}
