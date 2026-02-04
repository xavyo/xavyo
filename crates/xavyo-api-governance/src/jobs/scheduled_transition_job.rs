//! Scheduled Transition Job for F052 Object Lifecycle States.
//!
//! Polls for due scheduled transitions and executes them.
//! This job runs periodically (default: every minute) to process scheduled transitions.

use std::sync::Arc;

use tracing::{debug, error, info, instrument, warn};

use crate::services::{scheduled_transition_service::ProcessingStats, ScheduledTransitionService};

/// Default polling interval in seconds.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 60;

/// Default batch size for processing.
pub const DEFAULT_BATCH_SIZE: i32 = 50;

/// Job for executing scheduled state transitions.
///
/// This job polls the `gov_scheduled_transitions` table for due transitions
/// and processes them, either executing immediately or creating approval requests.
pub struct ScheduledTransitionJob {
    scheduled_transition_service: Arc<ScheduledTransitionService>,
    batch_size: i32,
}

// Re-export ProcessingStats from the service
pub use crate::services::scheduled_transition_service::ProcessingStats as JobProcessingStats;

impl ScheduledTransitionJob {
    /// Create a new scheduled transition job.
    #[must_use] 
    pub fn new(scheduled_transition_service: ScheduledTransitionService) -> Self {
        Self {
            scheduled_transition_service: Arc::new(scheduled_transition_service),
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }

    /// Create with custom batch size.
    #[must_use]
    pub fn with_batch_size(mut self, batch_size: i32) -> Self {
        self.batch_size = batch_size.max(1);
        self
    }

    /// Run a single poll cycle for all tenants.
    ///
    /// Returns the total number of transitions processed across all tenants.
    #[instrument(skip(self))]
    pub async fn poll(&self) -> Result<ProcessingStats, ScheduledTransitionJobError> {
        info!("Starting scheduled transition poll cycle");

        let stats = self
            .scheduled_transition_service
            .process_all_due_transitions(self.batch_size)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to process due transitions");
                ScheduledTransitionJobError::Processing(e.to_string())
            })?;

        if stats.processed > 0 {
            info!(
                processed = stats.processed,
                successful = stats.successful,
                failed = stats.failed,
                "Completed scheduled transition poll cycle"
            );
        } else {
            debug!("No scheduled transitions due for execution");
        }

        Ok(stats)
    }

    /// Run a single poll cycle for a specific tenant.
    ///
    /// Returns the number of transitions processed for the tenant.
    #[instrument(skip(self))]
    pub async fn poll_tenant(
        &self,
        tenant_id: uuid::Uuid,
    ) -> Result<usize, ScheduledTransitionJobError> {
        debug!(tenant_id = %tenant_id, "Processing due transitions for tenant");

        let processed = self
            .scheduled_transition_service
            .process_due_transitions_for_tenant(tenant_id, self.batch_size)
            .await
            .map_err(|e| {
                warn!(
                    tenant_id = %tenant_id,
                    error = %e,
                    "Failed to process due transitions for tenant"
                );
                ScheduledTransitionJobError::Processing(e.to_string())
            })?;

        if processed > 0 {
            info!(
                tenant_id = %tenant_id,
                processed = processed,
                "Processed due transitions for tenant"
            );
        }

        Ok(processed)
    }

    /// Get the recommended poll interval.
    #[must_use]
    pub const fn poll_interval_secs(&self) -> u64 {
        DEFAULT_POLL_INTERVAL_SECS
    }
}

/// Errors that can occur during scheduled transition job execution.
#[derive(Debug, thiserror::Error)]
pub enum ScheduledTransitionJobError {
    /// Database error.
    #[error("Database error: {0}")]
    Database(String),

    /// Error processing transitions.
    #[error("Processing error: {0}")]
    Processing(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poll_interval() {
        assert_eq!(DEFAULT_POLL_INTERVAL_SECS, 60);
    }

    #[test]
    fn test_processing_stats_default() {
        let stats = ProcessingStats::default();
        assert_eq!(stats.processed, 0);
        assert_eq!(stats.successful, 0);
        assert_eq!(stats.failed, 0);
        assert_eq!(stats.tenants_processed, 0);
    }

    #[test]
    fn test_job_error_display() {
        let err = ScheduledTransitionJobError::Processing("test error".to_string());
        assert!(err.to_string().contains("test error"));
    }
}
