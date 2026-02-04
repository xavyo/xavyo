//! Failed Operation Retry Job for F052 Object Lifecycle States.
//!
//! Polls for failed operations due for retry and processes them with exponential backoff.
//! This job runs periodically (default: every 30 seconds) to process retry queue.

use std::sync::Arc;

use tracing::{debug, error, info, instrument, warn};

use crate::services::failed_operation_service::{FailedOperationService, RetryStats};

/// Default polling interval in seconds.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 30;

/// Default batch size for processing.
pub const DEFAULT_BATCH_SIZE: i64 = 50;

/// Job for retrying failed lifecycle operations.
///
/// This job polls the `gov_lifecycle_failed_operations` table for operations
/// due for retry (`next_retry_at` <= now AND status IN ('pending', 'retrying'))
/// and attempts to execute them.
pub struct FailedOperationRetryJob {
    failed_operation_service: Arc<FailedOperationService>,
    batch_size: i64,
}

impl FailedOperationRetryJob {
    /// Create a new failed operation retry job.
    #[must_use] 
    pub fn new(failed_operation_service: FailedOperationService) -> Self {
        Self {
            failed_operation_service: Arc::new(failed_operation_service),
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }

    /// Create from an Arc-wrapped service.
    #[must_use] 
    pub fn from_arc(failed_operation_service: Arc<FailedOperationService>) -> Self {
        Self {
            failed_operation_service,
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }

    /// Create with custom batch size.
    #[must_use]
    pub fn with_batch_size(mut self, batch_size: i64) -> Self {
        self.batch_size = batch_size.max(1);
        self
    }

    /// Run a single poll cycle for all tenants.
    ///
    /// Returns the retry statistics across all tenants.
    #[instrument(skip(self))]
    pub async fn poll(&self) -> Result<RetryStats, FailedOperationJobError> {
        info!("Starting failed operation retry poll cycle");

        let stats = self
            .failed_operation_service
            .process_all_retries(self.batch_size)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to process retry queue");
                FailedOperationJobError::Processing(e.to_string())
            })?;

        if stats.total.processed > 0 {
            info!(
                processed = stats.total.processed,
                succeeded = stats.total.succeeded,
                rescheduled = stats.total.rescheduled,
                dead_letter = stats.total.dead_letter,
                tenants = stats.tenants_processed,
                "Completed failed operation retry poll cycle"
            );
        } else {
            debug!("No failed operations due for retry");
        }

        Ok(stats)
    }

    /// Run a single poll cycle for a specific tenant.
    ///
    /// Returns the retry result for the tenant.
    #[instrument(skip(self))]
    pub async fn poll_tenant(
        &self,
        tenant_id: uuid::Uuid,
    ) -> Result<crate::services::failed_operation_service::RetryResult, FailedOperationJobError>
    {
        debug!(tenant_id = %tenant_id, "Processing failed operations for tenant");

        let result = self
            .failed_operation_service
            .process_retries(tenant_id, self.batch_size)
            .await
            .map_err(|e| {
                warn!(
                    tenant_id = %tenant_id,
                    error = %e,
                    "Failed to process retries for tenant"
                );
                FailedOperationJobError::Processing(e.to_string())
            })?;

        if result.processed > 0 {
            info!(
                tenant_id = %tenant_id,
                processed = result.processed,
                succeeded = result.succeeded,
                rescheduled = result.rescheduled,
                dead_letter = result.dead_letter,
                "Processed failed operations for tenant"
            );
        }

        Ok(result)
    }

    /// Get the recommended poll interval.
    #[must_use]
    pub const fn poll_interval_secs(&self) -> u64 {
        DEFAULT_POLL_INTERVAL_SECS
    }
}

/// Errors that can occur during failed operation retry job execution.
#[derive(Debug, thiserror::Error)]
pub enum FailedOperationJobError {
    /// Database error.
    #[error("Database error: {0}")]
    Database(String),

    /// Error processing retries.
    #[error("Processing error: {0}")]
    Processing(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poll_interval() {
        assert_eq!(DEFAULT_POLL_INTERVAL_SECS, 30);
    }

    #[test]
    fn test_batch_size() {
        assert_eq!(DEFAULT_BATCH_SIZE, 50);
    }

    #[test]
    fn test_job_error_display() {
        let err = FailedOperationJobError::Processing("test error".to_string());
        assert!(err.to_string().contains("test error"));
    }
}
