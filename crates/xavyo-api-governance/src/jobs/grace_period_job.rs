//! Grace Period Expiration Job for F052 Object Lifecycle States.
//!
//! Polls for expired grace periods and marks them as no longer rollbackable.
//! This job runs periodically (default: every minute) to expire grace periods.

use std::sync::Arc;

use tracing::{debug, error, info, instrument, warn};

use crate::services::{state_transition_service::ExpirationStats, StateTransitionService};

// Re-export ExpirationStats from the service for job users
pub use crate::services::state_transition_service::ExpirationStats as JobExpirationStats;

/// Default polling interval in seconds.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 60;

/// Default batch size for processing.
pub const DEFAULT_BATCH_SIZE: i32 = 100;

/// Job for expiring grace periods on state transitions.
///
/// This job polls the `gov_state_transition_requests` table for transitions
/// with expired grace periods (`grace_period_ends_at` < now AND `rollback_available` = true)
/// and marks them as no longer rollbackable.
pub struct GracePeriodExpirationJob {
    state_transition_service: Arc<StateTransitionService>,
    batch_size: i32,
}

impl GracePeriodExpirationJob {
    /// Create a new grace period expiration job.
    #[must_use]
    pub fn new(state_transition_service: StateTransitionService) -> Self {
        Self {
            state_transition_service: Arc::new(state_transition_service),
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }

    /// Create from an Arc-wrapped service.
    #[must_use]
    pub fn from_arc(state_transition_service: Arc<StateTransitionService>) -> Self {
        Self {
            state_transition_service,
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
    /// Returns the total number of grace periods expired across all tenants.
    #[instrument(skip(self))]
    pub async fn poll(&self) -> Result<ExpirationStats, GracePeriodJobError> {
        info!("Starting grace period expiration poll cycle");

        let stats = self
            .state_transition_service
            .expire_all_grace_periods(self.batch_size)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to expire grace periods");
                GracePeriodJobError::Processing(e.to_string())
            })?;

        if stats.expired > 0 {
            info!(
                expired = stats.expired,
                tenants = stats.tenants_processed,
                "Completed grace period expiration poll cycle"
            );
        } else {
            debug!("No grace periods due for expiration");
        }

        Ok(stats)
    }

    /// Run a single poll cycle for a specific tenant.
    ///
    /// Returns the number of grace periods expired for the tenant.
    #[instrument(skip(self))]
    pub async fn poll_tenant(&self, tenant_id: uuid::Uuid) -> Result<usize, GracePeriodJobError> {
        debug!(tenant_id = %tenant_id, "Expiring grace periods for tenant");

        let expired = self
            .state_transition_service
            .expire_grace_periods(tenant_id, self.batch_size)
            .await
            .map_err(|e| {
                warn!(
                    tenant_id = %tenant_id,
                    error = %e,
                    "Failed to expire grace periods for tenant"
                );
                GracePeriodJobError::Processing(e.to_string())
            })?;

        if expired > 0 {
            info!(
                tenant_id = %tenant_id,
                expired = expired,
                "Expired grace periods for tenant"
            );
        }

        Ok(expired)
    }

    /// Get the recommended poll interval.
    #[must_use]
    pub const fn poll_interval_secs(&self) -> u64 {
        DEFAULT_POLL_INTERVAL_SECS
    }
}

/// Errors that can occur during grace period expiration job execution.
#[derive(Debug, thiserror::Error)]
pub enum GracePeriodJobError {
    /// Database error.
    #[error("Database error: {0}")]
    Database(String),

    /// Error processing expirations.
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
    fn test_expiration_stats_default() {
        let stats = ExpirationStats::default();
        assert_eq!(stats.expired, 0);
        assert_eq!(stats.tenants_processed, 0);
    }

    #[test]
    fn test_job_error_display() {
        let err = GracePeriodJobError::Processing("test error".to_string());
        assert!(err.to_string().contains("test error"));
    }
}
