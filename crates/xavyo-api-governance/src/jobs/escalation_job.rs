//! Escalation Job for F054 Workflow Escalation.
//!
//! Polls for access requests with expired deadlines and processes escalations.
//! Also sends warning notifications before deadlines expire.
//! This job runs periodically (default: every minute) to process escalations.

use std::sync::Arc;

use chrono::Utc;
use tracing::{debug, error, info, instrument, warn};

use xavyo_db::models::{EscalationReason, GovAccessRequest, GovApprovalStep};

use crate::services::{EscalationPolicyService, EscalationService};

/// Default polling interval in seconds.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 60;

/// Default batch size for processing.
pub const DEFAULT_BATCH_SIZE: i64 = 50;

/// Default warning threshold before deadline (4 hours in seconds).
pub const DEFAULT_WARNING_THRESHOLD_SECS: i64 = 14400;

/// Job for processing escalation timeouts and warnings.
///
/// This job polls the gov_access_requests table for:
/// 1. Requests with expired deadlines (need escalation)
/// 2. Requests approaching deadline (need warning notification)
pub struct EscalationJob {
    escalation_service: Arc<EscalationService>,
    escalation_policy_service: Arc<EscalationPolicyService>,
    batch_size: i64,
    warning_threshold_secs: i64,
}

/// Statistics from processing escalations.
#[derive(Debug, Clone, Default)]
pub struct EscalationStats {
    /// Total requests processed.
    pub processed: usize,
    /// Successful escalations.
    pub escalated: usize,
    /// Fallback actions applied (levels exhausted).
    pub fallbacks_applied: usize,
    /// Warnings sent.
    pub warnings_sent: usize,
    /// Failed operations.
    pub failed: usize,
}

impl EscalationStats {
    /// Merge stats from another instance.
    pub fn merge(&mut self, other: &EscalationStats) {
        self.processed += other.processed;
        self.escalated += other.escalated;
        self.fallbacks_applied += other.fallbacks_applied;
        self.warnings_sent += other.warnings_sent;
        self.failed += other.failed;
    }
}

impl EscalationJob {
    /// Create a new escalation job.
    pub fn new(
        escalation_service: EscalationService,
        escalation_policy_service: EscalationPolicyService,
    ) -> Self {
        Self {
            escalation_service: Arc::new(escalation_service),
            escalation_policy_service: Arc::new(escalation_policy_service),
            batch_size: DEFAULT_BATCH_SIZE,
            warning_threshold_secs: DEFAULT_WARNING_THRESHOLD_SECS,
        }
    }

    /// Create with custom batch size.
    #[must_use]
    pub fn with_batch_size(mut self, batch_size: i64) -> Self {
        self.batch_size = batch_size.max(1);
        self
    }

    /// Create with custom warning threshold.
    #[must_use]
    pub fn with_warning_threshold_secs(mut self, warning_threshold_secs: i64) -> Self {
        self.warning_threshold_secs = warning_threshold_secs.max(60);
        self
    }

    /// Run a single poll cycle - process escalations and warnings.
    ///
    /// Returns statistics about the processing.
    #[instrument(skip(self))]
    pub async fn poll(&self) -> Result<EscalationStats, EscalationJobError> {
        info!("Starting escalation poll cycle");

        let now = Utc::now();
        let mut stats = EscalationStats::default();

        // Process expired deadlines (need escalation)
        let escalation_stats = self.process_expired_escalations(now).await?;
        stats.merge(&escalation_stats);

        // Process approaching deadlines (need warning)
        let warning_stats = self.process_pending_warnings(now).await?;
        stats.merge(&warning_stats);

        if stats.processed > 0 {
            info!(
                processed = stats.processed,
                escalated = stats.escalated,
                fallbacks_applied = stats.fallbacks_applied,
                warnings_sent = stats.warnings_sent,
                failed = stats.failed,
                "Completed escalation poll cycle"
            );
        } else {
            debug!("No pending escalations or warnings to process");
        }

        Ok(stats)
    }

    /// Process requests with expired deadlines.
    #[instrument(skip(self))]
    async fn process_expired_escalations(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> Result<EscalationStats, EscalationJobError> {
        let mut stats = EscalationStats::default();

        // Find requests that need escalation
        let expired_requests = GovAccessRequest::find_pending_escalation(
            self.escalation_service.pool(),
            now,
            self.batch_size,
        )
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to find pending escalations");
            EscalationJobError::Database(e.to_string())
        })?;

        if expired_requests.is_empty() {
            debug!("No expired escalations found");
            return Ok(stats);
        }

        info!(
            count = expired_requests.len(),
            "Found expired escalations to process"
        );

        for request in expired_requests {
            stats.processed += 1;

            match self.escalate_request(&request).await {
                Ok(escalated) => {
                    if escalated.levels_exhausted {
                        stats.fallbacks_applied += 1;
                    } else {
                        stats.escalated += 1;
                    }
                }
                Err(e) => {
                    warn!(
                        request_id = %request.id,
                        error = %e,
                        "Failed to escalate request"
                    );
                    stats.failed += 1;
                }
            }
        }

        Ok(stats)
    }

    /// Escalate a single request.
    async fn escalate_request(
        &self,
        request: &GovAccessRequest,
    ) -> Result<EscalationResult, EscalationJobError> {
        // Get the workflow step for this request
        let workflow_id = request.workflow_id.ok_or_else(|| {
            EscalationJobError::Processing(format!(
                "Request {} has no workflow assigned",
                request.id
            ))
        })?;

        // current_step is 0-indexed, step_order is 1-indexed
        let step_order = request.current_step + 1;
        let step = GovApprovalStep::find_by_workflow_and_order(
            self.escalation_service.pool(),
            workflow_id,
            step_order,
        )
        .await
        .map_err(|e| EscalationJobError::Database(e.to_string()))?
        .ok_or_else(|| {
            EscalationJobError::Processing(format!(
                "Step {} not found for workflow {}",
                step_order, workflow_id
            ))
        })?;

        // Get the current approver for audit trail
        let original_approver_id = self
            .escalation_service
            .get_current_approver_id(request.tenant_id, request, &step)
            .await
            .map_err(|e| EscalationJobError::Processing(e.to_string()))?;

        // Execute escalation
        let result = self
            .escalation_service
            .execute_escalation(
                request.tenant_id,
                request,
                &step,
                original_approver_id,
                EscalationReason::Timeout,
            )
            .await
            .map_err(|e| EscalationJobError::Processing(e.to_string()))?;

        info!(
            request_id = %request.id,
            new_level = result.new_level,
            levels_exhausted = result.levels_exhausted,
            "Processed escalation for request"
        );

        Ok(EscalationResult {
            levels_exhausted: result.levels_exhausted,
        })
    }

    /// Process requests approaching deadline that need warning.
    #[instrument(skip(self))]
    async fn process_pending_warnings(
        &self,
        now: chrono::DateTime<Utc>,
    ) -> Result<EscalationStats, EscalationJobError> {
        let mut stats = EscalationStats::default();

        // Calculate warning threshold
        let warning_threshold = now + chrono::Duration::seconds(self.warning_threshold_secs);

        // Find requests that need warning
        let pending_warnings = GovAccessRequest::find_pending_warning(
            self.escalation_service.pool(),
            now,
            warning_threshold,
            self.batch_size,
        )
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to find pending warnings");
            EscalationJobError::Database(e.to_string())
        })?;

        if pending_warnings.is_empty() {
            debug!("No pending warnings to send");
            return Ok(stats);
        }

        info!(
            count = pending_warnings.len(),
            "Found requests needing warning"
        );

        for request in pending_warnings {
            stats.processed += 1;

            match self
                .escalation_service
                .send_escalation_warning(request.tenant_id, &request)
                .await
            {
                Ok(()) => {
                    stats.warnings_sent += 1;
                    debug!(request_id = %request.id, "Sent escalation warning");
                }
                Err(e) => {
                    warn!(
                        request_id = %request.id,
                        error = %e,
                        "Failed to send escalation warning"
                    );
                    stats.failed += 1;
                }
            }
        }

        Ok(stats)
    }

    /// Get the recommended poll interval.
    #[must_use]
    pub const fn poll_interval_secs(&self) -> u64 {
        DEFAULT_POLL_INTERVAL_SECS
    }

    /// Get reference to the escalation policy service.
    /// Useful for retrieving tenant-specific escalation configurations.
    #[must_use]
    pub fn escalation_policy_service(&self) -> &EscalationPolicyService {
        &self.escalation_policy_service
    }
}

/// Internal result for escalation processing.
struct EscalationResult {
    levels_exhausted: bool,
}

/// Errors that can occur during escalation job execution.
#[derive(Debug, thiserror::Error)]
pub enum EscalationJobError {
    /// Database error.
    #[error("Database error: {0}")]
    Database(String),

    /// Error processing escalations.
    #[error("Processing error: {0}")]
    Processing(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_constants() {
        assert_eq!(DEFAULT_POLL_INTERVAL_SECS, 60);
        assert_eq!(DEFAULT_BATCH_SIZE, 50);
        assert_eq!(DEFAULT_WARNING_THRESHOLD_SECS, 14400); // 4 hours
    }

    #[test]
    fn test_escalation_stats_default() {
        let stats = EscalationStats::default();
        assert_eq!(stats.processed, 0);
        assert_eq!(stats.escalated, 0);
        assert_eq!(stats.fallbacks_applied, 0);
        assert_eq!(stats.warnings_sent, 0);
        assert_eq!(stats.failed, 0);
    }

    #[test]
    fn test_escalation_stats_merge() {
        let mut stats1 = EscalationStats {
            processed: 5,
            escalated: 3,
            fallbacks_applied: 1,
            warnings_sent: 2,
            failed: 1,
        };

        let stats2 = EscalationStats {
            processed: 3,
            escalated: 2,
            fallbacks_applied: 0,
            warnings_sent: 1,
            failed: 0,
        };

        stats1.merge(&stats2);

        assert_eq!(stats1.processed, 8);
        assert_eq!(stats1.escalated, 5);
        assert_eq!(stats1.fallbacks_applied, 1);
        assert_eq!(stats1.warnings_sent, 3);
        assert_eq!(stats1.failed, 1);
    }

    #[test]
    fn test_job_error_display() {
        let err = EscalationJobError::Processing("test error".to_string());
        assert!(err.to_string().contains("test error"));

        let db_err = EscalationJobError::Database("connection failed".to_string());
        assert!(db_err.to_string().contains("connection failed"));
    }
}
