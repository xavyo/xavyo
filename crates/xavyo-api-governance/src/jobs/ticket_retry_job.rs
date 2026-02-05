//! Ticket Retry Job for F064 Semi-manual Resources.
//!
//! Processes retry queue for failed ticket creation attempts.
//! Uses exponential backoff: 30s, 2m, 10m, 1h, 4h, 24h.
//! After 7 retries, tasks are marked as `failed_permanent`.

use std::sync::Arc;

use chrono::{Duration, Utc};
use tracing::{debug, error, info, instrument, warn};

use crate::services::ManualTaskService;

/// Default polling interval in seconds (30 seconds).
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 30;

/// Default batch size for processing.
pub const DEFAULT_BATCH_SIZE: i64 = 50;

/// Maximum number of retry attempts before marking as `failed_permanent`.
pub const MAX_RETRY_ATTEMPTS: i32 = 7;

/// Retry schedule in seconds: 30s, 2m, 10m, 1h, 4h, 24h, 24h.
pub const RETRY_SCHEDULE_SECS: [i64; 7] = [
    30,    // Attempt 1: 30 seconds
    120,   // Attempt 2: 2 minutes
    600,   // Attempt 3: 10 minutes
    3600,  // Attempt 4: 1 hour
    14400, // Attempt 5: 4 hours
    86400, // Attempt 6: 24 hours
    86400, // Attempt 7 (final): 24 hours
];

/// Job for processing ticket creation retries with exponential backoff.
///
/// This job polls for tasks in `retry_pending` state and attempts
/// to create tickets in external systems.
pub struct TicketRetryJob {
    task_service: Arc<ManualTaskService>,
    batch_size: i64,
}

/// Statistics from processing ticket retries.
#[derive(Debug, Clone, Default)]
pub struct TicketRetryStats {
    /// Total tasks processed.
    pub processed: usize,
    /// Successfully created tickets.
    pub succeeded: usize,
    /// Rescheduled for retry (still has attempts left).
    pub rescheduled: usize,
    /// Marked as permanently failed (exhausted retries).
    pub permanently_failed: usize,
    /// Failed operations (internal errors).
    pub failed: usize,
}

impl TicketRetryStats {
    /// Merge stats from another instance.
    pub fn merge(&mut self, other: &TicketRetryStats) {
        self.processed += other.processed;
        self.succeeded += other.succeeded;
        self.rescheduled += other.rescheduled;
        self.permanently_failed += other.permanently_failed;
        self.failed += other.failed;
    }
}

/// Errors that can occur during ticket retry processing.
#[derive(Debug, thiserror::Error)]
pub enum TicketRetryJobError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Service error: {0}")]
    Service(String),
}

impl TicketRetryJob {
    /// Create a new ticket retry job.
    #[must_use]
    pub fn new(task_service: ManualTaskService) -> Self {
        Self {
            task_service: Arc::new(task_service),
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }

    /// Create with custom batch size.
    #[must_use]
    pub fn with_batch_size(mut self, batch_size: i64) -> Self {
        self.batch_size = batch_size.max(1);
        self
    }

    /// Calculate next retry time based on retry count.
    #[must_use]
    pub fn calculate_next_retry(retry_count: i32) -> Option<chrono::DateTime<Utc>> {
        if retry_count >= MAX_RETRY_ATTEMPTS {
            return None; // Exhausted retries
        }

        let index = (retry_count as usize).min(RETRY_SCHEDULE_SECS.len() - 1);
        let delay_secs = RETRY_SCHEDULE_SECS[index];

        Some(Utc::now() + Duration::seconds(delay_secs))
    }

    /// Run a single poll cycle - process tasks pending retry.
    ///
    /// Returns statistics about the processing.
    #[instrument(skip(self))]
    pub async fn poll(&self) -> Result<TicketRetryStats, TicketRetryJobError> {
        info!("Starting ticket retry poll cycle");

        let mut stats = TicketRetryStats::default();
        let now = Utc::now();

        loop {
            // Get next batch of tasks ready for retry
            let tasks = self
                .task_service
                .get_tasks_pending_retry(now, self.batch_size)
                .await
                .map_err(|e| TicketRetryJobError::Service(e.to_string()))?;

            if tasks.is_empty() {
                break;
            }

            let batch_count = tasks.len();
            debug!("Processing batch of {} retry tasks", batch_count);

            for task in tasks {
                stats.processed += 1;

                match self
                    .task_service
                    .retry_ticket_creation(task.tenant_id, task.id)
                    .await
                {
                    Ok(result) => {
                        if result.ticket_created {
                            stats.succeeded += 1;
                        } else if result.exhausted_retries {
                            stats.permanently_failed += 1;
                            warn!(
                                task_id = %task.id,
                                retry_count = result.retry_count,
                                "Task exhausted retries, marked as permanently failed"
                            );
                        } else {
                            stats.rescheduled += 1;
                            debug!(
                                task_id = %task.id,
                                next_retry = ?result.next_retry_at,
                                "Task rescheduled for retry"
                            );
                        }
                    }
                    Err(e) => {
                        error!(
                            task_id = %task.id,
                            error = %e,
                            "Failed to process retry for task"
                        );
                        stats.failed += 1;
                    }
                }
            }

            // If we got less than batch_size, we're done
            if batch_count < self.batch_size as usize {
                break;
            }
        }

        info!(
            processed = stats.processed,
            succeeded = stats.succeeded,
            rescheduled = stats.rescheduled,
            permanently_failed = stats.permanently_failed,
            failed = stats.failed,
            "Ticket retry poll cycle complete"
        );

        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_next_retry_first_attempt() {
        let next = TicketRetryJob::calculate_next_retry(0);
        assert!(next.is_some());
        let delay = next.unwrap() - Utc::now();
        // Should be approximately 30 seconds (give or take 1 second for execution time)
        assert!(delay.num_seconds() >= 29 && delay.num_seconds() <= 31);
    }

    #[test]
    fn test_calculate_next_retry_second_attempt() {
        let next = TicketRetryJob::calculate_next_retry(1);
        assert!(next.is_some());
        let delay = next.unwrap() - Utc::now();
        // Should be approximately 2 minutes (120 seconds)
        assert!(delay.num_seconds() >= 119 && delay.num_seconds() <= 121);
    }

    #[test]
    fn test_calculate_next_retry_exhausted() {
        let next = TicketRetryJob::calculate_next_retry(7);
        assert!(next.is_none());
    }

    #[test]
    fn test_calculate_next_retry_beyond_max() {
        let next = TicketRetryJob::calculate_next_retry(10);
        assert!(next.is_none());
    }

    #[test]
    fn test_retry_schedule_values() {
        assert_eq!(RETRY_SCHEDULE_SECS[0], 30); // 30 seconds
        assert_eq!(RETRY_SCHEDULE_SECS[1], 120); // 2 minutes
        assert_eq!(RETRY_SCHEDULE_SECS[2], 600); // 10 minutes
        assert_eq!(RETRY_SCHEDULE_SECS[3], 3600); // 1 hour
        assert_eq!(RETRY_SCHEDULE_SECS[4], 14400); // 4 hours
        assert_eq!(RETRY_SCHEDULE_SECS[5], 86400); // 24 hours
        assert_eq!(RETRY_SCHEDULE_SECS[6], 86400); // 24 hours
    }

    #[test]
    fn test_stats_merge() {
        let mut stats1 = TicketRetryStats {
            processed: 10,
            succeeded: 5,
            rescheduled: 3,
            permanently_failed: 1,
            failed: 1,
        };

        let stats2 = TicketRetryStats {
            processed: 5,
            succeeded: 2,
            rescheduled: 2,
            permanently_failed: 1,
            failed: 0,
        };

        stats1.merge(&stats2);

        assert_eq!(stats1.processed, 15);
        assert_eq!(stats1.succeeded, 7);
        assert_eq!(stats1.rescheduled, 5);
        assert_eq!(stats1.permanently_failed, 2);
        assert_eq!(stats1.failed, 1);
    }

    #[test]
    fn test_stats_default() {
        let stats = TicketRetryStats::default();
        assert_eq!(stats.processed, 0);
        assert_eq!(stats.succeeded, 0);
        assert_eq!(stats.rescheduled, 0);
        assert_eq!(stats.permanently_failed, 0);
        assert_eq!(stats.failed, 0);
    }
}
