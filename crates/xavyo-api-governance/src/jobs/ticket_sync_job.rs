//! Ticket Sync Job for F064 Semi-manual Resources.
//!
//! Polls external ticketing systems (ServiceNow, Jira, webhooks) for status updates.
//! This job runs periodically (default: every 5 minutes) to sync ticket statuses.

use std::sync::Arc;

use tracing::{debug, info, instrument, warn};

use crate::services::TicketSyncService;

/// Default polling interval in seconds (5 minutes).
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 300;

/// Default batch size for processing.
pub const DEFAULT_BATCH_SIZE: i64 = 100;

/// Job for synchronizing ticket statuses from external systems.
///
/// This job polls external ticketing systems for tasks with open tickets
/// and updates their status accordingly.
pub struct TicketSyncJob {
    sync_service: Arc<TicketSyncService>,
    batch_size: i64,
}

/// Statistics from processing ticket sync.
#[derive(Debug, Clone, Default)]
pub struct TicketSyncStats {
    /// Total tickets processed.
    pub processed: usize,
    /// Successfully synced tickets.
    pub synced: usize,
    /// Tickets completed (resolved/closed).
    pub completed: usize,
    /// Tickets rejected/cancelled.
    pub rejected: usize,
    /// Tickets detected as missing (404).
    pub missing: usize,
    /// Failed sync operations.
    pub failed: usize,
}

impl TicketSyncStats {
    /// Merge stats from another instance.
    pub fn merge(&mut self, other: &TicketSyncStats) {
        self.processed += other.processed;
        self.synced += other.synced;
        self.completed += other.completed;
        self.rejected += other.rejected;
        self.missing += other.missing;
        self.failed += other.failed;
    }
}

/// Errors that can occur during ticket sync.
#[derive(Debug, thiserror::Error)]
pub enum TicketSyncJobError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Service error: {0}")]
    Service(String),
}

impl TicketSyncJob {
    /// Create a new ticket sync job.
    pub fn new(sync_service: TicketSyncService) -> Self {
        Self {
            sync_service: Arc::new(sync_service),
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }

    /// Create with custom batch size.
    #[must_use]
    pub fn with_batch_size(mut self, batch_size: i64) -> Self {
        self.batch_size = batch_size.max(1);
        self
    }

    /// Run a single poll cycle - sync all pending tickets.
    ///
    /// Returns statistics about the processing.
    #[instrument(skip(self))]
    pub async fn poll(&self) -> Result<TicketSyncStats, TicketSyncJobError> {
        info!("Starting ticket sync poll cycle");

        let mut stats = TicketSyncStats::default();
        let mut offset = 0;

        loop {
            // Get next batch of tasks with external tickets needing sync
            let tasks = self
                .sync_service
                .get_tasks_needing_sync(self.batch_size, offset)
                .await
                .map_err(|e| TicketSyncJobError::Service(e.to_string()))?;

            if tasks.is_empty() {
                break;
            }

            let batch_count = tasks.len();
            debug!("Processing batch of {} tickets", batch_count);

            for task in tasks {
                stats.processed += 1;

                match self
                    .sync_service
                    .sync_single_task(task.tenant_id, task.id)
                    .await
                {
                    Ok(result) => {
                        stats.synced += 1;
                        if result.task_completed {
                            stats.completed += 1;
                        }
                        if result.task_rejected {
                            stats.rejected += 1;
                        }
                        if result.ticket_missing {
                            stats.missing += 1;
                        }
                    }
                    Err(e) => {
                        warn!(
                            task_id = %task.id,
                            error = %e,
                            "Failed to sync ticket for task"
                        );
                        stats.failed += 1;
                    }
                }
            }

            offset += batch_count as i64;

            // If we got less than batch_size, we're done
            if batch_count < self.batch_size as usize {
                break;
            }
        }

        info!(
            processed = stats.processed,
            synced = stats.synced,
            completed = stats.completed,
            rejected = stats.rejected,
            missing = stats.missing,
            failed = stats.failed,
            "Ticket sync poll cycle complete"
        );

        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_merge() {
        let mut stats1 = TicketSyncStats {
            processed: 10,
            synced: 8,
            completed: 5,
            rejected: 1,
            missing: 1,
            failed: 2,
        };

        let stats2 = TicketSyncStats {
            processed: 5,
            synced: 4,
            completed: 3,
            rejected: 0,
            missing: 0,
            failed: 1,
        };

        stats1.merge(&stats2);

        assert_eq!(stats1.processed, 15);
        assert_eq!(stats1.synced, 12);
        assert_eq!(stats1.completed, 8);
        assert_eq!(stats1.rejected, 1);
        assert_eq!(stats1.missing, 1);
        assert_eq!(stats1.failed, 3);
    }

    #[test]
    fn test_stats_default() {
        let stats = TicketSyncStats::default();
        assert_eq!(stats.processed, 0);
        assert_eq!(stats.synced, 0);
        assert_eq!(stats.completed, 0);
        assert_eq!(stats.rejected, 0);
        assert_eq!(stats.missing, 0);
        assert_eq!(stats.failed, 0);
    }
}
