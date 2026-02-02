//! Schema Scheduler Job for F046 Schema Discovery.
//!
//! Polls for due schema refresh schedules and triggers automatic discovery.
//! This job runs periodically to execute scheduled schema refreshes.

use std::sync::Arc;

use sqlx::PgPool;
use tracing::{debug, error, info, instrument, warn};

use crate::services::{
    notification_service::{NotificationService, SchemaChangeNotification},
    ScheduleService, SchemaService,
};
use xavyo_db::models::{SchemaRefreshSchedule, TriggeredBy};

/// Default polling interval in seconds.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 60;

/// Maximum number of schedules to process in a single poll.
pub const DEFAULT_BATCH_SIZE: i32 = 10;

/// Job for executing scheduled schema refreshes.
///
/// This job polls the schema_refresh_schedules table for due schedules
/// and triggers schema discovery for each connector.
pub struct SchemaSchedulerJob {
    #[allow(dead_code)]
    pool: Arc<PgPool>,
    schedule_service: Arc<ScheduleService>,
    schema_service: Arc<SchemaService>,
    notification_service: Arc<NotificationService>,
    batch_size: i32,
}

impl SchemaSchedulerJob {
    /// Create a new schema scheduler job.
    pub fn new(
        pool: PgPool,
        schedule_service: ScheduleService,
        schema_service: SchemaService,
        notification_service: NotificationService,
    ) -> Self {
        Self {
            pool: Arc::new(pool),
            schedule_service: Arc::new(schedule_service),
            schema_service: Arc::new(schema_service),
            notification_service: Arc::new(notification_service),
            batch_size: DEFAULT_BATCH_SIZE,
        }
    }

    /// Create with custom batch size.
    pub fn with_batch_size(mut self, batch_size: i32) -> Self {
        self.batch_size = batch_size.max(1);
        self
    }

    /// Run a single poll cycle.
    ///
    /// Returns the number of schedules processed.
    #[instrument(skip(self))]
    pub async fn poll(&self) -> Result<usize, SchedulerError> {
        // Find due schedules
        let due_schedules = self
            .schedule_service
            .get_due_schedules(self.batch_size)
            .await
            .map_err(|e| SchedulerError::Database(e.to_string()))?;

        if due_schedules.is_empty() {
            debug!("No schedules due for execution");
            return Ok(0);
        }

        info!(count = due_schedules.len(), "Found due schedules");

        let mut processed = 0;

        for schedule in due_schedules {
            match self.process_schedule(&schedule).await {
                Ok(_) => {
                    processed += 1;
                    info!(
                        schedule_id = %schedule.id,
                        connector_id = %schedule.connector_id,
                        "Schedule executed successfully"
                    );
                }
                Err(e) => {
                    warn!(
                        schedule_id = %schedule.id,
                        connector_id = %schedule.connector_id,
                        error = %e,
                        "Schedule execution failed"
                    );
                    // Mark as failed with error message
                    if let Err(mark_err) = self
                        .schedule_service
                        .mark_executed(&schedule, false, Some(e.to_string()))
                        .await
                    {
                        error!(
                            schedule_id = %schedule.id,
                            error = %mark_err,
                            "Failed to mark schedule as failed"
                        );
                    }
                }
            }
        }

        Ok(processed)
    }

    /// Process a single schedule.
    #[instrument(skip(self, schedule), fields(schedule_id = %schedule.id))]
    async fn process_schedule(
        &self,
        schedule: &SchemaRefreshSchedule,
    ) -> Result<(), SchedulerError> {
        debug!(
            connector_id = %schedule.connector_id,
            schedule_type = %schedule.schedule_type,
            "Processing scheduled schema refresh"
        );

        // Get the current schema version before discovery
        let before_version = self
            .schema_service
            .get_latest_version(schedule.tenant_id, schedule.connector_id)
            .await
            .map_err(|e| SchedulerError::DiscoveryFailed(e.to_string()))?
            .map(|v| v.version);

        // Trigger schema discovery
        let discovery_result = self
            .schema_service
            .trigger_discovery(
                schedule.tenant_id,
                schedule.connector_id,
                TriggeredBy::Scheduled,
                None,
            )
            .await;

        match discovery_result {
            Ok(status) => {
                info!(
                    connector_id = %schedule.connector_id,
                    status = ?status,
                    "Schema discovery completed"
                );

                // Check if schema changed (new version)
                let after_version = self
                    .schema_service
                    .get_latest_version(schedule.tenant_id, schedule.connector_id)
                    .await
                    .map_err(|e| SchedulerError::DiscoveryFailed(e.to_string()))?
                    .map(|v| v.version);

                // If version changed and notification is configured, send notification
                if let (Some(before), Some(after)) = (before_version, after_version) {
                    if before != after {
                        info!(
                            connector_id = %schedule.connector_id,
                            before_version = before,
                            after_version = after,
                            "Schema version changed"
                        );

                        // Send notification if enabled and recipient configured
                        if schedule.notify_on_changes {
                            if let Some(ref email) = schedule.notify_email {
                                let connector_name = format!("Connector {}", schedule.connector_id);

                                // Create a basic diff summary (version change detected)
                                let summary = xavyo_connector::schema::DiffSummary {
                                    object_classes_added: 0,
                                    object_classes_removed: 0,
                                    attributes_added: 0,
                                    attributes_removed: 0,
                                    attributes_modified: 0,
                                    has_breaking_changes: false,
                                };

                                let notification = SchemaChangeNotification {
                                    connector_id: schedule.connector_id,
                                    connector_name,
                                    tenant_id: schedule.tenant_id,
                                    from_version: before,
                                    to_version: after,
                                    summary,
                                    recipient_email: email.clone(),
                                };

                                if let Err(e) = self
                                    .notification_service
                                    .send_schema_change_notification(&notification)
                                    .await
                                {
                                    warn!(
                                        connector_id = %schedule.connector_id,
                                        error = %e,
                                        "Failed to send schema change notification"
                                    );
                                }
                            }
                        }
                    }
                }

                // Mark as executed successfully
                self.schedule_service
                    .mark_executed(schedule, true, None)
                    .await
                    .map_err(|e| SchedulerError::MarkFailed(e.to_string()))?;

                Ok(())
            }
            Err(e) => {
                error!(
                    connector_id = %schedule.connector_id,
                    error = %e,
                    "Schema discovery failed"
                );
                Err(SchedulerError::DiscoveryFailed(e.to_string()))
            }
        }
    }

    /// Get the batch size for polling.
    pub fn batch_size(&self) -> i32 {
        self.batch_size
    }
}

/// Errors that can occur during scheduler operations.
#[derive(Debug, thiserror::Error)]
pub enum SchedulerError {
    /// Database error.
    #[error("Database error: {0}")]
    Database(String),

    /// Discovery failed.
    #[error("Discovery failed: {0}")]
    DiscoveryFailed(String),

    /// Failed to mark schedule as executed.
    #[error("Failed to mark schedule: {0}")]
    MarkFailed(String),

    /// Connector not found.
    #[error("Connector not found: {0}")]
    ConnectorNotFound(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_poll_interval() {
        assert_eq!(DEFAULT_POLL_INTERVAL_SECS, 60);
    }

    #[test]
    fn test_default_batch_size() {
        assert_eq!(DEFAULT_BATCH_SIZE, 10);
    }
}
