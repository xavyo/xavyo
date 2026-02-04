//! Job Service for background job tracking and management.
//!
//! Provides a high-level interface for viewing, cancelling, and replaying
//! provisioning operations (jobs) in the connector system.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use thiserror::Error;
use tracing::{debug, info, instrument};
use uuid::Uuid;

use xavyo_db::models::{
    connector_configuration::ConnectorConfiguration,
    operation_log::{LogStatus, OperationLog},
    provisioning_operation::{OperationFilter, OperationStatus, ProvisioningOperation},
};

use crate::handlers::jobs::{
    BulkReplayResponse, CancelJobResponse, DlqEntry, DlqListResponse, JobAttempt,
    JobDetailResponse, JobListResponse, JobSummary, ReplayResponse,
};

/// Job service errors.
#[derive(Debug, Error)]
pub enum JobServiceError {
    /// Database error.
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Job not found.
    #[error("Job not found: {0}")]
    NotFound(Uuid),

    /// Job cannot be cancelled.
    #[error("Job {0} cannot be cancelled: status is {1}")]
    CannotCancel(Uuid, String),

    /// DLQ entry not found.
    #[error("DLQ entry not found: {0}")]
    DlqNotFound(Uuid),

    /// Already replayed.
    #[error("DLQ entry {0} has already been replayed")]
    AlreadyReplayed(Uuid),
}

/// Result type for job service operations.
pub type JobServiceResult<T> = Result<T, JobServiceError>;

/// Job service for managing background provisioning operations.
#[derive(Clone)]
pub struct JobService {
    pool: Arc<PgPool>,
}

impl JobService {
    /// Create a new job service.
    #[must_use] 
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    /// List jobs with filtering and pagination.
    ///
    /// T013: Create `JobService` with `list_jobs()` method
    #[instrument(skip(self))]
    pub async fn list_jobs(
        &self,
        tenant_id: Uuid,
        connector_id: Option<Uuid>,
        status: Option<&str>,
        from: Option<DateTime<Utc>>,
        to: Option<DateTime<Utc>>,
        limit: i64,
        offset: i64,
    ) -> JobServiceResult<JobListResponse> {
        // Build filter
        let filter = OperationFilter {
            connector_id,
            user_id: None,
            status: status.and_then(|s| s.parse().ok()),
            operation_type: None,
            from_date: from,
            to_date: to,
        };

        // Fetch operations and count
        let operations =
            ProvisioningOperation::list_with_filter(&self.pool, tenant_id, &filter, limit, offset)
                .await?;
        let total =
            ProvisioningOperation::count_with_filter(&self.pool, tenant_id, &filter).await?;

        // Fetch connector names for display
        let connector_names = self.get_connector_names(tenant_id, &operations).await?;

        // Convert to job summaries
        let jobs = operations
            .into_iter()
            .map(|op| self.operation_to_summary(op, &connector_names))
            .collect();

        debug!(
            tenant_id = %tenant_id,
            total = total,
            returned = limit.min(total - offset),
            "Listed jobs"
        );

        Ok(JobListResponse {
            jobs,
            total,
            limit,
            offset,
        })
    }

    /// Get detailed job information including execution attempts.
    ///
    /// T014: Add `get_job_detail()` method to `JobService`
    #[instrument(skip(self))]
    pub async fn get_job_detail(
        &self,
        tenant_id: Uuid,
        job_id: Uuid,
    ) -> JobServiceResult<JobDetailResponse> {
        // Fetch the operation
        let operation = ProvisioningOperation::find_by_id(&self.pool, tenant_id, job_id)
            .await?
            .ok_or(JobServiceError::NotFound(job_id))?;

        // Fetch connector name
        let connector_name = self
            .get_connector_name(tenant_id, operation.connector_id)
            .await?;

        // Fetch execution attempts from operation logs
        let attempts = self.get_job_attempts(tenant_id, job_id).await?;

        debug!(
            job_id = %job_id,
            status = %operation.status,
            attempts = attempts.len(),
            "Got job detail"
        );

        Ok(self.operation_to_detail(operation, connector_name, attempts))
    }

    /// Cancel a job.
    ///
    /// T024: Add `cancel_job()` method to `JobService`
    #[instrument(skip(self))]
    pub async fn cancel_job(
        &self,
        tenant_id: Uuid,
        job_id: Uuid,
        cancelled_by: Uuid,
    ) -> JobServiceResult<CancelJobResponse> {
        // Fetch the operation first to check if it can be cancelled
        let operation = ProvisioningOperation::find_by_id(&self.pool, tenant_id, job_id)
            .await?
            .ok_or(JobServiceError::NotFound(job_id))?;

        if !operation.can_cancel() {
            return Err(JobServiceError::CannotCancel(
                job_id,
                operation.status.to_string(),
            ));
        }

        // Cancel the operation
        let cancelled =
            ProvisioningOperation::cancel(&self.pool, tenant_id, job_id, cancelled_by).await?;

        match cancelled {
            Some(op) => {
                info!(
                    job_id = %job_id,
                    cancelled_by = %cancelled_by,
                    "Job cancelled"
                );

                Ok(CancelJobResponse {
                    id: op.id,
                    status: "cancelled".to_string(),
                    cancelled_at: op.cancelled_at.unwrap_or_else(Utc::now),
                    message: Some("Job cancellation requested".to_string()),
                })
            }
            None => Err(JobServiceError::CannotCancel(job_id, "unknown".to_string())),
        }
    }

    /// List dead letter queue entries.
    ///
    /// T033: Add `list_dlq()` method to `JobService`
    #[instrument(skip(self))]
    pub async fn list_dlq(
        &self,
        tenant_id: Uuid,
        connector_id: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> JobServiceResult<DlqListResponse> {
        let entries = ProvisioningOperation::list_dead_letter(
            &self.pool,
            tenant_id,
            connector_id,
            limit,
            offset,
        )
        .await?;
        let total =
            ProvisioningOperation::count_dead_letter(&self.pool, tenant_id, connector_id).await?;

        // Fetch connector names
        let connector_names = self.get_connector_names(tenant_id, &entries).await?;

        let entries = entries
            .into_iter()
            .map(|op| self.operation_to_dlq_entry(op, &connector_names))
            .collect();

        debug!(
            tenant_id = %tenant_id,
            total = total,
            "Listed DLQ entries"
        );

        Ok(DlqListResponse {
            entries,
            total,
            limit,
            offset,
        })
    }

    /// Replay a single DLQ entry.
    ///
    /// T034: Add `replay_dlq_entry()` method to `JobService`
    #[instrument(skip(self))]
    pub async fn replay_dlq_entry(
        &self,
        tenant_id: Uuid,
        entry_id: Uuid,
        force: bool,
    ) -> JobServiceResult<ReplayResponse> {
        // Check if the entry exists and is in DLQ state
        let operation = ProvisioningOperation::find_by_id(&self.pool, tenant_id, entry_id)
            .await?
            .ok_or(JobServiceError::DlqNotFound(entry_id))?;

        if !operation.is_dead_letter() {
            if force {
                // For force replay, we still allow if it's not already completed
                if operation.status.is_terminal() && operation.status != OperationStatus::DeadLetter
                {
                    return Ok(ReplayResponse {
                        id: entry_id,
                        status: "already_replayed".to_string(),
                        message: Some("Entry is no longer in DLQ".to_string()),
                    });
                }
            } else {
                return Err(JobServiceError::AlreadyReplayed(entry_id));
            }
        }

        // Retry the dead letter entry
        let success =
            ProvisioningOperation::retry_dead_letter(&self.pool, tenant_id, entry_id).await?;

        if success {
            info!(entry_id = %entry_id, "DLQ entry replayed");

            Ok(ReplayResponse {
                id: entry_id,
                status: "queued".to_string(),
                message: Some("Entry requeued for processing".to_string()),
            })
        } else {
            Ok(ReplayResponse {
                id: entry_id,
                status: "already_replayed".to_string(),
                message: Some("Entry was not in dead letter state".to_string()),
            })
        }
    }

    /// Bulk replay multiple DLQ entries.
    ///
    /// T035: Add `bulk_replay_dlq()` method to `JobService`
    #[instrument(skip(self))]
    pub async fn bulk_replay_dlq(
        &self,
        tenant_id: Uuid,
        ids: &[Uuid],
        force: bool,
    ) -> JobServiceResult<BulkReplayResponse> {
        let mut results = Vec::with_capacity(ids.len());
        let mut queued = 0;
        let mut skipped = 0;
        let mut failed = 0;

        // Use bulk operation for efficiency
        let replayed_ids =
            ProvisioningOperation::bulk_retry_dead_letter(&self.pool, tenant_id, ids).await?;
        let replayed_set: std::collections::HashSet<_> = replayed_ids.into_iter().collect();

        for id in ids {
            if replayed_set.contains(id) {
                queued += 1;
                results.push(ReplayResponse {
                    id: *id,
                    status: "queued".to_string(),
                    message: None,
                });
            } else {
                // Check why it wasn't replayed
                match ProvisioningOperation::find_by_id(&self.pool, tenant_id, *id).await {
                    Ok(Some(op)) => {
                        if op.is_dead_letter() {
                            failed += 1;
                            results.push(ReplayResponse {
                                id: *id,
                                status: "failed".to_string(),
                                message: Some("Failed to replay".to_string()),
                            });
                        } else {
                            skipped += 1;
                            results.push(ReplayResponse {
                                id: *id,
                                status: "skipped".to_string(),
                                message: Some(format!("Not in DLQ: status is {}", op.status)),
                            });
                        }
                    }
                    Ok(None) => {
                        failed += 1;
                        results.push(ReplayResponse {
                            id: *id,
                            status: "failed".to_string(),
                            message: Some("Entry not found".to_string()),
                        });
                    }
                    Err(_) => {
                        failed += 1;
                        results.push(ReplayResponse {
                            id: *id,
                            status: "failed".to_string(),
                            message: Some("Database error".to_string()),
                        });
                    }
                }
            }
        }

        info!(
            total = ids.len(),
            queued = queued,
            skipped = skipped,
            failed = failed,
            "Bulk DLQ replay completed"
        );

        Ok(BulkReplayResponse {
            total: ids.len() as i32,
            queued,
            skipped,
            failed,
            results,
        })
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Get connector names for a list of operations.
    async fn get_connector_names(
        &self,
        tenant_id: Uuid,
        operations: &[ProvisioningOperation],
    ) -> JobServiceResult<HashMap<Uuid, String>> {
        let mut names = HashMap::new();
        let connector_ids: std::collections::HashSet<_> =
            operations.iter().map(|op| op.connector_id).collect();

        for connector_id in connector_ids {
            if let Ok(Some(config)) =
                ConnectorConfiguration::find_by_id(&self.pool, tenant_id, connector_id).await
            {
                names.insert(connector_id, config.name);
            }
        }

        Ok(names)
    }

    /// Get a single connector name.
    async fn get_connector_name(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> JobServiceResult<Option<String>> {
        Ok(
            ConnectorConfiguration::find_by_id(&self.pool, tenant_id, connector_id)
                .await?
                .map(|c| c.name),
        )
    }

    /// Get job execution attempts from operation logs.
    async fn get_job_attempts(
        &self,
        tenant_id: Uuid,
        job_id: Uuid,
    ) -> JobServiceResult<Vec<JobAttempt>> {
        let logs = OperationLog::list_by_operation(&self.pool, tenant_id, job_id).await?;

        // Group logs into attempts based on the operation log structure
        // Each log entry with status represents one attempt outcome
        let mut attempts = Vec::new();

        for (index, log) in logs.iter().enumerate() {
            let attempt_number = (index + 1) as i32;
            let success = log.status == LogStatus::Success;

            attempts.push(JobAttempt {
                attempt_number,
                started_at: log.created_at,
                completed_at: Some(log.created_at),
                success,
                error_code: None, // Operation logs don't have error codes
                error_message: log.error_message.clone(),
                duration_ms: log.duration_ms.map(i64::from),
            });
        }

        // If no attempts found but operation has been processed, create a synthetic attempt
        if attempts.is_empty() {
            if let Ok(Some(op)) =
                ProvisioningOperation::find_by_id(&self.pool, tenant_id, job_id).await
            {
                if op.started_at.is_some() {
                    attempts.push(JobAttempt {
                        attempt_number: 1,
                        started_at: op.started_at.unwrap_or(op.created_at),
                        completed_at: op.completed_at,
                        success: op.status == OperationStatus::Completed,
                        error_code: op.error_code.clone(),
                        error_message: op.error_message.clone(),
                        duration_ms: op
                            .completed_at
                            .and_then(|c| op.started_at.map(|s| (c - s).num_milliseconds())),
                    });
                }
            }
        }

        Ok(attempts)
    }

    /// Convert a provisioning operation to a job summary.
    fn operation_to_summary(
        &self,
        op: ProvisioningOperation,
        connector_names: &HashMap<Uuid, String>,
    ) -> JobSummary {
        JobSummary {
            id: op.id,
            connector_id: op.connector_id,
            connector_name: connector_names.get(&op.connector_id).cloned(),
            operation_type: op.operation_type.to_string(),
            status: op.status.to_string(),
            created_at: op.created_at,
            started_at: op.started_at,
            completed_at: op.completed_at,
            error_message: op.error_message,
        }
    }

    /// Convert a provisioning operation to a job detail response.
    fn operation_to_detail(
        &self,
        op: ProvisioningOperation,
        connector_name: Option<String>,
        attempts: Vec<JobAttempt>,
    ) -> JobDetailResponse {
        JobDetailResponse {
            id: op.id,
            connector_id: op.connector_id,
            connector_name,
            operation_type: op.operation_type.to_string(),
            status: op.status.to_string(),
            user_id: op.user_id,
            created_at: op.created_at,
            started_at: op.started_at,
            completed_at: op.completed_at,
            error_message: op.error_message,
            retry_count: op.retry_count,
            max_retries: op.max_retries,
            next_retry_at: op.next_retry_at,
            cancelled_by: op.cancelled_by,
            cancelled_at: op.cancelled_at,
            attempts,
        }
    }

    /// Convert a provisioning operation to a DLQ entry.
    fn operation_to_dlq_entry(
        &self,
        op: ProvisioningOperation,
        connector_names: &HashMap<Uuid, String>,
    ) -> DlqEntry {
        DlqEntry {
            id: op.id,
            connector_id: op.connector_id,
            connector_name: connector_names.get(&op.connector_id).cloned(),
            operation_type: op.operation_type.to_string(),
            error_message: op
                .error_message
                .unwrap_or_else(|| "Unknown error".to_string()),
            created_at: op.created_at,
            retry_count: op.retry_count,
            last_attempt_at: op.updated_at.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_service_error_display() {
        let err = JobServiceError::NotFound(Uuid::new_v4());
        assert!(err.to_string().contains("Job not found"));

        let err = JobServiceError::CannotCancel(Uuid::new_v4(), "completed".to_string());
        assert!(err.to_string().contains("cannot be cancelled"));

        let err = JobServiceError::DlqNotFound(Uuid::new_v4());
        assert!(err.to_string().contains("DLQ entry not found"));

        let err = JobServiceError::AlreadyReplayed(Uuid::new_v4());
        assert!(err.to_string().contains("already been replayed"));
    }
}
