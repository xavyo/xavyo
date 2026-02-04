//! Provisioning Worker
//!
//! Background worker that processes operations from the queue.
//! Handles retries, dead letter queue, and graceful shutdown.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::time::interval;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::processor::{OperationProcessor, ProcessorError};
use crate::queue::{OperationQueue, QueuedOperation};
use crate::shadow::{Shadow, ShadowRepository};

/// Worker configuration.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Number of concurrent operations to process.
    pub concurrency: usize,

    /// How often to poll the queue (in milliseconds).
    pub poll_interval_ms: u64,

    /// How often to release stale operations (in seconds).
    pub stale_release_interval_secs: u64,

    /// How often to cleanup dead shadows (in seconds).
    pub shadow_cleanup_interval_secs: u64,

    /// Retention period for dead shadows (in days).
    pub dead_shadow_retention_days: i32,

    /// Maximum operations per poll.
    pub batch_size: i32,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            concurrency: 4,
            poll_interval_ms: 1000,
            stale_release_interval_secs: 300,
            shadow_cleanup_interval_secs: 3600,
            dead_shadow_retention_days: 7,
            batch_size: 10,
        }
    }
}

/// Provisioning worker that processes the operation queue.
pub struct ProvisioningWorker<P: OperationProcessor> {
    queue: Arc<OperationQueue>,
    processor: Arc<P>,
    shadow_repo: Arc<ShadowRepository>,
    config: WorkerConfig,
    shutdown: Arc<AtomicBool>,
}

impl<P: OperationProcessor + Send + Sync + 'static> ProvisioningWorker<P> {
    /// Create a new worker.
    pub fn new(
        queue: Arc<OperationQueue>,
        processor: Arc<P>,
        shadow_repo: Arc<ShadowRepository>,
        config: WorkerConfig,
    ) -> Self {
        Self {
            queue,
            processor,
            shadow_repo,
            config,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start the worker.
    #[instrument(skip(self))]
    pub async fn run(&self) {
        info!(
            concurrency = self.config.concurrency,
            poll_interval_ms = self.config.poll_interval_ms,
            "Starting provisioning worker"
        );

        let semaphore = Arc::new(Semaphore::new(self.config.concurrency));
        let mut poll_interval = interval(Duration::from_millis(self.config.poll_interval_ms));
        let mut stale_interval =
            interval(Duration::from_secs(self.config.stale_release_interval_secs));
        let mut cleanup_interval = interval(Duration::from_secs(
            self.config.shadow_cleanup_interval_secs,
        ));

        loop {
            tokio::select! {
                _ = poll_interval.tick() => {
                    if self.shutdown.load(Ordering::Relaxed) {
                        info!("Worker shutdown requested, stopping poll loop");
                        break;
                    }
                    self.poll_and_process(&semaphore).await;
                }
                _ = stale_interval.tick() => {
                    self.release_stale_operations().await;
                }
                _ = cleanup_interval.tick() => {
                    self.cleanup_dead_shadows().await;
                }
            }
        }

        // Wait for in-flight operations to complete
        info!("Waiting for in-flight operations to complete...");
        let _ = semaphore.acquire_many(self.config.concurrency as u32).await;
        info!("Worker stopped");
    }

    /// Request graceful shutdown.
    pub fn shutdown(&self) {
        info!("Shutdown requested");
        self.shutdown.store(true, Ordering::Relaxed);
    }

    /// Check if shutdown was requested.
    #[must_use] 
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    /// Poll the queue and process operations.
    async fn poll_and_process(&self, semaphore: &Arc<Semaphore>) {
        // Dequeue a batch of operations
        let operations = match self.queue.dequeue(None, Some(self.config.batch_size)).await {
            Ok(ops) => ops,
            Err(e) => {
                error!(error = %e, "Failed to dequeue operations");
                return;
            }
        };

        if operations.is_empty() {
            return;
        }

        debug!(
            count = operations.len(),
            "Dequeued operations for processing"
        );

        for operation in operations {
            // Try to acquire a permit
            let permit = if let Ok(p) = semaphore.clone().try_acquire_owned() { p } else {
                debug!("All worker slots busy, skipping remaining operations");
                return;
            };

            let queue = self.queue.clone();
            let processor = self.processor.clone();
            let shadow_repo = self.shadow_repo.clone();

            // Process in background task
            tokio::spawn(async move {
                let _permit = permit; // Hold permit until task completes
                process_operation(queue, processor, shadow_repo, operation).await;
            });
        }
    }

    /// Release stale operations that are stuck in processing.
    async fn release_stale_operations(&self) {
        match self.queue.release_stale_operations().await {
            Ok(count) if count > 0 => {
                warn!(count = count, "Released stale operations");
            }
            Ok(_) => {}
            Err(e) => {
                error!(error = %e, "Failed to release stale operations");
            }
        }
    }

    /// Cleanup old dead shadows.
    async fn cleanup_dead_shadows(&self) {
        match self
            .shadow_repo
            .cleanup_dead_shadows(self.config.dead_shadow_retention_days)
            .await
        {
            Ok(count) if count > 0 => {
                info!(count = count, "Cleaned up dead shadows");
            }
            Ok(_) => {}
            Err(e) => {
                error!(error = %e, "Failed to cleanup dead shadows");
            }
        }
    }
}

/// Process a single operation.
#[instrument(skip(queue, processor, shadow_repo, operation), fields(operation_id = %operation.id))]
async fn process_operation<P: OperationProcessor>(
    queue: Arc<OperationQueue>,
    processor: Arc<P>,
    shadow_repo: Arc<ShadowRepository>,
    operation: QueuedOperation,
) {
    let operation_id = operation.id;
    let connector_id = operation.connector_id;
    let tenant_id = operation.tenant_id;
    let user_id = operation.user_id;
    let target_uid = operation.target_uid.clone();

    info!(
        operation_type = ?operation.operation_type,
        connector_id = %connector_id,
        "Processing operation"
    );

    let start = std::time::Instant::now();

    // Update shadow to pending state if we have a target_uid
    if let Some(ref uid) = target_uid {
        if let Ok(Some(mut shadow)) = shadow_repo
            .find_by_target_uid(tenant_id, connector_id, uid)
            .await
        {
            shadow.mark_pending();
            let _ = shadow_repo.upsert(&shadow).await;
        }
    }

    // Process the operation
    let result = processor.process(&operation).await;
    let duration_ms = start.elapsed().as_millis() as i64;

    match result {
        Ok(result_uid) => {
            info!(
                duration_ms = duration_ms,
                result_uid = ?result_uid,
                "Operation completed successfully"
            );

            // Mark as complete
            if let Err(e) = queue.complete(operation_id, result_uid.as_deref()).await {
                error!(error = %e, "Failed to mark operation as complete");
            }

            // Update or create shadow
            let uid = result_uid
                .or(target_uid)
                .unwrap_or_else(|| format!("unknown-{operation_id}"));
            update_shadow_success(
                &shadow_repo,
                tenant_id,
                connector_id,
                user_id,
                &operation.object_class,
                &uid,
                &operation.payload,
            )
            .await;
        }
        Err(e) => {
            let error_msg = e.to_string();
            warn!(
                duration_ms = duration_ms,
                error = %error_msg,
                retry_count = operation.retry_count,
                "Operation failed"
            );

            // Check if we should retry
            let can_retry = operation.retry_count < operation.max_retries && is_retryable_error(&e);

            if can_retry {
                // Schedule retry (transient error)
                if let Err(re) = queue.fail(operation_id, &error_msg, true).await {
                    error!(error = %re, "Failed to schedule retry");
                }
            } else {
                // Move to dead letter queue (permanent failure)
                if let Err(re) = queue.fail(operation_id, &error_msg, false).await {
                    error!(error = %re, "Failed to move to dead letter");
                }
            }

            // Update shadow with error
            if let Some(ref uid) = target_uid {
                update_shadow_failure(&shadow_repo, tenant_id, connector_id, uid, &error_msg).await;
            }
        }
    }
}

/// Update shadow after successful operation.
async fn update_shadow_success(
    shadow_repo: &ShadowRepository,
    tenant_id: Uuid,
    connector_id: Uuid,
    user_id: Uuid,
    object_class: &str,
    target_uid: &str,
    attributes: &serde_json::Value,
) {
    match shadow_repo
        .find_by_target_uid(tenant_id, connector_id, target_uid)
        .await
    {
        Ok(Some(mut shadow)) => {
            shadow.operation_completed(true, None);
            shadow.update_attributes(attributes.clone());
            shadow.link_to_user(user_id);
            if let Err(e) = shadow_repo.upsert(&shadow).await {
                error!(error = %e, "Failed to update shadow");
            }
        }
        Ok(None) => {
            // Create new shadow
            let shadow = Shadow::new_linked(
                tenant_id,
                connector_id,
                user_id,
                object_class.to_string(),
                target_uid.to_string(),
                attributes.clone(),
            );
            if let Err(e) = shadow_repo.upsert(&shadow).await {
                error!(error = %e, "Failed to create shadow");
            }
        }
        Err(e) => {
            error!(error = %e, "Failed to lookup shadow");
        }
    }
}

/// Update shadow after failed operation.
async fn update_shadow_failure(
    shadow_repo: &ShadowRepository,
    tenant_id: Uuid,
    connector_id: Uuid,
    target_uid: &str,
    error: &str,
) {
    match shadow_repo
        .find_by_target_uid(tenant_id, connector_id, target_uid)
        .await
    {
        Ok(Some(mut shadow)) => {
            shadow.operation_completed(false, Some(error.to_string()));
            if let Err(e) = shadow_repo.upsert(&shadow).await {
                error!(error = %e, "Failed to update shadow after failure");
            }
        }
        Ok(None) => {
            // No shadow to update
        }
        Err(e) => {
            error!(error = %e, "Failed to lookup shadow for failure update");
        }
    }
}

/// Check if an error is retryable.
fn is_retryable_error(error: &ProcessorError) -> bool {
    match error {
        // Connection errors are retryable
        ProcessorError::Connector(e) => {
            let msg = e.to_string().to_lowercase();
            msg.contains("connection")
                || msg.contains("timeout")
                || msg.contains("unavailable")
                || msg.contains("network")
                || msg.contains("temporary")
        }
        // Queue errors are generally not retryable
        ProcessorError::Queue(_) => false,
        // Other errors depend on the message
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_worker_config_default() {
        let config = WorkerConfig::default();
        assert_eq!(config.concurrency, 4);
        assert_eq!(config.poll_interval_ms, 1000);
        assert_eq!(config.batch_size, 10);
    }

    #[test]
    fn test_is_retryable_connection_error() {
        use crate::processor::ProcessorError;
        use xavyo_connector::error::ConnectorError;

        let error = ProcessorError::Connector(ConnectorError::ConnectionFailed {
            message: "Connection timeout".to_string(),
            source: None,
        });
        assert!(is_retryable_error(&error));
    }

    #[test]
    fn test_is_not_retryable_validation_error() {
        use crate::processor::ProcessorError;

        let error = ProcessorError::InvalidPayload {
            message: "Missing required field".to_string(),
        };
        assert!(!is_retryable_error(&error));
    }
}
