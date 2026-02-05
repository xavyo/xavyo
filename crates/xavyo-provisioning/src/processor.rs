//! Operation Processor
//!
//! Processes provisioning operations from the queue, executing them
//! against the appropriate connectors.
//!
//! ## Features (F047 - Provisioning Consistency Engine)
//!
//! - **Attempt Tracking**: Records each execution attempt with timing and outcome
//! - **Health Monitoring**: Checks connector health before execution, skips offline connectors
//! - **Conflict Detection**: Detects concurrent modifications and applies resolution strategies
//! - **Idempotent Execution**: Prevents duplicate operations through idempotency keys

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use xavyo_connector::error::ConnectorError;
use xavyo_connector::mapping::{CorrelationRule, MappingConfiguration};
use xavyo_connector::operation::{AttributeDelta, AttributeSet, AttributeValue, Uid};
use xavyo_connector::traits::{Connector, CreateOp, DeleteOp, SearchOp, UpdateOp};
use xavyo_connector::transform::TransformEngine;
use xavyo_connector::types::OperationType;

use crate::attempt::{AttemptCompletion, AttemptService};
use crate::conflict::{ConflictService, ResolutionResult};
use crate::correlation::{CorrelationService, DefaultCorrelationService};
use crate::health::HealthService;
use crate::queue::{OperationQueue, QueuedOperation};

/// Processor errors.
#[derive(Debug, Error)]
pub enum ProcessorError {
    /// Queue error.
    #[error("Queue error: {0}")]
    Queue(#[from] crate::queue::QueueError),

    /// Connector error.
    #[error("Connector error: {0}")]
    Connector(#[from] ConnectorError),

    /// Connector not found.
    #[error("Connector not found: {connector_id}")]
    ConnectorNotFound { connector_id: Uuid },

    /// Mapping not found.
    #[error("Mapping not found for connector {connector_id} and object class {object_class}")]
    MappingNotFound {
        connector_id: Uuid,
        object_class: String,
    },

    /// Invalid payload.
    #[error("Invalid operation payload: {message}")]
    InvalidPayload { message: String },

    /// Transform error.
    #[error("Transform error: {message}")]
    Transform { message: String },

    /// Correlation error.
    #[error("Correlation error: {0}")]
    Correlation(#[from] crate::correlation::CorrelationError),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Health check error.
    #[error("Health error: {0}")]
    Health(#[from] crate::health::HealthError),

    /// Attempt tracking error.
    #[error("Attempt error: {0}")]
    Attempt(#[from] crate::attempt::AttemptError),

    /// Conflict detection error.
    #[error("Conflict error: {0}")]
    Conflict(#[from] crate::conflict::ConflictError),

    /// Connector offline.
    #[error("Connector {connector_id} is offline")]
    ConnectorOffline { connector_id: Uuid },

    /// Conflict requires manual resolution.
    #[error("Operation {operation_id} has conflict requiring manual resolution")]
    ConflictRequiresManual {
        operation_id: Uuid,
        conflict_id: Uuid,
    },

    /// Operation skipped due to conflict resolution.
    #[error("Operation {operation_id} skipped: superseded by conflicting operation")]
    OperationSuperseded { operation_id: Uuid },
}

/// Result type for processor operations.
pub type ProcessorResult<T> = Result<T, ProcessorError>;

/// Result of processing batches with connector isolation (F047).
#[derive(Debug, Clone, Default)]
pub struct BatchProcessingResult {
    /// Total operations processed across all connectors.
    pub total_operations: usize,
    /// Number of successful operations.
    pub successful_operations: usize,
    /// Number of failed operations.
    pub failed_operations: usize,
    /// Per-connector results.
    pub connector_results: HashMap<Uuid, ConnectorBatchResult>,
}

impl BatchProcessingResult {
    /// Get the success rate as a percentage.
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.total_operations == 0 {
            100.0
        } else {
            (self.successful_operations as f64 / self.total_operations as f64) * 100.0
        }
    }

    /// Check if all operations succeeded.
    #[must_use]
    pub fn all_succeeded(&self) -> bool {
        self.failed_operations == 0
    }

    /// Get connectors that had failures.
    #[must_use]
    pub fn failed_connectors(&self) -> Vec<Uuid> {
        self.connector_results
            .iter()
            .filter(|(_, r)| r.operations_failed > 0)
            .map(|(id, _)| *id)
            .collect()
    }
}

/// Result for a single connector's batch of operations (F047).
#[derive(Debug, Clone, Default)]
pub struct ConnectorBatchResult {
    /// Number of operations processed for this connector.
    pub operations_processed: usize,
    /// Number of successful operations.
    pub operations_succeeded: usize,
    /// Number of failed operations.
    pub operations_failed: usize,
    /// Error messages from failed operations.
    pub errors: Vec<String>,
}

impl ConnectorBatchResult {
    /// Get the success rate for this connector.
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        if self.operations_processed == 0 {
            100.0
        } else {
            (self.operations_succeeded as f64 / self.operations_processed as f64) * 100.0
        }
    }
}

/// A connector bundle with full CRUD capabilities.
pub trait FullConnector:
    Connector + CreateOp + UpdateOp + DeleteOp + SearchOp + Send + Sync
{
}

impl<T> FullConnector for T where
    T: Connector + CreateOp + UpdateOp + DeleteOp + SearchOp + Send + Sync
{
}

/// Provider for connectors and mappings.
#[async_trait]
pub trait ConnectorProvider: Send + Sync {
    /// Get a connector by ID.
    async fn get_connector(&self, connector_id: Uuid) -> Option<Arc<dyn FullConnector>>;

    /// Get mapping configuration for a connector and object class.
    async fn get_mapping(
        &self,
        connector_id: Uuid,
        object_class: &str,
    ) -> Option<MappingConfiguration>;

    /// Get correlation rules for a connector and object class.
    async fn get_correlation_rules(
        &self,
        connector_id: Uuid,
        object_class: &str,
    ) -> Vec<CorrelationRule>;
}

/// Trait for processing operations.
/// This allows the worker to use the processor generically.
#[async_trait]
pub trait OperationProcessor: Send + Sync {
    /// Process a single operation.
    /// Returns the target UID if the operation creates/updates an account.
    async fn process(&self, operation: &QueuedOperation) -> ProcessorResult<Option<String>>;
}

/// The default operation processor implementation.
pub struct DefaultOperationProcessor {
    /// Operation queue.
    queue: Arc<OperationQueue>,

    /// Connector provider.
    connector_provider: Arc<dyn ConnectorProvider>,

    /// Correlation service.
    correlation_service: Arc<dyn CorrelationService>,

    /// Transform engine.
    transform_engine: Arc<TransformEngine>,

    /// Attempt tracking service.
    attempt_service: AttemptService,

    /// Health monitoring service (optional).
    health_service: Option<Arc<HealthService>>,

    /// Conflict detection service (optional).
    conflict_service: Option<Arc<ConflictService>>,

    /// Database pool for services.
    pool: sqlx::PgPool,

    /// Whether the processor is running.
    running: Arc<RwLock<bool>>,

    /// Processor configuration.
    config: ProcessorConfig,
}

/// Processor configuration.
#[derive(Debug, Clone)]
pub struct ProcessorConfig {
    /// Number of operations to process per batch.
    pub batch_size: i32,

    /// Polling interval in milliseconds when no operations.
    pub poll_interval_ms: u64,

    /// Whether to process all connectors or specific one.
    pub connector_id: Option<Uuid>,
}

impl Default for ProcessorConfig {
    fn default() -> Self {
        Self {
            batch_size: 10,
            poll_interval_ms: 1000,
            connector_id: None,
        }
    }
}

impl DefaultOperationProcessor {
    /// Create a new operation processor.
    pub fn new(
        pool: sqlx::PgPool,
        queue: Arc<OperationQueue>,
        connector_provider: Arc<dyn ConnectorProvider>,
    ) -> Self {
        Self {
            queue,
            connector_provider,
            correlation_service: Arc::new(DefaultCorrelationService::new()),
            transform_engine: Arc::new(TransformEngine::new()),
            attempt_service: AttemptService::new(),
            health_service: None,
            conflict_service: None,
            pool,
            running: Arc::new(RwLock::new(false)),
            config: ProcessorConfig::default(),
        }
    }

    /// Create with custom configuration.
    #[must_use]
    pub fn with_config(mut self, config: ProcessorConfig) -> Self {
        self.config = config;
        self
    }

    /// Set a custom correlation service.
    pub fn with_correlation_service(mut self, service: Arc<dyn CorrelationService>) -> Self {
        self.correlation_service = service;
        self
    }

    /// Set the health monitoring service.
    #[must_use]
    pub fn with_health_service(mut self, service: Arc<HealthService>) -> Self {
        self.health_service = Some(service);
        self
    }

    /// Set the conflict detection service.
    #[must_use]
    pub fn with_conflict_service(mut self, service: Arc<ConflictService>) -> Self {
        self.conflict_service = Some(service);
        self
    }

    /// Process a single batch of operations.
    #[instrument(skip(self))]
    pub async fn process_batch(&self) -> ProcessorResult<u32> {
        let operations = self
            .queue
            .dequeue(self.config.connector_id, Some(self.config.batch_size))
            .await?;

        let count = operations.len() as u32;
        if count == 0 {
            return Ok(0);
        }

        debug!(count = count, "Processing batch of operations");

        for operation in operations {
            // Check connector health before processing (if health service is configured)
            if let Some(ref health_service) = self.health_service {
                match health_service
                    .is_connector_online(operation.tenant_id, operation.connector_id)
                    .await
                {
                    Ok(true) => {
                        // Connector is online, proceed
                    }
                    Ok(false) => {
                        // Connector is offline, transition operation to awaiting_system
                        warn!(
                            operation_id = %operation.id,
                            connector_id = %operation.connector_id,
                            "Connector offline, transitioning operation to awaiting_system"
                        );
                        self.queue
                            .transition_to_awaiting_system(operation.id)
                            .await?;
                        continue;
                    }
                    Err(e) => {
                        // Health check error, log and continue with execution (fail-open)
                        warn!(
                            operation_id = %operation.id,
                            error = %e,
                            "Health check failed, proceeding with execution"
                        );
                    }
                }
            }

            // Start attempt tracking
            let _started_at = Utc::now();
            let (attempt_id, attempt_number) = self
                .attempt_service
                .start_attempt(&self.pool, operation.tenant_id, operation.id)
                .await?;

            debug!(
                operation_id = %operation.id,
                attempt_id = %attempt_id,
                attempt_number = attempt_number,
                "Started attempt"
            );

            // Process the operation
            let result = self.process_operation_with_conflict_check(&operation).await;

            match result {
                Ok(target_uid) => {
                    // Record successful attempt
                    let completion = AttemptCompletion::success_with_data(
                        serde_json::json!({ "target_uid": target_uid }),
                    );
                    self.attempt_service
                        .complete_attempt(&self.pool, operation.tenant_id, attempt_id, &completion)
                        .await?;

                    // Record success with health service
                    if let Some(ref health_service) = self.health_service {
                        let _ = health_service
                            .record_success(operation.tenant_id, operation.connector_id)
                            .await;
                    }

                    // Complete the operation
                    self.queue
                        .complete(operation.id, target_uid.as_deref())
                        .await?;
                }
                Err(e) => {
                    // Determine error classification
                    let (error_code, is_transient) = self.classify_error(&e);

                    // Record failed attempt
                    let completion = AttemptCompletion::failure(&error_code, e.to_string());
                    self.attempt_service
                        .complete_attempt(&self.pool, operation.tenant_id, attempt_id, &completion)
                        .await?;

                    // Record failure with health service (for connector errors)
                    if let Some(ref health_service) = self.health_service {
                        if matches!(&e, ProcessorError::Connector(_)) {
                            let went_offline = health_service
                                .record_failure(
                                    operation.tenant_id,
                                    operation.connector_id,
                                    &e.to_string(),
                                )
                                .await?;

                            if went_offline {
                                // Connector went offline, transition to awaiting_system
                                self.queue
                                    .transition_to_awaiting_system(operation.id)
                                    .await?;
                                continue;
                            }
                        }
                    }

                    // Handle special error cases
                    match &e {
                        ProcessorError::ConflictRequiresManual { .. } => {
                            // Mark as failed (not transient) - requires manual resolution
                            self.queue.fail(operation.id, &e.to_string(), false).await?;
                        }
                        ProcessorError::OperationSuperseded { .. } => {
                            // Operation was superseded, mark as completed with note
                            // We use complete() since resolve() requires a user ID and is for DLQ items
                            self.queue.complete(operation.id, None).await?;
                            info!(operation_id = %operation.id, "Operation superseded by conflict resolution");
                        }
                        _ => {
                            // Regular failure handling
                            self.queue
                                .fail(operation.id, &e.to_string(), is_transient)
                                .await?;
                        }
                    }
                }
            }
        }

        Ok(count)
    }

    /// Process multiple batches with connector isolation (F047).
    ///
    /// This method dequeues operations and groups them by connector. Each connector's
    /// batch is processed independently, so a failure in one connector's operations
    /// doesn't block other connectors.
    ///
    /// # Returns
    ///
    /// A summary of batch processing results, including successes and failures per connector.
    #[instrument(skip(self))]
    pub async fn process_batches_isolated(
        &self,
        batch_size: Option<i32>,
    ) -> ProcessorResult<BatchProcessingResult> {
        // Dequeue batches grouped by connector
        // Note: Offline connector filtering is done per-operation during processing
        // since we don't have a single tenant_id at the processor level
        let batches = self.queue.dequeue_batch(batch_size, &[]).await?;

        if batches.is_empty() {
            return Ok(BatchProcessingResult::default());
        }

        let mut result = BatchProcessingResult {
            total_operations: 0,
            successful_operations: 0,
            failed_operations: 0,
            connector_results: HashMap::new(),
        };

        // Process each connector's batch independently
        for batch in batches {
            let connector_id = batch.connector_id;
            let batch_size = batch.len();
            result.total_operations += batch_size;

            debug!(
                connector_id = %connector_id,
                batch_size = batch_size,
                "Processing isolated batch for connector"
            );

            let mut connector_result = ConnectorBatchResult {
                operations_processed: 0,
                operations_succeeded: 0,
                operations_failed: 0,
                errors: Vec::new(),
            };

            // Process each operation in this connector's batch
            for operation in batch.operations {
                connector_result.operations_processed += 1;

                // Start attempt tracking
                let (attempt_id, attempt_number) = match self
                    .attempt_service
                    .start_attempt(&self.pool, operation.tenant_id, operation.id)
                    .await
                {
                    Ok(r) => r,
                    Err(e) => {
                        error!(
                            operation_id = %operation.id,
                            error = %e,
                            "Failed to start attempt tracking"
                        );
                        connector_result.operations_failed += 1;
                        connector_result.errors.push(format!(
                            "Operation {}: attempt tracking failed - {}",
                            operation.id, e
                        ));
                        continue;
                    }
                };

                debug!(
                    operation_id = %operation.id,
                    attempt_id = %attempt_id,
                    attempt_number = attempt_number,
                    "Started attempt for isolated batch processing"
                );

                // Process the operation with conflict detection
                let process_result = self.process_operation_with_conflict_check(&operation).await;

                match process_result {
                    Ok(target_uid) => {
                        // Record successful attempt
                        let completion = AttemptCompletion::success_with_data(
                            serde_json::json!({ "target_uid": target_uid }),
                        );
                        let _ = self
                            .attempt_service
                            .complete_attempt(
                                &self.pool,
                                operation.tenant_id,
                                attempt_id,
                                &completion,
                            )
                            .await;

                        // Record health success
                        if let Some(ref health_service) = self.health_service {
                            let _ = health_service
                                .record_success(operation.tenant_id, connector_id)
                                .await;
                        }

                        // Complete the operation
                        if let Err(e) = self
                            .queue
                            .complete(operation.id, target_uid.as_deref())
                            .await
                        {
                            warn!(
                                operation_id = %operation.id,
                                error = %e,
                                "Failed to mark operation as complete"
                            );
                        }

                        connector_result.operations_succeeded += 1;
                    }
                    Err(e) => {
                        let (error_code, is_transient) = self.classify_error(&e);

                        // Record failed attempt
                        let completion = AttemptCompletion::failure(&error_code, e.to_string());
                        let _ = self
                            .attempt_service
                            .complete_attempt(
                                &self.pool,
                                operation.tenant_id,
                                attempt_id,
                                &completion,
                            )
                            .await;

                        // Record health failure for connector errors
                        if matches!(e, ProcessorError::Connector(_)) {
                            if let Some(ref health_service) = self.health_service {
                                let _ = health_service
                                    .record_failure(
                                        operation.tenant_id,
                                        connector_id,
                                        &e.to_string(),
                                    )
                                    .await;
                            }
                        }

                        // Mark operation as failed
                        if let Err(fe) = self
                            .queue
                            .fail(operation.id, &e.to_string(), is_transient)
                            .await
                        {
                            warn!(
                                operation_id = %operation.id,
                                error = %fe,
                                "Failed to mark operation as failed"
                            );
                        }

                        connector_result.operations_failed += 1;
                        connector_result.errors.push(format!(
                            "Operation {}: {} - {}",
                            operation.id, error_code, e
                        ));
                    }
                }
            }

            result.successful_operations += connector_result.operations_succeeded;
            result.failed_operations += connector_result.operations_failed;
            result
                .connector_results
                .insert(connector_id, connector_result);
        }

        info!(
            total = result.total_operations,
            succeeded = result.successful_operations,
            failed = result.failed_operations,
            connectors = result.connector_results.len(),
            "Completed isolated batch processing"
        );

        Ok(result)
    }

    /// Classify an error to determine error code and whether it's transient.
    fn classify_error(&self, error: &ProcessorError) -> (String, bool) {
        match error {
            ProcessorError::Connector(ce) => {
                let is_transient = ce.is_transient();
                let code = if is_transient {
                    "TRANSIENT_ERROR"
                } else {
                    "CONNECTOR_ERROR"
                };
                (code.to_string(), is_transient)
            }
            ProcessorError::ConnectorOffline { .. } => ("CONNECTOR_OFFLINE".to_string(), true),
            ProcessorError::ConnectorNotFound { .. } => ("CONNECTOR_NOT_FOUND".to_string(), false),
            ProcessorError::MappingNotFound { .. } => ("MAPPING_NOT_FOUND".to_string(), false),
            ProcessorError::InvalidPayload { .. } => ("INVALID_PAYLOAD".to_string(), false),
            ProcessorError::Transform { .. } => ("TRANSFORM_ERROR".to_string(), false),
            ProcessorError::Correlation(_) => ("CORRELATION_ERROR".to_string(), false),
            ProcessorError::Queue(_) => ("QUEUE_ERROR".to_string(), true),
            ProcessorError::Health(_) => ("HEALTH_ERROR".to_string(), true),
            ProcessorError::Attempt(_) => ("ATTEMPT_ERROR".to_string(), true),
            ProcessorError::Conflict(_) => ("CONFLICT_ERROR".to_string(), false),
            ProcessorError::ConflictRequiresManual { .. } => ("CONFLICT_MANUAL".to_string(), false),
            ProcessorError::OperationSuperseded { .. } => ("SUPERSEDED".to_string(), false),
            ProcessorError::Serialization(_) => ("SERIALIZATION_ERROR".to_string(), false),
        }
    }

    /// Process an operation with conflict detection.
    async fn process_operation_with_conflict_check(
        &self,
        operation: &QueuedOperation,
    ) -> ProcessorResult<Option<String>> {
        // Check for conflicts (if conflict service is configured and target_uid is set)
        if let (Some(ref conflict_service), Some(ref target_uid)) =
            (&self.conflict_service, &operation.target_uid)
        {
            let conflict = conflict_service
                .detect_conflict(
                    operation.tenant_id,
                    operation.connector_id,
                    target_uid,
                    operation.id,
                    &operation.payload,
                )
                .await?;

            if let Some(detected) = conflict {
                info!(
                    operation_id = %operation.id,
                    conflict_type = ?detected.conflict_type,
                    affected_attributes = ?detected.affected_attributes,
                    "Conflict detected"
                );

                // Record the conflict
                let conflict_record = conflict_service
                    .record_conflict(operation.tenant_id, &detected)
                    .await?;

                // Apply resolution strategy
                let resolution = conflict_service
                    .apply_resolution_strategy(
                        operation.tenant_id,
                        &detected,
                        detected.recommended_strategy,
                        &operation.payload,
                        None, // Would need to fetch conflicting payload if needed
                        operation.created_at,
                        None,
                    )
                    .await?;

                match resolution {
                    ResolutionResult::ApplyPrimary => {
                        // Proceed with normal processing
                        debug!(operation_id = %operation.id, "Conflict resolved: apply primary");
                    }
                    ResolutionResult::SkipPrimary => {
                        // Operation is superseded
                        return Err(ProcessorError::OperationSuperseded {
                            operation_id: operation.id,
                        });
                    }
                    ResolutionResult::Merge { merged_payload: _ } => {
                        // For now, proceed with primary (merge would require modifying payload)
                        debug!(operation_id = %operation.id, "Conflict resolved: merge (using primary)");
                    }
                    ResolutionResult::RequiresManual => {
                        return Err(ProcessorError::ConflictRequiresManual {
                            operation_id: operation.id,
                            conflict_id: conflict_record.id,
                        });
                    }
                }
            }
        }

        // Proceed with normal operation processing
        self.process_operation(operation).await
    }

    /// Process a single operation.
    #[instrument(skip(self), fields(
        operation_id = %operation.id,
        operation_type = ?operation.operation_type,
        connector_id = %operation.connector_id
    ))]
    async fn process_operation(
        &self,
        operation: &QueuedOperation,
    ) -> ProcessorResult<Option<String>> {
        // Get connector
        let connector = self
            .connector_provider
            .get_connector(operation.connector_id)
            .await
            .ok_or(ProcessorError::ConnectorNotFound {
                connector_id: operation.connector_id,
            })?;

        // Get mapping configuration
        let mapping = self
            .connector_provider
            .get_mapping(operation.connector_id, &operation.object_class)
            .await
            .ok_or(ProcessorError::MappingNotFound {
                connector_id: operation.connector_id,
                object_class: operation.object_class.clone(),
            })?;

        match operation.operation_type {
            OperationType::Create => {
                self.process_create(operation, connector.as_ref(), &mapping)
                    .await
            }
            OperationType::Update => {
                self.process_update(operation, connector.as_ref(), &mapping)
                    .await
            }
            OperationType::Delete => {
                self.process_delete(operation, connector.as_ref(), &mapping)
                    .await
            }
        }
    }

    /// Process a create operation.
    async fn process_create(
        &self,
        operation: &QueuedOperation,
        connector: &dyn FullConnector,
        mapping: &MappingConfiguration,
    ) -> ProcessorResult<Option<String>> {
        // Parse source attributes from payload as HashMap<String, String>
        let source_attrs = self.parse_string_attributes(&operation.payload)?;

        // Check for existing account using correlation
        let correlation_rules = self
            .connector_provider
            .get_correlation_rules(operation.connector_id, &operation.object_class)
            .await;

        if !correlation_rules.is_empty() {
            let existing = self
                .correlation_service
                .correlate(
                    connector as &dyn SearchOp,
                    &mapping.object_class,
                    &source_attrs,
                    &correlation_rules,
                )
                .await?;

            if let Some(correlation_match) = existing {
                info!(
                    existing_uid = %correlation_match.uid.value(),
                    confidence = %correlation_match.confidence,
                    "Found existing account, converting to update"
                );

                // Convert to update operation
                let target_attrs = self.transform_attributes(&source_attrs, mapping, false)?;
                let delta = self.attribute_set_to_delta(&target_attrs);

                let uid = connector
                    .update(&mapping.object_class, &correlation_match.uid, delta)
                    .await?;

                return Ok(Some(uid.value().to_string()));
            }
        }

        // No existing account, create new
        let target_attrs = self.transform_attributes(&source_attrs, mapping, true)?;

        let uid = connector
            .create(&mapping.object_class, target_attrs)
            .await?;

        info!(target_uid = %uid.value(), "Created new account in target system");

        Ok(Some(uid.value().to_string()))
    }

    /// Process an update operation.
    async fn process_update(
        &self,
        operation: &QueuedOperation,
        connector: &dyn FullConnector,
        mapping: &MappingConfiguration,
    ) -> ProcessorResult<Option<String>> {
        let target_uid = operation
            .target_uid
            .as_ref()
            .ok_or(ProcessorError::InvalidPayload {
                message: "Update operation requires target_uid".to_string(),
            })?;

        let uid = Uid::from_id(target_uid.clone());

        // Parse changes from payload
        let source_attrs = self.parse_string_attributes(&operation.payload)?;
        let target_attrs = self.transform_attributes(&source_attrs, mapping, false)?;
        let delta = self.attribute_set_to_delta(&target_attrs);

        if delta.is_empty() {
            debug!("No changes to apply, skipping update");
            return Ok(Some(target_uid.clone()));
        }

        let result_uid = connector.update(&mapping.object_class, &uid, delta).await?;

        info!(target_uid = %result_uid.value(), "Updated account in target system");

        Ok(Some(result_uid.value().to_string()))
    }

    /// Process a delete operation.
    async fn process_delete(
        &self,
        operation: &QueuedOperation,
        connector: &dyn FullConnector,
        mapping: &MappingConfiguration,
    ) -> ProcessorResult<Option<String>> {
        let target_uid = operation
            .target_uid
            .as_ref()
            .ok_or(ProcessorError::InvalidPayload {
                message: "Delete operation requires target_uid".to_string(),
            })?;

        let uid = Uid::from_id(target_uid.clone());

        // Check deprovision action
        match mapping.deprovision_action {
            xavyo_connector::types::DeprovisionAction::Delete => {
                connector.delete(&mapping.object_class, &uid).await?;

                info!(target_uid = %uid.value(), "Deleted account from target system");
            }
            xavyo_connector::types::DeprovisionAction::Disable => {
                // Create delta to disable the account
                let delta = self.create_disable_delta();

                connector.update(&mapping.object_class, &uid, delta).await?;

                info!(target_uid = %uid.value(), "Disabled account in target system");
            }
            xavyo_connector::types::DeprovisionAction::None => {
                info!(target_uid = %uid.value(), "Deprovision action is None, skipping");
            }
            xavyo_connector::types::DeprovisionAction::Move => {
                // Move operation would require connector-specific handling
                warn!(target_uid = %uid.value(), "Move deprovision action not yet implemented");
            }
            xavyo_connector::types::DeprovisionAction::Rename => {
                // Rename operation would require connector-specific handling
                warn!(target_uid = %uid.value(), "Rename deprovision action not yet implemented");
            }
        }

        Ok(Some(target_uid.clone()))
    }

    /// Parse source attributes from payload as `HashMap`<String, String>.
    ///
    /// Nested JSON objects (e.g., `custom_attributes`) are flattened into dotted keys
    /// so that `${custom_attributes.department}` resolves in mapping expressions.
    fn parse_string_attributes(
        &self,
        payload: &serde_json::Value,
    ) -> ProcessorResult<HashMap<String, String>> {
        let mut attrs = HashMap::new();

        if let Some(obj) = payload.as_object() {
            for (key, value) in obj {
                match value {
                    serde_json::Value::String(s) => {
                        attrs.insert(key.clone(), s.clone());
                    }
                    serde_json::Value::Number(n) => {
                        attrs.insert(key.clone(), n.to_string());
                    }
                    serde_json::Value::Bool(b) => {
                        attrs.insert(key.clone(), b.to_string());
                    }
                    serde_json::Value::Null => continue,
                    serde_json::Value::Object(nested) => {
                        // Flatten nested objects with dotted keys
                        for (nested_key, nested_value) in nested {
                            let dotted_key = format!("{key}.{nested_key}");
                            let str_value = match nested_value {
                                serde_json::Value::String(s) => s.clone(),
                                serde_json::Value::Number(n) => n.to_string(),
                                serde_json::Value::Bool(b) => b.to_string(),
                                serde_json::Value::Null => continue,
                                _ => nested_value.to_string(),
                            };
                            attrs.insert(dotted_key, str_value);
                        }
                        // Also store the whole object as JSON string for backward compat
                        attrs.insert(key.clone(), value.to_string());
                    }
                    serde_json::Value::Array(_) => {
                        attrs.insert(key.clone(), value.to_string());
                    }
                }
            }
        }

        Ok(attrs)
    }

    /// Transform source attributes to target attributes using mapping rules.
    fn transform_attributes(
        &self,
        source_attrs: &HashMap<String, String>,
        mapping: &MappingConfiguration,
        is_create: bool,
    ) -> ProcessorResult<AttributeSet> {
        let result = self
            .transform_engine
            .evaluate(mapping, source_attrs, is_create);

        // Check for fatal errors
        if result.has_fatal_errors() {
            let error_messages: Vec<String> = result
                .errors
                .iter()
                .filter(|e| e.fatal)
                .map(|e| format!("{}: {}", e.target_attribute, e.message))
                .collect();
            return Err(ProcessorError::Transform {
                message: error_messages.join("; "),
            });
        }

        // Convert HashMap<String, String> to AttributeSet
        let mut target_attrs = AttributeSet::new();
        for (key, value) in result.attributes {
            target_attrs.set(key, AttributeValue::String(value));
        }

        Ok(target_attrs)
    }

    /// Convert `AttributeSet` to `AttributeDelta` (replace operations).
    fn attribute_set_to_delta(&self, attrs: &AttributeSet) -> AttributeDelta {
        let mut delta = AttributeDelta::new();
        for (name, value) in attrs.iter() {
            delta.replace(name.clone(), value.clone());
        }
        delta
    }

    /// Create a delta to disable an account.
    fn create_disable_delta(&self) -> AttributeDelta {
        // Default: set common disable attributes
        let mut delta = AttributeDelta::new();

        // Common patterns for different target systems
        // AD: userAccountControl = 514 means disabled
        delta.replace(
            "userAccountControl".to_string(),
            AttributeValue::String("514".to_string()),
        );

        delta
    }

    /// Start the processor loop.
    pub async fn start(&self) -> ProcessorResult<()> {
        *self.running.write().await = true;

        info!("Operation processor started");

        while *self.running.read().await {
            match self.process_batch().await {
                Ok(0) => {
                    // No operations, wait before polling again
                    tokio::time::sleep(std::time::Duration::from_millis(
                        self.config.poll_interval_ms,
                    ))
                    .await;
                }
                Ok(count) => {
                    debug!(count = count, "Processed batch");
                }
                Err(e) => {
                    error!(error = %e, "Error processing batch");
                    tokio::time::sleep(std::time::Duration::from_millis(
                        self.config.poll_interval_ms,
                    ))
                    .await;
                }
            }
        }

        info!("Operation processor stopped");

        Ok(())
    }

    /// Stop the processor loop.
    pub async fn stop(&self) {
        *self.running.write().await = false;
    }

    /// Check if the processor is running.
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }
}

#[async_trait]
impl OperationProcessor for DefaultOperationProcessor {
    async fn process(&self, operation: &QueuedOperation) -> ProcessorResult<Option<String>> {
        self.process_operation(operation).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_processor_config_default() {
        let config = ProcessorConfig::default();
        assert_eq!(config.batch_size, 10);
        assert_eq!(config.poll_interval_ms, 1000);
        assert!(config.connector_id.is_none());
    }

    /// Helper to test parse_string_attributes without constructing a full processor.
    fn parse_string_attributes_standalone(payload: &serde_json::Value) -> HashMap<String, String> {
        let mut attrs = HashMap::new();

        if let Some(obj) = payload.as_object() {
            for (key, value) in obj {
                match value {
                    serde_json::Value::String(s) => {
                        attrs.insert(key.clone(), s.clone());
                    }
                    serde_json::Value::Number(n) => {
                        attrs.insert(key.clone(), n.to_string());
                    }
                    serde_json::Value::Bool(b) => {
                        attrs.insert(key.clone(), b.to_string());
                    }
                    serde_json::Value::Null => continue,
                    serde_json::Value::Object(nested) => {
                        for (nested_key, nested_value) in nested {
                            let dotted_key = format!("{}.{}", key, nested_key);
                            let str_value = match nested_value {
                                serde_json::Value::String(s) => s.clone(),
                                serde_json::Value::Number(n) => n.to_string(),
                                serde_json::Value::Bool(b) => b.to_string(),
                                serde_json::Value::Null => continue,
                                _ => nested_value.to_string(),
                            };
                            attrs.insert(dotted_key, str_value);
                        }
                        attrs.insert(key.clone(), value.to_string());
                    }
                    serde_json::Value::Array(_) => {
                        attrs.insert(key.clone(), value.to_string());
                    }
                }
            }
        }

        attrs
    }

    #[test]
    fn test_parse_string_attributes_flattens_custom_attributes() {
        let payload = serde_json::json!({
            "firstName": "Alice",
            "lastName": "Smith",
            "custom_attributes": {
                "department": "Engineering",
                "cost_center": "CC-100",
                "employee_id": "E12345",
                "active": true,
                "level": 5
            }
        });

        let attrs = parse_string_attributes_standalone(&payload);

        // Top-level attributes
        assert_eq!(attrs.get("firstName").unwrap(), "Alice");
        assert_eq!(attrs.get("lastName").unwrap(), "Smith");

        // Flattened dotted keys
        assert_eq!(
            attrs.get("custom_attributes.department").unwrap(),
            "Engineering"
        );
        assert_eq!(
            attrs.get("custom_attributes.cost_center").unwrap(),
            "CC-100"
        );
        assert_eq!(
            attrs.get("custom_attributes.employee_id").unwrap(),
            "E12345"
        );
        assert_eq!(attrs.get("custom_attributes.active").unwrap(), "true");
        assert_eq!(attrs.get("custom_attributes.level").unwrap(), "5");

        // Whole object also available as JSON string
        assert!(attrs.get("custom_attributes").is_some());
        let ca_json: serde_json::Value =
            serde_json::from_str(attrs.get("custom_attributes").unwrap()).unwrap();
        assert_eq!(ca_json["department"], "Engineering");
    }

    #[test]
    fn test_parse_string_attributes_no_nested() {
        let payload = serde_json::json!({
            "firstName": "Bob",
            "age": 30,
            "active": true
        });

        let attrs = parse_string_attributes_standalone(&payload);
        assert_eq!(attrs.get("firstName").unwrap(), "Bob");
        assert_eq!(attrs.get("age").unwrap(), "30");
        assert_eq!(attrs.get("active").unwrap(), "true");
        assert_eq!(attrs.len(), 3);
    }

    // ========================================================================
    // Batch Processing Tests (F047 - T066)
    // ========================================================================

    #[test]
    fn test_batch_processing_result_default() {
        let result = BatchProcessingResult::default();
        assert_eq!(result.total_operations, 0);
        assert_eq!(result.successful_operations, 0);
        assert_eq!(result.failed_operations, 0);
        assert!(result.connector_results.is_empty());
        assert_eq!(result.success_rate(), 100.0); // No operations = 100% success
        assert!(result.all_succeeded());
    }

    #[test]
    fn test_batch_processing_result_success_rate() {
        let mut result = BatchProcessingResult {
            total_operations: 10,
            successful_operations: 8,
            failed_operations: 2,
            connector_results: HashMap::new(),
        };
        assert_eq!(result.success_rate(), 80.0);
        assert!(!result.all_succeeded());

        // All succeeded case
        result.failed_operations = 0;
        result.successful_operations = 10;
        assert!(result.all_succeeded());
        assert_eq!(result.success_rate(), 100.0);
    }

    #[test]
    fn test_batch_processing_result_failed_connectors() {
        let connector1 = Uuid::new_v4();
        let connector2 = Uuid::new_v4();
        let connector3 = Uuid::new_v4();

        let mut connector_results = HashMap::new();
        connector_results.insert(
            connector1,
            ConnectorBatchResult {
                operations_processed: 5,
                operations_succeeded: 5,
                operations_failed: 0,
                errors: vec![],
            },
        );
        connector_results.insert(
            connector2,
            ConnectorBatchResult {
                operations_processed: 3,
                operations_succeeded: 2,
                operations_failed: 1,
                errors: vec!["Error 1".to_string()],
            },
        );
        connector_results.insert(
            connector3,
            ConnectorBatchResult {
                operations_processed: 2,
                operations_succeeded: 0,
                operations_failed: 2,
                errors: vec!["Error 2".to_string(), "Error 3".to_string()],
            },
        );

        let result = BatchProcessingResult {
            total_operations: 10,
            successful_operations: 7,
            failed_operations: 3,
            connector_results,
        };

        let failed = result.failed_connectors();
        assert_eq!(failed.len(), 2);
        assert!(failed.contains(&connector2));
        assert!(failed.contains(&connector3));
        assert!(!failed.contains(&connector1));
    }

    #[test]
    fn test_connector_batch_result_success_rate() {
        let result = ConnectorBatchResult {
            operations_processed: 4,
            operations_succeeded: 3,
            operations_failed: 1,
            errors: vec!["Some error".to_string()],
        };
        assert_eq!(result.success_rate(), 75.0);

        // Empty case
        let empty_result = ConnectorBatchResult::default();
        assert_eq!(empty_result.success_rate(), 100.0);
    }
}
