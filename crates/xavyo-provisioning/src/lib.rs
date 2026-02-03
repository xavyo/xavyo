//! # Provisioning Engine
//!
//! Queue management and operation processing for xavyo provisioning.
//!
//! This crate provides the infrastructure for:
//! - Operation queuing and scheduling
//! - Retry logic with exponential backoff
//! - Dead letter queue handling
//! - Health monitoring and circuit breaker
//! - Event-driven provisioning
//! - Correlation engine for finding existing accounts
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐     ┌──────────────┐     ┌───────────────┐
//! │  Event Source   │────►│   Queue      │────►│   Processor   │
//! │  (Kafka/User)   │     │              │     │               │
//! └─────────────────┘     └──────────────┘     └───────┬───────┘
//!                                                      │
//!                              ┌───────────────────────┼───────────────────────┐
//!                              │                       ▼                       │
//!                         ┌────────────┐        ┌───────────────┐        ┌─────────────┐
//!                         │ Correlation│───────►│   Connector   │◄───────│  Mapping    │
//!                         │   Engine   │        │               │        │  Engine     │
//!                         └────────────┘        └───────┬───────┘        └─────────────┘
//!                                                       │
//!                         ┌──────────────┐              │
//!                         │ Dead Letter  │◄─────────────┘
//!                         │    Queue     │     (on permanent failure)
//!                         └──────────────┘
//! ```
//!
//! ## Features
//!
//! - **Operation Queue**: Durable queue with priority support and FOR UPDATE SKIP LOCKED
//! - **Retry Logic**: Exponential backoff with jitter
//! - **Correlation Engine**: Find existing accounts using exact/fuzzy matching
//! - **Dead Letter Queue**: Failed operations for manual review
//! - **Transform Engine**: Attribute mapping and transformation
//!
//! ## Example
//!
//! ```ignore
//! use xavyo_provisioning::{OperationQueue, OperationProcessor, QueuedOperation};
//! use xavyo_connector::types::OperationType;
//!
//! // Enqueue an operation
//! let operation = QueuedOperation::new(
//!     tenant_id,
//!     connector_id,
//!     user_id,
//!     OperationType::Create,
//!     "user".to_string(),
//!     serde_json::json!({
//!         "firstName": "John",
//!         "lastName": "Doe",
//!         "email": "john.doe@example.com"
//!     }),
//! );
//!
//! queue.enqueue(operation).await?;
//!
//! // Processor will pick up and execute
//! processor.start().await?;
//! ```

pub mod attempt;
pub mod conflict;
pub mod correlation;
pub mod events;
pub mod health;
pub mod hooks;
pub mod idempotency;
pub mod processor;
pub mod queue;
pub mod reconciliation;
pub mod rhai_executor;
pub mod shadow;
pub mod sync;
pub mod transform;
pub mod worker;

// Re-exports for convenience
pub use attempt::{AttemptCompletion, AttemptError, AttemptInfo, AttemptResult, AttemptService};
pub use conflict::{
    ConflictError, ConflictResult, ConflictService, DetectedConflict, ResolutionResult,
};
pub use correlation::{
    default_correlation_service, CorrelationConfig, CorrelationError, CorrelationMatch,
    CorrelationResult, CorrelationService, DefaultCorrelationService,
};
pub use events::{
    ConnectorAssignment, ConnectorResolver, EventError, EventResult, ProvisioningEventHandler,
    UserCreatedEvent, UserDeactivatedEvent, UserUpdatedEvent,
};
pub use health::{
    ConnectorHealthInfo, HealthConfig, HealthError, HealthMonitor, HealthResult, HealthService,
};
pub use hooks::{
    ExpressionHookExecutor, HookContext, HookCriticality, HookDefinition, HookError,
    HookExecutionResult, HookExecutor, HookManager, HookPhase, HookResult, WebhookExecutor,
};
pub use idempotency::{IdempotencyError, IdempotencyResult, IdempotencyService};
pub use processor::{
    ConnectorProvider, DefaultOperationProcessor, FullConnector, OperationProcessor,
    ProcessorConfig, ProcessorError, ProcessorResult,
};
pub use queue::{
    EnqueueResult, OperationQueue, QueueConfig, QueueError, QueueResult, QueueStats,
    QueuedOperation,
};
pub use rhai_executor::{
    DryRunResult, RhaiExecutorConfig, RhaiScriptExecutor, ScriptValidationError,
};
pub use shadow::{Shadow, ShadowError, ShadowRepository, ShadowResult, ShadowState, SyncSituation};
pub use transform::{
    AttributeMapping, MappingConfig, MappingDirection, TransformConfig, TransformEngine,
    TransformError, TransformErrorCode, TransformResult, ValidationError,
};
pub use worker::{ProvisioningWorker, WorkerConfig};

// Reconciliation Engine exports (F049)
pub use reconciliation::{
    // Checkpoint for resumption
    checkpoint::{Checkpoint, CheckpointManager, CheckpointPhase},
    // Comparison logic
    comparator::{AccountComparator, AttributeDifference, ComparisonResult, MismatchedAttributes},
    // Discrepancy detection
    discrepancy::{DiscrepancyDetector, DiscrepancyFilter, DiscrepancyInfo},
    // Engine and orchestration
    engine::{
        ReconciliationConfig, ReconciliationEngine, ReconciliationError, ReconciliationRunInfo,
    },
    // Remediation actions
    remediation::{
        BulkRemediationItem, BulkRemediationRequest, BulkRemediationResult, BulkRemediationSummary,
        RemediationExecutor, RemediationPreview, RemediationPreviewItem, RemediationPreviewSummary,
        RemediationRequest, RemediationResult,
    },
    // Reporting
    report::{
        ActionSummary, AttributeMismatchCount, DiscrepancyCsvRow, DiscrepancySummary,
        DiscrepancyTrend, PerformanceMetrics, ReconciliationReport, ReportGenerator, RunInfo,
        TrendDataPoint,
    },
    // Scheduling
    scheduler::{ReconciliationScheduler, ScheduleConfig, ScheduleFrequency, ScheduleRequest},
    // Statistics tracking
    statistics::{RunStatistics, StatisticsTracker},
    // Types and enums
    types::{
        ActionResult, ActionType, DiscrepancyType, ReconciliationMode, RemediationDirection,
        ResolutionStatus, RunStatus,
    },
};

/// Initialize the provisioning engine (placeholder for future setup).
pub fn init() {
    tracing::info!("Provisioning engine initialized");
}
