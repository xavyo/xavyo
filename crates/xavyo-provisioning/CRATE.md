# xavyo-provisioning

> Provisioning engine with queue management, correlation, reconciliation, and Rhai scripting.

## Purpose

Provides the infrastructure for provisioning operations including durable operation queues, retry logic with exponential backoff, dead letter queue handling, correlation engine for matching accounts, reconciliation engine for detecting drift, and Rhai scripting for custom transformation logic. Orchestrates the entire provisioning pipeline from event to target system.

## Layer

domain

## Status

🟡 **beta**

Functional with good test coverage (260+ tests). Remediation executor is fully implemented with transaction support and rollback capabilities. RemediationExecutor supports Create, Update, Delete, Link, Unlink, InactivateIdentity, CreateIdentity, and DeleteIdentity actions with dry-run mode and state capture. Full identity service integration for identity lifecycle management.

## Dependencies

### Internal (xavyo)
- `xavyo-connector` - Connector abstractions
- `xavyo-events` - Event consumption
- `xavyo-db` - Operation persistence
- `xavyo-core` - TenantId, UserId types

### External (key)
- `tokio` - Async runtime
- `sqlx` - Queue persistence
- `rhai` - Scripting engine
- `reqwest` - Webhook delivery

## Public API

### Types

```rust
/// Queued provisioning operation
pub struct QueuedOperation {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub connector_id: Uuid,
    pub target_uid: Option<String>,
    pub operation_type: OperationType,
    pub object_class: String,
    pub attributes: Value,
    pub priority: i32,
    pub retry_count: i32,
    pub next_retry_at: Option<DateTime<Utc>>,
}

/// Queue statistics
pub struct QueueStats {
    pub pending: i64,
    pub in_progress: i64,
    pub failed: i64,
    pub dead_letter: i64,
}

/// Correlation match result
pub struct CorrelationMatch {
    pub uid: String,
    pub confidence: f64,
    pub match_type: MatchType,
}

/// Shadow account state
pub struct Shadow {
    pub tenant_id: Uuid,
    pub connector_id: Uuid,
    pub uid: String,
    pub state: ShadowState,
    pub attributes: Value,
}

/// Hook execution context
pub struct HookContext {
    pub tenant_id: Uuid,
    pub operation_type: OperationType,
    pub object_class: String,
    pub attributes: Value,
}

/// Reconciliation run info
pub struct ReconciliationRunInfo {
    pub id: Uuid,
    pub connector_id: Uuid,
    pub status: RunStatus,
    pub statistics: RunStatistics,
}

/// Remediation result with state capture
pub struct RemediationResult {
    pub discrepancy_id: Uuid,
    pub action: ActionType,
    pub success: bool,
    pub dry_run: bool,
    pub before_state: Option<Value>,
    pub after_state: Option<Value>,
    pub error_message: Option<String>,
}

/// Multi-step remediation transaction with rollback support
pub struct RemediationTransaction {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub status: TransactionStatus,
    pub steps: Vec<CompletedStep>,
    pub rollback_errors: Vec<RollbackError>,
}
```

### Traits

```rust
/// Operation processor interface
#[async_trait]
pub trait OperationProcessor: Send + Sync {
    async fn process(&self, operation: QueuedOperation) -> ProcessorResult<()>;
}

/// Correlation service interface
#[async_trait]
pub trait CorrelationService: Send + Sync {
    async fn correlate(&self, tenant_id: Uuid, connector_id: Uuid, attrs: &Value) -> CorrelationResult<Option<CorrelationMatch>>;
}

/// Hook executor interface
#[async_trait]
pub trait HookExecutor: Send + Sync {
    async fn execute(&self, hook: &HookDefinition, ctx: &HookContext) -> HookResult<HookExecutionResult>;
}
```

### Functions

```rust
/// Create operation queue
impl OperationQueue {
    pub async fn new(pool: PgPool, config: QueueConfig) -> Self;
    pub async fn enqueue(&self, op: QueuedOperation) -> QueueResult<Uuid>;
    pub async fn dequeue(&self, limit: i32) -> QueueResult<Vec<QueuedOperation>>;
    pub async fn stats(&self) -> QueueResult<QueueStats>;
}

/// Create reconciliation engine
impl ReconciliationEngine {
    pub async fn new(pool: PgPool, config: ReconciliationConfig) -> Self;
    pub async fn run(&self, connector_id: Uuid) -> Result<ReconciliationRunInfo>;
    pub async fn preview(&self, connector_id: Uuid) -> Result<DiscrepancySummary>;
}

/// Create Rhai script executor
impl RhaiScriptExecutor {
    pub fn new(config: RhaiExecutorConfig) -> Self;
    pub fn execute(&self, script: &str, ctx: &HookContext) -> Result<Value>;
    pub fn validate(&self, script: &str) -> Result<(), ScriptValidationError>;
}

/// Remediation executor for discrepancy resolution
impl RemediationExecutor {
    pub fn new(tenant_id: Uuid, connector_provider: Arc<dyn ConnectorProvider>, shadow_repo: Arc<ShadowRepository>, identity_service: Arc<dyn IdentityService>) -> Self;
    pub async fn execute_create(&self, discrepancy_id: Uuid, identity_id: Uuid, connector_id: Uuid, object_class: &str, dry_run: bool) -> RemediationResult;
    pub async fn execute_update(&self, discrepancy_id: Uuid, identity_id: Uuid, external_uid: &str, connector_id: Uuid, object_class: &str, direction: RemediationDirection, dry_run: bool) -> RemediationResult;
    pub async fn execute_delete(&self, discrepancy_id: Uuid, external_uid: &str, connector_id: Uuid, object_class: &str, dry_run: bool) -> RemediationResult;
    pub async fn execute_link(&self, discrepancy_id: Uuid, identity_id: Uuid, external_uid: &str, connector_id: Uuid, dry_run: bool) -> RemediationResult;
    pub async fn execute_unlink(&self, discrepancy_id: Uuid, identity_id: Uuid, external_uid: &str, connector_id: Uuid, dry_run: bool) -> RemediationResult;
    pub async fn execute_inactivate_identity(&self, discrepancy_id: Uuid, identity_id: Uuid, dry_run: bool) -> RemediationResult;
    pub async fn execute_create_identity(&self, discrepancy_id: Uuid, attributes: AttributeSet, dry_run: bool) -> RemediationResult;
    pub async fn execute_delete_identity(&self, discrepancy_id: Uuid, identity_id: Uuid, dry_run: bool) -> RemediationResult;
}

/// Identity service trait for identity lifecycle management
#[async_trait]
pub trait IdentityService: Send + Sync {
    async fn create_identity(&self, tenant_id: Uuid, attributes: AttributeSet) -> Result<Uuid, String>;
    async fn get_identity_attributes(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<AttributeSet, String>;
    async fn update_identity(&self, tenant_id: Uuid, identity_id: Uuid, attributes: AttributeSet) -> Result<(), String>;
    async fn delete_identity(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<(), String>;
    async fn inactivate_identity(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<(), String>;
    async fn is_identity_active(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<bool, String>;
    async fn identity_exists(&self, tenant_id: Uuid, identity_id: Uuid) -> Result<bool, String>;
}
```

## Usage Example

```rust
use xavyo_provisioning::{OperationQueue, QueueConfig, QueuedOperation};
use xavyo_connector::types::OperationType;

// Create queue
let queue = OperationQueue::new(pool.clone(), QueueConfig::default()).await;

// Enqueue an operation
let operation = QueuedOperation::new(
    tenant_id,
    connector_id,
    user_id,
    OperationType::Create,
    "user".to_string(),
    serde_json::json!({
        "firstName": "John",
        "lastName": "Doe",
        "email": "john.doe@example.com"
    }),
);

let op_id = queue.enqueue(operation).await?;

// Worker processes the queue
let worker = ProvisioningWorker::new(queue, processor, config);
worker.start().await?;
```

## Integration Points

- **Consumed by**: `xavyo-api-connectors`, `idp-api`
- **Consumes**: Events from `xavyo-events`
- **Uses**: Connectors via `xavyo-connector`

## Feature Flags

None - all features are enabled by default.

## Anti-Patterns

- Never process operations without idempotency checking
- Never skip correlation for create operations
- Never bypass the dead letter queue for permanent failures
- Never run reconciliation without proper tenant context
- Never execute untrusted Rhai scripts without validation

## Related Crates

- `xavyo-connector` - Connector abstractions
- `xavyo-api-connectors` - API layer for provisioning
- `xavyo-events` - Event-driven triggers
