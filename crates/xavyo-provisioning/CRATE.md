# xavyo-provisioning

> Provisioning engine with queue management, correlation, reconciliation, and Rhai scripting.

## Purpose

Provides the infrastructure for provisioning operations including durable operation queues, retry logic with exponential backoff, dead letter queue handling, correlation engine for matching accounts, reconciliation engine for detecting drift, and Rhai scripting for custom transformation logic. Orchestrates the entire provisioning pipeline from event to target system.

## Layer

domain

## Status

🟡 **beta**

Functional with good test coverage (290+ tests). Remediation executor is fully implemented with transaction support and rollback capabilities. RemediationExecutor supports Create, Update, Delete, Link, Unlink, InactivateIdentity, CreateIdentity, and DeleteIdentity actions with dry-run mode and state capture. Full identity service integration for identity lifecycle management. Transformation engine with 30+ built-in functions for attribute mapping.

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

/// Transformation engine for attribute mapping
impl TransformEngine {
    pub fn new() -> Self;
    pub fn with_config(config: TransformConfig) -> Self;
    pub fn validate_expression(&self, expression: &str) -> Vec<ValidationError>;
    pub fn validate_mapping(&self, mapping: &MappingConfig) -> Vec<ValidationError>;
    pub fn evaluate_expression(&self, expression: &str, value: &Value) -> Result<Value, String>;
    pub fn apply_mappings(&self, source: &Value, mapping: &MappingConfig) -> TransformResult;
}
```

## Transformation Engine

The transformation engine provides attribute mapping and transformation capabilities for provisioning operations using Rhai scripting.

### Built-in Functions

| Category | Function | Description | Example |
|----------|----------|-------------|---------|
| **String** | `concat2(a, b)` | Concatenate 2 strings | `concat2("Hello", " World")` → `"Hello World"` |
| | `concat3(a, b, c)` | Concatenate 3 strings | `concat3("a", "b", "c")` → `"abc"` |
| | `concat4(a, b, c, d)` | Concatenate 4 strings | `concat4("a", "b", "c", "d")` → `"abcd"` |
| | `split(str, sep)` | Split string into array | `split("a,b,c", ",")` → `["a", "b", "c"]` |
| | `join(arr, sep)` | Join array into string | `join(["a", "b"], "-")` → `"a-b"` |
| **Case** | `lowercase(str)` | Convert to lowercase | `lowercase("HELLO")` → `"hello"` |
| | `uppercase(str)` | Convert to uppercase | `uppercase("hello")` → `"HELLO"` |
| | `capitalize(str)` | Capitalize first letter | `capitalize("hello")` → `"Hello"` |
| **Trim** | `trim(str)` | Remove whitespace | `trim("  hello  ")` → `"hello"` |
| | `trim_start(str)` | Remove leading whitespace | `trim_start("  hello")` → `"hello"` |
| | `trim_end(str)` | Remove trailing whitespace | `trim_end("hello  ")` → `"hello"` |
| **Replace** | `replace(str, from, to)` | Replace all occurrences | `replace("hello", "l", "L")` → `"heLLo"` |
| | `replace_first(str, from, to)` | Replace first occurrence | `replace_first("hello", "l", "L")` → `"heLlo"` |
| **Substring** | `substring(str, start, len)` | Extract substring | `substring("hello", 0, 3)` → `"hel"` |
| | `left(str, n)` | Get first n chars | `left("hello", 3)` → `"hel"` |
| | `right(str, n)` | Get last n chars | `right("hello", 3)` → `"llo"` |
| **Predicates** | `starts_with(str, prefix)` | Check prefix | `starts_with("hello", "he")` → `true` |
| | `ends_with(str, suffix)` | Check suffix | `ends_with("hello", "lo")` → `true` |
| | `contains_str(str, substr)` | Check contains | `contains_str("hello", "ell")` → `true` |
| | `is_empty(str)` | Check if empty | `is_empty("")` → `true` |
| | `is_blank(str)` | Check if blank (whitespace) | `is_blank("  ")` → `true` |
| **Length** | `str_len(str)` | Get byte length | `str_len("hello")` → `5` |
| | `char_count(str)` | Get character count | `char_count("hello")` → `5` |
| **Padding** | `pad_left(str, len, char)` | Pad on left | `pad_left("42", 5, "0")` → `"00042"` |
| | `pad_right(str, len, char)` | Pad on right | `pad_right("42", 5, "0")` → `"42000"` |
| **Formatting** | `format_email(user, domain)` | Format email | `format_email("John", "EXAMPLE.COM")` → `"john@example.com"` |
| | `slugify(str)` | Convert to URL slug | `slugify("Hello World!")` → `"hello-world"` |
| **Default** | `default_str(str, default)` | Default if empty | `default_str("", "N/A")` → `"N/A"` |
| | `default_val(val, default)` | Default if nil | `default_val(nil, "N/A")` → `"N/A"` |
| | `coalesce2(a, b)` | First non-empty value | `coalesce2("", "fallback")` → `"fallback"` |
| | `coalesce3(a, b, c)` | First non-empty value | `coalesce3("", "", "fallback")` → `"fallback"` |
| **Array** | `array_first(arr)` | Get first element | `array_first(["a", "b"])` → `"a"` |
| | `array_last(arr)` | Get last element | `array_last(["a", "b"])` → `"b"` |
| | `array_get(arr, idx)` | Get element at index | `array_get(["a", "b"], 1)` → `"b"` |
| | `array_len(arr)` | Get array length | `array_len(["a", "b"])` → `2` |
| | `array_contains(arr, val)` | Check if contains | `array_contains(["a", "b"], "a")` → `true` |
| | `array_unique(arr)` | Remove duplicates | `array_unique(["a", "a", "b"])` → `["a", "b"]` |
| **Type Check** | `is_string(val)` | Check if string | `is_string("hello")` → `true` |
| | `is_int(val)` | Check if integer | `is_int(42)` → `true` |
| | `is_float(val)` | Check if float | `is_float(3.14)` → `true` |
| | `is_bool(val)` | Check if boolean | `is_bool(true)` → `true` |
| | `is_array(val)` | Check if array | `is_array([1, 2])` → `true` |
| | `is_map(val)` | Check if map | `is_map(#{})` → `true` |
| | `is_null(val)` | Check if null | `is_null(nil)` → `true` |
| **Conversion** | `to_string(val)` | Convert to string | `to_string(42)` → `"42"` |
| | `to_int(str)` | Convert to integer | `to_int("42")` → `42` |
| | `to_float(str)` | Convert to float | `to_float("3.14")` → `3.14` |
| | `to_bool(str)` | Convert to boolean | `to_bool("true")` → `true` |
| **Logging** | `log_info(msg)` | Log info message | `log_info("Processing...")` |
| | `log_warn(msg)` | Log warning message | `log_warn("Unexpected value")` |
| | `log_debug(msg)` | Log debug message | `log_debug("Value: " + x)` |

### Transformation Example

```rust
use xavyo_provisioning::{TransformEngine, MappingConfig, AttributeMapping, MappingDirection};

let engine = TransformEngine::new();

// Define attribute mappings
let mapping = MappingConfig {
    object_class: "user".to_string(),
    direction: MappingDirection::Inbound,
    mappings: vec![
        AttributeMapping {
            source: "firstName".to_string(),
            target: "givenName".to_string(),
            transform: Some(r#"uppercase(value)"#.to_string()),
            required: true,
            default_value: None,
        },
        AttributeMapping {
            source: "email".to_string(),
            target: "samAccountName".to_string(),
            transform: Some(r#"array_first(split(value, "@"))"#.to_string()),
            required: true,
            default_value: None,
        },
    ],
    post_transform: Some(r#"
        target["cn"] = concat3(target["givenName"], " ", source["lastName"]);
        target
    "#.to_string()),
};

// Apply mappings
let source = serde_json::json!({
    "firstName": "John",
    "lastName": "Doe",
    "email": "john.doe@example.com"
});

let result = engine.apply_mappings(&source, &mapping);
assert!(result.success);
// Result: { "givenName": "JOHN", "samAccountName": "john.doe", "cn": "JOHN Doe" }
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
