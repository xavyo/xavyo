# xavyo-webhooks

> Webhook delivery system for identity lifecycle event subscriptions.

## Purpose

Provides tenant-scoped webhook subscription management with async delivery, HMAC-SHA256 payload signing, exponential backoff retries, and delivery tracking. Webhooks enable external systems to react to identity events like user creation, role changes, and certification decisions without polling.

## Layer

domain

## Status

🟢 **stable**

Production-ready with comprehensive test coverage (157 tests: 119 unit tests + 38 integration tests). Core delivery system complete with full integration test coverage for delivery, retry logic, signature verification, concurrent delivery, failure scenarios, and tracking. Includes circuit breaker pattern for endpoint protection, dead letter queue for failed webhooks, and per-destination rate limiting.

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId, UserId types
- `xavyo-auth` - JWT validation for API
- `xavyo-tenant` - Middleware
- `xavyo-db` - Subscription storage

### External (key)
- `axum` - HTTP handlers
- `reqwest` - Webhook delivery
- `hmac` + `sha2` - Payload signing
- `aes-gcm` - Secret encryption

## Public API

### Types

```rust
/// Webhook event types
pub enum WebhookEventType {
    UserCreated,
    UserUpdated,
    UserDeleted,
    UserDisabled,
    RoleAssigned,
    RoleRevoked,
    EntitlementGranted,
    EntitlementRevoked,
    CertificationDecision,
    AccessRequestApproved,
    AccessRequestDenied,
}

/// Webhook event payload
pub struct WebhookEvent {
    pub event_id: Uuid,
    pub event_type: String,
    pub tenant_id: Uuid,
    pub actor_id: Option<Uuid>,
    pub timestamp: DateTime<Utc>,
    pub data: Value,
}

/// Webhook subscription (stored in DB)
pub struct WebhookSubscription {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub url: String,
    pub event_types: Vec<WebhookEventType>,
    pub secret: Vec<u8>,  // Encrypted
    pub enabled: bool,
}

/// Delivery attempt record
pub struct DeliveryAttempt {
    pub id: Uuid,
    pub subscription_id: Uuid,
    pub event_id: Uuid,
    pub status: DeliveryStatus,
    pub http_status: Option<u16>,
    pub attempt_number: i32,
    pub next_retry_at: Option<DateTime<Utc>>,
}

/// Webhook errors
pub enum WebhookError {
    SubscriptionNotFound(Uuid),
    DeliveryFailed { url: String, status: u16 },
    InvalidUrl(String),
    EncryptionError(String),
    CircuitBreakerOpen { subscription_id: Uuid },
    DlqEntryNotFound,
    RateLimitExceeded { subscription_id: Uuid },
}

/// Circuit breaker states
pub enum CircuitState {
    Closed,   // Normal operation
    Open,     // Rejecting requests
    HalfOpen, // Testing recovery
}

/// Circuit breaker status
pub struct CircuitBreakerStatus {
    pub subscription_id: Uuid,
    pub state: CircuitState,
    pub failure_count: u32,
    pub last_failure_at: Option<DateTime<Utc>>,
    pub opened_at: Option<DateTime<Utc>>,
}

/// DLQ entry summary
pub struct DlqEntrySummary {
    pub id: Uuid,
    pub subscription_id: Uuid,
    pub event_id: Uuid,
    pub event_type: String,
    pub failure_reason: String,
    pub attempt_count: i32,
    pub created_at: DateTime<Utc>,
}

/// Rate limit configuration
pub struct RateLimitConfig {
    pub requests_per_second: f64,
    pub burst_size: u32,
}
```

### Traits

None - uses concrete implementations.

### Functions

```rust
/// Event publisher for async delivery
impl EventPublisher {
    pub fn new(pool: PgPool, encryption_key: &[u8]) -> Self;
    pub fn publish(&self, event: WebhookEvent);
    pub async fn flush(&self);
}

/// Webhook worker for background delivery
impl WebhookWorker {
    pub fn new(pool: PgPool, config: WorkerConfig) -> Self;
    pub async fn start(&self, shutdown: CancellationToken);
}

/// Router for webhook management API
pub fn webhooks_router() -> Router<WebhooksState>;

/// Circuit breaker registry
impl CircuitBreakerRegistry {
    pub fn new(pool: PgPool, config: CircuitBreakerConfig) -> Self;
    pub async fn can_execute(&self, tenant_id: Uuid, subscription_id: Uuid) -> Result<bool, Error>;
    pub async fn record_success(&self, tenant_id: Uuid, subscription_id: Uuid) -> Result<(), Error>;
    pub async fn record_failure(&self, tenant_id: Uuid, subscription_id: Uuid, failure: FailureRecord) -> Result<(), Error>;
    pub async fn get_all_status(&self, tenant_id: Uuid) -> Result<Vec<CircuitBreakerStatus>, Error>;
}

/// DLQ service
impl DlqService {
    pub fn new(pool: PgPool) -> Self;
    pub async fn add_to_dlq(&self, ...) -> Result<WebhookDlqEntry, Error>;
    pub async fn list_entries(&self, tenant_id: Uuid, filter: DlqFilter, ...) -> Result<DlqEntryList, Error>;
    pub async fn replay_single(&self, tenant_id: Uuid, id: Uuid) -> Result<ReplayResponse, Error>;
    pub async fn replay_bulk(&self, tenant_id: Uuid, request: BulkReplayRequest) -> Result<BulkReplayResponse, Error>;
}

/// Rate limiter registry
impl RateLimiterRegistry {
    pub fn new(default_config: RateLimitConfig) -> Self;
    pub async fn try_acquire(&self, subscription_id: Uuid) -> bool;
    pub async fn acquire(&self, subscription_id: Uuid) -> Duration;
}
```

## Usage Example

```rust
use xavyo_webhooks::{EventPublisher, WebhookEvent, WebhookWorker};

// Create publisher
let publisher = EventPublisher::new(pool.clone(), &encryption_key);

// Publish event (non-blocking)
publisher.publish(WebhookEvent {
    event_id: Uuid::new_v4(),
    event_type: "user.created".to_string(),
    tenant_id,
    actor_id: Some(admin_id),
    timestamp: Utc::now(),
    data: serde_json::json!({
        "user_id": user_id,
        "email": "new.user@example.com"
    }),
});

// Start background worker
let worker = WebhookWorker::new(pool, WorkerConfig::default());
tokio::spawn(async move {
    worker.start(shutdown_token).await;
});
```

## Circuit Breaker Pattern

The circuit breaker protects webhook endpoints from being overwhelmed when they are failing:

1. **Closed State**: Normal operation, all deliveries proceed
2. **Open State**: After 5 consecutive failures, circuit opens and rejects deliveries immediately
3. **Half-Open State**: After 30 seconds recovery timeout, allows one probe request
4. **Recovery**: If probe succeeds, circuit closes; if probe fails, circuit reopens

```rust
// Circuit breaker is automatically integrated into DeliveryService
let delivery_service = DeliveryService::new(pool.clone(), encryption_key)?
    .with_circuit_breaker(Arc::new(registry));
```

### Circuit Breaker API

```
GET /webhooks/circuit-breakers          - List all circuit breaker statuses
GET /webhooks/circuit-breakers/{id}     - Get status for specific subscription
```

## Dead Letter Queue (DLQ)

Webhooks that exhaust all retry attempts (6 by default) are moved to the DLQ for investigation and replay:

```rust
// DLQ is automatically integrated into DeliveryService
let delivery_service = DeliveryService::new(pool.clone(), encryption_key)?
    .with_dlq_service(Arc::new(dlq_service));
```

### DLQ API

```
GET  /webhooks/dlq              - List DLQ entries with filtering
GET  /webhooks/dlq/{id}         - Get DLQ entry details
DELETE /webhooks/dlq/{id}       - Delete DLQ entry
POST /webhooks/dlq/{id}/replay  - Replay single entry
POST /webhooks/dlq/replay       - Bulk replay by filter
```

### DLQ Entry Contents

- Full request payload for replay
- Attempt history with timestamps and errors
- Last response code and body
- Subscription URL at time of failure

## Rate Limiting

Per-destination rate limiting prevents overwhelming webhook endpoints:

- **Token Bucket Algorithm**: 10 requests/second default, burst of 20
- **Automatic Throttling**: Excess requests wait for available tokens
- **Per-Subscription**: Each subscription has independent rate limit

```rust
// Rate limiting is automatically integrated into DeliveryService
let delivery_service = DeliveryService::new(pool.clone(), encryption_key)?
    .with_rate_limiter(Arc::new(registry));
```

## Integration Points

- **Consumed by**: All crates that emit lifecycle events
- **Provides**: Async event delivery to external systems
- **HTTP headers**: `X-Webhook-Signature`, `X-Webhook-ID`, `X-Webhook-Timestamp`

## Feature Flags

- `integration` - Enables integration tests (disabled by default)

## Integration Tests

The crate includes 105 integration and unit tests covering real-world webhook delivery scenarios:

### Test Suites

| Suite | Tests | Description |
|-------|-------|-------------|
| `delivery_tests` | 5 | Successful delivery, multiple subscriptions, 2xx handling, payload structure |
| `retry_tests` | 6 | 5xx retry, exponential backoff, eventual success, max retries, abandonment |
| `signature_tests` | 7 | HMAC-SHA256 presence, format, verification, different payloads, no secret |
| `concurrent_tests` | 4 | Concurrent delivery, independent completion, no blocking, same endpoint |
| `failure_tests` | 8 | Timeout, 4xx/5xx errors, network errors, consecutive failures, redirect blocking |
| `tracking_tests` | 8 | Delivery records, attempt tracking, response codes, latency, timestamps |
| `circuit_breaker_tests` | 22 | State transitions, failure threshold, recovery timeout, half-open probes |
| `dlq_tests` | 23 | DLQ entry creation, filtering, replay single/bulk, tenant isolation |
| `rate_limiter_tests` | 22 | Token bucket, burst limits, throttling, refill over time |

### Running Integration Tests

```bash
# Run all integration tests
cargo test -p xavyo-webhooks --features integration

# Run specific test suite
cargo test -p xavyo-webhooks --features integration --test delivery_tests

# Run single test
cargo test -p xavyo-webhooks --features integration --test signature_tests test_hmac_signature_header_present
```

### Test Infrastructure

Integration tests use [wiremock](https://github.com/LukeMathWalker/wiremock-rs) to mock HTTP endpoints:

- **CaptureResponder**: Captures request body and headers for verification
- **CountingResponder**: Counts requests for concurrency testing
- **FailingResponder**: Fails N times then succeeds for retry testing
- **DelayedResponder**: Adds response delay for timeout testing

## Anti-Patterns

- Never deliver webhooks synchronously in request handlers
- Never log webhook secrets or payload signatures
- Never skip signature verification documentation for consumers
- Never retry indefinitely - use dead letter queue

## Related Crates

- `xavyo-events` - Kafka events (different delivery mechanism)
- `xavyo-siem` - Audit export (different purpose)
- `xavyo-api-governance` - Triggers governance events
