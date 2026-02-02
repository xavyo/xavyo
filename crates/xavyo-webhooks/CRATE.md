# xavyo-webhooks

> Webhook delivery system for identity lifecycle event subscriptions.

## Purpose

Provides tenant-scoped webhook subscription management with async delivery, HMAC-SHA256 payload signing, exponential backoff retries, and delivery tracking. Webhooks enable external systems to react to identity events like user creation, role changes, and certification decisions without polling.

## Layer

domain

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

## Integration Points

- **Consumed by**: All crates that emit lifecycle events
- **Provides**: Async event delivery to external systems
- **HTTP headers**: `X-Webhook-Signature`, `X-Webhook-ID`, `X-Webhook-Timestamp`

## Feature Flags

None - all features are enabled by default.

## Anti-Patterns

- Never deliver webhooks synchronously in request handlers
- Never log webhook secrets or payload signatures
- Never skip signature verification documentation for consumers
- Never retry indefinitely - use dead letter queue

## Related Crates

- `xavyo-events` - Kafka events (different delivery mechanism)
- `xavyo-siem` - Audit export (different purpose)
- `xavyo-api-governance` - Triggers governance events
