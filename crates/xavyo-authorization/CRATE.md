# xavyo-authorization

> Fine-grained authorization engine (Policy Decision Point) for xavyo.

## Purpose

Provides runtime policy evaluation for access control decisions. Implements a Policy Decision Point (PDP) that evaluates authorization policies against request context. Supports ABAC (Attribute-Based Access Control) with conditions on time, location, risk level, and custom attributes. Includes in-memory caching via Moka for high-performance policy lookups.

Key features:
- **Policy evaluation**: ABAC with time/location/risk conditions
- **Role resolution**: Cached role lookups with tenant isolation
- **Obligation execution**: on_permit/on_deny action handlers
- **Policy versioning**: History tracking with rollback support
- **Audit logging**: Comprehensive policy change tracking

## Layer

domain

## Status

🟢 **stable**

Full implementation with comprehensive test coverage (105 unit tests, 3 doc tests). Core PDP, SearchOp trait, role resolution, obligation handling, policy versioning, and audit logging all complete.

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId, UserId types
- `xavyo-db` - Policy storage models

### External (key)
- `sqlx` - Policy persistence
- `moka` - Async LRU cache
- `chrono` - Time-based conditions
- `serde` - Policy serialization
- `async-trait` - Async trait support

## Public API

### Types

```rust
/// Authorization request
pub struct AuthorizationRequest {
    pub subject_id: Uuid,
    pub tenant_id: Uuid,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
}

/// Authorization decision
pub struct AuthorizationDecision {
    pub allowed: bool,
    pub reason: String,
    pub source: DecisionSource,
    pub policy_id: Option<Uuid>,
    pub decision_id: Uuid,
    pub latency_ms: f64,
}

/// Policy effect
pub enum PolicyEffect { Allow, Deny }

/// Decision source
pub enum DecisionSource { Policy, Entitlement, DefaultDeny }

/// Resolved role with metadata
pub struct ResolvedRole {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
}

/// Policy obligation
pub struct PolicyObligation {
    pub id: Uuid,
    pub policy_id: Uuid,
    pub trigger: ObligationTrigger,
    pub obligation_type: String,
    pub parameters: Option<serde_json::Value>,
    pub enabled: bool,
}

/// Obligation trigger
pub enum ObligationTrigger { OnPermit, OnDeny }

/// Policy version snapshot
pub struct PolicyVersion {
    pub id: Uuid,
    pub policy_id: Uuid,
    pub tenant_id: Uuid,
    pub version: i32,
    pub policy_snapshot: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub created_by: Uuid,
    pub change_summary: Option<String>,
}

/// Policy audit event
pub struct PolicyAuditEvent {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub policy_id: Option<Uuid>,
    pub action: PolicyAction,
    pub actor_id: Uuid,
    pub actor_ip: Option<IpAddr>,
    pub before_state: Option<serde_json::Value>,
    pub after_state: Option<serde_json::Value>,
    pub timestamp: DateTime<Utc>,
}

/// Policy action for audit
pub enum PolicyAction { Created, Updated, Deleted, Enabled, Disabled, RolledBack }
```

### Traits

```rust
/// Policy Decision Point
impl PolicyDecisionPoint {
    pub fn new(policy_cache: Arc<PolicyCache>, mapping_cache: Arc<MappingCache>) -> Self;
    pub async fn evaluate(&self, pool: &PgPool, request: AuthorizationRequest, ...) -> AuthorizationDecision;
    pub async fn invalidate_policies(&self, tenant_id: Uuid);
    pub async fn invalidate_mappings(&self, tenant_id: Uuid);
}

/// SearchOp trait for searchable types
pub trait SearchOp: Sized {
    fn table_name() -> &'static str;
    fn searchable_fields() -> &'static [&'static str];
    fn default_sort_field() -> &'static str;
}

/// Role resolution trait
#[async_trait]
pub trait RoleResolver: Send + Sync {
    async fn resolve_roles(&self, tenant_id: Uuid, user_id: Uuid) -> Result<Vec<ResolvedRole>>;
    async fn invalidate_user_roles(&self, tenant_id: Uuid, user_id: Uuid);
    async fn invalidate_tenant_roles(&self, tenant_id: Uuid);
}

/// Obligation handler trait
#[async_trait]
pub trait ObligationHandler: Send + Sync {
    fn obligation_type(&self) -> &str;
    async fn execute(&self, context: &ObligationContext, parameters: Option<&serde_json::Value>) -> Result<()>;
}
```

### Services

```rust
/// Role caching service
pub struct RoleCache {
    pub fn new(ttl: Duration) -> Self;
    pub async fn get(&self, tenant_id: Uuid, user_id: Uuid) -> Option<Vec<ResolvedRole>>;
    pub async fn insert(&self, tenant_id: Uuid, user_id: Uuid, roles: Vec<ResolvedRole>);
    pub async fn invalidate_user(&self, tenant_id: Uuid, user_id: Uuid);
}

/// Obligation execution registry
pub struct ObligationRegistry {
    pub fn new() -> Self;
    pub fn register(&mut self, handler: Box<dyn ObligationHandler>);
    pub async fn execute(&self, trigger: ObligationTrigger, obligations: &[PolicyObligation], context: &ObligationContext);
}

/// Policy version service
pub struct PolicyVersionService {
    pub fn new(store: Arc<dyn VersionStore>) -> Self;
    pub fn in_memory() -> Self;
    pub async fn create_version(&self, tenant_id, policy_id, snapshot, actor_id, summary) -> Result<PolicyVersion>;
    pub async fn get_version_history(&self, tenant_id, policy_id) -> Result<Vec<PolicyVersionSummary>>;
    pub async fn rollback_to_version(&self, tenant_id, policy_id, version, actor_id) -> Result<PolicyVersion>;
}

/// Policy audit service
pub struct PolicyAuditService {
    pub fn new(store: Arc<dyn AuditStore>) -> Self;
    pub fn in_memory() -> Self;
    pub async fn log_event(&self, input: PolicyAuditEventInput) -> Result<PolicyAuditEvent>;
    pub async fn query_events(&self, tenant_id, filter: AuditEventFilter) -> Result<Vec<PolicyAuditEvent>>;
}
```

## Usage Example

```rust
use xavyo_authorization::{
    PolicyDecisionPoint, AuthorizationRequest, DecisionSource,
    RoleCache, PolicyVersionService, PolicyAuditService,
};
use std::time::Duration;

// Role resolution with caching
let role_cache = RoleCache::new(Duration::from_secs(300));
let resolver = InMemoryRoleResolver::new();
resolver.assign_role(tenant_id, user_id, role).await;
let roles = resolver.resolve_roles(tenant_id, user_id).await?;

// Policy versioning
let version_service = PolicyVersionService::in_memory();
let v1 = version_service.create_version(
    tenant_id, policy_id, &snapshot, actor_id, Some("Initial".into())
).await?;
// Later: rollback to version 1
let v3 = version_service.rollback_to_version(tenant_id, policy_id, 1, actor_id).await?;

// Audit logging
let audit_service = PolicyAuditService::in_memory();
audit_service.log_event(PolicyAuditEventInput {
    tenant_id,
    policy_id: Some(policy_id),
    action: PolicyAction::Created,
    actor_id,
    ..Default::default()
}).await?;
```

## Integration Points

- **Consumed by**: All API crates for access control
- **Provides**: Authorization decisions for HTTP handlers
- **Caches**: Policies, entitlements, and roles in Moka

## Feature Flags

| Flag | Description | Dependencies Added |
|------|-------------|-------------------|
| `integration` | Enable integration tests | - |

## Anti-Patterns

- Never bypass PDP for "admin" users - always evaluate
- Never cache decisions longer than policy TTL
- Never ignore DefaultDeny - it means no policy matched
- Never leak policy details in error messages to clients
- Never build SQL without parameterization - use SearchQuery
- Never skip audit logging for policy changes

## Related Crates

- `xavyo-api-authorization` - REST API for policy management
- `xavyo-governance` - Entitlement definitions
- `xavyo-db` - Policy and entitlement storage
