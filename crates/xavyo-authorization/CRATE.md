# xavyo-authorization

> Fine-grained authorization engine (Policy Decision Point) for xavyo.

## Purpose

Provides runtime policy evaluation for access control decisions. Implements a Policy Decision Point (PDP) that evaluates authorization policies against request context. Supports ABAC (Attribute-Based Access Control) with conditions on time, location, risk level, and custom attributes. Includes in-memory caching via Moka for high-performance policy lookups.

## Layer

domain

## Status

🔴 **alpha**

Experimental with foundation-level implementation (47 tests, 16 public items). Core PDP types defined; full policy evaluation not yet complete.

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId, UserId types
- `xavyo-db` - Policy storage models

### External (key)
- `sqlx` - Policy persistence
- `moka` - Async LRU cache
- `chrono` - Time-based conditions
- `serde` - Policy serialization

## Public API

### Types

```rust
/// Authorization request context
pub struct AuthzContext {
    pub tenant_id: Uuid,
    pub subject_id: Uuid,          // User or agent ID
    pub subject_type: SubjectType, // User, Agent, Service
    pub resource_type: String,     // e.g., "user", "report"
    pub resource_id: Option<Uuid>,
    pub action: String,            // e.g., "read", "write", "delete"
    pub environment: Environment,  // Time, IP, risk score
}

/// Authorization decision
pub enum Decision {
    Allow,
    Deny,
    NotApplicable,
}

/// Authorization response
pub struct AuthzResponse {
    pub decision: Decision,
    pub policy_id: Option<Uuid>,
    pub reason: Option<String>,
    pub obligations: Vec<Obligation>,
}

/// Policy condition
pub struct Condition {
    pub attribute: String,
    pub operator: ConditionOperator,
    pub value: Value,
}

/// Condition operators
pub enum ConditionOperator {
    Equals,
    NotEquals,
    Contains,
    GreaterThan,
    LessThan,
    InRange,
    TimeWithin,
}

/// Environment attributes
pub struct Environment {
    pub timestamp: DateTime<Utc>,
    pub ip_address: Option<IpAddr>,
    pub risk_score: Option<f64>,
    pub custom: HashMap<String, Value>,
}
```

### Traits

```rust
/// Policy Decision Point interface
#[async_trait]
pub trait PolicyDecisionPoint: Send + Sync {
    async fn evaluate(&self, ctx: &AuthzContext) -> Result<AuthzResponse, AuthorizationError>;
    async fn batch_evaluate(&self, contexts: Vec<AuthzContext>) -> Result<Vec<AuthzResponse>, AuthorizationError>;
}
```

### Functions

```rust
/// Create PDP with database pool
impl PolicyDecisionPoint {
    pub fn new(pool: PgPool, cache_config: CacheConfig) -> Self;
}

/// Entitlement resolver
impl EntitlementResolver {
    pub fn new(pool: PgPool) -> Self;
    pub async fn get_effective_entitlements(&self, tenant_id: Uuid, user_id: Uuid) -> Result<Vec<Entitlement>>;
    pub async fn has_entitlement(&self, tenant_id: Uuid, user_id: Uuid, entitlement: &str) -> Result<bool>;
}

/// Policy cache
impl PolicyCache {
    pub fn new(max_capacity: u64, ttl_seconds: u64) -> Self;
    pub async fn get(&self, key: &str) -> Option<Policy>;
    pub async fn invalidate(&self, tenant_id: Uuid);
}
```

## Usage Example

```rust
use xavyo_authorization::{
    PolicyDecisionPoint, AuthzContext, Decision, Environment,
    EntitlementResolver,
};

// Create PDP
let pdp = PolicyDecisionPoint::new(pool.clone(), CacheConfig::default());

// Build authorization context
let ctx = AuthzContext {
    tenant_id,
    subject_id: user_id,
    subject_type: SubjectType::User,
    resource_type: "report".to_string(),
    resource_id: Some(report_id),
    action: "read".to_string(),
    environment: Environment {
        timestamp: Utc::now(),
        ip_address: Some("192.168.1.100".parse().unwrap()),
        risk_score: Some(0.2),
        custom: HashMap::new(),
    },
};

// Evaluate policy
let response = pdp.evaluate(&ctx).await?;

match response.decision {
    Decision::Allow => { /* proceed */ }
    Decision::Deny => { /* reject with reason */ }
    Decision::NotApplicable => { /* default deny */ }
}

// Check specific entitlement
let resolver = EntitlementResolver::new(pool);
if resolver.has_entitlement(tenant_id, user_id, "reports:export").await? {
    // Allow export
}
```

## Integration Points

- **Consumed by**: All API crates for access control
- **Provides**: Authorization decisions for HTTP handlers
- **Caches**: Policies and entitlements in Moka

## Feature Flags

| Flag | Description | Dependencies Added |
|------|-------------|-------------------|
| `integration` | Enable integration tests | - |

## Anti-Patterns

- Never bypass PDP for "admin" users - always evaluate
- Never cache decisions longer than policy TTL
- Never ignore NotApplicable - default to Deny
- Never leak policy details in error messages to clients

## Related Crates

- `xavyo-api-authorization` - REST API for policy management
- `xavyo-governance` - Entitlement definitions
- `xavyo-db` - Policy and entitlement storage
