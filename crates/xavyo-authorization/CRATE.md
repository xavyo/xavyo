# xavyo-authorization

> Fine-grained authorization engine (Policy Decision Point) for xavyo.

## Purpose

Provides runtime policy evaluation for access control decisions. Implements a Policy Decision Point (PDP) that evaluates authorization policies against request context. Supports ABAC (Attribute-Based Access Control) with conditions on time, location, risk level, and custom attributes. Includes in-memory caching via Moka for high-performance policy lookups.

## Layer

domain

## Status

🟡 **beta**

Functional implementation with comprehensive test coverage (73 unit tests, 3 doc tests). Core PDP working, SearchOp trait implemented for policy queries.

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

/// Search filter operator
pub enum FilterOp { Eq, Ne, Contains, StartsWith, In }

/// Search filter
pub struct SearchFilter {
    pub field: String,
    pub op: FilterOp,
    pub value: serde_json::Value,
}

/// Search query
pub struct SearchQuery {
    pub filters: Vec<SearchFilter>,
    pub sort_field: Option<String>,
    pub sort_dir: SortDir,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Search result
pub struct SearchResult<T> {
    pub items: Vec<T>,
    pub total: i64,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}
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
```

## Usage Example

```rust
use xavyo_authorization::{
    PolicyDecisionPoint, AuthorizationRequest, DecisionSource,
};
use xavyo_authorization::search::{SearchQuery, SearchFilter, FilterOp};

// Search for deny policies
let query = SearchQuery::new()
    .with_filter(SearchFilter::eq("effect", "deny"))
    .with_pagination(10, 0);

// Build safe SQL
let (where_clause, params) = query.build_where_clause(
    tenant_id,
    &["effect", "status", "name"],
).unwrap();
// where_clause = "tenant_id = $1 AND effect = $2"
// params = [tenant_id, "deny"]
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
- Never ignore DefaultDeny - it means no policy matched
- Never leak policy details in error messages to clients
- Never build SQL without parameterization - use SearchQuery

## Related Crates

- `xavyo-api-authorization` - REST API for policy management
- `xavyo-governance` - Entitlement definitions
- `xavyo-db` - Policy and entitlement storage
