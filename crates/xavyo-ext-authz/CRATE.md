# xavyo-ext-authz

> Envoy ext_authz v3 gRPC server for AgentGateway ↔ Xavyo-IDP integration.

## Purpose

Implements the `envoy.service.auth.v3.Authorization/Check` gRPC service, allowing AgentGateway to delegate all authorization decisions to Xavyo-IDP at runtime. No code changes to AgentGateway are required — only YAML/CEL configuration.

Key features:
- **JWT claim extraction**: From metadata_context or Authorization header
- **NHI lifecycle checks**: Only active identities are allowed
- **Risk score enforcement**: Configurable threshold with deny above
- **PDP authorization**: Full ABAC policy evaluation via xavyo-authorization
- **Tool permission resolution**: Populates `allowed_tools` for MCP RBAC
- **Dynamic metadata**: Rich NHI context for CEL policies in AgentGateway
- **Activity tracking**: Async batched updates for last_activity_at
- **In-memory caching**: Moka cache for NHI lookups with configurable TTL

## Layer

domain

## Status

🟡 **beta**

Core implementation complete with comprehensive unit tests. Requires integration tests with a real PostgreSQL database and end-to-end testing with AgentGateway for stable promotion.

## Dependencies

### Internal (xavyo)
- `xavyo-core` — TenantId type-safe identifiers
- `xavyo-db` — NHI database models (NhiIdentity, NhiAgent, NhiToolPermission, GovNhiRiskScore)
- `xavyo-nhi` — NHI types (NhiType, NhiLifecycleState, NhiRiskLevel)
- `xavyo-authorization` — PolicyDecisionPoint, PolicyCache, MappingCache

### External (key)
- `tonic` 0.12 — gRPC server framework
- `tonic-health` 0.12 — gRPC health check service
- `prost` 0.13, `prost-types` 0.13 — Protobuf serialization
- `moka` 0.12 — Async in-memory cache
- `sqlx` 0.8 — PostgreSQL database access
- `base64` 0.22 — JWT payload decoding

## Public API

### Types

```rust
/// Parsed authorization context from CheckRequest.
pub struct AuthzContext {
    pub subject_id: Uuid,
    pub tenant_id: TenantId,
    pub roles: Vec<String>,
    pub method: String,
    pub path: String,
    pub action: String,
    pub resource_type: String,
}

/// Metadata for ALLOW responses.
pub struct AllowMetadata {
    pub nhi_id: Uuid,
    pub nhi_type: String,
    pub tenant_id: TenantId,
    pub risk_score: i32,
    pub risk_level: String,
    pub allowed_tools: Vec<String>,
    // ... and more
}

/// Configuration loaded from environment variables.
pub struct ExtAuthzConfig {
    pub listen_addr: SocketAddr,
    pub database_url: String,
    pub fail_open: bool,
    pub risk_score_deny_threshold: i32,
    pub nhi_cache_ttl_secs: u64,
    pub activity_flush_interval_secs: u64,
}
```

### Services

```rust
/// The ext_authz gRPC service.
pub struct ExtAuthzService;

impl ExtAuthzService {
    pub fn new(pool, config, policy_cache, mapping_cache) -> Self;
}

// Implements envoy.service.auth.v3.Authorization/Check
impl Authorization for ExtAuthzService {
    async fn check(&self, request) -> Result<Response<CheckResponse>, Status>;
}
```

## Usage Example

```yaml
# AgentGateway configuration (YAML only, no code changes)
extAuthz:
  host: xavyo-ext-authz:50051
  protocol:
    grpc: {}
  timeout: 500ms
  failureMode: deny

# CEL policies using dynamic_metadata from ext_authz
authorization:
  - action: Deny
    policy:
      matchExpressions:
        - 'extauthz.risk_level == "critical"'
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | (required) | PostgreSQL connection string |
| `EXT_AUTHZ_LISTEN_ADDR` | `0.0.0.0:50051` | gRPC listen address |
| `FAIL_OPEN` | `false` | Allow requests on internal errors |
| `RISK_SCORE_DENY_THRESHOLD` | `75` | Deny above this risk score |
| `NHI_CACHE_TTL_SECS` | `60` | NHI cache TTL in seconds |
| `ACTIVITY_FLUSH_INTERVAL_SECS` | `30` | Activity batch flush interval |
| `REQUIRE_METADATA_CONTEXT` | `false` | Reject requests without trusted metadata_context |

## Integration Points

- **Consumed by**: AgentGateway (via Envoy ext_authz v3 gRPC protocol)
- **Depends on**: xavyo-authorization PDP, xavyo-db NHI models
- **Provides**: Authorization decisions with rich NHI dynamic_metadata

## Feature Flags

| Flag | Description | Dependencies Added |
|------|-------------|-------------------|
| `integration` | Enable integration tests | - |

## Security

### Trust Boundary Assumptions

This service assumes it runs **behind AgentGateway** (or an Envoy proxy) that validates JWT signatures before calling ext_authz. The primary JWT extraction path reads pre-validated claims from `metadata_context` (set by Envoy's `jwt_authn` filter). A fallback path decodes the JWT payload from the Authorization header **without signature verification** — it exists for flexibility but logs a warning when used.

**For production deployments**, set `REQUIRE_METADATA_CONTEXT=true` to reject requests that lack trusted `metadata_context`, eliminating the unverified fallback path entirely.

### Multi-Tenant Isolation

- **Cache keys** include `(TenantId, Uuid)` — no cross-tenant data leakage
- **All DB queries** include `WHERE tenant_id = $1` — enforced at the SQL level
- **PDP evaluation** loads policies and entitlements scoped to the request tenant
- **Activity tracking** is keyed by `(TenantId, NhiId)`

### Deny Response Sanitization

Client-facing deny responses use generic messages (`"access denied"`, `"authentication required"`, `"internal error"`) to prevent leaking NHI UUIDs, risk scores, lifecycle states, or policy reasons. Detailed error context is logged server-side with `tracing::warn!`.

### Fail-Open Behavior

When `FAIL_OPEN=true` and a database/internal error occurs:
- The response includes **minimal metadata**: `tenant_id`, `nhi_id` (from the JWT), empty `allowed_tools`, and `fail_open: true`
- Downstream CEL policies can detect fail-open via `extauthz.fail_open == true`
- If JWT parsing itself fails, fail-open is **not applied** (no tenant context available)
- **Recommendation**: never enable in production without alerting on the `fail_open` flag

### Dynamic Metadata Exposure

ALLOW responses include NHI metadata (`risk_score`, `risk_level`, `model_provider`, etc.) in `dynamic_metadata` for use in AgentGateway CEL policies. This data should be treated as internal — ensure AgentGateway does not expose it to end clients via response headers or logs.

## Anti-Patterns

- Never bypass the NHI lifecycle check — suspended agents MUST be denied
- Never cache authorization decisions — only cache NHI identity data
- Never expose internal error details in deny responses to clients
- Never use fail_open in production without monitoring
- Never deploy without upstream JWT signature validation

## Related Crates

- `xavyo-authorization` — Policy Decision Point engine
- `xavyo-nhi` — NHI type definitions
- `xavyo-db` — Database models for NHI identities
