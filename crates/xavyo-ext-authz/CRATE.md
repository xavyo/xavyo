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

## Integration Points

- **Consumed by**: AgentGateway (via Envoy ext_authz v3 gRPC protocol)
- **Depends on**: xavyo-authorization PDP, xavyo-db NHI models
- **Provides**: Authorization decisions with rich NHI dynamic_metadata

## Feature Flags

| Flag | Description | Dependencies Added |
|------|-------------|-------------------|
| `integration` | Enable integration tests | - |

## Anti-Patterns

- Never bypass the NHI lifecycle check — suspended agents MUST be denied
- Never cache authorization decisions — only cache NHI identity data
- Never expose internal error details in deny responses to clients
- Never use fail_open in production without monitoring

## Related Crates

- `xavyo-authorization` — Policy Decision Point engine
- `xavyo-nhi` — NHI type definitions
- `xavyo-db` — Database models for NHI identities
