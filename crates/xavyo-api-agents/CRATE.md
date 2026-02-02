# xavyo-api-agents

> AI agent security API: registration, tool authorization, audit, MCP/A2A protocol.

## Purpose

Implements OWASP ASI (AI Security Initiative) guidelines for AI agent management. Provides agent registration, tool authorization with JSON Schema validation, real-time authorization decisions (<100ms), comprehensive audit logging, dynamic secrets provisioning, workload identity federation, and MCP/A2A protocol support.

## Layer

api

## Status

🟢 **stable**

Production-ready with comprehensive test coverage (335 tests). Complete AI agent security platform with MCP/A2A, HITL, and PKI support.

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId, UserId types
- `xavyo-auth` - JWT validation
- `xavyo-db` - Agent and tool models
- `xavyo-tenant` - Multi-tenant middleware
- `xavyo-nhi` - Non-human identity types
- `xavyo-events` - Kafka events (optional)
- `xavyo-secrets` - Dynamic credential provisioning

### External (key)
- `axum` - Web framework
- `jsonschema` - Parameter validation
- `reqwest` - Webhook delivery
- `rcgen` - Certificate generation
- `aws-sdk-sts` - AWS federation (optional)

## Public API

### Routers

```rust
/// Main agent management router
pub fn agents_router() -> Router<AgentsState>;

/// A2A protocol router
pub fn a2a_router() -> Router<AgentsState>;

/// MCP (Model Context Protocol) router
pub fn mcp_router() -> Router<AgentsState>;

/// Discovery router
pub fn discovery_router() -> Router<AgentsState>;
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/agents` | Register agent |
| GET | `/agents` | List agents |
| GET | `/agents/:id` | Get agent |
| PATCH | `/agents/:id` | Update agent |
| DELETE | `/agents/:id` | Delete agent |
| POST | `/agents/:id/suspend` | Suspend agent |
| POST | `/agents/:id/reactivate` | Reactivate agent |
| POST | `/tools` | Register tool |
| GET | `/tools` | List tools |
| GET | `/tools/:id` | Get tool |
| PATCH | `/tools/:id` | Update tool |
| DELETE | `/tools/:id` | Delete tool |
| POST | `/agents/:id/permissions` | Grant permission |
| DELETE | `/agents/:id/permissions/:tool_id` | Revoke permission |
| POST | `/authorize` | Real-time authorization |
| GET | `/audit` | Query audit trail |
| GET | `/.well-known/agents/:id.json` | AgentCard discovery |
| POST | `/mcp/tasks` | Create MCP task |
| GET | `/mcp/tasks/:id` | Get MCP task status |
| POST | `/credentials/request` | Request dynamic credential |
| GET | `/identity/token` | Get workload identity token |
| POST | `/certificates/issue` | Issue agent certificate |

### Types

```rust
/// Agents state container
pub struct AgentsState {
    pub pool: PgPool,
    pub secret_provider: Arc<dyn SecretProvider>,
}

/// Agent registration
pub struct CreateAgentRequest {
    pub name: String,
    pub description: Option<String>,
    pub agent_type: AgentType,
    pub owner_id: Uuid,
    pub allowed_tools: Vec<Uuid>,
}

/// Tool registration
pub struct CreateToolRequest {
    pub name: String,
    pub description: String,
    pub endpoint: String,
    pub parameters_schema: Value,  // JSON Schema
    pub risk_level: RiskLevel,
}

/// Authorization request (<100ms SLA)
pub struct AuthorizeRequest {
    pub agent_id: Uuid,
    pub tool_id: Uuid,
    pub parameters: Value,
    pub context: AuthorizationContext,
}

/// Authorization response
pub struct AuthorizeResponse {
    pub allowed: bool,
    pub reason: Option<String>,
    pub audit_id: Uuid,
}

/// AgentCard (A2A protocol)
pub struct AgentCard {
    pub id: Uuid,
    pub name: String,
    pub capabilities: Vec<String>,
    pub endpoints: AgentEndpoints,
    pub public_key: Option<String>,
}

/// Dynamic credential request
pub struct CredentialRequest {
    pub agent_id: Uuid,
    pub secret_type: String,
    pub scope: String,
    pub ttl_seconds: u32,
}
```

## Usage Example

```rust
use xavyo_api_agents::{agents_router, discovery_router, AgentsState};
use axum::Router;

// Create state
let agents_state = AgentsState::new(pool.clone(), secret_provider);

// Build application
let app = Router::new()
    .nest("/api/v1/agents", agents_router())
    .merge(discovery_router())
    .with_state(agents_state);

// Agent lifecycle:
// 1. Register agent: POST /api/v1/agents
// 2. Register tools: POST /api/v1/agents/tools
// 3. Grant permissions: POST /api/v1/agents/:id/permissions
// 4. Agent requests authorization: POST /api/v1/agents/authorize
// 5. Agent executes tool (if authorized)
// 6. Audit trail recorded automatically

// Dynamic secrets:
// 1. Agent requests credential: POST /api/v1/agents/credentials/request
// 2. System provisions short-lived credential
// 3. Agent uses credential for external service
// 4. Credential auto-expires after TTL
```

## Integration Points

- **Consumed by**: `idp-api` main application, AI orchestrators
- **Provides**: AgentCard at `/.well-known/agents/:id.json`
- **Integrates with**: HashiCorp Vault, AWS STS, OpenBao

## Feature Flags

| Flag | Description | Dependencies Added |
|------|-------------|-------------------|
| `openapi` | OpenAPI documentation | utoipa |
| `kafka` | Kafka event publishing | xavyo-events |
| `aws-federation` | AWS STS assume role | aws-sdk-sts |

## Anti-Patterns

- Never skip parameter validation against JSON Schema
- Never allow agents without assigned owners
- Never grant broad permissions (least privilege)
- Never ignore audit trail for compliance

## Related Crates

- `xavyo-nhi` - Non-human identity types
- `xavyo-governance` - NHI certification campaigns
- `xavyo-secrets` - Dynamic credential providers
