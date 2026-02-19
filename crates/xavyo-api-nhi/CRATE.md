# xavyo-api-nhi

> Non-Human Identity API: unified service account and agent management.

## Purpose

Provides a unified REST API for managing all non-human identities (NHIs) including service accounts and AI agents. Consolidates lifecycle management, certification, risk scoring, and credential rotation for machine identities.

## Layer

api

## Status

🟢 **stable**

Production-ready with comprehensive test coverage (55 unit tests + 22 integration tests). Unified NHI API with complete risk scoring, staleness detection, certification workflows, and multi-tenant isolation.

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId types
- `xavyo-db` - NHI models
- `xavyo-nhi` - NHI types and traits
- `xavyo-governance` - Certification integration

### External (key)
- `axum` - Web framework
- `sqlx` - Database queries

## Public API

### Routers

```rust
pub fn nhi_router() -> Router<NhiState>;       // Unified NHI CRUD, lifecycle, permissions, risk, certs
pub fn mcp_router(state: NhiState) -> Router;   // MCP protocol (tool listing + invocation)
pub fn a2a_router(state: NhiState) -> Router;   // A2A protocol (agent-to-agent task management)
pub fn discovery_router(state: NhiState) -> Router; // Agent discovery (/.well-known/agents/:id)
```

### Key Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/nhi` | List all NHIs |
| GET | `/nhi/:id` | Get NHI by ID |
| GET | `/nhi/:id/risk` | Get risk score |
| POST | `/nhi/:id/certify` | Certify NHI |
| GET | `/nhi/agents` | List agents |
| GET | `/nhi/tools` | List tools |
| GET | `/nhi/service-accounts` | List service accounts |
| GET | `/mcp/tools` | List permitted MCP tools for calling agent |
| POST | `/mcp/tools/:name/call` | Invoke an MCP tool |
| POST | `/a2a/tasks` | Create A2A task (with NHI-to-NHI permission check) |
| GET | `/a2a/tasks` | List A2A tasks |
| GET | `/a2a/tasks/:id` | Get A2A task |
| POST | `/a2a/tasks/:id/cancel` | Cancel A2A task |
| GET | `/.well-known/agents/:id` | Get agent discovery card |

## Usage Example

```rust
use xavyo_api_nhi::{nhi_router, mcp_router, a2a_router, discovery_router, NhiState};
use axum::Router;

let state = NhiState::new(pool.clone());

let app = Router::new()
    .nest("/nhi", nhi_router())
    .nest("/mcp", mcp_router(state.clone()))
    .nest("/a2a", a2a_router(state.clone()))
    .merge(discovery_router(state))
    ;
```

## Integration Points

- **Consumed by**: `idp-api` main application
- **Integrates**: Service accounts and AI agents under one API

## Feature Flags

None

## Testing

### Integration Tests (F-047)

The crate includes 22 integration tests organized by user story:

| Test File | Description | Tests |
|-----------|-------------|-------|
| `service_account_tests.rs` | Service account lifecycle (CRUD, suspend, reactivate) | 6 |
| `credential_tests.rs` | Credential rotation and revocation | 4 |
| `unified_list_tests.rs` | Unified NHI listing with filters and pagination | 4 |
| `governance_tests.rs` | Risk scoring and certification | 4 |
| `tenant_isolation_tests.rs` | Multi-tenant data isolation | 4 |

Run integration tests:
```bash
cargo test -p xavyo-api-nhi --test integration_tests
```

## Risk Scoring (F-048)

The crate implements comprehensive risk scoring for NHIs:

### Risk Factors (0-100 scale)
| Factor | Weight | Low | Medium | High |
|--------|--------|-----|--------|------|
| Staleness | 0-40 pts | <30 days | 30-89 days | ≥90 days |
| Credential Age | 0-30 pts | <30 days | 30-89 days | ≥90 days |
| Access Scope | 0-30 pts | <20 entitlements | 20-49 | ≥50 |

### Risk Levels
| Score Range | Level | Action |
|-------------|-------|--------|
| 0-25 | Low | No action needed |
| 26-50 | Medium | Monitor |
| 51-75 | High | Recommend remediation |
| 76-100 | Critical | Immediate action |

### Features
- **Staleness Detection**: Identifies inactive NHIs via `GET /nhi/staleness-report`
- **Risk Summary**: Aggregated statistics via `GET /nhi/risk-summary`
- **Per-NHI Risk**: Individual scores via `GET /nhi/:id/risk`

## Anti-Patterns

- Never create NHIs without owners
- Never skip risk scoring
- Never ignore risk scoring policies

## Related Crates

- `xavyo-nhi` - NHI types
- `xavyo-governance` - NHI certification
