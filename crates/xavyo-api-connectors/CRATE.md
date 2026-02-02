# xavyo-api-connectors

> Connector management API: configuration, sync operations, reconciliation.

## Purpose

Provides REST endpoints for managing identity connectors to external systems. Includes connector configuration, schema discovery, sync operations, reconciliation runs, and provisioning queue management.

## Layer

api

## Status

🟡 **beta**

Functional with adequate test coverage (69 tests). Has 6 TODOs; connector management working but some edge cases incomplete.

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId types
- `xavyo-db` - Connector models
- `xavyo-connector` - Connector framework
- `xavyo-provisioning` - Sync engine

### External (key)
- `axum` - Web framework
- `sqlx` - Database queries

## Public API

### Routers

```rust
pub fn connectors_router() -> Router<ConnectorsState>;
pub fn provisioning_router() -> Router<ConnectorsState>;
pub fn reconciliation_router() -> Router<ConnectorsState>;
```

### Key Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/connectors` | List connectors |
| POST | `/connectors` | Create connector |
| GET | `/connectors/:id` | Get connector |
| PATCH | `/connectors/:id` | Update connector |
| DELETE | `/connectors/:id` | Delete connector |
| POST | `/connectors/:id/test` | Test connection |
| GET | `/connectors/:id/schema` | Get schema |
| POST | `/connectors/:id/sync` | Trigger sync |
| GET | `/connectors/:id/sync/status` | Sync status |
| POST | `/reconciliation/runs` | Start reconciliation |
| GET | `/reconciliation/runs` | List runs |
| GET | `/reconciliation/runs/:id` | Run details |
| GET | `/provisioning/queue` | Queue stats |
| GET | `/provisioning/dlq` | Dead letter queue |

## Usage Example

```rust
use xavyo_api_connectors::{connectors_router, ConnectorsState};
use axum::Router;

let state = ConnectorsState::new(pool.clone(), connector_registry);

let app = Router::new()
    .nest("/connectors", connectors_router())
    .with_state(state);
```

## Integration Points

- **Consumed by**: `idp-api` main application
- **Uses**: `xavyo-connector` implementations
- **Uses**: `xavyo-provisioning` sync engine

## Feature Flags

None

## Anti-Patterns

- Never store credentials unencrypted
- Never skip schema validation for mappings
- Never ignore reconciliation discrepancies

## Related Crates

- `xavyo-connector` - Framework traits
- `xavyo-provisioning` - Sync engine
- `xavyo-connector-*` - Implementations
