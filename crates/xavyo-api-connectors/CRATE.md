# xavyo-api-connectors

> Connector management API: configuration, sync operations, reconciliation, job tracking.

## Purpose

Provides REST endpoints for managing identity connectors to external systems. Includes connector configuration, schema discovery, sync operations, reconciliation runs, provisioning queue management, and background job tracking with DLQ management.

## Layer

api

## Status

🟢 **stable**

Production-ready with comprehensive test coverage (157+ tests). Full connector management, reconciliation, and background job tracking (F-044).

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
| POST | `/connectors/:id/reconciliation/discrepancies/:id/remediate` | 501 until connector-side remediation exists |
| POST | `/connectors/:id/reconciliation/discrepancies/bulk-remediate` | 501 until connector-side remediation exists |
| GET | `/provisioning/queue` | Queue stats |
| GET | `/provisioning/dlq` | Dead letter queue |
| GET | `/jobs` | List background jobs (F-044) |
| GET | `/jobs/:id` | Get job details with attempts |
| POST | `/jobs/:id/cancel` | Cancel pending/running job |
| GET | `/dlq` | List dead letter queue entries |
| POST | `/dlq/:id/replay` | Replay single DLQ entry |
| POST | `/dlq/replay` | Bulk replay DLQ entries |

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
- Never mark a discrepancy resolved or record remediation `success` without executing the connector action (501 until wired)
- Never return HTTP success for sync config enable/disable/update without persisting to `gov_sync_configurations`
- Never look up a connector by id without `tenant_id` from the JWT
- Never return HTTP 200 for trigger/retry/link/list inbound sync until execution is wired (501)
- Never persist `Uuid::nil()` as `resolved_by` when ignoring a discrepancy

## Related Crates

- `xavyo-connector` - Framework traits
- `xavyo-provisioning` - Sync engine
- `xavyo-connector-*` - Implementations
