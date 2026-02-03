# xavyo-api-authorization

> Authorization API: policies, entitlements, access decisions.

## Purpose

Provides REST endpoints for managing authorization policies and evaluating access decisions. Includes policy CRUD, entitlement-to-action mappings, and real-time policy evaluation via the Policy Decision Point (PDP).

## Layer

api

## Status

🟡 **beta**

Functional with comprehensive integration test coverage (60 tests). Policy CRUD operations fully tested (36 tests) including validation, authorization checks, tenant isolation, and edge cases. Authorization decision endpoints fully tested (24 tests) including single/batch decisions, caching, and tenant isolation. Ready for production use with monitoring.

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId types
- `xavyo-db` - Policy models
- `xavyo-authorization` - PDP engine

### External (key)
- `axum` - Web framework
- `sqlx` - Database queries

## Public API

### Routers

```rust
pub fn policies_router() -> Router<AuthzState>;
pub fn entitlements_router() -> Router<AuthzState>;
pub fn decisions_router() -> Router<AuthzState>;
```

### Key Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/policies` | List policies |
| POST | `/policies` | Create policy |
| GET | `/policies/:id` | Get policy |
| PATCH | `/policies/:id` | Update policy |
| DELETE | `/policies/:id` | Delete policy |
| GET | `/policies/:id/conditions` | List conditions |
| POST | `/policies/:id/conditions` | Add condition |
| GET | `/entitlement-mappings` | List mappings |
| POST | `/entitlement-mappings` | Create mapping |
| GET | `/authorization/can-i` | Single authorization decision |
| GET | `/admin/authorization/check` | Admin check on behalf of user |
| POST | `/admin/authorization/bulk-check` | Batch authorization (max 100) |

## Usage Example

```rust
use xavyo_api_authorization::{policies_router, decisions_router, AuthzState};
use axum::Router;

let state = AuthzState::new(pool.clone(), pdp);

let app = Router::new()
    .nest("/authz/policies", policies_router())
    .nest("/authz", decisions_router())
    .with_state(state);
```

## Integration Points

- **Consumed by**: `idp-api` main application
- **Uses**: `xavyo-authorization` PDP

## Feature Flags

- `integration` - Enable integration tests (requires test database)

## Anti-Patterns

- Never cache decisions longer than policy TTL
- Never bypass PDP for "admin" users
- Never expose policy internals in errors

## Related Crates

- `xavyo-authorization` - PDP engine
- `xavyo-governance` - Entitlements
