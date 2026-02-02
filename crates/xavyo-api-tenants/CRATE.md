# xavyo-api-tenants

> Tenant management API: provisioning, configuration, API keys.

## Purpose

Provides REST endpoints for tenant lifecycle management. Includes tenant provisioning, configuration settings, policy management, API key generation, and tenant-level branding.

## Layer

api

## Status

🟢 **stable**

Production-ready with comprehensive test coverage (121 tests). Multi-tenant bootstrap and management complete.

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId types
- `xavyo-db` - Tenant models
- `xavyo-auth` - JWT validation

### External (key)
- `axum` - Web framework
- `sqlx` - Database queries
- `sha2` - API key hashing

## Public API

### Routers

```rust
pub fn tenants_router() -> Router<TenantsState>;
pub fn api_keys_router() -> Router<TenantsState>;
```

### Key Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/tenants` | List tenants (super admin) |
| POST | `/tenants` | Create tenant |
| GET | `/tenants/:id` | Get tenant |
| PATCH | `/tenants/:id` | Update tenant |
| DELETE | `/tenants/:id` | Delete tenant |
| GET | `/tenants/:id/settings` | Get settings |
| PATCH | `/tenants/:id/settings` | Update settings |
| GET | `/tenants/:id/api-keys` | List API keys |
| POST | `/tenants/:id/api-keys` | Create API key |
| DELETE | `/tenants/:id/api-keys/:key_id` | Revoke key |
| POST | `/tenants/:id/api-keys/:key_id/rotate` | Rotate key |

## Usage Example

```rust
use xavyo_api_tenants::{tenants_router, api_keys_router, TenantsState};
use axum::Router;

let state = TenantsState::new(pool.clone());

let app = Router::new()
    .nest("/tenants", tenants_router())
    .with_state(state);
```

## Integration Points

- **Consumed by**: `idp-api` main application
- **Provides**: Tenant context for all other APIs

## Feature Flags

None

## Anti-Patterns

- Never expose API key secrets after creation
- Never allow cross-tenant access
- Never delete tenants without proper cleanup

## Related Crates

- `xavyo-tenant` - Middleware
- `xavyo-db` - Tenant models
