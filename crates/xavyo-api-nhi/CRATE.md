# xavyo-api-nhi

> Non-Human Identity API: unified service account and agent management.

## Purpose

Provides a unified REST API for managing all non-human identities (NHIs) including service accounts and AI agents. Consolidates lifecycle management, certification, risk scoring, and credential rotation for machine identities.

## Layer

api

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
pub fn nhi_router() -> Router<NhiState>;
pub fn service_accounts_router() -> Router<NhiState>;
```

### Key Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/nhi` | List all NHIs |
| GET | `/nhi/:id` | Get NHI by ID |
| GET | `/nhi/:id/risk` | Get risk score |
| POST | `/nhi/:id/certify` | Certify NHI |
| GET | `/service-accounts` | List service accounts |
| POST | `/service-accounts` | Create service account |
| PATCH | `/service-accounts/:id` | Update account |
| DELETE | `/service-accounts/:id` | Delete account |
| POST | `/service-accounts/:id/rotate` | Rotate credentials |
| POST | `/service-accounts/:id/suspend` | Suspend account |

## Usage Example

```rust
use xavyo_api_nhi::{nhi_router, NhiState};
use axum::Router;

let state = NhiState::new(pool.clone());

let app = Router::new()
    .nest("/nhi", nhi_router())
    .with_state(state);
```

## Integration Points

- **Consumed by**: `idp-api` main application
- **Integrates**: Service accounts and AI agents under one API

## Feature Flags

None

## Anti-Patterns

- Never create NHIs without owners
- Never skip risk scoring
- Never ignore credential rotation policies

## Related Crates

- `xavyo-nhi` - NHI types
- `xavyo-api-agents` - AI agent specifics
- `xavyo-governance` - NHI certification
