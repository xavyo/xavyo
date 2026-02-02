# xavyo-api-governance

> IGA API: access requests, certification campaigns, SoD rules, compliance reporting.

## Purpose

Provides REST endpoints for Identity Governance and Administration (IGA) operations. Includes access request workflows, certification campaigns, Separation of Duties (SoD) rule enforcement, entitlement management, compliance reporting, and orphan account detection.

## Layer

api

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId, UserId types
- `xavyo-db` - Governance models
- `xavyo-auth` - JWT validation
- `xavyo-governance` - Domain logic
- `xavyo-tenant` - Multi-tenant middleware

### External (key)
- `axum` - Web framework
- `sqlx` - Database queries
- `csv` - Report export

## Public API

### Routers

```rust
pub fn access_requests_router() -> Router<GovState>;
pub fn certifications_router() -> Router<GovState>;
pub fn sod_rules_router() -> Router<GovState>;
pub fn entitlements_router() -> Router<GovState>;
pub fn applications_router() -> Router<GovState>;
pub fn compliance_router() -> Router<GovState>;
pub fn risk_router() -> Router<GovState>;
```

### Key Endpoints

| Category | Method | Path | Description |
|----------|--------|------|-------------|
| Access Requests | POST | `/requests` | Submit access request |
| Access Requests | GET | `/requests` | List requests |
| Access Requests | POST | `/requests/:id/approve` | Approve request |
| Access Requests | POST | `/requests/:id/reject` | Reject request |
| Certifications | POST | `/campaigns` | Create campaign |
| Certifications | GET | `/campaigns` | List campaigns |
| Certifications | POST | `/campaigns/:id/items/:item_id/certify` | Certify item |
| Certifications | POST | `/campaigns/:id/items/:item_id/revoke` | Revoke item |
| SoD Rules | POST | `/sod/rules` | Create SoD rule |
| SoD Rules | GET | `/sod/violations` | List violations |
| Entitlements | GET | `/entitlements` | List entitlements |
| Entitlements | GET | `/users/:id/entitlements` | User's entitlements |
| Compliance | GET | `/reports` | List reports |
| Compliance | POST | `/reports/:id/generate` | Generate report |
| Risk | GET | `/risk/scores` | List risk scores |
| Risk | GET | `/risk/alerts` | List risk alerts |

## Usage Example

```rust
use xavyo_api_governance::{access_requests_router, certifications_router, GovState};
use axum::Router;

let gov_state = GovState::new(pool.clone());

let app = Router::new()
    .nest("/gov/requests", access_requests_router())
    .nest("/gov/campaigns", certifications_router())
    .with_state(gov_state);
```

## Integration Points

- **Consumed by**: `idp-api` main application
- **Uses**: `xavyo-governance` domain logic
- **Emits**: Webhooks for workflow events

## Feature Flags

| Flag | Description |
|------|-------------|
| `integration` | Enable integration tests |

## Anti-Patterns

- Never bypass approval workflows for privileged access
- Never skip SoD checks before granting entitlements
- Never allow campaign decisions without audit trail

## Related Crates

- `xavyo-governance` - Domain logic
- `xavyo-api-users` - User management
- `xavyo-authorization` - Policy enforcement
