# xavyo-api-governance

> IGA API: access requests, certification campaigns, SoD rules, compliance reporting, identity archetypes.

## Purpose

Provides REST endpoints for Identity Governance and Administration (IGA) operations. Includes access request workflows, certification campaigns, Separation of Duties (SoD) rule enforcement, entitlement management, compliance reporting, orphan account detection, and identity archetype management.

## Layer

api

## Status

🟢 **stable**

Production-ready with extensive test coverage (1076+ tests). 135K LOC comprehensive IGA platform with full workflow support. Includes F-193 lifecycle state machine extensions for transition conditions and state actions. Includes F-067 GDPR/Data Protection metadata on entitlements with classification filtering and compliance reporting.

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
pub fn archetypes_router() -> Router<GovState>;  // F-058 Identity Archetypes
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
| Archetypes | GET | `/archetypes` | List identity archetypes |
| Archetypes | POST | `/archetypes` | Create archetype |
| Archetypes | GET | `/archetypes/:id` | Get archetype |
| Archetypes | PUT | `/archetypes/:id` | Update archetype |
| Archetypes | DELETE | `/archetypes/:id` | Delete archetype |
| Archetypes | GET | `/archetypes/:id/ancestry` | Get archetype ancestry chain |
| Archetypes | GET | `/archetypes/:id/policies` | List policy bindings |
| Archetypes | POST | `/archetypes/:id/policies` | Bind policy to archetype |
| Archetypes | DELETE | `/archetypes/:id/policies/:type` | Unbind policy |
| Archetypes | GET | `/archetypes/:id/effective-policies` | Get effective policies |
| Archetypes | GET | `/users/:id/archetype` | Get user's archetype |
| Archetypes | PUT | `/users/:id/archetype` | Assign archetype to user |
| Archetypes | DELETE | `/users/:id/archetype` | Remove user's archetype |
| Archetypes | GET | `/archetypes/:id/lifecycle` | Get archetype lifecycle model (F-193) |
| Archetypes | PUT | `/archetypes/:id/lifecycle` | Assign lifecycle to archetype (F-193) |
| Archetypes | DELETE | `/archetypes/:id/lifecycle` | Remove lifecycle assignment (F-193) |
| Lifecycle | GET | `/lifecycle/configs/:id/transitions/:tid/conditions` | Get transition conditions (F-193) |
| Lifecycle | PUT | `/lifecycle/configs/:id/transitions/:tid/conditions` | Update transition conditions (F-193) |
| Lifecycle | POST | `/lifecycle/configs/:id/transitions/:tid/conditions/evaluate` | Evaluate conditions (F-193) |
| Lifecycle | GET | `/lifecycle/configs/:id/states/:sid/actions` | Get state entry/exit actions (F-193) |
| Lifecycle | PUT | `/lifecycle/configs/:id/states/:sid/actions` | Update state actions (F-193) |
| Lifecycle | GET | `/users/:id/lifecycle/status` | Get user lifecycle status (F-193) |
| Manual Tasks | GET | `/manual-tasks/audit` | List manual task audit events |
| NHI | GET | `/nhis` | Do not advertise `user_id` as a distinct linked user; `owner_id` is null when unassigned |
| Service Accounts | GET | `/service-accounts` | Do not advertise `user_id` as a distinct linked user; `owner_id` is null when unassigned |
| Identity Correlation | PUT | `/identity-correlation-rules/:id` | Persist advertised `attribute` and `match_type` |
| Connector Correlation | PUT | `/connectors/:id/correlation/rules/:id` | Persist advertised `match_type` |
| NHI Certification | POST | `/nhis/certification/campaigns` | Persist advertised owner/type filters |
| NHI Certification | POST | `/nhis/certification/campaigns/:id/launch` | Launch using stored create-time filters |
| NHI Usage | POST | `/nhis/:id/usage` | Return created usage event; look up `nhi_identities` |
| Personas | POST | `/personas` | Persist advertised `valid_from` / `valid_until` |
| Meta-roles | POST | `/meta-roles` | Persist advertised entitlements and constraints |
| Object Templates | POST | `/object-templates` | Persist advertised initial rules and scopes |
| GDPR | GET | `/gdpr/report` | Generate tenant GDPR compliance report (F-067) |
| GDPR | GET | `/gdpr/users/:user_id/data-protection` | Per-user data protection summary (F-067) |
| Context | POST | `/context/switch` | 501 until identity-switch JWT issuance exists |
| Context | POST | `/context/switch-back` | 501 until identity-switch JWT issuance exists |
| PoA | POST | `/power-of-attorney/:id/assume` | 501 until identity-switch JWT issuance exists |
| PoA | POST | `/power-of-attorney/drop` | 501 until identity-switch JWT issuance exists |

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
- Never extend a persona that requires approval on behalf of a non-owner until an approval workflow exists
- Never return a placeholder `access_token` for persona switch or PoA assume/drop (501 until signed JWT re-issuance is wired)
- Never return `Uuid::nil()` as merge-audit `operator_id` (load it from the merge operation)

## Related Crates

- `xavyo-governance` - Domain logic
- `xavyo-api-users` - User management
- `xavyo-authorization` - Policy enforcement
