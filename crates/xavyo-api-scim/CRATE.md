# xavyo-api-scim

> SCIM 2.0 server implementation for automated user and group provisioning.

## Purpose

Implements the SCIM 2.0 protocol (RFC 7643/7644) for inbound provisioning from enterprise identity providers like Okta, Azure AD, and OneLogin. Handles user and group CRUD operations, SCIM filter parsing, bearer token authentication, and audit logging.

## Layer

api

## Status

🟢 **stable**

Production-ready with comprehensive test coverage (381 tests). RFC 7644 compliant with full protocol compliance test suite and IdP interoperability tests for Okta, Azure AD, and OneLogin.

### Test Coverage

| Test Suite | Count | Description |
|------------|-------|-------------|
| Unit tests | 45 | Core service tests |
| Protocol compliance | 156 | RFC 7644 compliance (filter, PATCH, error, ETag, bulk) |
| IdP interoperability | 120 | Okta, Azure AD, OneLogin mock clients |
| Quirks validation | 60 | Mock client accuracy validation |

### IdP Compatibility

| IdP | Status | Quirks Documented |
|-----|--------|-------------------|
| Okta | ✅ Tested | 5 quirks (OKTA-001 to OKTA-005) |
| Azure AD | ✅ Tested | 6 quirks (AAD-001 to AAD-006) |
| OneLogin | ✅ Tested | 5 quirks (OL-001 to OL-005) |

See `docs/scim-idp-quirks.md` for detailed quirk documentation.

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId, UserId types
- `xavyo-db` - User, Group models
- `xavyo-tenant` - Multi-tenant middleware
- `xavyo-auth` - Bearer token validation
- `xavyo-webhooks` - Event publishing

### External (key)
- `axum` - Web framework
- `sqlx` - Database queries
- `sha2` - Token hashing
- `rand` - Token generation

## Public API

### Routers

```rust
/// Main SCIM 2.0 router
pub fn scim_router() -> Router<ScimState>;

/// Admin router for SCIM configuration
pub fn scim_admin_router() -> Router<ScimState>;

/// Resource operations router
pub fn scim_resource_router() -> Router<ScimState>;
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/scim/v2/Users` | List users |
| POST | `/scim/v2/Users` | Create user |
| GET | `/scim/v2/Users/:id` | Get user |
| PUT | `/scim/v2/Users/:id` | Replace user |
| PATCH | `/scim/v2/Users/:id` | Update user |
| DELETE | `/scim/v2/Users/:id` | Delete user |
| GET | `/scim/v2/Groups` | List groups |
| POST | `/scim/v2/Groups` | Create group |
| GET | `/scim/v2/Groups/:id` | Get group |
| PUT | `/scim/v2/Groups/:id` | Replace group |
| PATCH | `/scim/v2/Groups/:id` | Update group (membership) |
| DELETE | `/scim/v2/Groups/:id` | Delete group |
| GET | `/scim/v2/ServiceProviderConfig` | SCIM capabilities |
| GET | `/scim/v2/Schemas` | Schema definitions |
| GET | `/scim/v2/ResourceTypes` | Resource type definitions |

### Types

```rust
/// SCIM configuration
pub struct ScimConfig {
    pub tenant_id: Uuid,
    pub bearer_token_hash: String,
    pub rate_limit_per_second: u32,
}

/// SCIM User resource
pub struct ScimUser {
    pub schemas: Vec<String>,
    pub id: Option<String>,
    pub external_id: Option<String>,
    pub user_name: String,
    pub name: Option<ScimName>,
    pub emails: Vec<ScimEmail>,
    pub active: Option<bool>,
    pub meta: Option<ScimMeta>,
}

/// SCIM Group resource
pub struct ScimGroup {
    pub schemas: Vec<String>,
    pub id: Option<String>,
    pub external_id: Option<String>,
    pub display_name: String,
    pub members: Vec<ScimMember>,
    pub meta: Option<ScimMeta>,
}

/// SCIM List response
pub struct ScimListResponse<T> {
    pub schemas: Vec<String>,
    pub total_results: i64,
    pub items_per_page: i64,
    pub start_index: i64,
    pub resources: Vec<T>,
}
```

## Usage Example

```rust
use xavyo_api_scim::{scim_router, ScimConfig};
use axum::Router;

// SCIM routes are typically mounted under /scim/v2
let app = Router::new()
    .nest("/scim/v2", scim_router())
    .with_state(scim_state);

// SCIM filter examples:
// GET /scim/v2/Users?filter=userName eq "john@example.com"
// GET /scim/v2/Users?filter=emails.value co "@example.com"
// GET /scim/v2/Groups?filter=displayName sw "Engineering"

// SCIM PATCH for group membership:
// PATCH /scim/v2/Groups/{id}
// {
//   "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
//   "Operations": [
//     {"op": "add", "path": "members", "value": [{"value": "user-id"}]}
//   ]
// }
```

## Integration Points

- **Consumed by**: `idp-api` main application
- **Receives from**: Okta, Azure AD, OneLogin, other SCIM clients
- **Emits**: Webhooks for provisioning events

## Feature Flags

None - all features are enabled by default.

## Anti-Patterns

- Never expose bearer tokens in logs or responses
- Never skip filter validation (SQL injection risk)
- Never allow unauthenticated SCIM access
- Never ignore rate limits (DoS protection)

## Related Crates

- `xavyo-scim-client` - Outbound SCIM (to other systems)
- `xavyo-api-users` - Manual user management
- `xavyo-provisioning` - Internal provisioning queue
