# xavyo-api-users

> User management CRUD API: list, create, update, delete users and groups.

## Purpose

Provides administrative REST endpoints for user lifecycle management. Includes user CRUD operations, group management with hierarchy support, custom attribute definitions, and bulk operations for enterprise-scale identity management.

## Layer

api

## Status

🟡 **beta**

Functional with adequate test coverage (56 tests). Core CRUD operations complete; lacks integration tests.

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId, UserId types
- `xavyo-db` - User, Group models
- `xavyo-auth` - JWT validation
- `xavyo-webhooks` - Event publishing
- `xavyo-events` - Kafka events (optional)

### External (key)
- `axum` - Web framework
- `sqlx` - Database queries
- `uuid` - Identifier generation

## Public API

### Routers

```rust
/// User management router
pub fn users_router() -> Router<UsersState>;

/// Group management router
pub fn groups_router() -> Router<UsersState>;

/// Custom attribute definitions router
pub fn attribute_definitions_router() -> Router<UsersState>;

/// Bulk operations router
pub fn bulk_operations_router() -> Router<UsersState>;
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/users` | List users (paginated) |
| POST | `/users` | Create user |
| GET | `/users/:id` | Get user by ID |
| PATCH | `/users/:id` | Update user |
| DELETE | `/users/:id` | Delete user |
| POST | `/users/:id/disable` | Disable user |
| POST | `/users/:id/enable` | Enable user |
| GET | `/groups` | List groups |
| POST | `/groups` | Create group |
| GET | `/groups/:id` | Get group by ID |
| PATCH | `/groups/:id` | Update group |
| DELETE | `/groups/:id` | Delete group |
| GET | `/groups/:id/members` | List group members |
| POST | `/groups/:id/members` | Add group members |
| DELETE | `/groups/:id/members/:user_id` | Remove member |
| GET | `/attribute-definitions` | List attribute definitions |
| POST | `/attribute-definitions` | Create attribute definition |
| POST | `/bulk/users` | Bulk create/update users |

### Services

```rust
pub struct UserService {
    pub async fn list(&self, tenant_id: Uuid, query: ListUsersQuery) -> Result<UserListResponse>;
    pub async fn create(&self, tenant_id: Uuid, req: CreateUserRequest) -> Result<UserResponse>;
    pub async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<UserResponse>;
    pub async fn update(&self, tenant_id: Uuid, id: Uuid, req: UpdateUserRequest) -> Result<UserResponse>;
    pub async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<()>;
}

pub struct GroupHierarchyService { ... }
pub struct AttributeDefinitionService { ... }
pub struct AttributeValidationService { ... }
```

### Request/Response Types

```rust
pub struct CreateUserRequest {
    pub email: String,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub password: Option<String>,
    pub custom_attributes: Option<HashMap<String, Value>>,
}

pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub status: UserStatus,
    pub created_at: DateTime<Utc>,
    pub custom_attributes: HashMap<String, Value>,
}

pub struct ListUsersQuery {
    pub page: Option<u32>,
    pub page_size: Option<u32>,
    pub filter: Option<String>,
    pub sort_by: Option<String>,
}
```

## Usage Example

```rust
use xavyo_api_users::{users_router, groups_router, UsersState, UserService};
use axum::Router;

// Create state
let users_state = UsersState::new(pool.clone());

// Build application with user management routes
let app = Router::new()
    .nest("/admin/users", users_router())
    .nest("/admin/groups", groups_router())
    .with_state(users_state);

// Direct service usage
let user_service = UserService::new(pool.clone());
let users = user_service.list(tenant_id, ListUsersQuery {
    page: Some(1),
    page_size: Some(50),
    filter: Some("status eq 'active'".to_string()),
    sort_by: Some("created_at desc".to_string()),
}).await?;
```

## Integration Points

- **Consumed by**: `idp-api` main application
- **Emits**: Kafka events (`user.created`, `user.updated`, `user.deleted`)
- **Emits**: Webhooks for user lifecycle events

## Feature Flags

| Flag | Description | Dependencies Added |
|------|-------------|-------------------|
| `kafka` | Enable Kafka event publishing | xavyo-events |

## Anti-Patterns

- Never delete users without proper audit trail
- Never expose password hashes in responses
- Never allow bulk operations without rate limiting
- Never skip tenant_id validation in queries

## Related Crates

- `xavyo-api-scim` - SCIM provisioning (automated)
- `xavyo-api-import` - Bulk CSV import
- `xavyo-governance` - User assignments and certifications
