# xavyo-db

> PostgreSQL database layer with multi-tenant Row-Level Security (RLS) support.

## Purpose

Provides the data access layer for xavyo with built-in multi-tenant isolation. Uses SQLx for compile-time checked queries and PostgreSQL Row-Level Security to enforce tenant boundaries at the database level. Includes connection pooling, migrations, and all domain models.

## Layer

foundation

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId, UserId types
- `xavyo-nhi` - Non-human identity types

### External (key)
- `sqlx` - Compile-time checked PostgreSQL queries
- `tokio` - Async runtime
- `chrono` - Timestamps
- `serde` - Model serialization

## Public API

### Types

```rust
/// PostgreSQL connection pool
pub struct DbPool(PgPool);

/// Pool configuration options
pub struct DbPoolOptions { ... }

/// Tenant-scoped connection wrapper
pub struct TenantConnection<'a> { ... }

/// Database errors
pub enum DbError { ... }

// 700+ domain models exported, including:
pub struct User { ... }
pub struct Tenant { ... }
pub struct OAuth2Client { ... }
pub struct Session { ... }
pub struct GovAccessRequest { ... }
// ... (see lib.rs for full list)
```

### Functions

```rust
/// Connect to database and create pool
impl DbPool {
    pub async fn connect(url: &str) -> Result<Self, DbError>;
    pub async fn connect_with_options(url: &str, options: DbPoolOptions) -> Result<Self, DbError>;
}

/// Run database migrations
pub async fn run_migrations(pool: &DbPool) -> Result<(), DbError>;

/// Set tenant context for RLS (MUST be called before queries)
pub async fn set_tenant_context(conn: &mut PgConnection, tenant_id: TenantId) -> Result<(), DbError>;

/// Clear tenant context
pub async fn clear_tenant_context(conn: &mut PgConnection) -> Result<(), DbError>;

/// Get current tenant from connection
pub async fn get_current_tenant(conn: &mut PgConnection) -> Result<Option<Uuid>, DbError>;

/// Bootstrap system tenant and CLI client
pub async fn run_bootstrap(pool: &DbPool) -> BootstrapResult;
```

## Usage Example

```rust
use xavyo_db::{DbPool, run_migrations, set_tenant_context};
use xavyo_core::TenantId;

// Connect to database
let pool = DbPool::connect(&std::env::var("DATABASE_URL")?).await?;

// Run migrations on startup
run_migrations(&pool).await?;

// In request handler - set tenant context for RLS
let tenant_id = TenantId::from_uuid(claims.tid);
let mut tx = pool.begin().await?;
set_tenant_context(&mut *tx, tenant_id).await?;

// All queries now automatically filtered by tenant
let users = sqlx::query_as!(User, "SELECT * FROM users")
    .fetch_all(&mut *tx)
    .await?;
// RLS ensures only this tenant's users are returned

tx.commit().await?;
```

## Integration Points

- **Consumed by**: All API crates, domain crates
- **Requires**: PostgreSQL 15+ with RLS enabled
- **Environment**: `DATABASE_URL` connection string

## Feature Flags

| Flag | Description | Dependencies Added |
|------|-------------|-------------------|
| `integration` | Enable integration tests | - |
| `openapi` | Generate OpenAPI schemas | utoipa |
| `argon2` | Enable password hashing | argon2 |

## Anti-Patterns

- Never query tenant-scoped tables without calling `set_tenant_context` first
- Never use `SELECT *` without `WHERE tenant_id = $1` as fallback
- Never use raw SQL for JOINs without tenant filters on both sides
- Never commit transactions without proper error handling
- Never store `TenantConnection` across await points

## Related Crates

- `xavyo-tenant` - Middleware that extracts tenant context
- `xavyo-core` - TenantId and UserId types
- `xavyo-governance` - Uses governance models from this crate
