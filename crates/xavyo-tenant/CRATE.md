# xavyo-tenant

> Tower/Axum middleware for multi-tenant context extraction and validation.

## Purpose

Extracts tenant identity from HTTP requests and makes it available to route handlers. Supports extraction from `X-Tenant-ID` header or JWT claims. Validates tenant ID format (UUID) and returns structured JSON errors for invalid/missing context. Designed as a composable Tower middleware.

## Layer

foundation

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId type

### External (key)
- `axum` - Web framework integration
- `tower` - Middleware composition
- `http` - HTTP types

## Public API

### Types

```rust
/// Tower Layer for tenant extraction
pub struct TenantLayer { ... }

/// Tower Service for tenant extraction
pub struct TenantService<S> { ... }

/// Configuration for tenant extraction behavior
pub struct TenantConfig {
    pub header_name: String,      // Default: "X-Tenant-ID"
    pub require_tenant: bool,     // Default: true
}

/// Builder for TenantConfig
pub struct TenantConfigBuilder { ... }

/// Extracted tenant context
pub struct TenantContext {
    pub tenant_id: TenantId,
    pub source: TenantSource, // Header or JWT
}

/// Error types for tenant extraction
pub enum TenantError {
    MissingTenant,
    InvalidTenantId { value: String },
}

/// Structured error response
pub struct ErrorResponse { ... }
```

### Functions

```rust
/// Extract tenant ID from request (for manual extraction)
pub fn extract_tenant_id(req: &Request) -> Result<TenantContext, TenantError>;
```

## Usage Example

```rust
use xavyo_tenant::TenantLayer;
use axum::{Router, Extension, routing::get};
use xavyo_core::TenantId;

// Handler receives TenantId via Extension
async fn list_users(
    Extension(tenant_id): Extension<TenantId>,
) -> String {
    format!("Users for tenant: {}", tenant_id)
}

// Apply middleware to router
let app = Router::new()
    .route("/api/users", get(list_users))
    .layer(TenantLayer::new());

// With custom configuration
use xavyo_tenant::TenantConfig;

let config = TenantConfig::builder()
    .header_name("X-Tenant-ID")
    .require_tenant(true)
    .build();

let app = Router::new()
    .route("/api/users", get(list_users))
    .layer(TenantLayer::with_config(config));
```

## Integration Points

- **Consumed by**: `idp-api` application
- **Provides**: `Extension<TenantId>` to downstream handlers
- **Works with**: `xavyo-db::set_tenant_context` for RLS

## Feature Flags

None - all features are enabled by default.

## Anti-Patterns

- Never access tenant-scoped data without applying this middleware
- Never trust client-provided tenant IDs without validation
- Never skip tenant validation for "internal" endpoints
- Never use string tenant IDs directly - always use TenantId type

## Related Crates

- `xavyo-core` - Provides TenantId type
- `xavyo-db` - `set_tenant_context` uses the extracted TenantId
- `xavyo-auth` - JWT claims can also provide tenant context
