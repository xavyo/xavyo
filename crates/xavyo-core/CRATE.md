# xavyo-core

> Shared types and traits for xavyo: TenantId, UserId, XavyoError, TenantAware.

## Purpose

Provides foundational types used across all xavyo crates. This includes strongly-typed identifiers (TenantId, UserId, SessionId) that prevent accidental misuse at compile time, a standardized error type (XavyoError) that maps to HTTP status codes, and the TenantAware trait for multi-tenant entities.

## Layer

foundation

## Dependencies

### Internal (xavyo)
None (this is the root crate)

### External (key)
- `serde` - Serialization/deserialization
- `uuid` - UUID v4 generation
- `thiserror` - Error derive macros

## Public API

### Types

```rust
/// Strongly typed identifier for tenants (UUID v4 wrapper)
pub struct TenantId(Uuid);

/// Strongly typed identifier for users (UUID v4 wrapper)
pub struct UserId(Uuid);

/// Strongly typed identifier for sessions (UUID v4 wrapper)
pub struct SessionId(Uuid);

/// Standardized error type with HTTP status code mapping
pub enum XavyoError {
    Unauthorized { message: Option<String> },      // HTTP 401
    NotFound { resource: String, id: Option<String> }, // HTTP 404
    TenantMismatch { expected: TenantId, actual: TenantId }, // HTTP 403
    ValidationError { field: String, message: String }, // HTTP 400
}
```

### Traits

```rust
/// Marks an entity as belonging to a specific tenant
pub trait TenantAware {
    fn tenant_id(&self) -> TenantId;
}
```

### Functions

```rust
// ID types provide these methods:
impl TenantId {
    pub fn new() -> Self;                    // Create random UUID v4
    pub fn from_uuid(uuid: Uuid) -> Self;    // From existing UUID
    pub fn as_uuid(&self) -> &Uuid;          // Get underlying UUID
}

// Result type alias
pub type Result<T> = std::result::Result<T, XavyoError>;
```

## Usage Example

```rust
use xavyo_core::{TenantId, UserId, XavyoError, Result, TenantAware};

// Create strongly typed IDs
let tenant_id = TenantId::new();
let user_id = UserId::new();

// Parse from string
let tenant: TenantId = "550e8400-e29b-41d4-a716-446655440000".parse()?;

// Use in error handling
fn find_user(id: &str) -> Result<String> {
    if id.is_empty() {
        return Err(XavyoError::NotFound {
            resource: "User".to_string(),
            id: None,
        });
    }
    Ok(format!("User {}", id))
}

// Implement TenantAware for your types
struct Document {
    tenant_id: TenantId,
    title: String,
}

impl TenantAware for Document {
    fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}
```

## Integration Points

- **Consumed by**: Every other xavyo crate
- **Provides**: Type safety for tenant isolation throughout the platform

## Feature Flags

None - this crate has no optional features.

## Anti-Patterns

- Never use `Uuid` directly where `TenantId` or `UserId` is expected
- Never use `Uuid::nil()` as a placeholder for tenant IDs
- Never serialize XavyoError without the `type` discriminator field

## Related Crates

- `xavyo-db` - Uses these types for database models
- `xavyo-auth` - Uses TenantId in JWT claims
- `xavyo-tenant` - Extracts TenantId from HTTP requests
