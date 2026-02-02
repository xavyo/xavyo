# xavyo-api-import

> Bulk import API: CSV user import with validation.

## Purpose

Provides REST endpoints for bulk user import from CSV files. Includes file upload, validation preview, progress tracking, and error reporting for enterprise migration scenarios.

## Layer

api

## Status

🔴 **alpha**

Experimental with limited test coverage (22 tests). Basic import structure defined; not validated with production data.

## Dependencies

### Internal (xavyo)
- `xavyo-core` - TenantId types
- `xavyo-db` - User models
- `xavyo-webhooks` - Event publishing

### External (key)
- `axum` - Web framework
- `csv` - CSV parsing
- `sha2` - File checksums

## Public API

### Routers

```rust
pub fn import_router() -> Router<ImportState>;
```

### Key Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/import/users/upload` | Upload CSV |
| POST | `/import/users/validate` | Validate CSV |
| POST | `/import/users/execute` | Execute import |
| GET | `/import/jobs` | List jobs |
| GET | `/import/jobs/:id` | Job status |
| GET | `/import/jobs/:id/errors` | Job errors |

## Usage Example

```rust
use xavyo_api_import::{import_router, ImportState};
use axum::Router;

let state = ImportState::new(pool.clone());

let app = Router::new()
    .nest("/import", import_router())
    .with_state(state);
```

## Integration Points

- **Consumed by**: `idp-api` main application
- **Emits**: Webhooks for import completion

## Feature Flags

None

## Anti-Patterns

- Never import without validation preview
- Never skip duplicate detection
- Never import passwords in plaintext

## Related Crates

- `xavyo-api-users` - User CRUD
- `xavyo-api-scim` - Automated provisioning
