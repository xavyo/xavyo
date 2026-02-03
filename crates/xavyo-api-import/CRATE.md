# xavyo-api-import

> Bulk import API: CSV user import with validation.

## Purpose

Provides REST endpoints for bulk user import from CSV files. Includes file upload, validation preview, progress tracking, and error reporting for enterprise migration scenarios.

## Layer

api

## Status

🟢 **stable**

Production-ready with comprehensive test coverage (45+ integration tests, 47+ unit tests). Covers:
- Job lifecycle (pending/processing/completed/failed state transitions)
- Multi-tenant isolation (strict RLS enforcement)
- Error scenarios (invalid email, duplicates, missing fields, wrong delimiter)
- Large file performance (10k rows in <30 seconds)
- Concurrent import jobs (5+ simultaneous)
- Invitation workflow (create, validate, accept, expire)

F-021 enhancements include configurable delimiters, extended duplicate detection, column mapping, and streaming parser support.

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

### CSV Parsing Configuration (F-021)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| delimiter | string | `,` | Field delimiter: `,`, `;`, `\t`, `|` |
| column_mapping | JSON | null | Map source headers to target fields |
| duplicate_check_fields | string | `email` | Comma-separated: email, username, external_id |
| check_database_duplicates | bool | false | Check DB for existing records |

### Supported Delimiters

- **Comma** (`,`) - Default, standard CSV
- **Semicolon** (`;`) - Common in European exports
- **Tab** (`\t`) - TSV files
- **Pipe** (`|`) - Pipe-delimited files

### Column Mapping Example

```json
{
  "E-mail": "email",
  "Given Name": "first_name",
  "Surname": "last_name",
  "Employee ID": "external_id"
}
```

### Known Columns

email, first_name, last_name, display_name, roles, groups, department, is_active, username, external_id

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

| Flag | Description |
|------|-------------|
| `openapi` | Enable OpenAPI documentation generation |
| `integration` | Enable integration tests requiring PostgreSQL |

## Anti-Patterns

- Never import without validation preview
- Never skip duplicate detection
- Never import passwords in plaintext
- Never use wrong delimiter without detecting errors

## Related Crates

- `xavyo-api-users` - User CRUD
- `xavyo-api-scim` - Automated provisioning
