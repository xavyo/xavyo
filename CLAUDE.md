# xavyo-idp Development Guidelines

## Quick Reference

- **Docs**: `llms.txt` (index), `llms-full.txt` (complete), `docs/crates/index.md`
- **Per-crate**: `crates/<name>/CRATE.md`

## Tech Stack

- **Rust 1.75+** with Axum + Tower + SQLx (compile-time checked)
- **PostgreSQL 15+** with RLS for tenant isolation
- **Core crates**: xavyo-core, xavyo-auth, xavyo-db, xavyo-tenant

## Commands

```bash
# Verify code
cargo check -p <crate>
cargo test -p <crate>
cargo clippy -p <crate> -- -D warnings
cargo fmt --check

# Run all tests
cargo test --workspace
```

## Critical Rules

### 1. API-Only (NO UI)

- All features exposed as REST APIs only
- **NEVER** create React/frontend code
- `apps/idp-web/` and `packages/ui/` are FROZEN

### 2. Multi-Tenancy (MANDATORY)

Every data access MUST be tenant-isolated. Violations = security breach.

**Handler pattern:**
```rust
pub async fn handler(Extension(claims): Extension<JwtClaims>) -> Result<...> {
    let tenant_id = claims.tenant_id().map(|t| *t.as_uuid())
        .ok_or_else(|| /* error */)?;
    // Use tenant_id in ALL DB calls
}
```

**SQL rules:**
```sql
-- ALWAYS include tenant_id
SELECT * FROM resources WHERE tenant_id = $1 AND id = $2;
UPDATE resources SET name = $3 WHERE tenant_id = $1 AND id = $2;
DELETE FROM resources WHERE tenant_id = $1 AND id = $2;

-- JOINs: filter BOTH sides
SELECT u.* FROM group_memberships gm
JOIN users u ON gm.user_id = u.id AND u.tenant_id = $1
WHERE gm.tenant_id = $1;
```

**NEVER:**
- Use `Uuid::nil()` as tenant_id placeholder
- Store tenant_id in shared State
- Write queries without `WHERE tenant_id = $N`

### 3. Before Committing

1. Run `cargo test -p <crate>` - tests pass
2. Run `cargo clippy -p <crate> -- -D warnings` - no warnings
3. Run `cargo fmt --check` - formatting OK
4. Update `CRATE.md` if API changed
5. Update maturity in `docs/crates/index.md`, `maturity-matrix.md`, `llms.txt` if status changed

### 4. Maturity Levels

- 🔴 **alpha**: Experimental (<20 tests)
- 🟡 **beta**: Functional (20+ tests, needs integration tests)
- 🟢 **stable**: Production-ready (comprehensive tests, docs complete)

## Project Structure

```
crates/           # Rust libraries (32 crates)
apps/idp-api/     # Main API service
specs/            # Feature specifications
docs/             # Documentation
```

## Active Technologies
- Rust 1.75+ (per constitution) + xavyo-governance (F-004 services), xavyo-core (TenantId, UserId), xavyo-db (PostgreSQL/SQLx), async-trait, chrono, uuid, serde/serde_json, thiserror (132-sod-validation)
- PostgreSQL 15+ with SQLx compile-time checking, RLS for tenant isolation (132-sod-validation)
- Rust 1.75+ (per constitution) + xavyo-governance (F-004, F-005 services), xavyo-core (TenantId, UserId), xavyo-db (PostgreSQL/SQLx), async-trait, chrono, uuid, serde/serde_json, thiserror (133-risk-assessment)
- PostgreSQL (via existing xavyo-db patterns) with in-memory stores for testing (133-risk-assessment)
- Rust 1.75+ (per constitution) + xavyo-governance (existing services), xavyo-db (SQLx + PostgreSQL), tokio (async runtime) (134-governance-integration-tests)
- PostgreSQL 15+ with Row-Level Security (existing infrastructure) (134-governance-integration-tests)
- Rust 1.75+ (per constitution) + xavyo-connector (CreateOp, UpdateOp, DeleteOp traits), xavyo-db (shadow links), async-trait, tokio (135-remediation-executor)
- PostgreSQL via SQLx for shadow links and remediation records (135-remediation-executor)
- Rust 1.75+ (per constitution) + xavyo-api-import, xavyo-db (SQLx), tokio (async runtime), uuid, chrono (143-import-integration-tests)
- PostgreSQL 15+ with RLS (via xavyo-db test infrastructure) (143-import-integration-tests)
- Rust 1.75+ (per constitution) + reqwest (existing), tokio (async runtime), rand (jitter) (144-entra-rate-limiting)
- N/A (in-memory state only) (144-entra-rate-limiting)
- Rust 1.75+ + wiremock 0.6 (already a dev dependency), tokio, reqwest, hmac/sha2 (146-webhooks-integration-tests)
- PostgreSQL (via xavyo-db mocks or in-memory stores) (146-webhooks-integration-tests)
- Rust 1.75+ (per constitution) + xavyo-webhooks (existing), tokio (async runtime), chrono (timestamps) (147-webhook-circuit-breaker)
- PostgreSQL 15+ via xavyo-db (for DLQ and circuit breaker state persistence) (147-webhook-circuit-breaker)

## Recent Changes
- 132-sod-validation: Added Rust 1.75+ (per constitution) + xavyo-governance (F-004 services), xavyo-core (TenantId, UserId), xavyo-db (PostgreSQL/SQLx), async-trait, chrono, uuid, serde/serde_json, thiserror
