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

# Start dev environment (PostgreSQL, Kafka, Mailpit)
docker compose -f docker/docker-compose.yml up -d
```

## Dev Email Testing (Mailpit)

Mailpit catches all outbound emails in development. No real emails are ever sent.

- **SMTP**: `localhost:1025` (no TLS, any credentials accepted)
- **Web UI**: http://localhost:8025 (browse all captured emails)
- **REST API**: http://localhost:8025/api/v1/messages (programmatic access)

Configuration in `.env`:
```bash
EMAIL_SMTP_HOST=localhost
EMAIL_SMTP_PORT=1025
EMAIL_SMTP_TLS=false          # Required for Mailpit (plain SMTP)
EMAIL_SMTP_USERNAME=dev
EMAIL_SMTP_PASSWORD=dev
EMAIL_FROM_ADDRESS=noreply@xavyo.local
FRONTEND_BASE_URL=http://localhost:3000
```

Useful for testing:
```bash
# List all captured emails
curl http://localhost:8025/api/v1/messages

# Clear all emails
curl -X DELETE http://localhost:8025/api/v1/messages

# Search emails by query
curl "http://localhost:8025/api/v1/search?query=to:user@test.com"
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
- Rust 1.75+ (per constitution) + xavyo-siem (existing), tokio (async runtime), wiremock (HTTP mocking), tokio-test (async test utilities) (148-siem-integration-tests)
- N/A (testing crate only - uses in-memory mock servers) (148-siem-integration-tests)
- Rust 1.75+ (per constitution) + xavyo-scim-client (existing), tokio (async runtime), wiremock (HTTP mocking), tokio-test (async test utilities) (149-scim-client-tests)
- Rust 1.75+ (per constitution) + xavyo-api-users, xavyo-db (User/Group models), xavyo-auth (JwtClaims), sqlx, tokio (150-api-users-tests)
- PostgreSQL 15+ with RLS for tenant isolation (150-api-users-tests)
- Rust 1.75+ (per constitution) + xavyo-api-users (existing), validator crate (for email RFC 5322), regex (existing) (151-api-users-validation)
- PostgreSQL (existing, no changes needed) (151-api-users-validation)
- Rust 1.75+ (per constitution) + xavyo-api-scim, axum-test, tokio-test, serde_json (152-scim-idp-interop-tests)
- N/A (tests use in-memory or mocked database) (152-scim-idp-interop-tests)
- Rust 1.75+ (per constitution) + xavyo-api-saml (existing), xavyo-db (Group/GroupMembership models), async-trait, chrono, uuid, serde/serde_json (155-saml-group-assertions)
- Rust 1.75+ (per constitution) + xavyo-api-saml (existing), xavyo-db (SP models), tokio (async testing) (156-saml-sp-interop-tests)
- N/A (tests only, using in-memory test fixtures) (156-saml-sp-interop-tests)
- Rust 1.75+ (per constitution) + xavyo-api-social (existing), wiremock (mock HTTP server), tokio (async runtime), serde_json (JSON handling), jsonwebtoken (JWT generation for Apple mocks) (157-social-provider-tests)
- N/A (tests only, no persistent storage) (157-social-provider-tests)
- Rust 1.75+ (per constitution) + xavyo-api-connectors (existing), xavyo-db (existing models), xavyo-provisioning (queue) (160-job-tracking)
- PostgreSQL 15+ with existing operation tables (160-job-tracking)
- Rust 1.75+ + xavyo-auth (JWT encoding/decoding), jsonwebtoken, reqwest (JWKS fetching) (161-oidc-jwt-integration)
- PostgreSQL 15+ (via xavyo-db for tenant keys) (161-oidc-jwt-integration)
- Docker Compose 2.x, Rust 1.75+ (tests) + Docker Compose, wiremock (existing), tokio-test (existing) (165-siem-docker-tests)
- N/A (containers only persist during test run) (165-siem-docker-tests)
- Rust 1.75+ (per constitution) + clap 4 (CLI), reqwest 0.12 (HTTP), dialoguer 0.11 (interactive), serde (JSON) (181-multi-tenant-switch)
- Local session file (`~/.xavyo/session.json`) for tenant context persistence (181-multi-tenant-switch)
- Rust 1.75+ (per constitution) + serde, uuid, chrono, async-trait (existing) (182-nhi-foundation-types)
- N/A (foundation types crate - no persistence) (182-nhi-foundation-types)
- Rust 1.75+ (per constitution) + criterion (benchmarking), xavyo-authorization (existing crate) (183-authorization-perf-benchmark)
- N/A (in-memory benchmarks only) (183-authorization-perf-benchmark)
- Rust 1.75+ (per constitution) + axum, tower, serde, chrono, uuid, utoipa (OpenAPI), xavyo-auth (JwtClaims), xavyo-db (ApiKey model) (184-api-key-creation)
- PostgreSQL 15+ via SQLx (existing `api_keys` table) (184-api-key-creation)
- Rust 1.75+ (per constitution) + clap 4 (CLI), reqwest (HTTP), dialoguer (prompts), serde (JSON) (185-cli-api-keys)
- Local session file for tenant context (`~/.xavyo/session.json`) (185-cli-api-keys)
- Rust 1.75+ (per constitution) + clap 4 (CLI), reqwest (HTTP), serde (JSON) - all existing (186-cli-agents-enhance)
- N/A (CLI client only) (186-cli-agents-enhance)
- Rust 1.75+ (per constitution) + clap 4 (CLI), reqwest (HTTP), serde (serialization), chrono (datetime) (187-cli-credential-commands)
- N/A (CLI communicates via HTTP API) (187-cli-credential-commands)
- Rust 1.75+ (per constitution) + clap 4 (CLI), dialoguer 0.11 (interactive prompts - already present) (188-cli-interactive-mode)
- N/A (uses existing API client) (188-cli-interactive-mode)
- Rust 1.75+ (per constitution) + Axum, Tower, SQLx, chrono, serde, uuid (189-api-key-usage-stats)
- PostgreSQL 15+ (with RLS for tenant isolation) (189-api-key-usage-stats)
- Rust 1.75+ (per constitution) + xavyo-api-tenants (handlers), xavyo-api-auth (ApiKeyContext middleware), xavyo-db (ApiKey model) (190-api-key-introspect)
- PostgreSQL 15+ (existing api_keys table) (190-api-key-introspect)
- Rust 1.75+ (per constitution) + xavyo-api-tenants (existing), xavyo-db (Tenant model), xavyo-auth (JwtClaims), Axum + Tower (191-tenant-settings)
- PostgreSQL 15+ (existing tenant.settings JSON column) (191-tenant-settings)
- Rust 1.75+ + Axum, Tower, xavyo-db (UserInvitation model), xavyo-auth (JwtClaims) (192-tenant-invitation)
- PostgreSQL 15+ (existing `user_invitations` table) (192-tenant-invitation)
- Rust 1.75+ (per constitution) + Axum, Tower, SQLx, serde, uuid, chrono, validator (058-identity-archetype)
- Rust 1.75+ (per constitution) + xavyo-api-governance (existing lifecycle services), xavyo-db (existing lifecycle models), async-trait, chrono, uuid, serde/serde_json (193-lifecycle-state-machine)
- PostgreSQL 15+ via SQLx (existing tables) (193-lifecycle-state-machine)
- Rust 1.75+ (per constitution) + xavyo-api-governance (handlers), xavyo-db (models), xavyo-auth (JWT/claims), Axum + Tower (194-power-of-attorney)
- Rust 1.75+ (per constitution) + xavyo-api-governance (existing), xavyo-db (models), xavyo-auth (JwtClaims), Axum + Tower, serde, chrono, uuid, utoipa (OpenAPI) (195-request-catalog)
- PostgreSQL 15+ with RLS for tenant isolation (existing infrastructure) (195-request-catalog)
- Rust 1.75+ (per constitution) + Axum, Tower, SQLx, serde, chrono, uuid, async-trait (existing), utoipa (OpenAPI) (196-role-inducements)
- PostgreSQL 15+ (existing, with RLS for tenant isolation) (196-role-inducements)
- Rust 1.75+ (per constitution) + Axum + Tower (REST API), SQLx (database), tokio (async runtime), serde (serialization) (197-bulk-action-engine)
- Rust 1.75+ (per constitution) + xavyo-db (SQLx), xavyo-api-auth, xavyo-api-tenants, xavyo-core (TenantId, UserId), async-trait, chrono, uuid, serde (199-org-security-policies)
- Rust 1.75+ + Axum + Tower (HTTP), SQLx (database), serde (serialization), utoipa (OpenAPI) (200-gdpr-data-protection)
- Rust 1.75+ (per constitution) + Axum + Tower (HTTP), SQLx (database, compile-time checked), serde/serde_json, chrono, uuid, async-trait, utoipa (OpenAPI), validator (input validation) (201-tool-nhi-promotion)
- Rust 1.75+ + Axum + Tower (middleware), SQLx (compile-time checked), xavyo-auth (JwtClaims), xavyo-db (ApiKey, UserRole models) (202-api-key-identity-fix)
- Rust 1.75+ (existing CLI crate) + clap 4, reqwest, serde, chrono, uuid (all existing) (203-cli-tool-model-fix)
- Rust 1.75+ (per constitution) + Axum + Tower (HTTP), SQLx (compile-time checked queries), serde/serde_json, chrono, uuid, async-trait, utoipa (OpenAPI) (204-nhi-permission-model)
- Rust 1.75+ (per constitution) + Axum + Tower (HTTP), SQLx (database), xavyo-api-nhi (existing NHI API crate), xavyo-db (models), xavyo-auth (JwtClaims), jsonschema (MCP parameter validation), reqwest (A2A webhooks) (205-protocol-migration)

## Recent Changes
- 132-sod-validation: Added Rust 1.75+ (per constitution) + xavyo-governance (F-004 services), xavyo-core (TenantId, UserId), xavyo-db (PostgreSQL/SQLx), async-trait, chrono, uuid, serde/serde_json, thiserror
