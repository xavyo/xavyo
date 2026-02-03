# Research: NHI Integration Tests

**Branch**: `163-nhi-integration-tests` | **Date**: 2026-02-03

## Existing Test Infrastructure

### xavyo-api-nhi Test Dependencies
From `Cargo.toml`:
```toml
[dev-dependencies]
axum-test.workspace = true
tokio-test.workspace = true
```

### Database Test Pattern (from xavyo-api-users)
- `create_test_pool()` - Connects to test PostgreSQL database
- `create_test_tenant()` - Creates isolated tenant for tests
- `cleanup_test_tenant()` - Cleans up after tests

### NHI API Router Structure
From `router.rs`, the API exposes:

**Unified NHI Endpoints:**
- `GET /nhi` - List all NHIs (service accounts + agents)
- `GET /nhi/:id` - Get specific NHI
- `GET /nhi/risk-summary` - Risk statistics
- `GET /nhi/staleness-report` - Inactive NHI report

**Service Accounts (`/nhi/service-accounts/*`):**
- CRUD: GET, POST, PUT, DELETE
- Lifecycle: suspend, reactivate, transfer-ownership, certify
- Credentials: list, rotate, get, revoke (T026)
- Usage: list, record, summary (T027)
- Risk: get, calculate (T028)
- Requests: workflow management (T029)

**AI Agents (`/nhi/agents/*`):**
- CRUD: GET, POST, PATCH, DELETE
- Lifecycle: suspend, reactivate
- Permissions: list, grant, revoke
- Credentials: list, rotate, validate, revoke (F110)
- Security: assessment, anomalies, baseline, thresholds

**Tools (`/nhi/tools/*`):**
- CRUD: GET, POST, PATCH, DELETE

**Approvals (`/nhi/approvals/*`):**
- List, get, status, approve, deny

**Certifications (`/nhi/certifications/*`):**
- Campaigns: CRUD, launch, cancel
- Items: list, decide, bulk-decide

## Test Strategy

### State Management
The NHI API uses multiple state types:
- `NhiState` - For unified list/get handlers
- `RiskState` - For risk and staleness handlers
- `CertificationState` - For certification campaigns
- `AgentsState` - For agent handlers
- `ServiceAccountsState` - For service account handlers
- `ToolsState` - For tool handlers
- `ApprovalsState` - For approval handlers

### Test Categories

1. **Service Account Lifecycle** (User Story 1)
   - Create, read, update, suspend, reactivate, delete

2. **Credential Rotation** (User Story 2)
   - Rotate credentials, verify old invalid, new works

3. **Unified NHI List** (User Story 3)
   - List aggregates both service accounts and agents
   - Filtering by type works
   - Pagination works

4. **Risk/Certification** (User Story 4)
   - Get risk score returns factors
   - Certify marks NHI as certified
   - Certification status persists

5. **Multi-Tenant Isolation** (User Story 5)
   - Tenant A cannot list Tenant B's NHIs
   - Tenant A cannot access Tenant B's NHI by ID
   - Cross-tenant mutations rejected

## Existing Crate Unit Tests

From `crates/xavyo-api-nhi/src/` - 55 existing unit tests covering:
- Handler parameter validation
- Service method unit tests
- Router configuration

Integration tests will add end-to-end HTTP request testing.

## Dependencies for Testing

```toml
[dev-dependencies]
axum-test.workspace = true
tokio-test.workspace = true
sqlx = { version = "0.7", features = ["runtime-tokio", "postgres"] }
uuid = { version = "1.6", features = ["v4"] }
```
