# Data Model: NHI Integration Tests

**Branch**: `163-nhi-integration-tests` | **Date**: 2026-02-03

## Test Fixture Structures

### Test Context
```rust
pub struct TestContext {
    pub pool: PgPool,
    pub tenant_a: Uuid,
    pub tenant_b: Uuid,
}
```

### Service Account Fixture
```rust
pub struct ServiceAccountFixture {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub owner_id: Uuid,
    pub status: ServiceAccountStatus,
}
```

### Agent Fixture
```rust
pub struct AgentFixture {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub agent_type: AgentType,
    pub status: AgentStatus,
}
```

### Credential Fixture
```rust
pub struct CredentialFixture {
    pub id: Uuid,
    pub service_account_id: Uuid,
    pub credential_type: CredentialType,
    pub is_active: bool,
}
```

## Database Tables Involved

### Core NHI Tables
- `service_accounts` - Service account records
- `service_account_credentials` - Credentials for service accounts
- `agents` - AI agent records
- `agent_credentials` - Credentials for agents
- `tools` - Tool registry
- `agent_permissions` - Agent-to-tool permissions

### Governance Tables
- `nhi_risk_scores` - Calculated risk scores
- `nhi_certifications` - Certification records
- `certification_campaigns` - Campaign metadata
- `certification_items` - Campaign items

### Supporting Tables
- `tenants` - Multi-tenant isolation
- `users` - Owner references

## Test Data Patterns

### Tenant Isolation
```
Tenant A:
  - service_account_a1, service_account_a2
  - agent_a1

Tenant B:
  - service_account_b1
  - agent_b1
```

### Lifecycle States
```
Service Account States:
  - Active (default)
  - Suspended
  - Deleted (soft-delete)

Agent States:
  - Active
  - Suspended
  - Inactive
```

### Risk Factors
```
Risk Score Components:
  - credential_age_days
  - unused_permissions_count
  - privilege_level
  - last_activity_days
```

## Helper Functions

```rust
// Create test pool
pub async fn create_test_pool() -> PgPool

// Create test tenant
pub async fn create_test_tenant(pool: &PgPool) -> Uuid

// Create service account
pub async fn create_test_service_account(
    pool: &PgPool,
    tenant_id: Uuid,
    name: &str,
) -> Uuid

// Create agent
pub async fn create_test_agent(
    pool: &PgPool,
    tenant_id: Uuid,
    name: &str,
) -> Uuid

// Generate unique names
pub fn unique_service_account_name() -> String
pub fn unique_agent_name() -> String

// Cleanup
pub async fn cleanup_test_tenant(pool: &PgPool, tenant_id: Uuid)
```
