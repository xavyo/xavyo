# Agent / AI Agent CRUD Functional Tests

**API Endpoints**:
- `POST /nhi/agents` - Create agent
- `GET /nhi/agents` - List agents
- `GET /nhi/agents/:id` - Get agent by ID
- `PATCH /nhi/agents/:id` - Update agent
- `DELETE /nhi/agents/:id` - Delete agent
- `POST /nhi/agents/:id/suspend` - Suspend agent
- `POST /nhi/agents/:id/reactivate` - Reactivate agent

**Authentication**: Bearer JWT with `admin` role (mutation endpoints) or any authenticated user (read endpoints)
**Required Headers**: `Content-Type: application/json`, `Authorization: Bearer <jwt>`
**Applicable Standards**: NIST SP 800-63C (Federation and Assertions), NIST SP 800-207 (Zero Trust), SOC 2 CC6.1 (Logical Access)

---

## Nominal Cases

### TC-AGENT-CRUD-001: Create agent with all required fields
- **Category**: Nominal
- **Standard**: NIST SP 800-63C, NHI management best practices
- **Preconditions**: Authenticated user with `admin` role in tenant
- **Input**:
  ```json
  POST /nhi/agents
  {
    "name": "sales-assistant",
    "agent_type": "copilot",
    "description": "AI assistant for the sales team",
    "risk_level": "medium",
    "max_token_lifetime_secs": 900,
    "requires_human_approval": false
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<uuid>",
    "name": "sales-assistant",
    "agent_type": "copilot",
    "description": "AI assistant for the sales team",
    "status": "active",
    "risk_level": "medium",
    "max_token_lifetime_secs": 900,
    "requires_human_approval": false,
    "created_at": "<ISO8601>",
    "updated_at": "<ISO8601>"
  }
  ```
- **Side Effects**:
  - Agent record created in database with tenant_id from JWT
  - `owner_id` set to JWT subject (user_id)

### TC-AGENT-CRUD-002: Create agent with minimal fields (defaults applied)
- **Category**: Nominal
- **Preconditions**: Authenticated admin user
- **Input**:
  ```json
  POST /nhi/agents
  {
    "name": "minimal-agent",
    "agent_type": "autonomous"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "name": "minimal-agent",
    "agent_type": "autonomous",
    "risk_level": "medium",
    "max_token_lifetime_secs": 900,
    "requires_human_approval": false,
    "status": "active",
    "inactivity_threshold_days": 90,
    ...
  }
  ```
- **Verification**: Default values applied: `risk_level=medium`, `max_token_lifetime_secs=900`, `inactivity_threshold_days=90`

### TC-AGENT-CRUD-003: Create agent with all optional fields
- **Category**: Nominal
- **Input**:
  ```json
  POST /nhi/agents
  {
    "name": "full-featured-agent",
    "agent_type": "orchestrator",
    "description": "Orchestrator with full config",
    "owner_id": "<user-uuid>",
    "team_id": "<group-uuid>",
    "backup_owner_id": "<backup-user-uuid>",
    "model_provider": "anthropic",
    "model_name": "claude-sonnet-4",
    "model_version": "2025-06-01",
    "risk_level": "critical",
    "max_token_lifetime_secs": 300,
    "requires_human_approval": true,
    "expires_at": "2027-01-01T00:00:00Z",
    "inactivity_threshold_days": 30,
    "rotation_interval_days": 90
  }
  ```
- **Expected Output**: Status 201 with all fields populated in response

### TC-AGENT-CRUD-004: List agents returns paginated results
- **Category**: Nominal
- **Preconditions**: 5 agents exist in tenant
- **Input**:
  ```
  GET /nhi/agents?limit=2&offset=0
  ```
- **Expected Output**:
  ```json
  Status: 200 OK
  {
    "agents": [ {...}, {...} ],
    "total": 5,
    "limit": 2,
    "offset": 0
  }
  ```

### TC-AGENT-CRUD-005: List agents with status filter
- **Category**: Nominal
- **Preconditions**: Mix of active and suspended agents
- **Input**: `GET /nhi/agents?status=active`
- **Expected Output**: Status 200, only active agents returned

### TC-AGENT-CRUD-006: List agents with agent_type filter
- **Category**: Nominal
- **Input**: `GET /nhi/agents?agent_type=copilot`
- **Expected Output**: Status 200, only copilot agents returned

### TC-AGENT-CRUD-007: List agents with name search
- **Category**: Nominal
- **Input**: `GET /nhi/agents?name=sales`
- **Expected Output**: Status 200, agents matching name prefix "sales"

### TC-AGENT-CRUD-008: Get agent by ID
- **Category**: Nominal
- **Preconditions**: Agent `<agent-id>` exists in tenant
- **Input**: `GET /nhi/agents/<agent-id>`
- **Expected Output**: Status 200, full agent object with all fields

### TC-AGENT-CRUD-009: Update agent description and risk level
- **Category**: Nominal
- **Preconditions**: Agent `<agent-id>` exists
- **Input**:
  ```json
  PATCH /nhi/agents/<agent-id>
  {
    "description": "Updated description",
    "risk_level": "high"
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "description": "Updated description", "risk_level": "high", ... }
  ```
- **Verification**: `updated_at` timestamp is newer than `created_at`

### TC-AGENT-CRUD-010: Delete agent
- **Category**: Nominal
- **Preconditions**: Agent `<agent-id>` exists
- **Input**: `DELETE /nhi/agents/<agent-id>`
- **Expected Output**: Status 204 No Content
- **Verification**: Subsequent `GET /nhi/agents/<agent-id>` returns 404

### TC-AGENT-CRUD-011: Suspend active agent
- **Category**: Nominal
- **Preconditions**: Agent is `active`
- **Input**: `POST /nhi/agents/<agent-id>/suspend`
- **Expected Output**:
  ```json
  Status: 200 OK
  { "status": "suspended", ... }
  ```
- **Side Effects**: Agent status set to `suspended` in database

### TC-AGENT-CRUD-012: Reactivate suspended agent
- **Category**: Nominal
- **Preconditions**: Agent is `suspended`
- **Input**: `POST /nhi/agents/<agent-id>/reactivate`
- **Expected Output**:
  ```json
  Status: 200 OK
  { "status": "active", ... }
  ```

### TC-AGENT-CRUD-013: Create agents with each valid agent_type
- **Category**: Nominal
- **Input**: Create agents with `agent_type` values: `autonomous`, `copilot`, `workflow`, `orchestrator`
- **Expected Output**: Status 201 for each type

### TC-AGENT-CRUD-014: Update agent model provider and name
- **Category**: Nominal
- **Input**:
  ```json
  PATCH /nhi/agents/<agent-id>
  {
    "model_provider": "openai",
    "model_name": "gpt-4o",
    "model_version": "2025-05-01"
  }
  ```
- **Expected Output**: Status 200, model fields updated

---

## Edge Cases

### TC-AGENT-CRUD-020: Create agent with duplicate name in same tenant
- **Category**: Edge Case
- **Preconditions**: Agent named "sales-assistant" already exists
- **Input**:
  ```json
  POST /nhi/agents
  { "name": "sales-assistant", "agent_type": "copilot" }
  ```
- **Expected Output**: Status 409 Conflict

### TC-AGENT-CRUD-021: Create agent with same name in different tenant
- **Category**: Edge Case
- **Preconditions**: Agent "sales-assistant" exists in Tenant A
- **Input**: Authenticated as Tenant B admin, create agent with same name
- **Expected Output**: Status 201 (names are unique per-tenant, not globally)

### TC-AGENT-CRUD-022: Get agent with non-existent UUID
- **Category**: Edge Case
- **Input**: `GET /nhi/agents/00000000-0000-0000-0000-000000000099`
- **Expected Output**: Status 404

### TC-AGENT-CRUD-023: Get agent with invalid UUID format
- **Category**: Edge Case
- **Input**: `GET /nhi/agents/not-a-uuid`
- **Expected Output**: Status 400 or 422

### TC-AGENT-CRUD-024: Update agent with empty body
- **Category**: Edge Case
- **Input**: `PATCH /nhi/agents/<id>` with `{}`
- **Expected Output**: Status 200 (no-op update, returns current state)

### TC-AGENT-CRUD-025: Delete already-deleted agent
- **Category**: Edge Case
- **Input**: Delete agent, then delete same ID again
- **Expected Output**: Status 404 on second call

### TC-AGENT-CRUD-026: Suspend already-suspended agent
- **Category**: Edge Case
- **Input**: Suspend active agent, then suspend again
- **Expected Output**: Status 409 Conflict (already suspended)

### TC-AGENT-CRUD-027: Reactivate agent that is not suspended
- **Category**: Edge Case
- **Input**: Reactivate an active agent
- **Expected Output**: Status 409 Conflict (not suspended)

### TC-AGENT-CRUD-028: List agents with offset beyond total count
- **Category**: Edge Case
- **Preconditions**: 5 agents exist
- **Input**: `GET /nhi/agents?offset=100`
- **Expected Output**: Status 200, `agents: []`, `total: 5`

### TC-AGENT-CRUD-029: Create agent with past expiration date
- **Category**: Edge Case
- **Input**:
  ```json
  POST /nhi/agents
  { "name": "expired-agent", "agent_type": "copilot", "expires_at": "2020-01-01T00:00:00Z" }
  ```
- **Expected Output**: Status 400 (expiration in the past) OR Status 201 with immediate `expired` status

### TC-AGENT-CRUD-030: Update agent with invalid risk_level
- **Category**: Edge Case
- **Input**: `{ "risk_level": "extreme" }`
- **Expected Output**: Status 400 (valid values: low, medium, high, critical)

### TC-AGENT-CRUD-031: Create agent with name containing special characters
- **Category**: Edge Case
- **Input**: `{ "name": "agent/with<special>chars&more", "agent_type": "copilot" }`
- **Expected Output**: Status 400 (if name validation enforced) OR Status 201

---

## Security Cases

### TC-AGENT-CRUD-040: Create agent without admin role
- **Category**: Security
- **Standard**: NIST SP 800-53 AC-6 (Least Privilege)
- **Preconditions**: Authenticated user with `viewer` role only
- **Input**: `POST /nhi/agents { "name": "unauthorized", "agent_type": "copilot" }`
- **Expected Output**: Status 403 Forbidden ("Admin role required")

### TC-AGENT-CRUD-041: Update agent without admin role
- **Category**: Security
- **Input**: `PATCH /nhi/agents/<id> { "description": "hacked" }`
- **Expected Output**: Status 403 Forbidden

### TC-AGENT-CRUD-042: Delete agent without admin role
- **Category**: Security
- **Input**: `DELETE /nhi/agents/<id>`
- **Expected Output**: Status 403 Forbidden

### TC-AGENT-CRUD-043: Suspend agent without admin role
- **Category**: Security
- **Input**: `POST /nhi/agents/<id>/suspend`
- **Expected Output**: Status 403 Forbidden

### TC-AGENT-CRUD-044: Access agent from different tenant (cross-tenant isolation)
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Agent created in Tenant A
- **Input**: Authenticated as Tenant B admin, `GET /nhi/agents/<tenant-a-agent-id>`
- **Expected Output**: Status 404 (tenant isolation must prevent access)

### TC-AGENT-CRUD-045: Create agent without authentication
- **Category**: Security
- **Input**: `POST /nhi/agents` without Authorization header
- **Expected Output**: Status 401 Unauthorized

### TC-AGENT-CRUD-046: Create agent with missing tenant_id in JWT
- **Category**: Security
- **Input**: JWT without `tid` claim
- **Expected Output**: Status 400 or 401

### TC-AGENT-CRUD-047: SQL injection in agent name
- **Category**: Security
- **Standard**: OWASP ASVS 5.3.4
- **Input**: `{ "name": "'; DROP TABLE agents; --", "agent_type": "copilot" }`
- **Expected Output**: Status 400 or 201 (parameterized queries prevent injection), no SQL execution

### TC-AGENT-CRUD-048: Response does not leak internal errors
- **Category**: Security
- **Standard**: OWASP ASVS 7.4.1
- **Verification**: All error responses contain sanitized messages, no stack traces or SQL fragments

### TC-AGENT-CRUD-049: Pagination limit clamped to maximum 100
- **Category**: Security
- **Input**: `GET /nhi/agents?limit=10000`
- **Expected Output**: Status 200, response contains at most 100 agents (limit clamped)
