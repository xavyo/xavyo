# Tool Registration and Agent Binding Functional Tests

**API Endpoints**:
- `POST /nhi/tools` - Register a tool
- `GET /nhi/tools` - List tools
- `GET /nhi/tools/:id` - Get tool by ID
- `PATCH /nhi/tools/:id` - Update tool
- `DELETE /nhi/tools/:id` - Delete tool
- `POST /nhi/agents/:id/permissions` - Grant tool permission to agent
- `GET /nhi/agents/:id/permissions` - List agent permissions
- `DELETE /nhi/agents/:agent_id/permissions/:tool_id` - Revoke permission
- `POST /nhi/agents/authorize` - Real-time authorization check

**Authentication**: Bearer JWT (admin role for tool mutations and permission grants)
**Required Headers**: `Content-Type: application/json`, `Authorization: Bearer <jwt>`
**Applicable Standards**: NIST SP 800-207 (Zero Trust), OWASP Top 10 for Agentic Applications, SOC 2 CC6.1

---

## Nominal Cases

### TC-AGENT-TOOL-001: Register a new tool
- **Category**: Nominal
- **Standard**: Zero Trust tool authorization
- **Preconditions**: Authenticated admin user
- **Input**:
  ```json
  POST /nhi/tools
  {
    "name": "send_email",
    "description": "Send emails on behalf of users",
    "category": "communication",
    "input_schema": {
      "type": "object",
      "properties": {
        "to": { "type": "string", "format": "email" },
        "subject": { "type": "string" },
        "body": { "type": "string" }
      },
      "required": ["to", "subject", "body"]
    },
    "risk_level": "medium",
    "requires_approval": false,
    "max_calls_per_hour": 100
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<uuid>",
    "name": "send_email",
    "description": "Send emails on behalf of users",
    "category": "communication",
    "input_schema": { ... },
    "risk_level": "medium",
    "requires_approval": false,
    "max_calls_per_hour": 100,
    "status": "active",
    "provider_verified": false,
    "created_at": "<ISO8601>",
    "updated_at": "<ISO8601>"
  }
  ```

### TC-AGENT-TOOL-002: Register a high-risk tool requiring approval
- **Category**: Nominal
- **Input**:
  ```json
  POST /nhi/tools
  {
    "name": "delete_database_records",
    "description": "Delete records from production database",
    "category": "data",
    "input_schema": { "type": "object", "properties": { "table": { "type": "string" } } },
    "risk_level": "critical",
    "requires_approval": true,
    "max_calls_per_hour": 5
  }
  ```
- **Expected Output**: Status 201, `requires_approval=true`, `risk_level=critical`

### TC-AGENT-TOOL-003: List all tools with pagination
- **Category**: Nominal
- **Preconditions**: 10 tools registered
- **Input**: `GET /nhi/tools?limit=5&offset=0`
- **Expected Output**:
  ```json
  Status: 200 OK
  {
    "tools": [ {...}, {...}, {...}, {...}, {...} ],
    "total": 10,
    "limit": 5,
    "offset": 0
  }
  ```

### TC-AGENT-TOOL-004: List tools filtered by category
- **Category**: Nominal
- **Input**: `GET /nhi/tools?category=communication`
- **Expected Output**: Status 200, only tools with `category=communication`

### TC-AGENT-TOOL-005: List tools filtered by risk_level
- **Category**: Nominal
- **Input**: `GET /nhi/tools?risk_level=critical`
- **Expected Output**: Status 200, only critical-risk tools

### TC-AGENT-TOOL-006: Get tool by ID
- **Category**: Nominal
- **Input**: `GET /nhi/tools/<tool-id>`
- **Expected Output**: Status 200, full tool object

### TC-AGENT-TOOL-007: Update tool description and approval requirement
- **Category**: Nominal
- **Input**:
  ```json
  PATCH /nhi/tools/<tool-id>
  {
    "description": "Updated tool description",
    "requires_approval": true
  }
  ```
- **Expected Output**: Status 200, updated fields reflected

### TC-AGENT-TOOL-008: Delete a tool
- **Category**: Nominal
- **Input**: `DELETE /nhi/tools/<tool-id>`
- **Expected Output**: Status 204 No Content

### TC-AGENT-TOOL-009: Grant tool permission to agent
- **Category**: Nominal
- **Standard**: Zero Trust - explicit permission grant
- **Preconditions**: Agent and tool exist in same tenant
- **Input**:
  ```json
  POST /nhi/agents/<agent-id>/permissions
  {
    "tool_id": "<tool-uuid>",
    "allowed_parameters": { "max_recipients": 10 },
    "max_calls_per_hour": 50,
    "expires_at": "2027-01-01T00:00:00Z"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<permission-uuid>",
    "agent_id": "<agent-id>",
    "tool_id": "<tool-uuid>",
    "tool_name": "send_email",
    "allowed_parameters": { "max_recipients": 10 },
    "max_calls_per_hour": 50,
    "granted_at": "<ISO8601>",
    "granted_by": "<actor-uuid>",
    "expires_at": "2027-01-01T00:00:00Z"
  }
  ```

### TC-AGENT-TOOL-010: Grant permission without parameter restrictions
- **Category**: Nominal
- **Input**:
  ```json
  POST /nhi/agents/<agent-id>/permissions
  { "tool_id": "<tool-uuid>" }
  ```
- **Expected Output**: Status 201, `allowed_parameters=null` (no restrictions)

### TC-AGENT-TOOL-011: List agent permissions
- **Category**: Nominal
- **Preconditions**: Agent has 3 tool permissions
- **Input**: `GET /nhi/agents/<agent-id>/permissions`
- **Expected Output**:
  ```json
  Status: 200 OK
  {
    "permissions": [ {...}, {...}, {...} ],
    "total": 3,
    "limit": 100,
    "offset": 0
  }
  ```

### TC-AGENT-TOOL-012: Revoke tool permission from agent
- **Category**: Nominal
- **Input**: `DELETE /nhi/agents/<agent-id>/permissions/<tool-id>`
- **Expected Output**: Status 204 No Content
- **Verification**: Agent can no longer authorize against this tool

### TC-AGENT-TOOL-013: Authorize agent for permitted tool
- **Category**: Nominal
- **Standard**: Zero Trust real-time authorization
- **Preconditions**: Agent has permission for "send_email" tool
- **Input**:
  ```json
  POST /nhi/agents/authorize
  {
    "agent_id": "<agent-uuid>",
    "tool": "send_email",
    "parameters": { "to": "user@example.com", "subject": "Hello" },
    "context": {
      "conversation_id": "conv-123",
      "session_id": "sess-456",
      "user_instruction": "Send follow-up email"
    }
  }
  ```
- **Expected Output**:
  ```json
  Status: 200 OK
  {
    "decision": "allow",
    "decision_id": "<uuid>",
    "reason": "Agent has permission for tool",
    "latency_ms": 12.5
  }
  ```
- **Verification**: `latency_ms < 100` (real-time requirement)

### TC-AGENT-TOOL-014: Authorization returns require_approval for high-risk tools
- **Category**: Nominal
- **Preconditions**: Agent has permission for tool with `requires_approval=true`
- **Input**: Authorization request for the approval-required tool
- **Expected Output**:
  ```json
  {
    "decision": "require_approval",
    "approval_request_id": "<uuid>",
    ...
  }
  ```

---

## Edge Cases

### TC-AGENT-TOOL-020: Register tool with duplicate name in same tenant
- **Category**: Edge Case
- **Preconditions**: Tool "send_email" exists
- **Input**: `POST /nhi/tools { "name": "send_email", ... }`
- **Expected Output**: Status 409 Conflict

### TC-AGENT-TOOL-021: Get non-existent tool
- **Category**: Edge Case
- **Input**: `GET /nhi/tools/<nonexistent-uuid>`
- **Expected Output**: Status 404

### TC-AGENT-TOOL-022: Delete non-existent tool
- **Category**: Edge Case
- **Input**: `DELETE /nhi/tools/<nonexistent-uuid>`
- **Expected Output**: Status 404

### TC-AGENT-TOOL-023: Grant duplicate permission (same agent + tool)
- **Category**: Edge Case
- **Preconditions**: Permission already exists for agent+tool pair
- **Input**: Grant same permission again
- **Expected Output**: Status 409 Conflict

### TC-AGENT-TOOL-024: Revoke non-existent permission
- **Category**: Edge Case
- **Input**: `DELETE /nhi/agents/<agent-id>/permissions/<unrelated-tool-id>`
- **Expected Output**: Status 404

### TC-AGENT-TOOL-025: Authorize agent for tool without permission
- **Category**: Edge Case
- **Input**: Agent does not have permission for "dangerous_tool"
- **Expected Output**:
  ```json
  Status: 200 OK
  { "decision": "deny", "reason": "Agent does not have permission for tool", ... }
  ```

### TC-AGENT-TOOL-026: Authorize suspended agent
- **Category**: Edge Case
- **Input**: Authorization request for a suspended agent
- **Expected Output**: `{ "decision": "deny", "reason": "Agent is suspended", ... }`

### TC-AGENT-TOOL-027: List tools with name partial match
- **Category**: Edge Case
- **Input**: `GET /nhi/tools?name=send`
- **Expected Output**: Status 200, tools matching name prefix

### TC-AGENT-TOOL-028: Update tool to inactive status
- **Category**: Edge Case
- **Input**: `PATCH /nhi/tools/<id> { "status": "inactive" }`
- **Expected Output**: Status 200, tool status updated
- **Verification**: Authorization requests against inactive tool are denied

### TC-AGENT-TOOL-029: Grant permission with past expiration
- **Category**: Edge Case
- **Input**: `{ "tool_id": "<id>", "expires_at": "2020-01-01T00:00:00Z" }`
- **Expected Output**: Status 400 (expiration in the past) OR Status 201 with immediately expired permission

### TC-AGENT-TOOL-030: Register tool with empty input_schema
- **Category**: Edge Case
- **Input**: `{ "name": "no-schema-tool", "input_schema": {}, "risk_level": "low" }`
- **Expected Output**: Status 201 (empty schema is valid JSON)

---

## Security Cases

### TC-AGENT-TOOL-040: Tool registration without admin role
- **Category**: Security
- **Standard**: NIST SP 800-53 AC-6
- **Input**: Non-admin user attempts `POST /nhi/tools { ... }`
- **Expected Output**: Status 403 Forbidden

### TC-AGENT-TOOL-041: Permission grant without admin role
- **Category**: Security
- **Input**: Non-admin attempts `POST /nhi/agents/<id>/permissions { ... }`
- **Expected Output**: Status 403 Forbidden

### TC-AGENT-TOOL-042: Cross-tenant tool access
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Tool created in Tenant A
- **Input**: Tenant B attempts `GET /nhi/tools/<tenant-a-tool-id>`
- **Expected Output**: Status 404

### TC-AGENT-TOOL-043: Cross-tenant permission grant
- **Category**: Security
- **Input**: Tenant B attempts to grant permission using Tenant A's tool_id
- **Expected Output**: Status 404 (tool not found in Tenant B's scope)

### TC-AGENT-TOOL-044: Authorization audit trail created
- **Category**: Security
- **Standard**: SOC 2 CC7.2
- **Input**: Any authorization request (allow or deny)
- **Verification**: Audit event created with agent_id, tool_name, decision, decision_reason, timestamp, conversation_id

### TC-AGENT-TOOL-045: Expired permission denies authorization
- **Category**: Security
- **Preconditions**: Permission with `expires_at` in the past
- **Input**: Authorization request for tool with expired permission
- **Expected Output**: `{ "decision": "deny", "reason": "Permission expired", ... }`

### TC-AGENT-TOOL-046: Authorization with anomaly detection warnings
- **Category**: Security
- **Standard**: NIST SP 800-207 (Continuous Monitoring)
- **Preconditions**: Agent behavior deviates from baseline (F094)
- **Input**: Authorization request triggering anomaly detection
- **Expected Output**:
  ```json
  {
    "decision": "allow",
    "anomaly_warnings": [
      {
        "anomaly_type": "unusual_tool",
        "severity": "medium",
        "description": "Tool rarely used by this agent",
        "score": 65
      }
    ]
  }
  ```
- **Note**: Anomalies are warnings only, do not block the request

### TC-AGENT-TOOL-047: SQL injection in tool name
- **Category**: Security
- **Input**: `{ "name": "'; DROP TABLE tools; --", "input_schema": {}, "risk_level": "low" }`
- **Expected Output**: Status 400 or 201 (parameterized queries prevent injection)

### TC-AGENT-TOOL-048: Tool input_schema XSS payload
- **Category**: Security
- **Input**: `{ "name": "xss-tool", "input_schema": { "description": "<script>alert('xss')</script>" }, "risk_level": "low" }`
- **Expected Output**: Status 201 (stored as JSON, no execution), output-encoded when rendered

### TC-AGENT-TOOL-049: Pagination limit enforcement on permissions
- **Category**: Security
- **Input**: `GET /nhi/agents/<id>/permissions?limit=10000`
- **Expected Output**: Status 200, at most 100 permissions returned (limit clamped)
