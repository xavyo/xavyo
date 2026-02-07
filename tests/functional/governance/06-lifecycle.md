# Lifecycle State Machine Functional Tests

**API Base Path**: `/governance/lifecycle/configs`, `/governance/lifecycle/transitions`, `/governance/lifecycle/audit`
**Authentication**: JWT Bearer token with `admin` role required for configuration; authenticated for transitions
**Required Headers**: `Content-Type: application/json`, `Authorization: Bearer <jwt>`
**Applicable Standards**: NIST SP 800-53 AC-2 (Account Management), ISO 27001 A.9.2.1 (User Registration)

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: Some tests require existing lifecycle configurations with states and transitions, and users with lifecycle state assignments

---

## Nominal Cases

### TC-GOV-LIFE-001: Create lifecycle configuration
- **Category**: Nominal
- **Standard**: NIST SP 800-53 AC-2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as tenant admin
- **Input**:
  ```json
  POST /governance/lifecycle/configs
  {
    "name": "Standard Employee Lifecycle",
    "object_type": "user",
    "description": "Joiner-Mover-Leaver lifecycle for full-time employees",
    "auto_assign_initial_state": true
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<uuid>",
    "name": "Standard Employee Lifecycle",
    "object_type": "user",
    "is_active": true,
    "auto_assign_initial_state": true,
    "state_count": 0,
    "transition_count": 0,
    "created_at": "<iso8601>"
  }
  ```

### TC-GOV-LIFE-002: List lifecycle configurations
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```
  GET /governance/lifecycle/configs?object_type=user&limit=10&offset=0
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [...], "total": <count> }
  ```

### TC-GOV-LIFE-003: Get lifecycle configuration by ID
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Lifecycle config exists with known ID
- **Input**:
  ```
  GET /governance/lifecycle/configs/<config-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "id": "<config-id>", "name": "Standard Employee Lifecycle", ... }
  ```

### TC-GOV-LIFE-004: Update lifecycle configuration
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Lifecycle config exists
- **Input**:
  ```json
  PUT /governance/lifecycle/configs/<config-id>
  {
    "name": "Updated Employee Lifecycle",
    "description": "Updated with contractor states"
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  ```

### TC-GOV-LIFE-005: Add states to lifecycle configuration
- **Category**: Nominal
- **Standard**: NIST SP 800-53 AC-2 (Account Management)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Lifecycle config exists
- **Steps**:
  1. Add "pre_hire" state (initial):
     ```json
     POST /governance/lifecycle/configs/<config-id>/states
     { "name": "pre_hire", "display_name": "Pre-Hire", "is_initial": true, "is_terminal": false }
     ```
  2. Add "active" state:
     ```json
     POST /governance/lifecycle/configs/<config-id>/states
     { "name": "active", "display_name": "Active", "is_initial": false, "is_terminal": false }
     ```
  3. Add "suspended" state:
     ```json
     POST /governance/lifecycle/configs/<config-id>/states
     { "name": "suspended", "display_name": "Suspended" }
     ```
  4. Add "terminated" state (terminal):
     ```json
     POST /governance/lifecycle/configs/<config-id>/states
     { "name": "terminated", "display_name": "Terminated", "is_terminal": true }
     ```
- **Expected Output**: Each returns 201 Created
- **Verification**: `state_count = 4` on config

### TC-GOV-LIFE-006: Add transitions between states
- **Category**: Nominal
- **Standard**: NIST SP 800-53 AC-2 (Joiner-Mover-Leaver)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. States exist in lifecycle config
- **Steps**:
  1. Add "onboard" transition (pre_hire -> active):
     ```json
     POST /governance/lifecycle/configs/<config-id>/transitions
     {
       "name": "onboard",
       "from_state_id": "<pre-hire-state-id>",
       "to_state_id": "<active-state-id>",
       "requires_approval": true
     }
     ```
  2. Add "suspend" transition (active -> suspended):
     ```json
     POST /governance/lifecycle/configs/<config-id>/transitions
     { "name": "suspend", "from_state_id": "<active-id>", "to_state_id": "<suspended-id>" }
     ```
  3. Add "reactivate" transition (suspended -> active)
  4. Add "terminate" transition (active -> terminated)
- **Expected Output**: Each returns 201 Created

### TC-GOV-LIFE-007: Execute state transition
- **Category**: Nominal
- **Standard**: NIST SP 800-53 AC-2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User is in "pre_hire" state; "onboard" transition exists
- **Input**:
  ```json
  POST /governance/lifecycle/transitions
  {
    "object_type": "user",
    "object_id": "<user-id>",
    "transition_id": "<onboard-transition-id>",
    "justification": "Employee start date reached"
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "request_id": "<uuid>",
    "status": "completed",
    "from_state": "pre_hire",
    "to_state": "active"
  }
  ```

### TC-GOV-LIFE-008: Get object current state
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Object has been transitioned
- **Input**:
  ```
  GET /governance/lifecycle/objects/user/<user-id>/state
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "object_type": "user", "object_id": "<user-id>", "current_state": "active", ... }
  ```

### TC-GOV-LIFE-009: List transition requests
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```
  GET /governance/lifecycle/transitions?limit=50&offset=0
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [...], "total": <count> }
  ```

### TC-GOV-LIFE-010: Get transition request details
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Transition request exists
- **Input**:
  ```
  GET /governance/lifecycle/transitions/<request-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  ```

### TC-GOV-LIFE-011: Rollback transition
- **Category**: Nominal
- **Standard**: IGA Error Recovery
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Transition was recently executed
- **Input**:
  ```
  POST /governance/lifecycle/transitions/<request-id>/rollback
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "status": "rolled_back", ... }
  ```

### TC-GOV-LIFE-012: Get affected entitlements preview
- **Category**: Nominal
- **Standard**: IGA Impact Analysis
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Transition has entitlement actions configured
- **Input**:
  ```
  GET /governance/lifecycle/transitions/<transition-id>/affected-entitlements/<user-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "entitlements_to_grant": [...], "entitlements_to_revoke": [...] }
  ```

### TC-GOV-LIFE-013: Get transition audit trail
- **Category**: Nominal
- **Standard**: SOC 2 CC7.2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```
  GET /governance/lifecycle/audit?limit=50&offset=0
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [{ "audit_id": "...", "action": "transition", "actor_id": "...", "timestamp": "..." }] }
  ```

### TC-GOV-LIFE-014: Export transition audit as CSV
- **Category**: Nominal
- **Standard**: SOX Section 404 (Audit Evidence)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```
  GET /governance/lifecycle/audit/export
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Content-Type: text/csv
  ```

### TC-GOV-LIFE-015: Schedule future transition
- **Category**: Nominal
- **Standard**: NIST SP 800-53 AC-2 (Automated Account Management)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User is "active"; "terminate" transition exists
- **Input**:
  ```json
  POST /governance/lifecycle/transitions
  {
    "object_type": "user",
    "object_id": "<user-id>",
    "transition_id": "<terminate-transition-id>",
    "scheduled_at": "2026-06-30T17:00:00Z",
    "justification": "Contract end date"
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "status": "scheduled", ... }
  ```

### TC-GOV-LIFE-016: Trigger due scheduled transitions
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Scheduled transitions past their execution time
- **Input**:
  ```
  POST /governance/lifecycle/scheduled/trigger-due
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "triggered": <count> }
  ```

### TC-GOV-LIFE-017: Cancel scheduled transition
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Scheduled transition exists
- **Input**:
  ```
  POST /governance/lifecycle/scheduled/<schedule-id>/cancel
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  ```

### TC-GOV-LIFE-018: Get transition conditions
- **Category**: Nominal
- **Standard**: IGA Conditional Transitions (F-193)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Lifecycle config with transitions exists
- **Input**:
  ```
  GET /governance/lifecycle/configs/<config-id>/transitions/<transition-id>/conditions
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "conditions": [...] }
  ```

### TC-GOV-LIFE-019: Evaluate transition conditions
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Conditions configured on transition
- **Input**:
  ```json
  POST /governance/lifecycle/configs/<config-id>/transitions/<transition-id>/conditions/evaluate
  { "object_id": "<user-id>" }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "can_transition": true, "condition_results": [...] }
  ```

### TC-GOV-LIFE-020: Get user lifecycle status
- **Category**: Nominal
- **Standard**: NIST SP 800-53 AC-2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User exists with lifecycle state
- **Input**:
  ```
  GET /governance/users/<user-id>/lifecycle/status
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "current_state": "active", "config_id": "<config-id>", "available_transitions": [...] }
  ```

---

## Edge Cases

### TC-GOV-LIFE-025: Execute invalid transition (not allowed from current state)
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User is in "terminated" state; only "pre_hire -> active" transition exists
- **Input**:
  ```json
  POST /governance/lifecycle/transitions
  { "object_type": "user", "object_id": "<user-id>", "transition_id": "<onboard-transition-id>" }
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  Body: { "error": "Transition not valid from current state" }
  ```

### TC-GOV-LIFE-026: Delete state that is part of active transitions
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. State is referenced by transitions
- **Input**:
  ```
  DELETE /governance/lifecycle/configs/<config-id>/states/<state-id>
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  ```

### TC-GOV-LIFE-027: Delete lifecycle config with objects in non-initial states
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Lifecycle config has objects in non-initial states
- **Input**:
  ```
  DELETE /governance/lifecycle/configs/<config-id>
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  ```

### TC-GOV-LIFE-028: Create bulk state operation
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Multiple users need state transition
- **Input**:
  ```json
  POST /governance/lifecycle/bulk-operations
  {
    "object_ids": ["<user-1>", "<user-2>", "<user-3>"],
    "object_type": "user",
    "transition_id": "<terminate-id>"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: { "operation_id": "<uuid>", "status": "pending", "total_objects": 3 }
  ```

---

## Security Tests

### TC-GOV-LIFE-030: Create lifecycle config without admin role
- **Category**: Security
- **Standard**: NIST SP 800-53 AC-6
- **Preconditions**: Fixtures: `TEST_TENANT`
- **Input**:
  ```json
  POST /governance/lifecycle/configs
  { "name": "Unauthorized", "object_type": "user" }
  ```
  (JWT with user role only)
- **Expected Output**:
  ```
  Status: 403 Forbidden
  ```

### TC-GOV-LIFE-031: Execute transition cross-tenant
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User in tenant A; JWT for tenant B (second tenant required)
- **Input**:
  ```json
  POST /governance/lifecycle/transitions
  { "object_type": "user", "object_id": "<tenant-a-user>", "transition_id": "<id>" }
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-GOV-LIFE-032: Access audit trail from different tenant
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. JWT for tenant B; only tenant B records should be returned (second tenant required)
- **Input**:
  ```
  GET /governance/lifecycle/audit
  ```
  (JWT for tenant B; only tenant B records returned)
- **Expected Output**: Only tenant B audit records visible

---

## Compliance Tests

### TC-GOV-LIFE-040: NIST SP 800-53 AC-2 - Complete Joiner-Mover-Leaver cycle
- **Category**: Compliance
- **Standard**: NIST SP 800-53 AC-2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**:
  1. Configure lifecycle: pre_hire -> active -> suspended -> terminated
  2. Create user (assigned to pre_hire state)
  3. Onboard: pre_hire -> active (entitlements provisioned)
  4. Suspend: active -> suspended (entitlements temporarily revoked)
  5. Reactivate: suspended -> active (entitlements restored)
  6. Terminate: active -> terminated (all entitlements permanently revoked)
- **Expected Output**: Complete lifecycle with entitlement provisioning/deprovisioning at each stage

### TC-GOV-LIFE-041: ISO 27001 A.9.2.6 - Removal of access rights
- **Category**: Compliance
- **Standard**: ISO 27001 A.9.2.6
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**:
  1. Configure terminate transition with entitlement revocation actions
  2. Execute terminate transition
  3. Verify all user entitlements revoked
  4. Verify audit trail records revocation
- **Expected Output**: Access removal is immediate and auditable upon termination

### TC-GOV-LIFE-042: Scheduled transition for planned departures
- **Category**: Compliance
- **Standard**: NIST SP 800-53 AC-2(2) (Automated Temporary Accounts)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**:
  1. Schedule terminate transition for contractor's end date
  2. Verify scheduled transition visible in list
  3. When due date passes, verify auto-execution
  4. Verify access revoked on schedule
- **Expected Output**: Automated lifecycle management for time-bounded identities

### TC-GOV-LIFE-043: Lifecycle audit trail completeness
- **Category**: Compliance
- **Standard**: SOC 2 CC7.2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**:
  1. Execute multiple lifecycle transitions
  2. Export audit trail
  3. Verify each entry contains: timestamp, actor, object, from_state, to_state, justification
- **Expected Output**: Audit trail meets SOC 2 evidence requirements
