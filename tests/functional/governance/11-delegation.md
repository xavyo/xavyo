# Delegation and Power of Attorney Functional Tests

**API Base Path**: `/governance/delegations`, `/governance/power-of-attorney`, `/governance/admin/power-of-attorney`
**Authentication**: JWT Bearer token; admin for some operations, authenticated user for self-service
**Required Headers**: `Content-Type: application/json`, `Authorization: Bearer <jwt>`
**Applicable Standards**: ISO 27001 A.9.2 (Delegation of Authority), IGA Approval Delegation

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`
- **Special Setup**: At least two users (delegator and delegate) must exist. For PoA tests, grantor and attorney users are needed. Admin authentication is required for admin PoA operations.

## Nominal Cases

### TC-GOV-DEL-001: Create delegation
- **Category**: Nominal
- **Standard**: ISO 27001 A.9.2 (User Access Management)
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated user (delegator) and delegate user exist
- **Input**:
  ```json
  POST /governance/delegations
  {
    "delegate_id": "<delegate-user-id>",
    "starts_at": "2026-03-01T00:00:00Z",
    "ends_at": "2026-03-15T23:59:59Z"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<uuid>",
    "delegator_id": "<current-user-id>",
    "delegate_id": "<delegate-user-id>",
    "starts_at": "2026-03-01T00:00:00Z",
    "ends_at": "2026-03-15T23:59:59Z",
    "status": "pending",
    "created_at": "<iso8601>"
  }
  ```

### TC-GOV-DEL-002: Create delegation with scope restrictions
- **Category**: Nominal
- **Standard**: ISO 27001 A.9.2 (Scoped Delegation)
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Delegator and delegate users exist; applications exist for scoping
- **Input**:
  ```json
  POST /governance/delegations
  {
    "delegate_id": "<delegate-user-id>",
    "starts_at": "2026-03-01T00:00:00Z",
    "ends_at": "2026-03-15T23:59:59Z",
    "scope": {
      "application_ids": ["<app-1>", "<app-2>"],
      "entitlement_ids": [],
      "role_ids": [],
      "workflow_types": ["access_request"]
    }
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: { "scope": { "application_ids": [...], ... }, ... }
  ```

### TC-GOV-DEL-003: List my delegations (outgoing)
- **Category**: Nominal
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. User has created delegations
- **Input**:
  ```
  GET /governance/delegations?limit=50&offset=0
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [...], "total": <count> }
  ```

### TC-GOV-DEL-004: List delegations as deputy (incoming)
- **Category**: Nominal
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. User is delegate for other users
- **Input**:
  ```
  GET /governance/delegations/as-deputy
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [...] }
  ```

### TC-GOV-DEL-005: Get delegation details
- **Category**: Nominal
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Delegation exists
- **Input**:
  ```
  GET /governance/delegations/<delegation-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "id": "<delegation-id>", "delegator_id": "...", "delegate_id": "...", ... }
  ```

### TC-GOV-DEL-006: Get delegation scope
- **Category**: Nominal
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Delegation with scope exists
- **Input**:
  ```
  GET /governance/delegations/<delegation-id>/scope
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "application_ids": [...], "workflow_types": [...], ... }
  ```

### TC-GOV-DEL-007: Revoke delegation
- **Category**: Nominal
- **Standard**: ISO 27001 A.9.2 (Access Revocation)
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Active delegation exists
- **Input**:
  ```
  POST /governance/delegations/<delegation-id>/revoke
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "status": "revoked", ... }
  ```

### TC-GOV-DEL-008: Extend delegation end date
- **Category**: Nominal
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Active delegation exists
- **Input**:
  ```json
  PATCH /governance/delegations/<delegation-id>/extend
  { "new_ends_at": "2026-04-15T23:59:59Z" }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "ends_at": "2026-04-15T23:59:59Z", ... }
  ```

### TC-GOV-DEL-009: List delegated work items
- **Category**: Nominal
- **Standard**: IGA Workflow Delegation
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Active delegation exists; delegator has pending approvals
- **Input**:
  ```
  GET /governance/work-items/delegated
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [{ "type": "access_request", "request_id": "...", "delegated_from": "..." }] }
  ```

### TC-GOV-DEL-010: Process delegation lifecycle
- **Category**: Nominal
- **Standard**: IGA Delegation Management
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Delegations with various start/end dates exist
- **Input**:
  ```
  POST /governance/delegations/process-lifecycle
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "activated": <count>, "expired": <count> }
  ```

### TC-GOV-DEL-011: Get delegation audit trail
- **Category**: Nominal
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Delegations with audit events exist
- **Input**:
  ```
  GET /governance/delegations/audit?limit=50&offset=0
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [{ "action": "created", "actor_id": "...", "timestamp": "..." }] }
  ```

### TC-GOV-DEL-012: Grant Power of Attorney
- **Category**: Nominal
- **Standard**: ISO 27001 A.9.2 (Identity Assumption)
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Grantor and attorney users exist
- **Input**:
  ```json
  POST /governance/power-of-attorney
  {
    "attorney_id": "<attorney-user-id>",
    "starts_at": "2026-03-01T00:00:00Z",
    "ends_at": "2026-03-15T23:59:59Z",
    "reason": "Covering for medical leave",
    "scope": {
      "application_ids": ["<app-id>"],
      "workflow_types": ["access_request", "certification"]
    }
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<uuid>",
    "grantor_id": "<current-user>",
    "attorney_id": "<attorney-user-id>",
    "status": "pending",
    "reason": "Covering for medical leave",
    ...
  }
  ```

### TC-GOV-DEL-013: List Power of Attorney grants
- **Category**: Nominal
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. PoA grants exist
- **Input**:
  ```
  GET /governance/power-of-attorney?direction=outgoing
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [...] }
  ```

### TC-GOV-DEL-014: Get PoA details
- **Category**: Nominal
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. PoA exists
- **Input**:
  ```
  GET /governance/power-of-attorney/<poa-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  ```

### TC-GOV-DEL-015: Assume identity via PoA
- **Category**: Nominal
- **Standard**: IGA Identity Assumption
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Active PoA exists; authenticated as attorney
- **Input**:
  ```
  POST /governance/power-of-attorney/<poa-id>/assume
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "assumed_identity": "<grantor-user-id>", "assumption_token": "<jwt>", ... }
  ```

### TC-GOV-DEL-016: Drop assumed identity
- **Category**: Nominal
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Currently assuming another identity
- **Input**:
  ```
  POST /governance/power-of-attorney/drop
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "restored_identity": "<original-user-id>" }
  ```

### TC-GOV-DEL-017: Get current assumption status
- **Category**: Nominal
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. User has an active PoA assumption
- **Input**:
  ```
  GET /governance/power-of-attorney/current-assumption
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "is_assuming": true, "assumed_user_id": "...", "poa_id": "...", ... }
  ```

### TC-GOV-DEL-018: Revoke PoA
- **Category**: Nominal
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Active PoA exists
- **Input**:
  ```json
  POST /governance/power-of-attorney/<poa-id>/revoke
  { "reason": "No longer needed" }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "status": "revoked" }
  ```

### TC-GOV-DEL-019: Extend PoA
- **Category**: Nominal
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Active PoA exists
- **Input**:
  ```json
  POST /governance/power-of-attorney/<poa-id>/extend
  { "new_ends_at": "2026-06-01T00:00:00Z" }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  ```

### TC-GOV-DEL-020: Get PoA audit trail
- **Category**: Nominal
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. PoA with audit events exists
- **Input**:
  ```
  GET /governance/power-of-attorney/<poa-id>/audit
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "events": [{ "event_type": "granted", "timestamp": "..." }, { "event_type": "assumed", ... }] }
  ```

### TC-GOV-DEL-021: Admin list all PoA grants
- **Category**: Nominal
- **Standard**: IGA Administrative Oversight
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Admin authenticated
- **Input**:
  ```
  GET /governance/admin/power-of-attorney
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [...] }
  ```

### TC-GOV-DEL-022: Admin revoke PoA
- **Category**: Nominal
- **Standard**: Emergency Access Revocation
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Admin authenticated; PoA exists
- **Input**:
  ```
  POST /governance/admin/power-of-attorney/<poa-id>/revoke
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  ```

---

## Edge Cases

### TC-GOV-DEL-025: Create delegation to self
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`
- **Input**:
  ```json
  POST /governance/delegations
  { "delegate_id": "<same-as-current-user>", "starts_at": "...", "ends_at": "..." }
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  Body: { "error": "Cannot delegate to yourself" }
  ```

### TC-GOV-DEL-026: Extend delegation to earlier date
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Delegation ends on March 15
- **Input**:
  ```json
  PATCH /governance/delegations/<id>/extend
  { "new_ends_at": "2026-03-01T00:00:00Z" }
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  Body: { "error": "New end date must be after current end date" }
  ```

### TC-GOV-DEL-027: PoA exceeding 90-day maximum
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Attorney user exists
- **Input**:
  ```json
  POST /governance/power-of-attorney
  {
    "attorney_id": "<id>",
    "starts_at": "2026-01-01T00:00:00Z",
    "ends_at": "2027-01-01T00:00:00Z"
  }
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  Body: { "error": "PoA duration cannot exceed 90 days" }
  ```

### TC-GOV-DEL-028: Assume identity without active PoA
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. PoA is expired or revoked
- **Input**:
  ```
  POST /governance/power-of-attorney/<expired-poa-id>/assume
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  ```

---

## Security Tests

### TC-GOV-DEL-030: Cross-tenant delegation attempt
- **Category**: Security
- **Standard**: Multi-tenancy Isolation
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Delegate user in different tenant (second tenant required)
- **Input**:
  ```json
  POST /governance/delegations
  { "delegate_id": "<user-in-other-tenant>", "starts_at": "...", "ends_at": "..." }
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-GOV-DEL-031: PoA assumption creates audit trail
- **Category**: Security
- **Standard**: ISO 27001 A.12.4 (Logging)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Active PoA between two users exists
- **Steps**:
  1. Attorney assumes grantor's identity
  2. Attorney performs actions (approve request, etc.)
  3. Attorney drops identity
  4. Verify all actions logged with both attorney_id and grantor_id
- **Expected Output**: Complete audit trail distinguishes assumed actions from normal actions

### TC-GOV-DEL-032: Admin PoA revoke from different tenant
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. PoA in tenant A; admin JWT for tenant B (second tenant required)
- **Input**:
  ```
  POST /governance/admin/power-of-attorney/<tenant-a-poa>/revoke
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

---

## Compliance Tests

### TC-GOV-DEL-040: ISO 27001 A.9.2 - Time-bounded delegation
- **Category**: Compliance
- **Standard**: ISO 27001 A.9.2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Delegator and delegate users exist
- **Steps**:
  1. Create delegation with starts_at and ends_at
  2. Verify delegation becomes active at starts_at
  3. Verify delegation expires at ends_at
  4. Verify expired delegation cannot be used
- **Expected Output**: Delegation is automatically time-bounded per ISO 27001

### TC-GOV-DEL-041: PoA audit trail completeness
- **Category**: Compliance
- **Standard**: SOC 2 CC6.2 (Prior to Issuing System Credentials)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Grantor and attorney users exist
- **Steps**:
  1. Grant PoA
  2. Assume identity
  3. Perform governance actions
  4. Drop identity
  5. Revoke PoA
  6. Verify audit trail contains all events: grant, assume, actions, drop, revoke
- **Expected Output**: Complete chronological audit trail of all PoA operations

### TC-GOV-DEL-042: Scoped delegation limits approval authority
- **Category**: Compliance
- **Standard**: IGA Least Privilege Delegation
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Delegator and delegate users exist; applications configured
- **Steps**:
  1. Create delegation scoped to application "SAP" and workflow type "access_request"
  2. Verify delegate can approve SAP access requests
  3. Verify delegate CANNOT approve requests for other applications
  4. Verify delegate CANNOT make certification decisions
- **Expected Output**: Delegation scope is enforced; delegate cannot exceed granted authority
