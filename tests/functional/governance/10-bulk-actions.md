# Bulk Action Engine Functional Tests

**API Base Path**: `/governance/admin/bulk-actions`
**Authentication**: JWT Bearer token with `admin` role required
**Required Headers**: `Content-Type: application/json`, `Authorization: Bearer <jwt>`
**Applicable Standards**: IGA Operational Efficiency, ISO 27001 A.9.2 (Change Management)

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: Users with various department and lifecycle_state attributes should exist to test filter expressions. At least one governance role must exist for assign_role/revoke_role action types.

## Nominal Cases

### TC-GOV-BULK-001: Create bulk action with filter expression
- **Category**: Nominal
- **Standard**: IGA Mass Operations
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin; users exist with department attributes
- **Input**:
  ```json
  POST /governance/admin/bulk-actions
  {
    "filter_expression": "department = 'engineering' AND lifecycle_state = 'active'",
    "action_type": "assign_role",
    "action_params": { "role_id": "<role-id>" },
    "justification": "Quarterly role alignment per engineering leadership request"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<uuid>",
    "filter_expression": "department = 'engineering' AND lifecycle_state = 'active'",
    "action_type": "assign_role",
    "status": "pending",
    "total_matched": 0,
    "processed_count": 0,
    "justification": "Quarterly role alignment...",
    "created_at": "<iso8601>"
  }
  ```

### TC-GOV-BULK-002: Create bulk revoke role action
- **Category**: Nominal
- **Standard**: Least Privilege Enforcement
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Users with roles and lifecycle_state attributes exist
- **Input**:
  ```json
  POST /governance/admin/bulk-actions
  {
    "filter_expression": "department = 'marketing' AND lifecycle_state = 'terminated'",
    "action_type": "revoke_role",
    "action_params": { "role_id": "<role-id>" },
    "justification": "Cleanup terminated marketing employee roles"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  ```

### TC-GOV-BULK-003: Create bulk disable action
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Active users exist with various last_login dates
- **Input**:
  ```json
  POST /governance/admin/bulk-actions
  {
    "filter_expression": "last_login < '2025-01-01' AND lifecycle_state = 'active'",
    "action_type": "disable",
    "action_params": {},
    "justification": "Disable dormant accounts per security policy"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  ```

### TC-GOV-BULK-004: List bulk actions
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Multiple bulk actions exist
- **Input**:
  ```
  GET /governance/admin/bulk-actions?limit=20&offset=0
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [...], "total": <count> }
  ```

### TC-GOV-BULK-005: Get bulk action details
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Bulk action exists
- **Input**:
  ```
  GET /governance/admin/bulk-actions/<action-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "id": "<action-id>",
    "status": "pending",
    "filter_expression": "...",
    "action_type": "assign_role",
    "total_matched": <count>,
    "processed_count": <count>,
    "failed_count": <count>,
    ...
  }
  ```

### TC-GOV-BULK-006: Preview bulk action (dry run)
- **Category**: Nominal
- **Standard**: IGA Impact Assessment
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Bulk action in "pending" status
- **Input**:
  ```
  POST /governance/admin/bulk-actions/<action-id>/preview
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "total_matched": 42,
    "sample_users": [
      { "user_id": "...", "display_name": "...", "email": "..." }
    ],
    "estimated_impact": "42 users will receive role 'Finance Analyst'"
  }
  ```

### TC-GOV-BULK-007: Execute bulk action
- **Category**: Nominal
- **Standard**: IGA Mass Provisioning
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Bulk action in "pending" status, preview reviewed
- **Input**:
  ```
  POST /governance/admin/bulk-actions/<action-id>/execute
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "status": "executing", "total_matched": 42, ... }
  ```
- **Side Effects**: Async processing begins; roles assigned to matched users

### TC-GOV-BULK-008: Cancel executing bulk action
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Bulk action in "executing" status
- **Input**:
  ```
  POST /governance/admin/bulk-actions/<action-id>/cancel
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "status": "cancelled", "processed_count": <partial>, ... }
  ```

### TC-GOV-BULK-009: Delete completed bulk action record
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Bulk action is completed or cancelled
- **Input**:
  ```
  DELETE /governance/admin/bulk-actions/<action-id>
  ```
- **Expected Output**:
  ```
  Status: 204 No Content
  ```

### TC-GOV-BULK-010: Validate filter expression
- **Category**: Nominal
- **Standard**: IGA Expression Safety
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```json
  POST /governance/admin/bulk-actions/validate-expression
  { "filter_expression": "department = 'engineering' AND status = 'active'" }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "valid": true, "parsed_tokens": [...] }
  ```

### TC-GOV-BULK-011: Bulk action with modify_attribute type
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Users with department attributes exist
- **Input**:
  ```json
  POST /governance/admin/bulk-actions
  {
    "filter_expression": "department = 'old_name'",
    "action_type": "modify_attribute",
    "action_params": { "attribute": "department", "value": "new_name" },
    "justification": "Department rename per HR restructuring"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  ```

### TC-GOV-BULK-012: Bulk action progress tracking
- **Category**: Nominal
- **Standard**: IGA Operational Monitoring
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Bulk action is executing
- **Steps**:
  1. Execute bulk action
  2. Poll GET `/governance/admin/bulk-actions/<id>` periodically
  3. Verify `processed_count` increases
  4. Verify final status is "completed"
- **Expected Output**: Progress tracked from 0 to `total_matched`

---

## Edge Cases

### TC-GOV-BULK-020: Invalid filter expression
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```json
  POST /governance/admin/bulk-actions/validate-expression
  { "filter_expression": "SELECT * FROM users; DROP TABLE users;" }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "valid": false, "error": "Invalid expression syntax" }
  ```

### TC-GOV-BULK-021: Empty filter expression
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```json
  POST /governance/admin/bulk-actions
  {
    "filter_expression": "",
    "action_type": "assign_role",
    "action_params": { "role_id": "<id>" },
    "justification": "Empty filter"
  }
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  Body: { "error": "Filter expression must be between 1 and 10000 characters" }
  ```

### TC-GOV-BULK-022: Justification too short
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```json
  POST /governance/admin/bulk-actions
  {
    "filter_expression": "department = 'eng'",
    "action_type": "assign_role",
    "action_params": { "role_id": "<id>" },
    "justification": "short"
  }
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  Body: { "error": "Justification must be between 10 and 2000 characters" }
  ```

### TC-GOV-BULK-023: Execute already-completed bulk action
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Bulk action status is "completed"
- **Input**:
  ```
  POST /governance/admin/bulk-actions/<action-id>/execute
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  Body: { "error": "Bulk action is not in pending state" }
  ```

### TC-GOV-BULK-024: Filter matching zero users
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```json
  POST /governance/admin/bulk-actions
  {
    "filter_expression": "department = 'nonexistent_dept_xyz'",
    "action_type": "assign_role",
    "action_params": { "role_id": "<id>" },
    "justification": "Testing zero match scenario"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  ```
- **Verification**: Preview shows `total_matched: 0`; execute completes immediately

### TC-GOV-BULK-025: Delete executing bulk action
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Bulk action is "executing"
- **Input**:
  ```
  DELETE /governance/admin/bulk-actions/<action-id>
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  Body: { "error": "Cannot delete executing bulk action; cancel it first" }
  ```

### TC-GOV-BULK-026: Filter expression at maximum length (10000 chars)
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: Valid expression with many conditions totaling 10000 characters
- **Expected Output**:
  ```
  Status: 201 Created
  ```

---

## Security Tests

### TC-GOV-BULK-030: Create bulk action without admin role
- **Category**: Security
- **Standard**: NIST SP 800-53 AC-6 (Least Privilege)
- **Preconditions**: Fixtures: `TEST_TENANT`. JWT with non-admin role
- **Input**:
  ```json
  POST /governance/admin/bulk-actions
  { "filter_expression": "department = 'eng'", "action_type": "disable", "action_params": {}, "justification": "Unauthorized action" }
  ```
- **Expected Output**:
  ```
  Status: 403 Forbidden
  ```

### TC-GOV-BULK-031: Execute bulk action without admin role
- **Category**: Security
- **Preconditions**: Fixtures: `TEST_TENANT`. Bulk action exists; authenticated with non-admin JWT
- **Input**:
  ```
  POST /governance/admin/bulk-actions/<id>/execute
  ```
  (JWT with non-admin role)
- **Expected Output**:
  ```
  Status: 403 Forbidden
  ```

### TC-GOV-BULK-032: Cross-tenant bulk action access
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Bulk action in tenant A; JWT for tenant B admin (second tenant required)
- **Input**:
  ```
  GET /governance/admin/bulk-actions/<tenant-a-action-id>
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-GOV-BULK-033: SQL injection via filter expression
- **Category**: Security
- **Standard**: OWASP Top 10 (Injection)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```json
  POST /governance/admin/bulk-actions
  {
    "filter_expression": "department = 'eng'; DROP TABLE users; --",
    "action_type": "assign_role",
    "action_params": { "role_id": "<id>" },
    "justification": "SQL injection test scenario"
  }
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity  (or 201 with expression treated as literal)
  ```
- **Verification**: No SQL executed; expression parsed by safe expression evaluator with recursion depth limit

---

## Compliance Tests

### TC-GOV-BULK-040: Bulk action audit trail for SOX compliance
- **Category**: Compliance
- **Standard**: SOX Section 404 (Change Management)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Users with filterable attributes exist
- **Steps**:
  1. Create bulk action
  2. Preview (record of who previewed)
  3. Execute (record of who executed)
  4. Verify audit log contains: creator, justification, expression, action type, execution time, results
- **Expected Output**: Complete audit trail for all bulk operations

### TC-GOV-BULK-041: Justification requirement for bulk operations
- **Category**: Compliance
- **Standard**: ISO 27001 A.12.1.2 (Change Management)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**:
  1. Attempt bulk action without justification -> rejected
  2. Attempt bulk action with justification < 10 chars -> rejected
  3. Create bulk action with valid justification -> accepted
- **Expected Output**: All bulk operations require documented business justification

### TC-GOV-BULK-042: Preview-before-execute pattern
- **Category**: Compliance
- **Standard**: IGA Change Approval
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Users with filterable attributes exist
- **Steps**:
  1. Create bulk action
  2. Execute preview to see affected users
  3. Review matched user count and sample
  4. Execute or cancel based on review
- **Expected Output**: Two-step process prevents accidental mass changes
