# Role Management Functional Tests

**API Base Path**: `GET/POST /governance/roles`, `GET/PUT/DELETE /governance/roles/:role_id`
**Authentication**: JWT Bearer token with `admin` role required for mutations
**Required Headers**: `Content-Type: application/json`, `Authorization: Bearer <jwt>`
**Applicable Standards**: NIST RBAC (Role-Based Access Control), ISO 27001 A.9.2, NIST SP 800-53 AC-2

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: Some tests require existing role hierarchies, entitlements, and user-role assignments

---

## Nominal Cases

### TC-GOV-ROLE-001: Create business role
- **Category**: Nominal
- **Standard**: NIST RBAC Core
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as tenant admin
- **Input**:
  ```json
  POST /governance/roles
  {
    "name": "Finance Analyst",
    "description": "Role for financial reporting and analysis",
    "role_type": "business",
    "risk_level": "medium"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<uuid>",
    "tenant_id": "<tenant-uuid>",
    "name": "Finance Analyst",
    "description": "Role for financial reporting and analysis",
    "role_type": "business",
    "risk_level": "medium",
    "parent_role_id": null,
    "is_active": true,
    "created_at": "<iso8601>"
  }
  ```

### TC-GOV-ROLE-002: Create role with parent (hierarchy)
- **Category**: Nominal
- **Standard**: NIST Hierarchical RBAC
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Parent role "Finance Department" exists
- **Input**:
  ```json
  POST /governance/roles
  {
    "name": "Finance Manager",
    "parent_role_id": "<finance-dept-role-id>",
    "role_type": "business"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: { "parent_role_id": "<finance-dept-role-id>", ... }
  ```

### TC-GOV-ROLE-003: List roles with pagination
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Multiple roles exist in tenant
- **Input**:
  ```
  GET /governance/roles?limit=10&offset=0
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [...], "total": <count> }
  ```

### TC-GOV-ROLE-004: Get role by ID
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role exists with known ID
- **Input**:
  ```
  GET /governance/roles/<role-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "id": "<role-id>", "name": "Finance Analyst", ... }
  ```

### TC-GOV-ROLE-005: Update role
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role exists
- **Input**:
  ```json
  PUT /governance/roles/<role-id>
  {
    "name": "Senior Finance Analyst",
    "description": "Updated role with elevated privileges",
    "risk_level": "high"
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "name": "Senior Finance Analyst", "risk_level": "high", ... }
  ```

### TC-GOV-ROLE-006: Delete role
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role exists with no active assignments
- **Input**:
  ```
  DELETE /governance/roles/<role-id>
  ```
- **Expected Output**:
  ```
  Status: 204 No Content
  ```

### TC-GOV-ROLE-007: Get role hierarchy tree
- **Category**: Nominal
- **Standard**: NIST Hierarchical RBAC
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role hierarchy exists (Organization -> Department -> Team)
- **Input**:
  ```
  GET /governance/roles/tree
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "tree": [{ "id": "<org-role>", "children": [{ "id": "<dept-role>", "children": [...] }] }] }
  ```

### TC-GOV-ROLE-008: Get role ancestors
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role is child in hierarchy
- **Input**:
  ```
  GET /governance/roles/<child-role-id>/ancestors
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "ancestors": [<grandparent-role>, <parent-role>] }
  ```

### TC-GOV-ROLE-009: Get role descendants
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role is parent in hierarchy
- **Input**:
  ```
  GET /governance/roles/<parent-role-id>/descendants
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "descendants": [<child-role>, <grandchild-role>] }
  ```

### TC-GOV-ROLE-010: Get role children (direct only)
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role has direct children
- **Input**:
  ```
  GET /governance/roles/<parent-role-id>/children
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "children": [<child-role-1>, <child-role-2>] }
  ```

### TC-GOV-ROLE-011: Move role in hierarchy
- **Category**: Nominal
- **Standard**: NIST RBAC Role Engineering
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role exists as child of one parent; new parent exists
- **Input**:
  ```json
  POST /governance/roles/<role-id>/move
  { "new_parent_id": "<new-parent-role-id>" }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  ```

### TC-GOV-ROLE-012: Assign role to user
- **Category**: Nominal
- **Standard**: NIST RBAC User-Role Assignment
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role and user exist
- **Input**:
  ```json
  POST /governance/roles/<role-id>/assignments/<user-id>
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  ```

### TC-GOV-ROLE-013: List user's roles
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User has multiple role assignments
- **Input**:
  ```
  GET /governance/users/<user-id>/roles
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "roles": [<role-1>, <role-2>] }
  ```

### TC-GOV-ROLE-014: Revoke role from user
- **Category**: Nominal
- **Standard**: Least Privilege Principle
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User has role assigned
- **Input**:
  ```
  DELETE /governance/roles/<role-id>/assignments/<user-id>
  ```
- **Expected Output**:
  ```
  Status: 204 No Content
  ```

### TC-GOV-ROLE-015: Check if user has specific role
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User has role assigned
- **Input**:
  ```
  GET /governance/roles/<role-id>/assignments/<user-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "has_role": true, ... }
  ```

### TC-GOV-ROLE-016: Add entitlement to role
- **Category**: Nominal
- **Standard**: NIST RBAC Permission-Role Assignment
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role and entitlement exist
- **Input**:
  ```json
  POST /governance/roles/<role-id>/entitlements
  { "entitlement_id": "<entitlement-id>" }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  ```

### TC-GOV-ROLE-017: Get effective entitlements (including inherited)
- **Category**: Nominal
- **Standard**: NIST Hierarchical RBAC
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Parent role has entitlement A; child role has entitlement B
- **Input**:
  ```
  GET /governance/roles/<child-role-id>/effective-entitlements
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "entitlements": [<entitlement-A-from-parent>, <entitlement-B-direct>] }
  ```

### TC-GOV-ROLE-018: Get role impact analysis
- **Category**: Nominal
- **Standard**: IGA Change Impact Assessment
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role has users and child roles assigned
- **Input**:
  ```
  GET /governance/roles/<role-id>/impact
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "affected_users": <count>, "affected_child_roles": <count>, ... }
  ```

---

## Edge Cases

### TC-GOV-ROLE-020: Create role with duplicate name
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role "Finance Analyst" already exists
- **Input**:
  ```json
  POST /governance/roles
  { "name": "Finance Analyst" }
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  ```

### TC-GOV-ROLE-021: Delete role with active assignments
- **Category**: Edge Case
- **Standard**: NIST RBAC Referential Integrity
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role has users assigned
- **Input**:
  ```
  DELETE /governance/roles/<role-id>
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  Body: { "error": "Cannot delete role with active assignments" }
  ```

### TC-GOV-ROLE-022: Move role to create circular hierarchy
- **Category**: Edge Case
- **Standard**: NIST RBAC DAG constraint
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role A is ancestor of Role B
- **Input**:
  ```json
  POST /governance/roles/<role-a-id>/move
  { "new_parent_id": "<role-b-id>" }
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  Body: { "error": "Circular hierarchy detected" }
  ```

### TC-GOV-ROLE-023: Assign same role to user twice
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User already has the role
- **Input**:
  ```json
  POST /governance/roles/<role-id>/assignments/<user-id>
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  ```

### TC-GOV-ROLE-024: Get non-existent role
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```
  GET /governance/roles/00000000-0000-0000-0000-000000000099
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-GOV-ROLE-025: Add inheritance block to role
- **Category**: Edge Case
- **Standard**: NIST RBAC Constrained RBAC
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Child role inherits from parent
- **Input**:
  ```json
  POST /governance/roles/<child-role-id>/inheritance-blocks
  { "blocked_entitlement_id": "<entitlement-id>" }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  ```
- **Verification**: Blocked entitlement excluded from effective entitlements

### TC-GOV-ROLE-026: Remove role entitlement
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Entitlement is mapped to role
- **Input**:
  ```
  DELETE /governance/roles/<role-id>/entitlements/<entitlement-id>
  ```
- **Expected Output**:
  ```
  Status: 204 No Content
  ```

---

## Security Tests

### TC-GOV-ROLE-030: Create role without admin privileges
- **Category**: Security
- **Standard**: NIST SP 800-53 AC-6 (Least Privilege)
- **Preconditions**: Fixtures: `TEST_TENANT`. JWT with `user` role only
- **Input**:
  ```json
  POST /governance/roles
  { "name": "Unauthorized Role" }
  ```
- **Expected Output**:
  ```
  Status: 403 Forbidden
  ```

### TC-GOV-ROLE-031: Access role from different tenant
- **Category**: Security
- **Standard**: ISO 27001 A.9.4.1 (Tenant Isolation)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role belongs to tenant A; JWT for tenant B (second tenant required)
- **Input**:
  ```
  GET /governance/roles/<tenant-a-role-id>
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-GOV-ROLE-032: Assign role cross-tenant
- **Category**: Security
- **Standard**: Multi-tenancy isolation
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role in tenant A; user in tenant B; JWT for tenant A (second tenant required)
- **Input**:
  ```json
  POST /governance/roles/<role-id>/assignments/<user-in-tenant-b>
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-GOV-ROLE-033: Delete role without authentication
- **Category**: Security
- **Preconditions**: Fixtures: `TEST_TENANT`
- **Input**:
  ```
  DELETE /governance/roles/<role-id>
  ```
  (No Authorization header)
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  ```

---

## Compliance Tests

### TC-GOV-ROLE-040: Role hierarchy supports NIST RBAC model
- **Category**: Compliance
- **Standard**: NIST SP 800-53 AC-2 (Account Management)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**:
  1. Create role hierarchy: Organization -> Department -> Team -> Individual
  2. Assign entitlements at each level
  3. Verify effective entitlements cascade correctly
- **Expected Output**: Child roles inherit parent entitlements per NIST hierarchical RBAC

### TC-GOV-ROLE-041: Role assignment enforces least privilege
- **Category**: Compliance
- **Standard**: NIST SP 800-53 AC-6 (Least Privilege)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**:
  1. Create role with minimal entitlements
  2. Assign to user
  3. Verify user effective access contains only role entitlements
  4. Remove role
  5. Verify user loses those entitlements
- **Expected Output**: Access granted and revoked cleanly with no residual permissions

### TC-GOV-ROLE-042: Role recompute updates effective entitlements
- **Category**: Compliance
- **Standard**: SOC 2 CC6.1 (Logical Access)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role hierarchy with entitlements
- **Input**:
  ```
  POST /governance/roles/<role-id>/effective-entitlements/recompute
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  ```
- **Verification**: After adding new entitlement to parent, recompute propagates to children

### TC-GOV-ROLE-043: Role deletion audit trail
- **Category**: Compliance
- **Standard**: SOX Section 404 (Change Management)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**:
  1. Create role
  2. Assign entitlements
  3. Delete role
  4. Verify audit log contains role deletion event with actor, timestamp, details
- **Expected Output**: Audit trail preserved for compliance review
