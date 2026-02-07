# Role Inducements Functional Tests

**API Base Path**: `/governance/roles/:role_id/inducements`, `/governance/roles/:role_id/induced-roles`
**Authentication**: JWT Bearer token with `admin` role required for mutations
**Required Headers**: `Content-Type: application/json`, `Authorization: Bearer <jwt>`
**Applicable Standards**: IGA Role Engineering, RBAC Automatic Entitlement Propagation

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: At least two governance roles must exist before inducement tests. For transitive inducement tests, a three-level role hierarchy is needed.

## Nominal Cases

### TC-GOV-IND-001: Create role inducement
- **Category**: Nominal
- **Standard**: IGA Role Engineering - Automatic Entitlement Inheritance
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Inducing role (parent) and induced role (child) exist
- **Input**:
  ```json
  POST /governance/roles/<inducing-role-id>/inducements
  {
    "induced_role_id": "<induced-role-id>",
    "description": "Finance Manager induces Finance Reader - all managers get read access automatically"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<uuid>",
    "inducing_role_id": "<inducing-role-id>",
    "induced_role_id": "<induced-role-id>",
    "is_enabled": true,
    "description": "Finance Manager induces Finance Reader...",
    "created_by": "<admin-user-id>",
    "created_at": "<iso8601>"
  }
  ```

### TC-GOV-IND-002: List role inducements
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role has multiple inducements
- **Input**:
  ```
  GET /governance/roles/<role-id>/inducements?limit=20&offset=0
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [...], "total": <count> }
  ```

### TC-GOV-IND-003: List inducements filtered by enabled status
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role has both enabled and disabled inducements
- **Input**:
  ```
  GET /governance/roles/<role-id>/inducements?enabled_only=true
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [...] }  // All items have is_enabled: true
  ```

### TC-GOV-IND-004: Get single inducement
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Inducement exists for the role
- **Input**:
  ```
  GET /governance/roles/<role-id>/inducements/<inducement-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "id": "<inducement-id>",
    "inducing_role_id": "<role-id>",
    "induced_role_id": "...",
    "inducing_role_name": "Finance Manager",
    "induced_role_name": "Finance Reader",
    ...
  }
  ```

### TC-GOV-IND-005: Delete inducement
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Inducement exists
- **Input**:
  ```
  DELETE /governance/roles/<role-id>/inducements/<inducement-id>
  ```
- **Expected Output**:
  ```
  Status: 204 No Content
  ```

### TC-GOV-IND-006: Enable inducement
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Inducement is disabled
- **Input**:
  ```
  POST /governance/roles/<role-id>/inducements/<inducement-id>/enable
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "is_enabled": true, ... }
  ```

### TC-GOV-IND-007: Disable inducement
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Inducement is enabled
- **Input**:
  ```
  POST /governance/roles/<role-id>/inducements/<inducement-id>/disable
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "is_enabled": false, ... }
  ```

### TC-GOV-IND-008: Get induced roles for a role
- **Category**: Nominal
- **Standard**: IGA Role Decomposition
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role has multiple inducements configured
- **Input**:
  ```
  GET /governance/roles/<role-id>/induced-roles
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "induced_roles": [
      { "role_id": "<induced-1>", "role_name": "Finance Reader", "via_inducement_id": "..." },
      { "role_id": "<induced-2>", "role_name": "Report Viewer", "via_inducement_id": "..." }
    ]
  }
  ```
- **Verification**: Returns transitively induced roles (chain resolution)

### TC-GOV-IND-009: Role assignment triggers inducement execution
- **Category**: Nominal
- **Standard**: IGA Automatic Provisioning
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role A induces Role B; Role B has constructions
- **Steps**:
  1. Assign Role A to user
  2. Verify user gets Role A constructions
  3. Verify induced Role B constructions also triggered
- **Expected Output**: Both direct and induced role constructions executed

### TC-GOV-IND-010: Role revocation triggers induced role cleanup
- **Category**: Nominal
- **Standard**: IGA Automatic Deprovisioning
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User has Role A which induces Role B
- **Steps**:
  1. Revoke Role A from user
  2. Verify Role A constructions deprovisioned
  3. Verify induced Role B constructions also deprovisioned
- **Expected Output**: Cascading deprovisioning through inducement chain

### TC-GOV-IND-011: Multiple inducements on same role
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role "Department Manager" exists
- **Steps**:
  1. Create inducement: Department Manager -> Basic Access
  2. Create inducement: Department Manager -> Report Viewer
  3. Create inducement: Department Manager -> Team Lead Tools
  4. Assign Department Manager to user
  5. Verify all three induced roles' constructions executed
- **Expected Output**: All inducements processed

---

## Edge Cases

### TC-GOV-IND-020: Create inducement with self-reference
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role exists
- **Input**:
  ```json
  POST /governance/roles/<role-id>/inducements
  { "induced_role_id": "<same-role-id>" }
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  Body: { "error": "Role cannot induce itself" }
  ```

### TC-GOV-IND-021: Create inducement causing circular dependency
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role A induces Role B; attempting to make Role B induce Role A
- **Input**:
  ```json
  POST /governance/roles/<role-b-id>/inducements
  { "induced_role_id": "<role-a-id>" }
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  Body: { "error": "Circular inducement dependency detected" }
  ```

### TC-GOV-IND-022: Create duplicate inducement
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Inducement from Role A to Role B already exists
- **Input**:
  ```json
  POST /governance/roles/<role-a-id>/inducements
  { "induced_role_id": "<role-b-id>" }
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  ```

### TC-GOV-IND-023: Delete non-existent inducement
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role exists
- **Input**:
  ```
  DELETE /governance/roles/<role-id>/inducements/00000000-0000-0000-0000-000000000099
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-GOV-IND-024: Create inducement with non-existent induced role
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Inducing role exists
- **Input**:
  ```json
  POST /governance/roles/<role-id>/inducements
  { "induced_role_id": "00000000-0000-0000-0000-000000000099" }
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-GOV-IND-025: Disabled inducement does not trigger on assignment
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role A has disabled inducement to Role B
- **Steps**:
  1. Assign Role A to user
  2. Verify Role B constructions NOT triggered
- **Expected Output**: Disabled inducements are skipped

### TC-GOV-IND-026: Description exceeding max length
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Inducing and induced roles exist
- **Input**:
  ```json
  POST /governance/roles/<role-id>/inducements
  { "induced_role_id": "<id>", "description": "<2001-chars>" }
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  ```

---

## Security Tests

### TC-GOV-IND-030: Create inducement without admin role
- **Category**: Security
- **Standard**: NIST SP 800-53 AC-6
- **Preconditions**: Fixtures: `TEST_TENANT`. JWT with user role only
- **Input**:
  ```json
  POST /governance/roles/<role-id>/inducements
  { "induced_role_id": "<id>" }
  ```
- **Expected Output**:
  ```
  Status: 403 Forbidden
  ```

### TC-GOV-IND-031: Access inducements cross-tenant
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role in tenant A; JWT for tenant B (second tenant required)
- **Input**:
  ```
  GET /governance/roles/<tenant-a-role>/inducements
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-GOV-IND-032: Create cross-tenant inducement
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Inducing role in tenant A; induced role in tenant B (second tenant required)
- **Input**:
  ```json
  POST /governance/roles/<tenant-a-role>/inducements
  { "induced_role_id": "<tenant-b-role>" }
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

---

## Compliance Tests

### TC-GOV-IND-040: Inducement supports automated access provisioning
- **Category**: Compliance
- **Standard**: IGA Birthright Access / ISO 27001 A.9.2.2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Roles, inducements, and constructions configured
- **Steps**:
  1. Create "Employee" role with inducement to "Email Access" role
  2. "Email Access" role has AD group membership construction
  3. Assign "Employee" role to new hire
  4. Verify email access provisioned automatically via inducement
- **Expected Output**: New employees automatically receive email access without separate request

### TC-GOV-IND-041: Inducement chain provides complete role decomposition
- **Category**: Compliance
- **Standard**: RBAC Engineering Best Practices
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Three-level role hierarchy with inducements and constructions
- **Steps**:
  1. Create hierarchy: "VP Finance" induces "Finance Manager" induces "Finance Analyst"
  2. Assign "VP Finance" to user
  3. Verify all three levels of constructions applied
- **Expected Output**: Transitive inducement resolution provides complete access profile

### TC-GOV-IND-042: Inducement revocation cascades through chain
- **Category**: Compliance
- **Standard**: ISO 27001 A.9.2.6 (Removal of Access Rights)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User has role with transitive inducements configured
- **Steps**:
  1. User has "VP Finance" role with transitive inducements
  2. Revoke "VP Finance" from user
  3. Verify all induced constructions deprovisioned in reverse order
- **Expected Output**: Clean removal of all access granted through inducement chain
