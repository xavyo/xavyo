# Entitlement Management Functional Tests

**API Base Path**: `GET/POST /governance/entitlements`, `GET/PUT/DELETE /governance/entitlements/:id`
**Related APIs**: `/governance/assignments`, `/governance/role-entitlements`, `/governance/users/:user_id/effective-access`
**Authentication**: JWT Bearer token with `admin` role required for mutations
**Required Headers**: `Content-Type: application/json`, `Authorization: Bearer <jwt>`
**Applicable Standards**: IGA Entitlement Lifecycle, ISO 27001 A.9.2, GDPR Article 6

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: Some tests require existing applications, entitlements with assignments, roles, and users with effective access

---

## Nominal Cases

### TC-GOV-ENT-001: Create entitlement with required fields
- **Category**: Nominal
- **Standard**: IGA Entitlement Catalog
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Application exists in governance registry
- **Input**:
  ```json
  POST /governance/entitlements
  {
    "application_id": "<app-id>",
    "name": "Read Financial Reports",
    "risk_level": "low"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<uuid>",
    "tenant_id": "<tenant-uuid>",
    "application_id": "<app-id>",
    "name": "Read Financial Reports",
    "risk_level": "low",
    "status": "active",
    "is_delegable": true,
    "created_at": "<iso8601>"
  }
  ```

### TC-GOV-ENT-002: Create entitlement with full metadata
- **Category**: Nominal
- **Standard**: IGA Entitlement Lifecycle
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Application and owner user exist
- **Input**:
  ```json
  POST /governance/entitlements
  {
    "application_id": "<app-id>",
    "name": "Write Financial Data",
    "description": "Allows modification of financial records",
    "risk_level": "high",
    "owner_id": "<user-id>",
    "external_id": "FIN-WRITE-001",
    "is_delegable": false,
    "metadata": { "compliance_tag": "SOX-critical" }
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: { "risk_level": "high", "owner_id": "<user-id>", "is_delegable": false, ... }
  ```

### TC-GOV-ENT-003: Create entitlement with GDPR data protection fields
- **Category**: Nominal
- **Standard**: GDPR Article 6 (Lawful Basis)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Application exists
- **Input**:
  ```json
  POST /governance/entitlements
  {
    "application_id": "<app-id>",
    "name": "Access PII Records",
    "risk_level": "critical",
    "data_protection_classification": "personal_data",
    "legal_basis": "legitimate_interest",
    "retention_period_days": 365,
    "data_controller": "Acme Corp",
    "data_processor": "Cloud Provider Inc",
    "purposes": ["customer_support", "billing"]
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: { "data_protection_classification": "personal_data", "legal_basis": "legitimate_interest", ... }
  ```

### TC-GOV-ENT-004: List entitlements with pagination
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Multiple entitlements exist
- **Input**:
  ```
  GET /governance/entitlements?limit=10&offset=0
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [...], "total": <count> }
  ```

### TC-GOV-ENT-005: Get entitlement by ID
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Entitlement exists
- **Input**:
  ```
  GET /governance/entitlements/<entitlement-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "id": "<entitlement-id>", "name": "Read Financial Reports", ... }
  ```

### TC-GOV-ENT-006: Update entitlement
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Entitlement exists
- **Input**:
  ```json
  PUT /governance/entitlements/<entitlement-id>
  {
    "name": "Read All Financial Reports",
    "risk_level": "medium",
    "description": "Expanded scope to include all financial reports"
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "name": "Read All Financial Reports", "risk_level": "medium", ... }
  ```

### TC-GOV-ENT-007: Delete entitlement
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Entitlement exists with no active assignments
- **Input**:
  ```
  DELETE /governance/entitlements/<entitlement-id>
  ```
- **Expected Output**:
  ```
  Status: 204 No Content
  ```

### TC-GOV-ENT-008: Set entitlement owner
- **Category**: Nominal
- **Standard**: IGA Entitlement Ownership
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Entitlement and user exist
- **Input**:
  ```json
  PUT /governance/entitlements/<entitlement-id>/owner
  { "owner_id": "<user-id>" }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  ```

### TC-GOV-ENT-009: Remove entitlement owner
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Entitlement has an owner
- **Input**:
  ```
  DELETE /governance/entitlements/<entitlement-id>/owner
  ```
- **Expected Output**:
  ```
  Status: 204 No Content
  ```

### TC-GOV-ENT-010: Create entitlement assignment (direct)
- **Category**: Nominal
- **Standard**: IGA Assignment Management
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Entitlement and target user exist
- **Input**:
  ```json
  POST /governance/assignments
  {
    "entitlement_id": "<entitlement-id>",
    "target_id": "<user-id>",
    "target_type": "user"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: { "id": "<assignment-id>", "status": "active", ... }
  ```

### TC-GOV-ENT-011: Bulk create assignments
- **Category**: Nominal
- **Standard**: IGA Operational Efficiency
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Multiple entitlements and users exist
- **Input**:
  ```json
  POST /governance/assignments/bulk
  {
    "assignments": [
      { "entitlement_id": "<ent-1>", "target_id": "<user-1>", "target_type": "user" },
      { "entitlement_id": "<ent-2>", "target_id": "<user-2>", "target_type": "user" }
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: { "created": 2, "assignments": [...] }
  ```

### TC-GOV-ENT-012: List assignments with filters
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Assignments exist
- **Input**:
  ```
  GET /governance/assignments?entitlement_id=<ent-id>&limit=50&offset=0
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [...], "total": <count> }
  ```

### TC-GOV-ENT-013: Revoke assignment
- **Category**: Nominal
- **Standard**: IGA Entitlement Revocation
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Assignment exists
- **Input**:
  ```
  DELETE /governance/assignments/<assignment-id>
  ```
- **Expected Output**:
  ```
  Status: 204 No Content
  ```

### TC-GOV-ENT-014: Map entitlement to role
- **Category**: Nominal
- **Standard**: NIST RBAC Permission-Role Assignment
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Role and entitlement exist
- **Input**:
  ```json
  POST /governance/role-entitlements
  { "role_id": "<role-id>", "entitlement_id": "<entitlement-id>" }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  ```

### TC-GOV-ENT-015: Get user effective access
- **Category**: Nominal
- **Standard**: IGA Effective Access Computation
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User has direct assignments + role-based assignments
- **Input**:
  ```
  GET /governance/users/<user-id>/effective-access
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "direct_entitlements": [...],
    "role_entitlements": [...],
    "effective_entitlements": [...]
  }
  ```

### TC-GOV-ENT-016: Check specific entitlement access for user
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User has the entitlement (via role or direct)
- **Input**:
  ```
  GET /governance/users/<user-id>/entitlements/<entitlement-id>/check
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "has_access": true, "source": "role", "role_id": "<role-id>" }
  ```

---

## Edge Cases

### TC-GOV-ENT-020: Create entitlement with non-existent application
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```json
  POST /governance/entitlements
  {
    "application_id": "00000000-0000-0000-0000-000000000099",
    "name": "Orphan Entitlement",
    "risk_level": "low"
  }
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  Body: { "error": "Application not found" }
  ```

### TC-GOV-ENT-021: Delete entitlement with active assignments
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Entitlement has active assignments
- **Input**:
  ```
  DELETE /governance/entitlements/<entitlement-id>
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  Body: { "error": "Cannot delete entitlement with active assignments" }
  ```

### TC-GOV-ENT-022: Create duplicate entitlement name in same application
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Entitlement "Read Reports" exists for application
- **Input**:
  ```json
  POST /governance/entitlements
  { "application_id": "<same-app>", "name": "Read Reports", "risk_level": "low" }
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  ```

### TC-GOV-ENT-023: Set owner to non-existent user
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Entitlement exists
- **Input**:
  ```json
  PUT /governance/entitlements/<ent-id>/owner
  { "owner_id": "00000000-0000-0000-0000-000000000099" }
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-GOV-ENT-024: Assign entitlement that is in deprecated status
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Entitlement status is "deprecated"
- **Input**:
  ```json
  POST /governance/assignments
  { "entitlement_id": "<deprecated-ent>", "target_id": "<user>", "target_type": "user" }
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  Body: { "error": "Cannot assign deprecated entitlement" }
  ```

### TC-GOV-ENT-025: Name exceeding 255 characters
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```json
  POST /governance/entitlements
  { "application_id": "<app>", "name": "<256-chars>", "risk_level": "low" }
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  Body: { "error": "Name must be between 1 and 255 characters" }
  ```

### TC-GOV-ENT-026: Negative retention period
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```json
  POST /governance/entitlements
  { "application_id": "<app>", "name": "Bad Retention", "risk_level": "low", "retention_period_days": -30 }
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  ```

---

## Security Tests

### TC-GOV-ENT-030: Create entitlement without admin role
- **Category**: Security
- **Standard**: NIST SP 800-53 AC-6
- **Preconditions**: Fixtures: `TEST_TENANT`. JWT with non-admin role
- **Input**:
  ```json
  POST /governance/entitlements
  { "application_id": "<app>", "name": "Unauthorized", "risk_level": "low" }
  ```
- **Expected Output**:
  ```
  Status: 403 Forbidden
  ```

### TC-GOV-ENT-031: Access entitlement from different tenant
- **Category**: Security
- **Standard**: ISO 27001 A.9.4.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Entitlement in tenant A; JWT for tenant B (second tenant required)
- **Input**:
  ```
  GET /governance/entitlements/<tenant-a-ent-id>
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-GOV-ENT-032: View other user's effective access cross-tenant
- **Category**: Security
- **Standard**: Multi-tenancy isolation
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User in tenant A; JWT for tenant B admin (second tenant required)
- **Input**:
  ```
  GET /governance/users/<tenant-a-user>/effective-access
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

---

## Compliance Tests

### TC-GOV-ENT-040: GDPR data protection report
- **Category**: Compliance
- **Standard**: GDPR Article 30 (Records of Processing Activities)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Entitlements with data protection classifications exist
- **Input**:
  ```
  GET /governance/gdpr/report
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "total_entitlements": <count>,
    "personal_data_entitlements": <count>,
    "sensitive_data_entitlements": <count>,
    "entitlements": [...]
  }
  ```

### TC-GOV-ENT-041: GDPR user data protection summary
- **Category**: Compliance
- **Standard**: GDPR Article 15 (Right of Access)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User has assignments to entitlements with GDPR classifications
- **Input**:
  ```
  GET /governance/gdpr/users/<user-id>/data-protection
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "entitlements_with_personal_data": [...], "legal_bases": [...], "purposes": [...] }
  ```

### TC-GOV-ENT-042: Entitlement risk classification supports SOX controls
- **Category**: Compliance
- **Standard**: SOX Section 404
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**:
  1. Create entitlement with `risk_level: "critical"` and metadata `{ "compliance_tag": "SOX-critical" }`
  2. Verify entitlement appears in risk reports
  3. Verify SoD rules can reference this entitlement
- **Expected Output**: Critical entitlements tracked for SOX compliance

### TC-GOV-ENT-043: Entitlement ownership required for certification
- **Category**: Compliance
- **Standard**: SOC 2 CC6.1 (Logical Access Controls)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**:
  1. Create entitlement without owner
  2. Attempt to include in certification campaign
  3. Verify system flags unowned entitlements
- **Expected Output**: System tracks and reports entitlements lacking owners
