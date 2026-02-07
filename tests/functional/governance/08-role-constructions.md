# Role Construction Functional Tests

**API Base Path**: `/governance/roles/:role_id/constructions`, `/governance/roles/:role_id/effective-constructions`, `/governance/users/:user_id/effective-constructions`
**Authentication**: JWT Bearer token with `admin` role required for mutations
**Required Headers**: `Content-Type: application/json`, `Authorization: Bearer <jwt>`
**Applicable Standards**: RBAC Engineering, IGA Provisioning Automation

---

## Nominal Cases

### TC-GOV-CONS-001: Create role construction
- **Category**: Nominal
- **Standard**: RBAC Engineering - Role-to-Resource Mapping
- **Preconditions**: Role and connector exist
- **Input**:
  ```json
  POST /governance/roles/<role-id>/constructions
  {
    "connector_id": "<connector-id>",
    "object_class": "user",
    "account_type": "standard",
    "attribute_mappings": {
      "mappings": [
        { "target_attribute": "sAMAccountName", "source_expression": "user.username" },
        { "target_attribute": "mail", "source_expression": "user.email" },
        { "target_attribute": "memberOf", "source_expression": "'CN=Finance,DC=example,DC=com'" }
      ]
    },
    "deprovisioning_policy": {
      "action": "disable",
      "grace_period_days": 30
    },
    "priority": 10,
    "description": "Provisions AD account for finance role"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<uuid>",
    "role_id": "<role-id>",
    "connector_id": "<connector-id>",
    "object_class": "user",
    "account_type": "standard",
    "is_enabled": true,
    "priority": 10,
    "created_at": "<iso8601>"
  }
  ```

### TC-GOV-CONS-002: Create construction with condition
- **Category**: Nominal
- **Standard**: RBAC Conditional Provisioning
- **Input**:
  ```json
  POST /governance/roles/<role-id>/constructions
  {
    "connector_id": "<connector-id>",
    "object_class": "user",
    "condition": {
      "attribute": "department",
      "operator": "equals",
      "value": "finance"
    },
    "attribute_mappings": { "mappings": [] }
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: { "condition": { "attribute": "department", "operator": "equals", "value": "finance" }, ... }
  ```

### TC-GOV-CONS-003: List role constructions
- **Category**: Nominal
- **Preconditions**: Role has multiple constructions
- **Input**:
  ```
  GET /governance/roles/<role-id>/constructions?limit=20&offset=0
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [...], "total": <count> }
  ```

### TC-GOV-CONS-004: Get single construction
- **Category**: Nominal
- **Input**:
  ```
  GET /governance/roles/<role-id>/constructions/<construction-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "id": "<construction-id>", "connector_id": "...", "attribute_mappings": {...}, ... }
  ```

### TC-GOV-CONS-005: Update construction
- **Category**: Nominal
- **Preconditions**: Construction exists
- **Input**:
  ```json
  PUT /governance/roles/<role-id>/constructions/<construction-id>
  {
    "description": "Updated provisioning rule",
    "priority": 20,
    "deprovisioning_policy": { "action": "delete", "grace_period_days": 0 }
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  ```

### TC-GOV-CONS-006: Delete construction
- **Category**: Nominal
- **Input**:
  ```
  DELETE /governance/roles/<role-id>/constructions/<construction-id>
  ```
- **Expected Output**:
  ```
  Status: 204 No Content
  ```

### TC-GOV-CONS-007: Enable construction
- **Category**: Nominal
- **Preconditions**: Construction is disabled
- **Input**:
  ```
  POST /governance/roles/<role-id>/constructions/<construction-id>/enable
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "is_enabled": true, ... }
  ```

### TC-GOV-CONS-008: Disable construction
- **Category**: Nominal
- **Preconditions**: Construction is enabled
- **Input**:
  ```
  POST /governance/roles/<role-id>/constructions/<construction-id>/disable
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "is_enabled": false, ... }
  ```

### TC-GOV-CONS-009: Get effective constructions for role (including inherited)
- **Category**: Nominal
- **Standard**: RBAC Inheritance
- **Preconditions**: Role hierarchy with constructions at multiple levels
- **Input**:
  ```
  GET /governance/roles/<child-role-id>/effective-constructions
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "effective_constructions": [
      { "construction_id": "...", "source_role_id": "<parent-role>", "inherited": true, ... },
      { "construction_id": "...", "source_role_id": "<child-role>", "inherited": false, ... }
    ]
  }
  ```

### TC-GOV-CONS-010: Get effective constructions for user
- **Category**: Nominal
- **Standard**: RBAC User Provisioning Plan
- **Preconditions**: User has multiple role assignments, each with constructions
- **Input**:
  ```
  GET /governance/users/<user-id>/effective-constructions
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "effective_constructions": [...] }
  ```

### TC-GOV-CONS-011: Filter constructions by connector
- **Category**: Nominal
- **Input**:
  ```
  GET /governance/roles/<role-id>/constructions?connector_id=<connector-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [...] }  // Only constructions for specified connector
  ```

### TC-GOV-CONS-012: Filter constructions by enabled status
- **Category**: Nominal
- **Input**:
  ```
  GET /governance/roles/<role-id>/constructions?enabled_only=true
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [...] }  // All items have is_enabled: true
  ```

---

## Edge Cases

### TC-GOV-CONS-020: Create construction with non-existent connector
- **Category**: Edge Case
- **Input**:
  ```json
  POST /governance/roles/<role-id>/constructions
  { "connector_id": "00000000-0000-0000-0000-000000000099", "object_class": "user" }
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-GOV-CONS-021: Create construction for non-existent role
- **Category**: Edge Case
- **Input**:
  ```json
  POST /governance/roles/00000000-0000-0000-0000-000000000099/constructions
  { "connector_id": "<valid>", "object_class": "user" }
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-GOV-CONS-022: Object class exceeding max length
- **Category**: Edge Case
- **Input**:
  ```json
  POST /governance/roles/<role-id>/constructions
  { "connector_id": "<id>", "object_class": "<256-chars>" }
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  ```

### TC-GOV-CONS-023: Update non-existent construction
- **Category**: Edge Case
- **Input**:
  ```json
  PUT /governance/roles/<role-id>/constructions/00000000-0000-0000-0000-000000000099
  { "description": "Ghost" }
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-GOV-CONS-024: Description exceeding 2000 characters
- **Category**: Edge Case
- **Input**:
  ```json
  POST /governance/roles/<role-id>/constructions
  { "connector_id": "<id>", "object_class": "user", "description": "<2001-chars>" }
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  ```

---

## Security Tests

### TC-GOV-CONS-030: Create construction without admin role
- **Category**: Security
- **Standard**: NIST SP 800-53 AC-6
- **Input**: POST with non-admin JWT
- **Expected Output**:
  ```
  Status: 403 Forbidden
  ```

### TC-GOV-CONS-031: Access construction cross-tenant
- **Category**: Security
- **Standard**: Multi-tenancy isolation
- **Preconditions**: Construction in tenant A; JWT for tenant B
- **Input**:
  ```
  GET /governance/roles/<tenant-a-role>/constructions/<construction-id>
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-GOV-CONS-032: Get user constructions cross-tenant
- **Category**: Security
- **Preconditions**: User in tenant A; JWT for tenant B
- **Input**:
  ```
  GET /governance/users/<tenant-a-user>/effective-constructions
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

---

## Compliance Tests

### TC-GOV-CONS-040: Construction deprovisioning policy enforces access removal
- **Category**: Compliance
- **Standard**: ISO 27001 A.9.2.6 (Removal of Access Rights)
- **Steps**:
  1. Create construction with `deprovisioning_policy: { "action": "delete", "grace_period_days": 0 }`
  2. Assign role to user (construction executes, account created)
  3. Revoke role from user
  4. Verify deprovisioning triggered per policy
- **Expected Output**: Account deleted immediately upon role revocation

### TC-GOV-CONS-041: Construction with grace period for compliance retention
- **Category**: Compliance
- **Standard**: SOX Section 802 (Record Retention)
- **Steps**:
  1. Create construction with 30-day grace period
  2. Revoke role from user
  3. Verify account disabled (not deleted) during grace period
  4. After 30 days, verify account deleted
- **Expected Output**: Grace period allows compliance retention before permanent deletion

### TC-GOV-CONS-042: Attribute mapping accuracy for provisioning
- **Category**: Compliance
- **Standard**: IGA Provisioning Accuracy
- **Steps**:
  1. Create construction with attribute mappings for email, name, department
  2. Assign role to user
  3. Verify provisioned account has correct attribute values from source user
- **Expected Output**: Provisioned accounts match source identity attributes exactly
