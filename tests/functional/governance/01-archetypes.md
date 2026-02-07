# Identity Archetype Management Functional Tests

**API Base Path**: `GET/POST /governance/archetypes`, `GET/PUT/DELETE /governance/archetypes/:id`
**Authentication**: JWT Bearer token with `admin` role required for mutations
**Required Headers**: `Content-Type: application/json`, `Authorization: Bearer <jwt>`
**Applicable Standards**: ISO 27001 A.9.1 (Access Control Policy), IGA Best Practices (Identity Classification)

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: Some tests require existing archetype hierarchies (parent/child), lifecycle configs, or user assignments

---

## Nominal Cases

### TC-GOV-ARCH-001: Create identity archetype with required fields
- **Category**: Nominal
- **Standard**: IGA Identity Classification
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as tenant admin
- **Input**:
  ```json
  POST /governance/archetypes
  {
    "name": "Employee",
    "description": "Full-time employee identity archetype"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<uuid>",
    "tenant_id": "<tenant-uuid>",
    "name": "Employee",
    "description": "Full-time employee identity archetype",
    "parent_archetype_id": null,
    "schema_extensions": null,
    "lifecycle_model_id": null,
    "is_active": true,
    "created_at": "<iso8601>",
    "updated_at": "<iso8601>"
  }
  ```
- **Side Effects**: Record created in `identity_archetypes` table with correct `tenant_id`

### TC-GOV-ARCH-002: Create archetype with parent inheritance
- **Category**: Nominal
- **Standard**: IGA Identity Hierarchy
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Parent archetype "Employee" exists with known ID
- **Input**:
  ```json
  POST /governance/archetypes
  {
    "name": "Contractor",
    "description": "External contractor archetype",
    "parent_archetype_id": "<employee-archetype-id>"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: { "parent_archetype_id": "<employee-archetype-id>", ... }
  ```
- **Verification**: Child archetype inherits effective policies from parent

### TC-GOV-ARCH-003: Create archetype with schema extensions
- **Category**: Nominal
- **Standard**: IGA Extensible Identity Schema
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as tenant admin
- **Input**:
  ```json
  POST /governance/archetypes
  {
    "name": "Vendor",
    "schema_extensions": {
      "attributes": [
        {"name": "company_name", "type": "string", "required": true},
        {"name": "contract_end_date", "type": "date", "required": true},
        {"name": "clearance_level", "type": "enum", "values": ["public", "confidential", "secret"]}
      ]
    }
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: { "schema_extensions": { "attributes": [...] }, ... }
  ```

### TC-GOV-ARCH-004: Create archetype with lifecycle model reference
- **Category**: Nominal
- **Standard**: IGA Lifecycle Integration (F-059)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Lifecycle config exists with known ID
- **Input**:
  ```json
  POST /governance/archetypes
  {
    "name": "Intern",
    "description": "Temporary intern archetype",
    "lifecycle_model_id": "<lifecycle-config-id>"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: { "lifecycle_model_id": "<lifecycle-config-id>", ... }
  ```

### TC-GOV-ARCH-005: List archetypes with pagination
- **Category**: Nominal
- **Standard**: IGA Best Practices
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. At least 5 archetypes exist in tenant
- **Input**:
  ```
  GET /governance/archetypes?limit=2&offset=0
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [<archetype>, <archetype>], "total": 5 }
  ```
- **Verification**: Returns exactly 2 items, total reflects all archetypes

### TC-GOV-ARCH-006: List archetypes filtered by active status
- **Category**: Nominal
- **Standard**: IGA Best Practices
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Mix of active and inactive archetypes exist
- **Input**:
  ```
  GET /governance/archetypes?active_only=true
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [...] }  // all items have is_active: true
  ```

### TC-GOV-ARCH-007: Get single archetype by ID
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Archetype exists with known ID
- **Input**:
  ```
  GET /governance/archetypes/<archetype-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "id": "<archetype-id>", "name": "Employee", ... }
  ```

### TC-GOV-ARCH-008: Update archetype name and description
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Archetype exists
- **Input**:
  ```json
  PUT /governance/archetypes/<archetype-id>
  {
    "name": "Full-Time Employee",
    "description": "Updated description for FTE"
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "name": "Full-Time Employee", "description": "Updated description for FTE", ... }
  ```

### TC-GOV-ARCH-009: Deactivate an archetype
- **Category**: Nominal
- **Standard**: IGA Lifecycle Management
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Active archetype exists
- **Input**:
  ```json
  PUT /governance/archetypes/<archetype-id>
  { "is_active": false }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "is_active": false, ... }
  ```

### TC-GOV-ARCH-010: Delete archetype
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Archetype exists with no user assignments
- **Input**:
  ```
  DELETE /governance/archetypes/<archetype-id>
  ```
- **Expected Output**:
  ```
  Status: 204 No Content
  ```

### TC-GOV-ARCH-011: Get archetype ancestry chain
- **Category**: Nominal
- **Standard**: IGA Inheritance Resolution
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Archetype hierarchy exists (Grandparent -> Parent -> Child)
- **Input**:
  ```
  GET /governance/archetypes/<child-id>/ancestry
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "ancestry": [<grandparent>, <parent>, <child>] }
  ```

### TC-GOV-ARCH-012: Bind policy to archetype
- **Category**: Nominal
- **Standard**: IGA Policy Governance
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Archetype exists
- **Input**:
  ```json
  POST /governance/archetypes/<archetype-id>/policies
  {
    "policy_type": "password",
    "policy_config": { "min_length": 12, "require_special": true }
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  ```

### TC-GOV-ARCH-013: Get effective policies with inheritance
- **Category**: Nominal
- **Standard**: IGA Policy Resolution
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Parent archetype has password policy; child archetype has MFA policy
- **Input**:
  ```
  GET /governance/archetypes/<child-id>/effective-policies
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "policies": [<password-policy-from-parent>, <mfa-policy-from-child>] }
  ```
- **Verification**: Effective policies merge parent and child; child overrides take precedence

### TC-GOV-ARCH-014: Assign archetype to user
- **Category**: Nominal
- **Standard**: IGA Identity Classification
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User and archetype exist in same tenant
- **Input**:
  ```json
  PUT /governance/users/<user-id>/archetype
  { "archetype_id": "<archetype-id>" }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  ```

### TC-GOV-ARCH-015: Get user's assigned archetype
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User has an archetype assigned
- **Input**:
  ```
  GET /governance/users/<user-id>/archetype
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "archetype_id": "<archetype-id>", "archetype_name": "Employee", ... }
  ```

---

## Edge Cases

### TC-GOV-ARCH-020: Create archetype with duplicate name in same tenant
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Archetype named "Employee" already exists
- **Input**:
  ```json
  POST /governance/archetypes
  { "name": "Employee" }
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  Body: { "error": "Archetype with this name already exists" }
  ```

### TC-GOV-ARCH-021: Create archetype with name exceeding 255 characters
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```json
  POST /governance/archetypes
  { "name": "<256-char-string>" }
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  Body: { "error": "Name must be between 1 and 255 characters" }
  ```

### TC-GOV-ARCH-022: Create archetype with empty name
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```json
  POST /governance/archetypes
  { "name": "" }
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  ```

### TC-GOV-ARCH-023: Create archetype with non-existent parent
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```json
  POST /governance/archetypes
  {
    "name": "Orphan",
    "parent_archetype_id": "00000000-0000-0000-0000-000000000099"
  }
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  Body: { "error": "Parent archetype not found" }
  ```

### TC-GOV-ARCH-024: Delete archetype with assigned users
- **Category**: Edge Case
- **Standard**: IGA Referential Integrity
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Archetype has at least one user assigned
- **Input**:
  ```
  DELETE /governance/archetypes/<archetype-id>
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  Body: { "error": "Cannot delete archetype with assigned users" }
  ```

### TC-GOV-ARCH-025: Delete archetype with child archetypes
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Archetype is parent of another archetype
- **Input**:
  ```
  DELETE /governance/archetypes/<parent-id>
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  Body: { "error": "Cannot delete archetype with child archetypes" }
  ```

### TC-GOV-ARCH-026: Get non-existent archetype
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```
  GET /governance/archetypes/00000000-0000-0000-0000-000000000099
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-GOV-ARCH-027: Unbind non-existent policy type from archetype
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```
  DELETE /governance/archetypes/<id>/policies/nonexistent_type
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-GOV-ARCH-028: Assign archetype from different tenant to user
- **Category**: Edge Case
- **Standard**: Multi-tenancy isolation
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Archetype belongs to tenant A; user belongs to tenant B (second tenant required)
- **Input**:
  ```json
  PUT /governance/users/<user-in-tenant-b>/archetype
  { "archetype_id": "<archetype-in-tenant-a>" }
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

---

## Security Tests

### TC-GOV-ARCH-030: Create archetype without admin role
- **Category**: Security
- **Standard**: ISO 27001 A.9.2.3 (Privileged Access Management)
- **Preconditions**: Fixtures: `TEST_TENANT`. Authenticated as non-admin user
- **Input**:
  ```json
  POST /governance/archetypes
  { "name": "Hacker Archetype" }
  ```
- **Expected Output**:
  ```
  Status: 403 Forbidden
  ```

### TC-GOV-ARCH-031: Access archetype from different tenant
- **Category**: Security
- **Standard**: ISO 27001 A.9.4.1 (Tenant Isolation)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Archetype belongs to tenant A; JWT is for tenant B (second tenant required)
- **Input**:
  ```
  GET /governance/archetypes/<tenant-a-archetype-id>
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```
- **Verification**: Must NOT return 403 (information leakage); 404 prevents enumeration

### TC-GOV-ARCH-032: Create archetype without authentication
- **Category**: Security
- **Standard**: OWASP ASVS 4.1.1
- **Preconditions**: Fixtures: `TEST_TENANT`
- **Input**:
  ```json
  POST /governance/archetypes
  { "name": "Unauthenticated" }
  ```
  (No Authorization header)
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  ```

### TC-GOV-ARCH-033: Modify archetype in different tenant
- **Category**: Security
- **Standard**: ISO 27001 A.9.4.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Archetype exists in tenant A; JWT for tenant B with admin role (second tenant required)
- **Input**:
  ```json
  PUT /governance/archetypes/<tenant-a-archetype-id>
  { "name": "Cross-Tenant Override" }
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

---

## Compliance Tests

### TC-GOV-ARCH-040: Archetype classification supports ISO 27001 identity types
- **Category**: Compliance
- **Standard**: ISO 27001 A.9.1.2 (Access to Networks and Network Services)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**:
  1. Create archetype "Employee" with `lifecycle_model_id` referencing standard employee lifecycle
  2. Create archetype "Contractor" with `lifecycle_model_id` referencing contractor lifecycle
  3. Create archetype "Service Account" with `lifecycle_model_id` referencing NHI lifecycle
- **Expected Output**: All three created successfully
- **Verification**: Platform supports distinct identity types per ISO 27001 classification

### TC-GOV-ARCH-041: Archetype policy binding enforces access control policy
- **Category**: Compliance
- **Standard**: ISO 27001 A.9.1.1 (Access Control Policy)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**:
  1. Create archetype "Privileged Admin"
  2. Bind MFA policy: `{ "policy_type": "mfa", "policy_config": { "required": true, "method": "webauthn" } }`
  3. Bind password policy: `{ "policy_type": "password", "policy_config": { "min_length": 16 } }`
  4. Verify effective policies include both
- **Expected Output**: Both policies returned in effective-policies endpoint
- **Verification**: Demonstrates that identity archetypes can enforce differentiated access control

### TC-GOV-ARCH-042: Schema extensions support custom attributes for regulatory compliance
- **Category**: Compliance
- **Standard**: GDPR Article 6 (Lawful Basis), ISO 27001 A.18.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**:
  1. Create archetype with schema_extensions including `data_classification`, `consent_obtained`, `processing_purpose`
  2. Assign archetype to user
  3. Verify user inherits schema requirements
- **Expected Output**: Archetype created with GDPR-relevant custom attributes

### TC-GOV-ARCH-043: Archetype deactivation does not remove existing user assignments
- **Category**: Compliance
- **Standard**: IGA Continuity
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**:
  1. Create archetype and assign to user
  2. Deactivate archetype (`is_active: false`)
  3. Verify user still has archetype assignment
  4. Verify new users cannot be assigned the deactivated archetype
- **Expected Output**: Existing assignments preserved; new assignments blocked
