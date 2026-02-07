# Object Templates Functional Tests

**API Base Path**: `/governance/object-templates`, `/governance/object-templates/:id/rules`, `/governance/object-templates/:id/scopes`
**Authentication**: JWT Bearer token with `admin` role required for mutations
**Required Headers**: `Content-Type: application/json`, `Authorization: Bearer <jwt>`
**Applicable Standards**: IGA Provisioning Standardization, ISO 27001 A.9.2.2

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: For scope-related tests, archetypes must exist. For parent template tests, at least one template must be created first. For simulation tests, an active template with rules is needed.

## Nominal Cases

### TC-GOV-TPL-001: Create object template
- **Category**: Nominal
- **Standard**: IGA Standardized Provisioning
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**:
  ```json
  POST /governance/object-templates
  {
    "name": "Standard Employee User Template",
    "description": "Default attribute values and validation rules for employee users",
    "object_type": "user",
    "priority": 100,
    "rules": [
      {
        "rule_type": "default_value",
        "target_attribute": "lifecycle_state",
        "value": "pre_hire",
        "strength": "normal"
      },
      {
        "rule_type": "validation",
        "target_attribute": "email",
        "validation_expression": "value MATCHES '^[^@]+@company\\.com$'",
        "strength": "strong"
      }
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<uuid>",
    "name": "Standard Employee User Template",
    "object_type": "user",
    "status": "draft",
    "priority": 100,
    "version": 1,
    "created_at": "<iso8601>"
  }
  ```

### TC-GOV-TPL-002: Create template with scopes
- **Category**: Nominal
- **Standard**: IGA Conditional Templates
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Archetypes exist for scoping
- **Input**:
  ```json
  POST /governance/object-templates
  {
    "name": "Finance Department Template",
    "object_type": "user",
    "priority": 50,
    "scopes": [
      { "scope_type": "archetype", "scope_id": "<finance-archetype-id>" }
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  ```

### TC-GOV-TPL-003: Create template with parent (inheritance)
- **Category**: Nominal
- **Standard**: IGA Template Hierarchy
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Parent template exists
- **Input**:
  ```json
  POST /governance/object-templates
  {
    "name": "Contractor User Template",
    "object_type": "user",
    "parent_template_id": "<employee-template-id>",
    "priority": 200
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: { "parent_template_id": "<employee-template-id>", ... }
  ```

### TC-GOV-TPL-004: List templates with filters
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Templates exist
- **Input**:
  ```
  GET /governance/object-templates?object_type=user&limit=20&offset=0
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [...], "total": <count> }
  ```

### TC-GOV-TPL-005: Get template by ID
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Template exists
- **Input**:
  ```
  GET /governance/object-templates/<template-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "id": "<template-id>", "name": "Standard Employee User Template", ... }
  ```

### TC-GOV-TPL-006: Update template
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Template exists
- **Input**:
  ```json
  PUT /governance/object-templates/<template-id>
  {
    "name": "Standard Employee Template v2",
    "description": "Updated with new compliance rules",
    "priority": 90
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  ```

### TC-GOV-TPL-007: Delete template
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Template in draft status
- **Input**:
  ```
  DELETE /governance/object-templates/<template-id>
  ```
- **Expected Output**:
  ```
  Status: 204 No Content
  ```

### TC-GOV-TPL-008: Activate template
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Template in draft status
- **Input**:
  ```
  POST /governance/object-templates/<template-id>/activate
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "status": "active", ... }
  ```

### TC-GOV-TPL-009: Disable template
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Template is active
- **Input**:
  ```
  POST /governance/object-templates/<template-id>/disable
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "status": "disabled", ... }
  ```

### TC-GOV-TPL-010: Add rule to template
- **Category**: Nominal
- **Standard**: IGA Attribute Normalization
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Template exists
- **Input**:
  ```json
  POST /governance/object-templates/<template-id>/rules
  {
    "rule_type": "normalization",
    "target_attribute": "display_name",
    "normalization_expression": "UPPER(SUBSTRING(first_name, 0, 1)) || '. ' || last_name",
    "strength": "normal"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: { "id": "<rule-id>", "rule_type": "normalization", ... }
  ```

### TC-GOV-TPL-011: List template rules
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Template with rules exists
- **Input**:
  ```
  GET /governance/object-templates/<template-id>/rules
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [...] }
  ```

### TC-GOV-TPL-012: Update template rule
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Template with at least one rule exists
- **Input**:
  ```json
  PUT /governance/object-templates/<template-id>/rules/<rule-id>
  {
    "strength": "strong",
    "value": "active"
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  ```

### TC-GOV-TPL-013: Delete template rule
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Template with at least one rule exists
- **Input**:
  ```
  DELETE /governance/object-templates/<template-id>/rules/<rule-id>
  ```
- **Expected Output**:
  ```
  Status: 204 No Content
  ```

### TC-GOV-TPL-014: List template versions
- **Category**: Nominal
- **Standard**: IGA Change Management
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Template with multiple versions exists
- **Input**:
  ```
  GET /governance/object-templates/<template-id>/versions
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "versions": [{ "version": 1, "created_at": "..." }, { "version": 2, ... }] }
  ```

### TC-GOV-TPL-015: Get specific template version
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Template with versions exists
- **Input**:
  ```
  GET /governance/object-templates/<template-id>/versions/<version-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  ```

### TC-GOV-TPL-016: List template events (audit)
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Template with events exists
- **Input**:
  ```
  GET /governance/object-templates/<template-id>/events
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "events": [{ "event_type": "created", ... }, { "event_type": "activated", ... }] }
  ```

### TC-GOV-TPL-017: Add scope to template
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Template and archetype exist
- **Input**:
  ```json
  POST /governance/object-templates/<template-id>/scopes
  { "scope_type": "archetype", "scope_id": "<archetype-id>" }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  ```

### TC-GOV-TPL-018: Remove scope from template
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Template with scope exists
- **Input**:
  ```
  DELETE /governance/object-templates/<template-id>/scopes/<scope-id>
  ```
- **Expected Output**:
  ```
  Status: 204 No Content
  ```

### TC-GOV-TPL-019: Simulate template application
- **Category**: Nominal
- **Standard**: IGA Impact Preview
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Active template with rules exists
- **Input**:
  ```json
  POST /governance/object-templates/<template-id>/simulate
  {
    "target_object": {
      "email": "john@company.com",
      "first_name": "John",
      "last_name": "Doe"
    }
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "applied_rules": [
      { "rule_id": "...", "attribute": "lifecycle_state", "computed_value": "pre_hire" },
      { "rule_id": "...", "attribute": "display_name", "computed_value": "J. Doe" }
    ],
    "validation_results": [
      { "attribute": "email", "valid": true }
    ]
  }
  ```

### TC-GOV-TPL-020: Create merge policy for template
- **Category**: Nominal
- **Standard**: IGA Template Conflict Resolution
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Template exists
- **Input**:
  ```json
  POST /governance/object-templates/<template-id>/merge-policies
  {
    "target_attribute": "department",
    "strategy": "first_wins",
    "null_handling": "skip"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  ```

### TC-GOV-TPL-021: Create template exclusion
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Template and user exist
- **Input**:
  ```json
  POST /governance/object-templates/<template-id>/exclusions
  { "excluded_object_id": "<user-id>" }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  ```

### TC-GOV-TPL-022: List application events by template
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Template with application events exists
- **Input**:
  ```
  GET /governance/object-templates/<template-id>/application-events
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "events": [...] }
  ```

### TC-GOV-TPL-023: List application events by object
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User with template application events exists
- **Input**:
  ```
  GET /governance/object-templates/application-events/user/<user-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "events": [...] }
  ```

---

## Edge Cases

### TC-GOV-TPL-025: Create template with duplicate name
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Template "Standard Employee User Template" exists
- **Input**:
  ```json
  POST /governance/object-templates
  { "name": "Standard Employee User Template", "object_type": "user" }
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  ```

### TC-GOV-TPL-026: Create template with priority out of range
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```json
  POST /governance/object-templates
  { "name": "Out of Range", "object_type": "user", "priority": 9999 }
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  Body: { "error": "Priority must be between 1 and 1000" }
  ```

### TC-GOV-TPL-027: Delete active template
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Template is active
- **Input**:
  ```
  DELETE /governance/object-templates/<active-template-id>
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  Body: { "error": "Cannot delete active template; disable it first" }
  ```

### TC-GOV-TPL-028: Name exceeding 255 characters
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```json
  POST /governance/object-templates
  { "name": "<256-chars>", "object_type": "user" }
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  ```

### TC-GOV-TPL-029: Get non-existent template
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```
  GET /governance/object-templates/00000000-0000-0000-0000-000000000099
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

---

## Security Tests

### TC-GOV-TPL-030: Create template without admin role
- **Category**: Security
- **Standard**: NIST SP 800-53 AC-6
- **Preconditions**: Fixtures: `TEST_TENANT`. JWT with user role only
- **Input**:
  ```json
  POST /governance/object-templates
  { "name": "Unauthorized", "object_type": "user" }
  ```
- **Expected Output**:
  ```
  Status: 403 Forbidden
  ```

### TC-GOV-TPL-031: Access template cross-tenant
- **Category**: Security
- **Standard**: Multi-tenancy isolation
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Template in tenant A; JWT for tenant B (second tenant required)
- **Input**:
  ```
  GET /governance/object-templates/<tenant-a-template-id>
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-GOV-TPL-032: Modify template cross-tenant
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Template in tenant A; JWT for tenant B admin (second tenant required)
- **Input**:
  ```json
  PUT /governance/object-templates/<tenant-a-template-id>
  { "name": "Cross-tenant modification" }
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

---

## Compliance Tests

### TC-GOV-TPL-040: Templates enforce standardized provisioning
- **Category**: Compliance
- **Standard**: ISO 27001 A.9.2.2 (User Access Provisioning)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Template with default values and validation rules configured
- **Steps**:
  1. Create template with default values for lifecycle_state, notification preferences
  2. Create validation rules for email domain, required fields
  3. Activate template
  4. Create new user
  5. Verify template rules applied: default values set, validation enforced
- **Expected Output**: All new users provisioned according to organizational standards

### TC-GOV-TPL-041: Template versioning supports change management
- **Category**: Compliance
- **Standard**: ISO 27001 A.12.1.2 (Change Management)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**:
  1. Create and activate template v1
  2. Modify template (creates v2)
  3. Verify both versions retrievable
  4. Verify audit events captured for version changes
- **Expected Output**: Template changes versioned and auditable

### TC-GOV-TPL-042: Template simulation enables safe previews
- **Category**: Compliance
- **Standard**: IGA Change Risk Assessment
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Template with complex rules exists
- **Steps**:
  1. Create template with complex rules
  2. Run simulation with sample object
  3. Verify simulation shows exactly what would change
  4. No actual changes applied during simulation
- **Expected Output**: Templates can be tested before activation without side effects

### TC-GOV-TPL-043: Scoped templates apply to correct identity types
- **Category**: Compliance
- **Standard**: IGA Identity Classification
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Employee and contractor archetypes exist
- **Steps**:
  1. Create template scoped to "Employee" archetype
  2. Create template scoped to "Contractor" archetype
  3. Create employee user -> verify employee template applied
  4. Create contractor user -> verify contractor template applied
  5. Verify templates do NOT cross-apply
- **Expected Output**: Templates apply only to matching identity archetypes
