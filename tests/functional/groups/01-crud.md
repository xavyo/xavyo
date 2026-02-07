# Group CRUD Functional Tests

**API Endpoints**:
- `POST /groups` -- Create a new group
- `GET /groups` -- List groups with pagination
- `GET /groups/:id` -- Get group details
- `PUT /groups/:id` -- Replace/update group (full update)
- `DELETE /groups/:id` -- Delete group

**Note**: Group management is exposed via two surfaces:
1. **Admin API** (`/admin/groups`) -- JWT auth + admin role, used for hierarchy operations (F071)
2. **SCIM 2.0** (`/scim/v2/Groups`) -- SCIM Bearer token auth, used for provisioning

This test suite covers the logical group CRUD operations applicable to both surfaces.

**Authentication**: JWT Bearer token with `admin` role OR SCIM Bearer token
**Required Headers**: `Content-Type: application/json`, `Authorization: Bearer <token>`
**Applicable Standards**: ISO 27001 Annex A.9.2 (User Access Management), SOC 2 CC6.1 (Logical Access), SCIM 2.0 RFC 7644

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: Group tests require admin role; some hierarchy tests need pre-existing parent groups

---

## Nominal Cases

### TC-GROUP-CRUD-001: Create group with display_name only
- **Category**: Nominal
- **Standard**: ISO 27001 A.9.2.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Admin JWT for tenant `T1`
- **Input**:
  ```json
  POST /groups
  {
    "display_name": "Engineering"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<uuid>",
    "tenant_id": "<T1-uuid>",
    "display_name": "Engineering",
    "external_id": null,
    "description": null,
    "parent_id": null,
    "group_type": "security_group",
    "created_at": "<iso8601>",
    "updated_at": "<iso8601>"
  }
  ```
- **Side Effects**: Group row inserted; `group_type` defaults to `"security_group"`; webhook event `group.created`

### TC-GROUP-CRUD-002: Create group with all optional fields
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**:
  ```json
  POST /groups
  {
    "display_name": "Platform Team",
    "external_id": "azure-group-12345",
    "description": "Cloud platform infrastructure team",
    "group_type": "department",
    "members": ["<user-uuid-1>", "<user-uuid-2>"]
  }
  ```
- **Expected Output**: Status 201; all fields populated; `group_type = "department"`

### TC-GROUP-CRUD-003: Create group with parent (nested hierarchy)
- **Category**: Nominal
- **Standard**: ISO 27001 A.9.2.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Parent group `G_PARENT` exists in tenant `T1`
- **Input**:
  ```json
  POST /groups
  {
    "display_name": "Backend Team",
    "parent_id": "<G_PARENT-uuid>"
  }
  ```
- **Expected Output**: Status 201; `"parent_id": "<G_PARENT-uuid>"`

### TC-GROUP-CRUD-004: Get group by ID
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group `G1` exists in tenant `T1`
- **Input**: `GET /groups/<G1-uuid>`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "id": "<G1-uuid>",
    "display_name": "Engineering",
    "group_type": "security_group",
    ...
  }
  ```

### TC-GROUP-CRUD-005: List groups with default pagination
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Tenant `T1` has 5 groups
- **Input**: `GET /groups`
- **Expected Output**: Status 200; groups returned ordered by `display_name`

### TC-GROUP-CRUD-006: List groups with explicit pagination
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Tenant has 30 groups
- **Input**: `GET /groups?limit=10&offset=0`
- **Expected Output**: Status 200; 10 groups returned

### TC-GROUP-CRUD-007: Update group display_name
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group `G1` exists with `display_name = "Engineering"`
- **Input**:
  ```json
  PUT /groups/<G1-uuid>
  {
    "display_name": "Engineering (Renamed)",
    "group_type": "security_group"
  }
  ```
- **Expected Output**: Status 200; `display_name` updated; `updated_at` advances

### TC-GROUP-CRUD-008: Update group description
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group `G1` exists in tenant
- **Input**:
  ```json
  PUT /groups/<G1-uuid>
  {
    "display_name": "Engineering",
    "description": "Updated description for the engineering team",
    "group_type": "security_group"
  }
  ```
- **Expected Output**: Status 200; description updated

### TC-GROUP-CRUD-009: Update group type
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group `G1` exists in tenant
- **Input**:
  ```json
  PUT /groups/<G1-uuid>
  {
    "display_name": "Engineering",
    "group_type": "organizational_unit"
  }
  ```
- **Expected Output**: Status 200; `group_type` changed to `"organizational_unit"`

### TC-GROUP-CRUD-010: Delete group
- **Category**: Nominal
- **Standard**: ISO 27001 A.9.2.6
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group `G1` exists with no child groups
- **Input**: `DELETE /groups/<G1-uuid>`
- **Expected Output**: Status 204 No Content
- **Side Effects**: Group row deleted (hard delete); webhook event `group.deleted`

### TC-GROUP-CRUD-011: Delete group removes memberships
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group `G1` has 3 members
- **Input**: `DELETE /groups/<G1-uuid>`
- **Expected Output**: Status 204; all `group_memberships` rows for `G1` also removed (cascade or pre-delete)

### TC-GROUP-CRUD-012: Create group with different group_type values
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: Create groups with types: `security_group`, `department`, `team`, `organizational_unit`, `distribution_list`
- **Expected Output**: Status 201 for each; `group_type` stored as provided

---

## Edge Cases

### TC-GROUP-CRUD-020: Create group with empty display_name
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `POST /groups { "display_name": "" }`
- **Expected Output**: Status 400 (display_name is required and cannot be empty)

### TC-GROUP-CRUD-021: Create group with duplicate display_name in same tenant
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group "Engineering" exists in tenant `T1`
- **Input**: `POST /groups { "display_name": "Engineering" }`
- **Expected Output**: Status 201 (duplicate display_name is allowed) OR Status 409 (if unique constraint exists)
- **Note**: Verify actual behavior -- SCIM allows duplicate `displayName` per RFC 7644

### TC-GROUP-CRUD-022: Create group with same display_name in different tenant
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. "Engineering" exists in T1
- **Input**: Create "Engineering" in T2
- **Expected Output**: Status 201 (names are scoped per tenant)

### TC-GROUP-CRUD-023: Get group with invalid UUID
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `GET /groups/not-a-uuid`
- **Expected Output**: Status 400 (invalid UUID format)

### TC-GROUP-CRUD-024: Get group that does not exist
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `GET /groups/<valid-uuid-not-in-db>`
- **Expected Output**: Status 404

### TC-GROUP-CRUD-025: Delete group that does not exist
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `DELETE /groups/<non-existent-uuid>`
- **Expected Output**: Status 404 (or 204 if idempotent)

### TC-GROUP-CRUD-026: Delete group with child groups
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group `G_PARENT` has child group `G_CHILD`
- **Input**: `DELETE /groups/<G_PARENT-uuid>`
- **Expected Output**: Status 400 with error: "Cannot delete group because it has child groups"

### TC-GROUP-CRUD-027: Create group with parent that does not exist
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `POST /groups { "display_name": "Orphan", "parent_id": "<non-existent-uuid>" }`
- **Expected Output**: Status 404 ("Parent group not found")

### TC-GROUP-CRUD-028: Create group exceeding max hierarchy depth (10 levels)
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. 10 levels of nested groups already exist
- **Input**: Create a group with parent at level 10
- **Expected Output**: Status 400 ("Maximum hierarchy depth of 10 levels exceeded")

### TC-GROUP-CRUD-029: Move group to create circular reference
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. G1 -> G2 -> G3 hierarchy
- **Input**: Move G1 to have parent G3 (creates G3 -> G1 -> G2 -> G3 cycle)
- **Expected Output**: Status 400 ("Moving this group would create a circular reference")

### TC-GROUP-CRUD-030: Update group with parent from different tenant
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group `G_OTHER` in tenant `T2`
- **Input**: `PUT /groups/<G1> { "parent_id": "<G_OTHER-uuid>" }` in tenant `T1`
- **Expected Output**: Status 400 ("Parent group belongs to a different tenant")

### TC-GROUP-CRUD-031: Create group with very long display_name
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `display_name` with 500 characters
- **Expected Output**: Status 400 (if length limit enforced) OR Status 201 (if no limit)

### TC-GROUP-CRUD-032: Create group with null external_id
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `POST /groups { "display_name": "NoExtId", "external_id": null }`
- **Expected Output**: Status 201; `external_id` is null

### TC-GROUP-CRUD-033: Update non-existent group
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `PUT /groups/<non-existent-uuid> { "display_name": "Ghost" }`
- **Expected Output**: Status 404

### TC-GROUP-CRUD-034: Empty request body on POST
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `POST /groups {}` (missing `display_name`)
- **Expected Output**: Status 400

### TC-GROUP-CRUD-035: List groups in empty tenant
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Tenant `T1` has no groups
- **Input**: `GET /groups`
- **Expected Output**: Status 200; empty array; `total_count: 0`

---

## Security Cases

### TC-GROUP-CRUD-040: Cross-tenant group access
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group `G1` belongs to tenant `T1`; admin JWT for tenant `T2`
- **Input**: `GET /groups/<G1-uuid>` with T2 admin JWT
- **Expected Output**: Status 404 (must NOT reveal group exists in another tenant)

### TC-GROUP-CRUD-041: Cross-tenant group modification
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group `G1` belongs to tenant `T1`; admin JWT for tenant `T2`
- **Input**: `PUT /groups/<G1-uuid> { "display_name": "Hacked" }` with T2 JWT
- **Expected Output**: Status 404

### TC-GROUP-CRUD-042: Cross-tenant group deletion
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group `G1` belongs to tenant `T1`; admin JWT for tenant `T2`
- **Input**: `DELETE /groups/<G1-uuid>` with T2 admin JWT
- **Expected Output**: Status 404

### TC-GROUP-CRUD-043: Cross-tenant group list isolation
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. T1 has groups A, B; T2 has groups X, Y
- **Input**: `GET /groups` with T2 admin JWT
- **Expected Output**: Only X, Y returned; A, B not visible

### TC-GROUP-CRUD-044: Unauthenticated access
- **Category**: Security
- **Standard**: ISO 27001 A.9.4.1
- **Preconditions**: Fixtures: `TEST_TENANT`. No authentication token provided
- **Input**: `GET /groups` without Authorization header
- **Expected Output**: Status 401

### TC-GROUP-CRUD-045: Non-admin role access
- **Category**: Security
- **Preconditions**: Fixtures: `TEST_TENANT`. JWT with `["user"]` role only
- **Input**: `POST /groups { "display_name": "Test" }`
- **Expected Output**: Status 403

### TC-GROUP-CRUD-046: SQL injection in display_name
- **Category**: Security
- **Standard**: OWASP ASVS 5.3.4
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `POST /groups { "display_name": "'; DROP TABLE groups; --" }`
- **Expected Output**: Status 201 (stored as literal string; parameterized queries prevent injection)

### TC-GROUP-CRUD-047: SQL injection in group ID path
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `GET /groups/'; DROP TABLE groups; --`
- **Expected Output**: Status 400 (invalid UUID format)

### TC-GROUP-CRUD-048: Error responses do not leak internals
- **Category**: Security
- **Standard**: OWASP ASVS 7.4.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: Various failing requests
- **Expected Output**: No SQL errors, stack traces, table names, or database schema in responses

### TC-GROUP-CRUD-049: Audit trail for group operations
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: Create, update, delete groups
- **Verification**: Audit log records each operation with actor, tenant_id, resource_id, operation type, timestamp, source IP, user agent

---

## Compliance Cases

### TC-GROUP-CRUD-060: Webhook events for group lifecycle
- **Category**: Compliance
- **Standard**: ISO 27001 A.9.2.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin; webhook endpoint configured
- **Input**: Create and delete a group
- **Verification**: `group.created` and `group.deleted` webhook events published with `event_id`, `tenant_id`, `timestamp`, and group details

### TC-GROUP-CRUD-061: Group operations auditable
- **Category**: Compliance
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: Full lifecycle (create, read, update, delete)
- **Verification**: Every operation logged with SCIM operation type (Create, Read, Update, Delete) and resource type (Group)

### TC-GROUP-CRUD-062: Group hierarchy respects organizational boundaries
- **Category**: Compliance
- **Standard**: ISO 27001 A.9.2.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Groups exist in multiple tenants
- **Input**: Attempt cross-tenant parent assignment
- **Verification**: Cross-tenant parent references rejected; hierarchy is strictly tenant-scoped
