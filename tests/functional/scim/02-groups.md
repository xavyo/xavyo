# SCIM 2.0 Group Resource Functional Tests

**API Endpoints**: `GET/POST /scim/v2/Groups`, `GET/PUT/PATCH/DELETE /scim/v2/Groups/:id`
**Authentication**: Bearer token (SCIM token via `Authorization: Bearer xscim_...`)
**Required Headers**: `Content-Type: application/scim+json`, `Authorization: Bearer <token>`
**Applicable Standards**: RFC 7643 (SCIM Core Schema), RFC 7644 (SCIM Protocol)

---

## Nominal Cases

### TC-SCIM-GROUP-001: Create group with display name only
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.3
- **Preconditions**: Valid SCIM Bearer token for tenant; no group named "Engineering"
- **Input**:
  ```json
  POST /scim/v2/Groups
  Content-Type: application/scim+json
  Authorization: Bearer xscim_<token>

  {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    "displayName": "Engineering"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Content-Type: application/scim+json
  Body: {
    "schemas": [
      "urn:ietf:params:scim:schemas:core:2.0:Group",
      "urn:ietf:params:scim:schemas:extension:xavyo:2.0:Group"
    ],
    "id": "<uuid>",
    "displayName": "Engineering",
    "meta": {
      "resourceType": "Group",
      "created": "<ISO8601>",
      "lastModified": "<ISO8601>",
      "location": "https://<host>/scim/v2/Groups/<uuid>"
    },
    "urn:ietf:params:scim:schemas:extension:xavyo:2.0:Group": {
      "groupType": "<default>"
    }
  }
  ```
- **Side Effects**:
  - Group record created in `groups` table
  - SCIM audit log entry (operation: `Create`, resource_type: `Group`)
  - Webhook event `group.created` published

### TC-SCIM-GROUP-002: Create group with members
- **Category**: Nominal
- **Standard**: RFC 7643 Section 4.2
- **Preconditions**: Users `<user1-id>` and `<user2-id>` exist in tenant
- **Input**:
  ```json
  POST /scim/v2/Groups
  {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    "displayName": "Backend Team",
    "externalId": "entra-group-001",
    "members": [
      {"value": "<user1-id>", "display": "Alice"},
      {"value": "<user2-id>", "display": "Bob"}
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body includes "members" array with both users
  ```
- **Verification**: `group_memberships` table has 2 rows for this group

### TC-SCIM-GROUP-003: Create group with xavyo hierarchy extension
- **Category**: Nominal
- **Standard**: RFC 7643 Section 3.3 (extensions)
- **Preconditions**: Parent group with externalId "dept-root" exists
- **Input**:
  ```json
  POST /scim/v2/Groups
  {
    "schemas": [
      "urn:ietf:params:scim:schemas:core:2.0:Group",
      "urn:ietf:params:scim:schemas:extension:xavyo:2.0:Group"
    ],
    "displayName": "Frontend Team",
    "externalId": "entra-group-002",
    "urn:ietf:params:scim:schemas:extension:xavyo:2.0:Group": {
      "groupType": "team",
      "parentExternalId": "dept-root"
    }
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body includes xavyo extension with groupType and parentExternalId
  ```
- **Verification**: `groups.parent_id` set to parent group's ID; `groups.group_type` is "team"

### TC-SCIM-GROUP-004: Get group by ID
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.4.1
- **Preconditions**: Group `<group-id>` exists in tenant with 2 members
- **Input**:
  ```
  GET /scim/v2/Groups/<group-id>
  Authorization: Bearer xscim_<token>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Content-Type: application/scim+json
  Body: {
    "schemas": [
      "urn:ietf:params:scim:schemas:core:2.0:Group",
      "urn:ietf:params:scim:schemas:extension:xavyo:2.0:Group"
    ],
    "id": "<group-id>",
    "displayName": "...",
    "members": [
      {
        "value": "<user-id>",
        "display": "User Name",
        "type": "User",
        "$ref": "https://<host>/scim/v2/Users/<user-id>"
      },
      ...
    ],
    "meta": {
      "resourceType": "Group",
      "location": "https://<host>/scim/v2/Groups/<group-id>",
      ...
    }
  }
  ```

### TC-SCIM-GROUP-005: List groups with default pagination
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.4.2
- **Preconditions**: Multiple groups exist in tenant
- **Input**:
  ```
  GET /scim/v2/Groups
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
    "totalResults": <N>,
    "startIndex": 1,
    "itemsPerPage": 25,
    "Resources": [...]
  }
  ```
- **Verification**: Groups sorted by displayName ASC by default

### TC-SCIM-GROUP-006: Replace group (PUT) with updated members
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.5.1
- **Preconditions**: Group exists with members [user1]; user2 and user3 also exist
- **Input**:
  ```json
  PUT /scim/v2/Groups/<group-id>
  {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    "displayName": "Updated Team",
    "members": [
      {"value": "<user2-id>"},
      {"value": "<user3-id>"}
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: group with updated displayName and new member list
  ```
- **Verification**: Previous members removed; only user2 and user3 remain as members

### TC-SCIM-GROUP-007: Patch group - add member
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.5.2
- **Preconditions**: Group exists; user `<user-id>` exists and is not a member
- **Input**:
  ```json
  PATCH /scim/v2/Groups/<group-id>
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {
        "op": "add",
        "path": "members",
        "value": [{"value": "<user-id>"}]
      }
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: group with new member included in members array
  ```

### TC-SCIM-GROUP-008: Patch group - remove specific member
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.5.2
- **Preconditions**: Group has member `<user-id>`
- **Input**:
  ```json
  PATCH /scim/v2/Groups/<group-id>
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {
        "op": "remove",
        "path": "members[value eq \"<user-id>\"]"
      }
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: group with member removed from members array
  ```

### TC-SCIM-GROUP-009: Patch group - replace displayName
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.5.2
- **Input**:
  ```json
  PATCH /scim/v2/Groups/<group-id>
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {"op": "replace", "path": "displayName", "value": "Renamed Group"}
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: group with "displayName": "Renamed Group"
  ```

### TC-SCIM-GROUP-010: Delete group
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.6
- **Preconditions**: Group exists with no child groups
- **Input**:
  ```
  DELETE /scim/v2/Groups/<group-id>
  ```
- **Expected Output**:
  ```
  Status: 204 No Content
  ```
- **Verification**: Group deleted from `groups` table; all `group_memberships` for this group removed
- **Side Effects**: Webhook event `group.deleted` published

---

## Edge Cases

### TC-SCIM-GROUP-020: Create group with duplicate displayName
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.3 (uniqueness)
- **Preconditions**: Group "Engineering" already exists
- **Input**:
  ```json
  POST /scim/v2/Groups
  {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    "displayName": "Engineering"
  }
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  Body: {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
    "scimType": "uniqueness",
    "detail": "A group with displayName 'Engineering' already exists",
    "status": "409"
  }
  ```

### TC-SCIM-GROUP-021: Get non-existent group
- **Category**: Edge Case
- **Input**:
  ```
  GET /scim/v2/Groups/00000000-0000-0000-0000-000000000099
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  Body: SCIM error response
  ```

### TC-SCIM-GROUP-022: Replace group causing displayName conflict
- **Category**: Edge Case
- **Preconditions**: Group A is "Alpha", Group B is "Beta"
- **Input**:
  ```json
  PUT /scim/v2/Groups/<group-A-id>
  {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    "displayName": "Beta"
  }
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  Body: SCIM error with scimType "uniqueness"
  ```

### TC-SCIM-GROUP-023: Delete group with child groups
- **Category**: Edge Case
- **Preconditions**: Group has child groups in hierarchy (F071)
- **Input**:
  ```
  DELETE /scim/v2/Groups/<parent-group-id>
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  Body: {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
    "scimType": "uniqueness",
    "detail": "Group <id> has child groups. Remove or reassign children first.",
    "status": "409"
  }
  ```

### TC-SCIM-GROUP-024: Delete non-existent group
- **Category**: Edge Case
- **Input**:
  ```
  DELETE /scim/v2/Groups/00000000-0000-0000-0000-000000000099
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-SCIM-GROUP-025: Create group with invalid groupType
- **Category**: Edge Case
- **Input**:
  ```json
  POST /scim/v2/Groups
  {
    "schemas": [
      "urn:ietf:params:scim:schemas:core:2.0:Group",
      "urn:ietf:params:scim:schemas:extension:xavyo:2.0:Group"
    ],
    "displayName": "Bad Type Group",
    "urn:ietf:params:scim:schemas:extension:xavyo:2.0:Group": {
      "groupType": "invalid_type"
    }
  }
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: SCIM error with detail "Invalid group_type 'invalid_type'. Allowed values: organizational_unit, department, team, security_group, distribution_list, custom"
  ```

### TC-SCIM-GROUP-026: Create group with all valid groupType values
- **Category**: Edge Case
- **Preconditions**: No groups with the test names exist
- **Input**: Create groups with each groupType: `organizational_unit`, `department`, `team`, `security_group`, `distribution_list`, `custom`
- **Expected Output**: All return `201 Created`

### TC-SCIM-GROUP-027: Create group with parent that exceeds max depth (10)
- **Category**: Edge Case
- **Preconditions**: Hierarchy chain of 9 levels already exists
- **Input**: Create group at level 11 (child of level 10 group)
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: SCIM error with detail "Maximum hierarchy depth of 10 levels exceeded"
  ```

### TC-SCIM-GROUP-028: Patch group - replace all members
- **Category**: Edge Case
- **Preconditions**: Group has 3 existing members
- **Input**:
  ```json
  PATCH /scim/v2/Groups/<group-id>
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {
        "op": "replace",
        "path": "members",
        "value": [{"value": "<new-user-id>"}]
      }
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: group with only the new user as member (previous members removed)
  ```

### TC-SCIM-GROUP-029: Patch group - remove member with filter path
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.5.2.2
- **Input**:
  ```json
  PATCH /scim/v2/Groups/<group-id>
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {"op": "remove", "path": "members[value eq \"550e8400-e29b-41d4-a716-446655440000\"]"}
    ]
  }
  ```
- **Expected Output**: Status 200 OK with the specified member removed

### TC-SCIM-GROUP-030: Create group with non-existent parentExternalId
- **Category**: Edge Case
- **Input**:
  ```json
  POST /scim/v2/Groups
  {
    "schemas": [
      "urn:ietf:params:scim:schemas:core:2.0:Group",
      "urn:ietf:params:scim:schemas:extension:xavyo:2.0:Group"
    ],
    "displayName": "Orphan Team",
    "urn:ietf:params:scim:schemas:extension:xavyo:2.0:Group": {
      "parentExternalId": "non-existent-parent"
    }
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  ```
- **Verification**: Group created as root (parent_id = NULL); warning logged

### TC-SCIM-GROUP-031: Move group creating hierarchy cycle
- **Category**: Edge Case
- **Preconditions**: Group A is parent of Group B; Group B is parent of Group C
- **Input**: Replace Group A with parentExternalId pointing to Group C
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: SCIM error with detail "Setting this parent would create a cycle in the hierarchy"
  ```

### TC-SCIM-GROUP-032: Create group with empty displayName
- **Category**: Edge Case
- **Input**:
  ```json
  POST /scim/v2/Groups
  {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    "displayName": ""
  }
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  ```

### TC-SCIM-GROUP-033: List groups with empty result set
- **Category**: Edge Case
- **Preconditions**: Tenant has no groups
- **Input**:
  ```
  GET /scim/v2/Groups
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: ListResponse with totalResults=0, Resources=[]
  ```

### TC-SCIM-GROUP-034: Patch group with invalid PatchOp schema
- **Category**: Edge Case
- **Input**:
  ```json
  PATCH /scim/v2/Groups/<group-id>
  {
    "schemas": ["wrong:schema"],
    "Operations": [{"op": "replace", "path": "displayName", "value": "Test"}]
  }
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: SCIM error with detail "Missing PatchOp schema"
  ```

---

## Security Cases

### TC-SCIM-GROUP-050: Cross-tenant group access
- **Category**: Security
- **Preconditions**: Group belongs to Tenant A; Bearer token belongs to Tenant B
- **Input**:
  ```
  GET /scim/v2/Groups/<tenant-A-group-id>
  Authorization: Bearer xscim_<tenant-B-token>
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```
- **Verification**: Tenant B token cannot access Tenant A groups

### TC-SCIM-GROUP-051: Cross-tenant group listing
- **Category**: Security
- **Preconditions**: Tenant A has 5 groups; Tenant B has 3 groups
- **Input**:
  ```
  GET /scim/v2/Groups
  Authorization: Bearer xscim_<tenant-B-token>
  ```
- **Expected Output**: totalResults=3, only Tenant B groups returned

### TC-SCIM-GROUP-052: Cross-tenant member addition
- **Category**: Security
- **Preconditions**: Group belongs to Tenant A; user belongs to Tenant B
- **Input**: PATCH to add Tenant B user as member of Tenant A group
- **Expected Output**: Membership not created (user not found in tenant scope)

### TC-SCIM-GROUP-053: Unauthenticated group creation
- **Category**: Security
- **Input**:
  ```json
  POST /scim/v2/Groups
  (no Authorization header)
  {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    "displayName": "Unauthorized Group"
  }
  ```
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  ```

### TC-SCIM-GROUP-054: SQL injection in displayName filter
- **Category**: Security
- **Input**:
  ```
  GET /scim/v2/Groups?filter=displayName eq "'; DROP TABLE groups; --"
  ```
- **Expected Output**:
  ```
  Status: 200 OK (empty result set)
  ```
- **Verification**: Filter values are parameterized; no SQL execution

---

## Response Format Compliance

### TC-SCIM-GROUP-060: Group response includes schemas array
- **Category**: Compliance
- **Standard**: RFC 7643 Section 3
- **Input**: Any successful group endpoint call
- **Expected Output**: Response body contains `"schemas"` array with `"urn:ietf:params:scim:schemas:core:2.0:Group"`

### TC-SCIM-GROUP-061: Members include $ref URI
- **Category**: Compliance
- **Standard**: RFC 7643 Section 4.2
- **Preconditions**: Group has members
- **Input**: `GET /scim/v2/Groups/<group-id>`
- **Expected Output**: Each member has `"$ref": "https://<host>/scim/v2/Users/<user-id>"`

### TC-SCIM-GROUP-062: Members include type field
- **Category**: Compliance
- **Standard**: RFC 7643 Section 4.2
- **Input**: GET group with members
- **Expected Output**: Each member includes `"type": "User"`

### TC-SCIM-GROUP-063: Meta.resourceType is "Group"
- **Category**: Compliance
- **Standard**: RFC 7643 Section 3.1
- **Input**: Any group endpoint returning a group resource
- **Expected Output**: `meta.resourceType` is `"Group"`
