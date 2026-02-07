# SCIM 2.0 User Resource Functional Tests

**API Endpoints**: `GET/POST /scim/v2/Users`, `GET/PUT/PATCH/DELETE /scim/v2/Users/:id`
**Authentication**: Bearer token (SCIM token via `Authorization: Bearer xscim_...`)
**Required Headers**: `Content-Type: application/scim+json`, `Authorization: Bearer <token>`
**Applicable Standards**: RFC 7643 (SCIM Core Schema), RFC 7644 (SCIM Protocol)

---

## Nominal Cases

### TC-SCIM-USER-001: Create user with minimal required attributes
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.3
- **Preconditions**: Valid SCIM Bearer token for tenant; no user with email `alice@example.com`
- **Input**:
  ```json
  POST /scim/v2/Users
  Content-Type: application/scim+json
  Authorization: Bearer xscim_<token>

  {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "alice@example.com"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Content-Type: application/scim+json
  Body: {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "id": "<uuid>",
    "userName": "alice@example.com",
    "active": true,
    "emails": [{"value": "alice@example.com", "type": "work", "primary": true}],
    "meta": {
      "resourceType": "User",
      "created": "<ISO8601>",
      "lastModified": "<ISO8601>",
      "location": "https://<host>/scim/v2/Users/<uuid>"
    }
  }
  ```
- **Side Effects**:
  - User record created in `users` table with `scim_provisioned = true`
  - `scim_last_sync` timestamp set
  - `email_verified = true` (SCIM-provisioned users skip verification)
  - SCIM audit log entry created (operation: `Create`, resource_type: `User`)
  - Webhook event `user.created` published

### TC-SCIM-USER-002: Create user with full attributes
- **Category**: Nominal
- **Standard**: RFC 7643 Section 4.1, RFC 7644 Section 3.3
- **Preconditions**: Valid SCIM Bearer token for tenant
- **Input**:
  ```json
  POST /scim/v2/Users
  {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "bob@example.com",
    "externalId": "entra-abc-123",
    "name": {
      "givenName": "Bob",
      "familyName": "Smith",
      "formatted": "Bob Smith"
    },
    "displayName": "Bob Smith",
    "active": true,
    "emails": [
      {"value": "bob@example.com", "type": "work", "primary": true}
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "id": "<uuid>",
    "userName": "bob@example.com",
    "externalId": "entra-abc-123",
    "name": {
      "givenName": "Bob",
      "familyName": "Smith",
      "formatted": "Bob Smith"
    },
    "displayName": "Bob Smith",
    "active": true,
    "emails": [{"value": "bob@example.com", "type": "work", "primary": true}],
    "meta": { "resourceType": "User", ... }
  }
  ```
- **Verification**: `external_id`, `first_name`, `last_name`, `display_name` all stored in DB

### TC-SCIM-USER-003: Create user with enterprise extension attributes
- **Category**: Nominal
- **Standard**: RFC 7643 Section 4.3 (Enterprise User)
- **Preconditions**: Valid SCIM Bearer token for tenant
- **Input**:
  ```json
  POST /scim/v2/Users
  {
    "schemas": [
      "urn:ietf:params:scim:schemas:core:2.0:User",
      "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
    ],
    "userName": "carol@example.com",
    "displayName": "Carol Davis",
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
      "department": "Engineering",
      "costCenter": "CC-1234",
      "employeeNumber": "EMP-5678",
      "manager": {"value": "<manager-uuid>", "displayName": "Alice Manager"}
    }
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body includes enterprise extension data in response
  ```
- **Verification**: `custom_attributes` JSONB column contains `{"department": "Engineering", "cost_center": "CC-1234", "employee_id": "EMP-5678", "manager_id": "<manager-uuid>"}`

### TC-SCIM-USER-004: Get user by ID
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.4.1
- **Preconditions**: User `<user-id>` exists in tenant
- **Input**:
  ```
  GET /scim/v2/Users/<user-id>
  Authorization: Bearer xscim_<token>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Content-Type: application/scim+json
  Body: {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "id": "<user-id>",
    "userName": "<email>",
    "active": true,
    "meta": {
      "resourceType": "User",
      "created": "<ISO8601>",
      "lastModified": "<ISO8601>",
      "location": "https://<host>/scim/v2/Users/<user-id>"
    },
    ...
  }
  ```

### TC-SCIM-USER-005: List users with default pagination
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.4.2
- **Preconditions**: Multiple users exist in tenant
- **Input**:
  ```
  GET /scim/v2/Users
  Authorization: Bearer xscim_<token>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
    "totalResults": <N>,
    "startIndex": 1,
    "itemsPerPage": 25,
    "Resources": [ ... ]
  }
  ```
- **Verification**: Default pagination is startIndex=1, count=25

### TC-SCIM-USER-006: List users with custom pagination
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.4.2.4
- **Preconditions**: 50+ users exist in tenant
- **Input**:
  ```
  GET /scim/v2/Users?startIndex=26&count=10
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
    "totalResults": <N>,
    "startIndex": 26,
    "itemsPerPage": 10,
    "Resources": [ ... (up to 10 users) ]
  }
  ```

### TC-SCIM-USER-007: Replace user (PUT) with full resource
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.5.1
- **Preconditions**: User `<user-id>` exists in tenant
- **Input**:
  ```json
  PUT /scim/v2/Users/<user-id>
  {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "updated@example.com",
    "displayName": "Updated Name",
    "name": {"givenName": "Updated", "familyName": "Name"},
    "active": true
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: updated user resource with new attributes
  ```
- **Verification**: `scim_last_sync` and `updated_at` timestamps updated
- **Side Effects**: Webhook event `user.updated` published

### TC-SCIM-USER-008: Patch user - replace single attribute
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.5.2
- **Preconditions**: User `<user-id>` exists in tenant with `active = true`
- **Input**:
  ```json
  PATCH /scim/v2/Users/<user-id>
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {"op": "replace", "path": "active", "value": false}
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: user resource with "active": false
  ```

### TC-SCIM-USER-009: Patch user - replace displayName
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.5.2
- **Preconditions**: User exists
- **Input**:
  ```json
  PATCH /scim/v2/Users/<user-id>
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {"op": "replace", "path": "displayName", "value": "New Display Name"}
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: user with "displayName": "New Display Name"
  ```

### TC-SCIM-USER-010: Patch user - multiple operations in one request
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.5.2
- **Preconditions**: User exists
- **Input**:
  ```json
  PATCH /scim/v2/Users/<user-id>
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {"op": "replace", "path": "displayName", "value": "Updated Name"},
      {"op": "replace", "path": "name.givenName", "value": "Updated"},
      {"op": "replace", "path": "name.familyName", "value": "Name"},
      {"op": "replace", "path": "active", "value": false}
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: user with all four attributes updated atomically
  ```

### TC-SCIM-USER-011: Delete user (soft delete / deactivate)
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.6
- **Preconditions**: User `<user-id>` exists in tenant with `active = true`
- **Input**:
  ```
  DELETE /scim/v2/Users/<user-id>
  Authorization: Bearer xscim_<token>
  ```
- **Expected Output**:
  ```
  Status: 204 No Content
  ```
- **Verification**: User's `is_active = false` in DB, `scim_last_sync` updated
- **Side Effects**: Webhook event `user.deleted` published

### TC-SCIM-USER-012: List users with filter (userName eq)
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.4.2.2
- **Preconditions**: User `alice@example.com` exists
- **Input**:
  ```
  GET /scim/v2/Users?filter=userName eq "alice@example.com"
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: ListResponse with totalResults=1, Resources containing the matching user
  ```

### TC-SCIM-USER-013: List users sorted by userName ascending
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.4.2.3
- **Preconditions**: Multiple users exist
- **Input**:
  ```
  GET /scim/v2/Users?sortBy=userName&sortOrder=ascending
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: Resources array sorted by userName (email) in ascending order
  ```

### TC-SCIM-USER-014: Patch user - replace with no path (bulk value object)
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.5.2
- **Preconditions**: User exists
- **Input**:
  ```json
  PATCH /scim/v2/Users/<user-id>
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {"op": "replace", "value": {"active": false, "displayName": "Bulk Updated"}}
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: user with both active=false and displayName="Bulk Updated"
  ```

### TC-SCIM-USER-015: Get user includes group memberships
- **Category**: Nominal
- **Standard**: RFC 7643 Section 4.1 (groups attribute)
- **Preconditions**: User belongs to group "Engineering"
- **Input**:
  ```
  GET /scim/v2/Users/<user-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body includes:
  "groups": [
    {
      "value": "<group-uuid>",
      "display": "Engineering",
      "$ref": "https://<host>/scim/v2/Groups/<group-uuid>"
    }
  ]
  ```

---

## Edge Cases

### TC-SCIM-USER-020: Create user with duplicate userName
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.3 (uniqueness)
- **Preconditions**: User `alice@example.com` already exists in tenant
- **Input**:
  ```json
  POST /scim/v2/Users
  {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "alice@example.com"
  }
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  Content-Type: application/scim+json
  Body: {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
    "scimType": "uniqueness",
    "detail": "A user with userName 'alice@example.com' already exists",
    "status": "409"
  }
  ```

### TC-SCIM-USER-021: Get non-existent user
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.1
- **Preconditions**: No user with ID `00000000-0000-0000-0000-000000000099`
- **Input**:
  ```
  GET /scim/v2/Users/00000000-0000-0000-0000-000000000099
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  Body: {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
    "detail": "User 00000000-0000-0000-0000-000000000099 not found",
    "status": "404"
  }
  ```

### TC-SCIM-USER-022: Get user with invalid UUID format
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.1
- **Input**:
  ```
  GET /scim/v2/Users/not-a-uuid
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  ```

### TC-SCIM-USER-023: Create user with missing schemas array
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.3
- **Input**:
  ```json
  POST /scim/v2/Users
  {"userName": "noschema@example.com"}
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: SCIM error response
  ```

### TC-SCIM-USER-024: Create user with empty userName
- **Category**: Edge Case
- **Standard**: RFC 7643 Section 4.1 (userName REQUIRED)
- **Input**:
  ```json
  POST /scim/v2/Users
  {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": ""
  }
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: SCIM error with scimType "invalidValue"
  ```

### TC-SCIM-USER-025: Create user with missing userName field
- **Category**: Edge Case
- **Standard**: RFC 7643 Section 4.1
- **Input**:
  ```json
  POST /scim/v2/Users
  {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "displayName": "No Username"
  }
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  ```

### TC-SCIM-USER-026: Replace non-existent user (PUT)
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.5.1
- **Input**:
  ```json
  PUT /scim/v2/Users/00000000-0000-0000-0000-000000000099
  {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "ghost@example.com"
  }
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-SCIM-USER-027: Replace user causing userName conflict with another user
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.5.1
- **Preconditions**: User A has email `a@example.com`, User B has email `b@example.com`
- **Input**:
  ```json
  PUT /scim/v2/Users/<user-A-id>
  {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "b@example.com"
  }
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  Body: SCIM error with scimType "uniqueness"
  ```

### TC-SCIM-USER-028: Patch user with invalid operation type
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.5.2
- **Input**:
  ```json
  PATCH /scim/v2/Users/<user-id>
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {"op": "invalidOp", "path": "active", "value": true}
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
    "scimType": "invalidPath",
    "detail": "Invalid operation 'invalidOp' at index 0",
    "status": "400"
  }
  ```

### TC-SCIM-USER-029: Patch user with missing PatchOp schema
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.5.2
- **Input**:
  ```json
  PATCH /scim/v2/Users/<user-id>
  {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "Operations": [
      {"op": "replace", "path": "active", "value": false}
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: SCIM error with detail "Missing PatchOp schema"
  ```

### TC-SCIM-USER-030: Patch user with remove operation missing path
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.5.2
- **Input**:
  ```json
  PATCH /scim/v2/Users/<user-id>
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {"op": "remove"}
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: SCIM error with detail "Remove operation at index 0 requires a path"
  ```

### TC-SCIM-USER-031: Patch user - remove optional attributes
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.5.2
- **Preconditions**: User has displayName, externalId, name.givenName, name.familyName set
- **Input**:
  ```json
  PATCH /scim/v2/Users/<user-id>
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {"op": "remove", "path": "displayName"},
      {"op": "remove", "path": "externalId"},
      {"op": "remove", "path": "name.givenName"},
      {"op": "remove", "path": "name.familyName"}
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: user with removed attributes absent or null
  ```

### TC-SCIM-USER-032: Delete non-existent user
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.6
- **Input**:
  ```
  DELETE /scim/v2/Users/00000000-0000-0000-0000-000000000099
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-SCIM-USER-033: Delete already-deactivated user
- **Category**: Edge Case
- **Preconditions**: User was previously deleted (deactivated via SCIM)
- **Input**:
  ```
  DELETE /scim/v2/Users/<deactivated-user-id>
  ```
- **Expected Output**:
  ```
  Status: 204 No Content (idempotent) OR 404 Not Found
  ```
- **Note**: Implementation uses `UPDATE SET is_active = false` which succeeds even if already false

### TC-SCIM-USER-034: List users with empty result set
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.2
- **Preconditions**: New tenant with no users
- **Input**:
  ```
  GET /scim/v2/Users
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
    "totalResults": 0,
    "startIndex": 1,
    "itemsPerPage": 25,
    "Resources": []
  }
  ```

### TC-SCIM-USER-035: Pagination startIndex beyond total results
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.2.4
- **Preconditions**: Only 5 users exist
- **Input**:
  ```
  GET /scim/v2/Users?startIndex=100
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: ListResponse with totalResults=5, startIndex=100, Resources=[]
  ```

### TC-SCIM-USER-036: Pagination count exceeds maximum (100)
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.2.4
- **Input**:
  ```
  GET /scim/v2/Users?count=500
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: ListResponse with itemsPerPage clamped to 100
  ```

### TC-SCIM-USER-037: Pagination with negative startIndex
- **Category**: Edge Case
- **Input**:
  ```
  GET /scim/v2/Users?startIndex=-1
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: startIndex adjusted to minimum of 1
  ```

### TC-SCIM-USER-038: Pagination with count of zero
- **Category**: Edge Case
- **Input**:
  ```
  GET /scim/v2/Users?count=0
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: count clamped to minimum of 1
  ```

### TC-SCIM-USER-039: Patch user with enterprise extension path
- **Category**: Edge Case
- **Standard**: RFC 7643 Section 4.3
- **Input**:
  ```json
  PATCH /scim/v2/Users/<user-id>
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {
        "op": "replace",
        "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
        "value": "Sales"
      }
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Verification: custom_attributes contains "department": "Sales"
  ```

---

## Security Cases

### TC-SCIM-USER-050: Request without Authorization header
- **Category**: Security
- **Standard**: RFC 7644 Section 2 (Authentication)
- **Input**:
  ```
  GET /scim/v2/Users
  (no Authorization header)
  ```
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  Content-Type: application/scim+json
  Body: {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
    "detail": "Invalid or expired bearer token",
    "status": "401"
  }
  ```

### TC-SCIM-USER-051: Request with invalid Bearer token
- **Category**: Security
- **Standard**: RFC 7644 Section 2
- **Input**:
  ```
  GET /scim/v2/Users
  Authorization: Bearer invalid_token_value
  ```
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  ```

### TC-SCIM-USER-052: Request with revoked SCIM token
- **Category**: Security
- **Preconditions**: SCIM token was created then revoked via `DELETE /admin/scim/tokens/:id`
- **Input**:
  ```
  GET /scim/v2/Users
  Authorization: Bearer xscim_<revoked-token>
  ```
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  ```

### TC-SCIM-USER-053: Request with wrong token prefix
- **Category**: Security
- **Input**:
  ```
  GET /scim/v2/Users
  Authorization: Bearer wrong_prefix_token
  ```
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  ```
- **Verification**: Token must start with `xscim_` prefix

### TC-SCIM-USER-054: Cross-tenant user access
- **Category**: Security
- **Preconditions**: User `<user-id>` belongs to Tenant A; Bearer token belongs to Tenant B
- **Input**:
  ```
  GET /scim/v2/Users/<user-id>
  Authorization: Bearer xscim_<tenant-B-token>
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```
- **Verification**: Tenant B token MUST NOT see Tenant A users (tenant isolation via `WHERE tenant_id = $1`)

### TC-SCIM-USER-055: Cross-tenant user listing
- **Category**: Security
- **Preconditions**: Tenant A has 10 users; Tenant B has 5 users; Bearer token for Tenant B
- **Input**:
  ```
  GET /scim/v2/Users
  Authorization: Bearer xscim_<tenant-B-token>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: totalResults=5, only Tenant B users in Resources
  ```

### TC-SCIM-USER-056: SQL injection via userName
- **Category**: Security
- **Input**:
  ```json
  POST /scim/v2/Users
  {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "'; DROP TABLE users; --@evil.com"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created OR 400 Bad Request
  ```
- **Verification**: No SQL execution; parameterized queries protect against injection

### TC-SCIM-USER-057: XSS in displayName
- **Category**: Security
- **Input**:
  ```json
  POST /scim/v2/Users
  {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "xss@example.com",
    "displayName": "<script>alert('xss')</script>"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: displayName stored as-is (API-only, no HTML rendering)
  ```

### TC-SCIM-USER-058: Rate limiting on SCIM endpoints
- **Category**: Security
- **Standard**: RFC 7644 Section 3.14 (rate limiting)
- **Input**: 100 rapid requests exceeding the 25/sec + 50 burst limits
- **Expected Output**:
  ```
  Status: 429 Too Many Requests
  Retry-After: <seconds>
  Body: {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
    "scimType": "tooMany",
    "detail": "Rate limit exceeded. Try again in <N> seconds.",
    "status": "429"
  }
  ```

### TC-SCIM-USER-059: Error responses do not leak internal details
- **Category**: Security
- **Standard**: OWASP ASVS 7.4.1
- **Input**: Any request that triggers an internal error
- **Expected Output**: Error response contains generic detail, not SQL errors, stack traces, or file paths
- **Verification**: ScimError::Internal and ScimError::Database both sanitize output to generic messages

---

## Response Format Compliance

### TC-SCIM-USER-060: All user responses include schemas array
- **Category**: Compliance
- **Standard**: RFC 7643 Section 3 (schema URIs)
- **Input**: Any successful user endpoint call
- **Expected Output**: Response body contains `"schemas"` array with `"urn:ietf:params:scim:schemas:core:2.0:User"`

### TC-SCIM-USER-061: Content-Type header is application/scim+json
- **Category**: Compliance
- **Standard**: RFC 7644 Section 3.1
- **Input**: Any SCIM endpoint call
- **Expected Output**: Response `Content-Type` header is `application/scim+json`

### TC-SCIM-USER-062: Meta.resourceType is "User"
- **Category**: Compliance
- **Standard**: RFC 7643 Section 3.1
- **Input**: GET/POST/PUT/PATCH on Users endpoint
- **Expected Output**: `meta.resourceType` is `"User"` in response

### TC-SCIM-USER-063: Meta.location contains absolute URI
- **Category**: Compliance
- **Standard**: RFC 7644 Section 3.4.1
- **Input**: GET/POST on Users endpoint
- **Expected Output**: `meta.location` matches pattern `https://<host>/scim/v2/Users/<uuid>`

### TC-SCIM-USER-064: List response uses "Resources" key (capital R)
- **Category**: Compliance
- **Standard**: RFC 7644 Section 3.4.2
- **Input**: `GET /scim/v2/Users`
- **Expected Output**: Response body uses `"Resources"` (capital R), not `"resources"`

### TC-SCIM-USER-065: Error responses use SCIM error schema
- **Category**: Compliance
- **Standard**: RFC 7644 Section 3.12
- **Input**: Any request that returns an error
- **Expected Output**: Error body contains `"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"]` and includes `"detail"` and `"status"` fields
