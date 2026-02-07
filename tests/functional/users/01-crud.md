# User CRUD Functional Tests

**API Endpoints**:
- `POST /users` -- Create a new user (admin)
- `GET /users` -- List users with pagination (admin)
- `GET /users/:id` -- Get user details (admin)
- `PUT /users/:id` -- Update user (admin)
- `DELETE /users/:id` -- Deactivate user / soft delete (admin)

**Authentication**: JWT Bearer token with `admin` role required
**Required Headers**: `Content-Type: application/json`, `Authorization: Bearer <jwt>`
**Applicable Standards**: NIST SP 800-63A (Identity Proofing), ISO 27001 Annex A.9.2 (User Access Management), SOC 2 CC6.1 (Logical Access)

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: Users are created and managed via admin endpoints; all mutations require admin role JWT

---

## Nominal Cases

### TC-USER-CRUD-001: Create user with valid email, password, and roles
- **Category**: Nominal
- **Standard**: NIST SP 800-63A IAL1, ISO 27001 A.9.2.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Admin JWT for tenant `T1`; no existing user with `newuser@example.com` in `T1`
- **Input**:
  ```json
  POST /users
  Authorization: Bearer <admin-jwt-T1>
  {
    "email": "newuser@example.com",
    "password": "MyP@ssw0rd_2026",
    "roles": ["user"]
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<uuid>",
    "email": "newuser@example.com",
    "is_active": true,
    "email_verified": false,
    "roles": ["user"],
    "created_at": "<iso8601>",
    "updated_at": "<iso8601>",
    "custom_attributes": {}
  }
  ```
- **Side Effects**:
  - User row inserted into `users` table with `tenant_id = T1`
  - Row in `user_roles` with `role_name = "user"`
  - Webhook event `user.created` published
  - Audit log entry created

### TC-USER-CRUD-002: Create user with multiple roles
- **Category**: Nominal
- **Standard**: ISO 27001 A.9.2.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Admin JWT for tenant `T1`
- **Input**:
  ```json
  POST /users
  {
    "email": "multirole@example.com",
    "password": "MyP@ssw0rd_2026",
    "roles": ["user", "editor", "reviewer"]
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: { "roles": ["user", "editor", "reviewer"], ... }
  ```

### TC-USER-CRUD-003: Create user with optional username
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Admin JWT for tenant `T1`
- **Input**:
  ```json
  POST /users
  {
    "email": "withname@example.com",
    "password": "MyP@ssw0rd_2026",
    "roles": ["user"],
    "username": "john_doe"
  }
  ```
- **Expected Output**: Status 201; user created successfully

### TC-USER-CRUD-004: Get user by ID
- **Category**: Nominal
- **Standard**: ISO 27001 A.9.2.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User `U1` exists in tenant `T1`; admin JWT for `T1`
- **Input**:
  ```
  GET /users/<U1-uuid>
  Authorization: Bearer <admin-jwt-T1>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "id": "<U1-uuid>",
    "email": "...",
    "is_active": true,
    "email_verified": false,
    "roles": ["user"],
    "created_at": "<iso8601>",
    "updated_at": "<iso8601>",
    "custom_attributes": {}
  }
  ```
- **Verification**: Response does NOT contain `password_hash`, `tenant_id`, or any internal fields

### TC-USER-CRUD-005: List users with default pagination
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Tenant `T1` has 5 users; admin JWT for `T1`
- **Input**:
  ```
  GET /users
  Authorization: Bearer <admin-jwt-T1>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "users": [ ... ],
    "pagination": {
      "total_count": 5,
      "offset": 0,
      "limit": 20,
      "has_more": false
    }
  }
  ```
- **Verification**: All 5 users returned; each has `roles` array populated

### TC-USER-CRUD-006: Update user email
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User `U1` exists in tenant `T1` with email `old@example.com`
- **Input**:
  ```json
  PUT /users/<U1-uuid>
  {
    "email": "new@example.com"
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "email": "new@example.com", "updated_at": "<newer-timestamp>", ... }
  ```
- **Side Effects**: Webhook event `user.updated` published; `updated_at` timestamp advances

### TC-USER-CRUD-007: Update user roles (replace all)
- **Category**: Nominal
- **Standard**: ISO 27001 A.9.2.2 (User Access Provisioning)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User `U1` has roles `["user"]`
- **Input**:
  ```json
  PUT /users/<U1-uuid>
  {
    "roles": ["user", "admin"]
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "roles": ["admin", "user"], ... }
  ```
- **Verification**: Old roles completely replaced; `user_roles` table reflects new set

### TC-USER-CRUD-008: Update user active status (disable)
- **Category**: Nominal
- **Standard**: ISO 27001 A.9.2.6 (Removal of Access Rights)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User `U1` is active
- **Input**:
  ```json
  PUT /users/<U1-uuid>
  {
    "is_active": false
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "is_active": false, ... }
  ```
- **Side Effects**: Webhook event `user.disabled` published (not generic `user.updated`)

### TC-USER-CRUD-009: Re-enable a disabled user
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User `U1` is inactive (`is_active = false`)
- **Input**:
  ```json
  PUT /users/<U1-uuid>
  {
    "is_active": true
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "is_active": true, ... }
  ```
- **Side Effects**: Webhook event `user.enabled` published

### TC-USER-CRUD-010: Delete (deactivate) user
- **Category**: Nominal
- **Standard**: ISO 27001 A.9.2.6, SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User `U1` exists and is active in tenant `T1`
- **Input**:
  ```
  DELETE /users/<U1-uuid>
  Authorization: Bearer <admin-jwt-T1>
  ```
- **Expected Output**:
  ```
  Status: 204 No Content
  (empty body)
  ```
- **Side Effects**:
  - User's `is_active` set to `false` in database
  - Webhook event `user.deleted` published
  - Subsequent `GET /users/<U1-uuid>` still returns the user (soft delete)
  - User can no longer authenticate

### TC-USER-CRUD-011: Update user with partial fields (only email, roles unchanged)
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User `U1` has roles `["user", "editor"]` and email `old@example.com`
- **Input**:
  ```json
  PUT /users/<U1-uuid>
  {
    "email": "updated@example.com"
  }
  ```
- **Expected Output**: Status 200; `email` changed; `roles` remain `["editor", "user"]`

### TC-USER-CRUD-012: Update user with no changes (idempotent)
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User `U1` with email `same@example.com`
- **Input**:
  ```json
  PUT /users/<U1-uuid>
  {
    "email": "same@example.com"
  }
  ```
- **Expected Output**: Status 200; user returned unchanged (email already matches)

---

## Edge Cases

### TC-USER-CRUD-020: Create user with duplicate email in same tenant
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User with `existing@example.com` exists in tenant `T1`
- **Input**:
  ```json
  POST /users
  { "email": "existing@example.com", "password": "MyP@ssw0rd_2026", "roles": ["user"] }
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  Body: { "title": "Conflict", "status": 409, "detail": "Email already exists in tenant" }
  ```

### TC-USER-CRUD-021: Create user with same email in different tenant (allowed)
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User `shared@example.com` exists in tenant `T1`; admin JWT for tenant `T2`
- **Input**:
  ```json
  POST /users
  Authorization: Bearer <admin-jwt-T2>
  { "email": "shared@example.com", "password": "MyP@ssw0rd_2026", "roles": ["user"] }
  ```
- **Expected Output**: Status 201 (email uniqueness is per-tenant, not global)

### TC-USER-CRUD-022: Create user with email case variation
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User `user@example.com` exists in tenant `T1`
- **Input**:
  ```json
  POST /users
  { "email": "User@Example.COM", "password": "MyP@ssw0rd_2026", "roles": ["user"] }
  ```
- **Expected Output**: Status 409 (email normalized to lowercase before comparison)

### TC-USER-CRUD-023: Create user with empty roles array
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**:
  ```json
  POST /users
  { "email": "noroles@example.com", "password": "MyP@ssw0rd_2026", "roles": [] }
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: { "errors": [{ "attribute": "roles", "error": "At least one role is required" }] }
  ```

### TC-USER-CRUD-024: Create user with too many roles (>20)
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `"roles"` array with 21 role names
- **Expected Output**: Status 400 with error code `too_many` for field `roles`

### TC-USER-CRUD-025: Create user with empty role name in array
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `"roles": ["user", "", "admin"]`
- **Expected Output**: Status 400 with error on `roles[1]` (empty role name)

### TC-USER-CRUD-026: Create user with role name exceeding 50 characters
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `"roles": ["a]` where "a" is repeated 51 times
- **Expected Output**: Status 400 with error code `too_long` for `roles[0]`

### TC-USER-CRUD-027: Create user with password below 8 characters
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `"password": "Short1!"`
- **Expected Output**: Status 400 with error on `password` field (code: `too_short`, min_length: 8)

### TC-USER-CRUD-028: Create user with password exceeding 128 characters
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: Password with 129 characters
- **Expected Output**: Status 400 with error on `password` field (code: `too_long`, max_length: 128)

### TC-USER-CRUD-029: Create user with invalid email format
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `"email": "not-an-email"`
- **Expected Output**: Status 400 with validation error on `email` field

### TC-USER-CRUD-030: Create user with email exceeding 254 characters
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: Email longer than 254 characters (RFC 5321 max)
- **Expected Output**: Status 400 with error code `too_long` on `email`

### TC-USER-CRUD-031: Create user with email shorter than 5 characters
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `"email": "a@b"`
- **Expected Output**: Status 400 with error code `too_short` on `email`

### TC-USER-CRUD-032: Create user with username starting with a number
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `"username": "123user"`
- **Expected Output**: Status 400 with error code `invalid_start` on `username`

### TC-USER-CRUD-033: Create user with username shorter than 3 characters
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `"username": "ab"`
- **Expected Output**: Status 400 with error code `too_short` on `username`

### TC-USER-CRUD-034: Create user with username containing special characters
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `"username": "user@name!"`
- **Expected Output**: Status 400 with validation error on `username`

### TC-USER-CRUD-035: Create user with unicode username
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `"username": "Jose"`  (non-ASCII characters)
- **Expected Output**: Status 400 with error code `non_ascii` on `username`

### TC-USER-CRUD-036: Get user with invalid UUID format
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `GET /users/not-a-uuid`
- **Expected Output**: Status 400 with `"Invalid user ID format"`

### TC-USER-CRUD-037: Get user that does not exist
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `GET /users/<valid-uuid-not-in-db>`
- **Expected Output**: Status 404 with `"User not found"`

### TC-USER-CRUD-038: Delete already-deactivated user (idempotent)
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User `U1` already has `is_active = false`
- **Input**: `DELETE /users/<U1-uuid>`
- **Expected Output**: Status 204 (idempotent -- succeeds even if already deactivated)

### TC-USER-CRUD-039: Delete user that does not exist
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `DELETE /users/<non-existent-uuid>`
- **Expected Output**: Status 404

### TC-USER-CRUD-040: Update user email to one already taken in same tenant
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User `U2` exists with email `taken@example.com` in tenant `T1`
- **Input**:
  ```json
  PUT /users/<U1-uuid>
  { "email": "taken@example.com" }
  ```
- **Expected Output**: Status 409 (email conflict)

### TC-USER-CRUD-041: Create user with multiple validation errors simultaneously
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**:
  ```json
  POST /users
  { "email": "bad", "password": "short", "roles": [] }
  ```
- **Expected Output**: Status 400 with `errors` array containing errors for `email`, `password`, AND `roles` (all returned at once, not one at a time)

### TC-USER-CRUD-042: Create user with email that has leading/trailing whitespace
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `"email": "  spaces@example.com  "`
- **Expected Output**: Status 201 (whitespace trimmed; email stored as `spaces@example.com`)

### TC-USER-CRUD-043: Create user with plus-addressing email
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `"email": "user+tag@example.com"`
- **Expected Output**: Status 201 (valid per RFC 5322)

### TC-USER-CRUD-044: Empty request body on POST /users
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `POST /users` with empty body `{}`
- **Expected Output**: Status 400 or 422 (deserialization error -- missing required fields)

---

## Security Cases

### TC-USER-CRUD-050: Access without authentication
- **Category**: Security
- **Standard**: ISO 27001 A.9.4.1
- **Preconditions**: Fixtures: `TEST_TENANT`. No authentication token provided
- **Input**: `GET /users` with no `Authorization` header
- **Expected Output**: Status 401 Unauthorized

### TC-USER-CRUD-051: Access with non-admin role
- **Category**: Security
- **Standard**: ISO 27001 A.9.4.1
- **Preconditions**: Fixtures: `TEST_TENANT`. JWT with role `["user"]` only (no `admin`)
- **Input**: `POST /users` with valid body
- **Expected Output**: Status 403 Forbidden

### TC-USER-CRUD-052: Cross-tenant user access (tenant isolation)
- **Category**: Security
- **Standard**: SOC 2 CC6.1 (Logical Access Controls)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User `U1` belongs to tenant `T1`; admin JWT for tenant `T2`
- **Input**:
  ```
  GET /users/<U1-uuid>
  Authorization: Bearer <admin-jwt-T2>
  ```
- **Expected Output**: Status 404 (must NOT reveal that user exists in another tenant)

### TC-USER-CRUD-053: Cross-tenant user update
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User `U1` belongs to tenant `T1`; admin JWT for tenant `T2`
- **Input**:
  ```json
  PUT /users/<U1-uuid>
  Authorization: Bearer <admin-jwt-T2>
  { "email": "hacked@evil.com" }
  ```
- **Expected Output**: Status 404 (not 200 -- cannot modify cross-tenant users)

### TC-USER-CRUD-054: Cross-tenant user deletion
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User `U1` belongs to tenant `T1`; admin JWT for tenant `T2`
- **Input**:
  ```
  DELETE /users/<U1-uuid>
  Authorization: Bearer <admin-jwt-T2>
  ```
- **Expected Output**: Status 404

### TC-USER-CRUD-055: Cross-tenant user list isolation
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Tenant `T1` has users; tenant `T2` has different users; admin JWT for `T2`
- **Input**: `GET /users` with admin JWT for `T2`
- **Expected Output**: Only `T2` users returned; no `T1` users visible

### TC-USER-CRUD-056: Password not returned in any response
- **Category**: Security
- **Standard**: OWASP ASVS 2.4.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `POST /users` (create) then `GET /users/:id` (read)
- **Expected Output**: Neither response contains `password`, `password_hash`, or any password-related field

### TC-USER-CRUD-057: SQL injection in email field
- **Category**: Security
- **Standard**: OWASP ASVS 5.3.4
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `"email": "'; DROP TABLE users; --@example.com"`
- **Expected Output**: Status 400 (invalid email format); database unaffected

### TC-USER-CRUD-058: SQL injection in user ID path parameter
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `GET /users/'; DROP TABLE users; --`
- **Expected Output**: Status 400 (invalid UUID format); database unaffected

### TC-USER-CRUD-059: Error responses do not leak internal details
- **Category**: Security
- **Standard**: OWASP ASVS 7.4.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: Various failing requests
- **Expected Output**: Error responses use RFC 7807 Problem Details format; never contain SQL error messages, stack traces, internal file paths, or database schema information

### TC-USER-CRUD-060: Expired JWT token
- **Category**: Security
- **Preconditions**: Fixtures: `TEST_TENANT`. Expired JWT token available
- **Input**: `GET /users` with an expired JWT
- **Expected Output**: Status 401 Unauthorized

### TC-USER-CRUD-061: JWT with tampered tenant_id
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `TEST_TENANT`. Tampered JWT with altered `tid` claim
- **Input**: JWT where `tid` claim has been manually altered (invalid signature)
- **Expected Output**: Status 401 (signature verification fails)

### TC-USER-CRUD-062: Privilege escalation via super_admin role assignment
- **Category**: Security
- **Standard**: ISO 27001 A.9.2.3
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin (non-super_admin)
- **Input**:
  ```json
  POST /users
  { "email": "escalate@example.com", "password": "MyP@ssw0rd_2026", "roles": ["super_admin"] }
  ```
- **Expected Output**: Status 400 or 403 (super_admin role assignment restricted)

### TC-USER-CRUD-063: RLS defense-in-depth verification
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. RLS policies active on `users` table
- **Input**: Create user via `POST /users`
- **Verification**: Transaction sets `app.current_tenant` via `set_config` before INSERT; RLS WITH CHECK clause enforces tenant_id matching

---

## Compliance Cases

### TC-USER-CRUD-070: Audit trail for user creation
- **Category**: Compliance
- **Standard**: SOC 2 CC6.1, ISO 27001 A.12.4.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: Create a user via `POST /users`
- **Verification**: Audit log contains: actor (admin user_id), action (`user.created`), target (new user_id), tenant_id, timestamp, source IP

### TC-USER-CRUD-071: Audit trail for user deletion
- **Category**: Compliance
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin; user exists to delete
- **Input**: Delete a user via `DELETE /users/:id`
- **Verification**: Audit log records `user.deleted` event with actor, target, and timestamp

### TC-USER-CRUD-072: Webhook events for user lifecycle
- **Category**: Compliance
- **Standard**: ISO 27001 A.9.2.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin; webhook endpoint configured
- **Input**: Create, update, disable, delete a user
- **Verification**: Webhook events published: `user.created`, `user.updated`, `user.disabled`, `user.deleted` -- each with `event_id`, `tenant_id`, `actor_id`, `timestamp`, and relevant `data` payload
