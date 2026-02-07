# User Search and Filtering Functional Tests

**API Endpoint**: `GET /users`
**Authentication**: JWT Bearer token with `admin` role required
**Required Headers**: `Authorization: Bearer <jwt>`
**Applicable Standards**: NIST SP 800-63A, ISO 27001 Annex A.9.2 (User Access Management), SOC 2 CC6.1

**Query Parameters**:
- `offset` (integer, default: 0, min: 0) -- Pagination offset
- `limit` (integer, default: 20, min: 1, max: 100) -- Page size
- `email` (string, optional) -- Case-insensitive partial match on email
- `custom_attr.{name}` (string, optional) -- Equality filter on custom attribute
- `custom_attr.{name}.lt|gt|lte|gte` (string, optional) -- Range filter on custom attribute

---

## Nominal Cases

### TC-USER-SEARCH-001: List users with default pagination
- **Category**: Nominal
- **Preconditions**: Tenant `T1` has 25 users; admin JWT for `T1`
- **Input**:
  ```
  GET /users
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "users": [ ... (20 users) ],
    "pagination": {
      "total_count": 25,
      "offset": 0,
      "limit": 20,
      "has_more": true
    }
  }
  ```
- **Verification**: Exactly 20 users returned; ordered by `created_at DESC`

### TC-USER-SEARCH-002: List users with explicit offset and limit
- **Category**: Nominal
- **Preconditions**: Tenant `T1` has 25 users
- **Input**: `GET /users?offset=20&limit=10`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "users": [ ... (5 users) ],
    "pagination": {
      "total_count": 25,
      "offset": 20,
      "limit": 10,
      "has_more": false
    }
  }
  ```

### TC-USER-SEARCH-003: Filter users by email (partial match)
- **Category**: Nominal
- **Preconditions**: Tenant has users with emails `alice@corp.com`, `alice.smith@corp.com`, `bob@corp.com`
- **Input**: `GET /users?email=alice`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "users": [ ... (2 users -- alice@corp.com, alice.smith@corp.com) ],
    "pagination": { "total_count": 2, ... }
  }
  ```

### TC-USER-SEARCH-004: Email filter is case-insensitive
- **Category**: Nominal
- **Preconditions**: User with email `Alice@Corp.com` exists
- **Input**: `GET /users?email=alice`
- **Expected Output**: Status 200; user with `Alice@Corp.com` (stored as `alice@corp.com`) is returned

### TC-USER-SEARCH-005: Email filter with domain
- **Category**: Nominal
- **Preconditions**: Users with `@corp.com` and `@personal.com` emails exist
- **Input**: `GET /users?email=corp.com`
- **Expected Output**: Only `@corp.com` users returned

### TC-USER-SEARCH-006: List first page then second page
- **Category**: Nominal
- **Preconditions**: Tenant has 30 users
- **Input**:
  1. `GET /users?offset=0&limit=20` -- returns 20 users, `has_more: true`
  2. `GET /users?offset=20&limit=20` -- returns 10 users, `has_more: false`
- **Expected Output**: Union of both pages contains all 30 users with no duplicates

### TC-USER-SEARCH-007: List with limit=1 (minimum page size)
- **Category**: Nominal
- **Preconditions**: Tenant has users
- **Input**: `GET /users?limit=1`
- **Expected Output**: Status 200; exactly 1 user returned; `pagination.limit = 1`

### TC-USER-SEARCH-008: List with limit=100 (maximum page size)
- **Category**: Nominal
- **Preconditions**: Tenant has 150 users
- **Input**: `GET /users?limit=100`
- **Expected Output**: Status 200; exactly 100 users returned; `has_more: true`

### TC-USER-SEARCH-009: List users returns roles for each user (no N+1)
- **Category**: Nominal
- **Preconditions**: Tenant has 5 users with varying roles
- **Input**: `GET /users`
- **Expected Output**: Each user in the response has a populated `roles` array matching their assigned roles
- **Verification**: Roles are fetched in a single batch query (not per-user)

### TC-USER-SEARCH-010: Filter by custom attribute (equality)
- **Category**: Nominal
- **Preconditions**: Users exist with custom attribute `department` set to `Engineering` or `Marketing`
- **Input**: `GET /users?custom_attr.department=Engineering`
- **Expected Output**: Only users with `department = "Engineering"` returned

### TC-USER-SEARCH-011: Filter by custom attribute (range -- greater than)
- **Category**: Nominal
- **Preconditions**: Users with custom attribute `hire_date` values
- **Input**: `GET /users?custom_attr.hire_date.gt=2025-01-01`
- **Expected Output**: Only users hired after 2025-01-01 returned

### TC-USER-SEARCH-012: Multiple custom attribute filters (AND logic)
- **Category**: Nominal
- **Preconditions**: Users with `department` and `level` custom attributes
- **Input**: `GET /users?custom_attr.department=Engineering&custom_attr.level.gte=3`
- **Expected Output**: Only users matching BOTH conditions returned

### TC-USER-SEARCH-013: List returns empty when no users match filter
- **Category**: Nominal
- **Input**: `GET /users?email=nonexistent-domain-xyz.com`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "users": [],
    "pagination": { "total_count": 0, "offset": 0, "limit": 20, "has_more": false }
  }
  ```

### TC-USER-SEARCH-014: List returns users ordered by created_at DESC
- **Category**: Nominal
- **Preconditions**: Create users U1, U2, U3 sequentially
- **Input**: `GET /users`
- **Expected Output**: Users returned in order U3, U2, U1 (newest first)

### TC-USER-SEARCH-015: Pagination has_more correctly computed
- **Category**: Nominal
- **Preconditions**: Tenant has exactly 20 users
- **Input**: `GET /users?limit=20`
- **Expected Output**: `"has_more": false` (offset=0, limit=20, total=20 => 0+20 >= 20)

---

## Edge Cases

### TC-USER-SEARCH-020: Negative offset is clamped to 0
- **Category**: Edge Case
- **Input**: `GET /users?offset=-5`
- **Expected Output**: Status 200; behaves as if `offset=0` (clamped, not rejected)

### TC-USER-SEARCH-021: Limit exceeding maximum is clamped to 100
- **Category**: Edge Case
- **Input**: `GET /users?limit=500`
- **Expected Output**: Status 200; at most 100 users returned; `pagination.limit = 100`

### TC-USER-SEARCH-022: Limit of 0 is clamped to 1
- **Category**: Edge Case
- **Input**: `GET /users?limit=0`
- **Expected Output**: Status 200; at least 1 user returned; `pagination.limit = 1`

### TC-USER-SEARCH-023: Negative limit is clamped to 1
- **Category**: Edge Case
- **Input**: `GET /users?limit=-10`
- **Expected Output**: Status 200; `pagination.limit = 1`

### TC-USER-SEARCH-024: Offset beyond total count returns empty list
- **Category**: Edge Case
- **Preconditions**: Tenant has 5 users
- **Input**: `GET /users?offset=1000`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "users": [], "pagination": { "total_count": 5, "offset": 1000, "limit": 20, "has_more": false } }
  ```

### TC-USER-SEARCH-025: Email filter with special regex characters
- **Category**: Edge Case
- **Input**: `GET /users?email=user%2Btag` (URL-encoded `user+tag`)
- **Expected Output**: Status 200; LIKE pattern matches correctly (no regex injection)

### TC-USER-SEARCH-026: Email filter with SQL wildcard characters
- **Category**: Edge Case
- **Input**: `GET /users?email=%25` (URL-encoded `%`)
- **Expected Output**: Status 200; pattern is safely escaped in LIKE clause

### TC-USER-SEARCH-027: Custom attribute filter with invalid attribute name
- **Category**: Edge Case
- **Input**: `GET /users?custom_attr.INVALID-NAME=value`
- **Expected Output**: Status 400 with validation error about invalid attribute name format

### TC-USER-SEARCH-028: Custom attribute filter name with SQL injection attempt
- **Category**: Edge Case
- **Input**: `GET /users?custom_attr.'; DROP TABLE users;--=value`
- **Expected Output**: Status 400 (attribute name fails regex validation `^[a-z][a-z0-9_]{0,63}$`)

### TC-USER-SEARCH-029: Very large offset value (integer overflow protection)
- **Category**: Edge Case
- **Input**: `GET /users?offset=9999999999999999`
- **Expected Output**: Status 200 (uses `saturating_add` arithmetic); empty result set

### TC-USER-SEARCH-030: Non-numeric offset parameter
- **Category**: Edge Case
- **Input**: `GET /users?offset=abc`
- **Expected Output**: Status 400 (query parameter deserialization failure)

### TC-USER-SEARCH-031: Empty email filter
- **Category**: Edge Case
- **Input**: `GET /users?email=`
- **Expected Output**: Status 200; returns all users (empty filter matches everything with LIKE `%%`)

---

## Security Cases

### TC-USER-SEARCH-040: Tenant isolation in list results
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Tenant `T1` has users A, B, C; Tenant `T2` has users X, Y; admin JWT for `T2`
- **Input**: `GET /users` with `T2` admin JWT
- **Expected Output**: Only users X, Y returned; users A, B, C from `T1` are NOT visible

### TC-USER-SEARCH-041: Tenant isolation in email filter
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: `alice@corp.com` exists in T1; admin JWT for T2
- **Input**: `GET /users?email=alice@corp.com` with T2 admin JWT
- **Expected Output**: Empty result (`total_count: 0`); does NOT reveal T1 user existence

### TC-USER-SEARCH-042: Unauthenticated access to list endpoint
- **Category**: Security
- **Input**: `GET /users` with no Authorization header
- **Expected Output**: Status 401

### TC-USER-SEARCH-043: Non-admin access to list endpoint
- **Category**: Security
- **Preconditions**: JWT with role `["user"]` (not admin)
- **Input**: `GET /users`
- **Expected Output**: Status 403 Forbidden

### TC-USER-SEARCH-044: Response does not contain sensitive fields
- **Category**: Security
- **Standard**: OWASP ASVS 2.4.1
- **Input**: `GET /users`
- **Expected Output**: No user object contains `password_hash`, `tenant_id` in the response

### TC-USER-SEARCH-045: SQL injection via email filter
- **Category**: Security
- **Input**: `GET /users?email=' OR '1'='1`
- **Expected Output**: Status 200 with 0 results (parameterized query prevents injection)

### TC-USER-SEARCH-046: Custom attribute filter SQL injection via value
- **Category**: Security
- **Input**: `GET /users?custom_attr.department=' OR 1=1 --`
- **Expected Output**: Status 200 with 0 results (values are parameterized)

### TC-USER-SEARCH-047: Pagination does not expose data from other tenants at boundary
- **Category**: Security
- **Preconditions**: T1 has 50 users, T2 has 50 users
- **Input**: `GET /users?limit=100` with T1 admin JWT
- **Expected Output**: Exactly 50 users returned (`total_count: 50`); `has_more: false`

### TC-USER-SEARCH-048: Error responses do not leak database schema
- **Category**: Security
- **Standard**: OWASP ASVS 7.4.1
- **Input**: `GET /users?offset=invalid`
- **Expected Output**: Generic error message; no SQL table names, column names, or query fragments in response
