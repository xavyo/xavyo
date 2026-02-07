# SCIM 2.0 Filtering and Pagination Functional Tests

**API Endpoints**: `GET /scim/v2/Users`, `GET /scim/v2/Groups`
**Authentication**: Bearer token (SCIM token via `Authorization: Bearer xscim_...`)
**Applicable Standards**: RFC 7644 Section 3.4.2 (Filtering), Section 3.4.2.2 (Filter Syntax), Section 3.4.2.4 (Pagination)

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `SCIM_TOKEN`, `TEST_TENANT`, `ADMIN_JWT`
- **Special Setup**: SCIM provisioning enabled for tenant

---

## Nominal Cases - Filter Operators

### TC-SCIM-FILTER-001: Filter by userName eq (exact match)
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.4.2.2
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. User `alice@example.com` exists
- **Input**:
  ```
  GET /scim/v2/Users?filter=userName eq "alice@example.com"
  Authorization: Bearer xscim_<token>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
    "totalResults": 1,
    "Resources": [
      {"userName": "alice@example.com", ...}
    ]
  }
  ```
- **Verification**: SQL maps `userName` to `email` column: `WHERE email = $1`

### TC-SCIM-FILTER-002: Filter by displayName co (contains)
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.4.2.2
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. Users with displayName containing "John" exist
- **Input**:
  ```
  GET /scim/v2/Users?filter=displayName co "John"
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: ListResponse with all users whose displayName contains "John" (case-insensitive)
  ```
- **Verification**: SQL uses `ILIKE '%John%'`

### TC-SCIM-FILTER-003: Filter by userName sw (starts with)
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.4.2.2
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. Users with emails starting with "admin" exist
- **Input**:
  ```
  GET /scim/v2/Users?filter=userName sw "admin"
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: ListResponse with users whose email starts with "admin"
  ```
- **Verification**: SQL uses `ILIKE 'admin%'`

### TC-SCIM-FILTER-004: Filter by externalId pr (present / not null)
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.4.2.2
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. Some users have externalId, some do not
- **Input**:
  ```
  GET /scim/v2/Users?filter=externalId pr
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: ListResponse with only users where externalId IS NOT NULL
  ```

### TC-SCIM-FILTER-005: Filter by active eq true
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.4.2.2
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=active eq true
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: ListResponse with only active users (is_active = true)
  ```

### TC-SCIM-FILTER-006: Filter with AND logical operator
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.4.2.2
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=userName eq "alice@example.com" and active eq true
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: ListResponse with users matching BOTH conditions
  ```
- **Verification**: SQL generates `(email = $1 AND is_active = $2)`

### TC-SCIM-FILTER-007: Filter with OR logical operator
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.4.2.2
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=userName eq "alice@example.com" or userName eq "bob@example.com"
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: ListResponse with users matching EITHER condition
  ```
- **Verification**: SQL generates `(email = $1 OR email = $2)`

### TC-SCIM-FILTER-008: Filter by nested attribute (name.givenName)
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.4.2.2
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. Users with first_name "John" exist
- **Input**:
  ```
  GET /scim/v2/Users?filter=name.givenName eq "John"
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: ListResponse with users where first_name = "John"
  ```

### TC-SCIM-FILTER-009: Filter groups by displayName
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.4.2.2
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. Group "Engineering" exists
- **Input**:
  ```
  GET /scim/v2/Groups?filter=displayName eq "Engineering"
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: ListResponse with totalResults=1, the Engineering group
  ```

### TC-SCIM-FILTER-010: Pagination with startIndex and count
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.4.2.4
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. 50 users exist
- **Input**:
  ```
  GET /scim/v2/Users?startIndex=11&count=10
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
    "totalResults": 50,
    "startIndex": 11,
    "itemsPerPage": 10,
    "Resources": [ ... (10 users) ]
  }
  ```
- **Verification**: SQL uses `OFFSET 10 LIMIT 10` (1-based startIndex converts to 0-based offset)

---

## Edge Cases - Filter Syntax

### TC-SCIM-FILTER-020: Filter with NOT operator
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.2.2
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=not (active eq false)
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: ListResponse with users where active is NOT false
  ```
- **Verification**: SQL generates `NOT (is_active = $1)`

### TC-SCIM-FILTER-021: Filter with grouped expression
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.2.2
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=(userName co "john" or userName co "jane") and active eq true
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: ListResponse with users matching grouped OR condition AND active=true
  ```
- **Verification**: SQL correctly parenthesizes: `((email ILIKE $1 OR email ILIKE $2)) AND is_active = $3`

### TC-SCIM-FILTER-022: Filter with ne (not equal) operator
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.2.2
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=active ne true
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: ListResponse with inactive users
  ```
- **Verification**: SQL generates `is_active <> $1`

### TC-SCIM-FILTER-023: Filter with ew (ends with) operator
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.2.2
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=userName ew "@example.com"
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: ListResponse with users whose email ends with "@example.com"
  ```
- **Verification**: SQL uses `ILIKE '%@example.com'`

### TC-SCIM-FILTER-024: Filter with gt (greater than) operator
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.2.2
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=userName gt "m"
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: ListResponse with users whose email sorts after "m"
  ```

### TC-SCIM-FILTER-025: Filter with ge (greater than or equal) operator
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.2.2
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=userName ge "alice@example.com"
  ```
- **Expected Output**: Status 200; users with email >= "alice@example.com"

### TC-SCIM-FILTER-026: Filter with lt (less than) operator
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.2.2
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=userName lt "m"
  ```
- **Expected Output**: Status 200; users with email < "m"

### TC-SCIM-FILTER-027: Filter with le (less than or equal) operator
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.2.2
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=userName le "alice@example.com"
  ```
- **Expected Output**: Status 200; users with email <= "alice@example.com"

### TC-SCIM-FILTER-028: Filter with unknown attribute
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.2.2
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=unknownAttr eq "value"
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
    "scimType": "invalidFilter",
    "detail": "Invalid filter: Unknown attribute: unknownAttr",
    "status": "400"
  }
  ```

### TC-SCIM-FILTER-029: Filter with invalid operator
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.2.2
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=userName invalidop "value"
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: SCIM error with scimType "invalidFilter"
  ```

### TC-SCIM-FILTER-030: Filter with unterminated string
- **Category**: Edge Case
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=userName eq "unterminated
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: SCIM error with detail containing "Unterminated string"
  ```

### TC-SCIM-FILTER-031: Filter with missing value after operator
- **Category**: Edge Case
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=userName eq
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: SCIM error with detail "Expected value"
  ```

### TC-SCIM-FILTER-032: Filter with empty string
- **Category**: Edge Case
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=
  ```
- **Expected Output**:
  ```
  Status: 200 OK (empty filter treated as no filter; returns all users)
  OR
  Status: 400 Bad Request (if empty filter is rejected)
  ```

### TC-SCIM-FILTER-033: Filter with unbalanced parentheses
- **Category**: Edge Case
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=(userName eq "alice@example.com"
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: SCIM error with detail "Expected ')' to close grouped expression"
  ```

### TC-SCIM-FILTER-034: Filter with NOT missing parentheses
- **Category**: Edge Case
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=not active eq true
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: SCIM error with detail "Expected '(' after 'not'"
  ```

---

## Edge Cases - Pagination

### TC-SCIM-FILTER-040: Default pagination (no params)
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.2.4
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users
  ```
- **Expected Output**: startIndex=1, itemsPerPage=25 (defaults)

### TC-SCIM-FILTER-041: Count exceeds maximum (clamped to 100)
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.2.4
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?count=999
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: ListResponse with itemsPerPage=100 (clamped)
  ```
- **Verification**: `ScimPagination::MAX_COUNT` is 100

### TC-SCIM-FILTER-042: Negative startIndex (adjusted to 1)
- **Category**: Edge Case
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?startIndex=-5
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: ListResponse with startIndex=1 (adjusted to minimum)
  ```

### TC-SCIM-FILTER-043: Zero count (clamped to 1)
- **Category**: Edge Case
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?count=0
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: ListResponse with itemsPerPage clamped to minimum 1
  ```

### TC-SCIM-FILTER-044: startIndex beyond totalResults
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.2.4
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. Only 5 users exist
- **Input**:
  ```
  GET /scim/v2/Users?startIndex=1000
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "totalResults": 5,
    "startIndex": 1000,
    "Resources": []
  }
  ```

### TC-SCIM-FILTER-045: Pagination through full result set
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.2.4
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. 30 users exist
- **Input**: Sequence of requests:
  1. `GET /scim/v2/Users?startIndex=1&count=10` --> 10 users
  2. `GET /scim/v2/Users?startIndex=11&count=10` --> 10 users
  3. `GET /scim/v2/Users?startIndex=21&count=10` --> 10 users
  4. `GET /scim/v2/Users?startIndex=31&count=10` --> 0 users
- **Expected Output**: All 30 users returned across 3 pages; 4th page empty; totalResults=30 in all responses

### TC-SCIM-FILTER-046: Sorting by userName ascending
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.2.3
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?sortBy=userName&sortOrder=ascending
  ```
- **Expected Output**: Resources sorted by email ASC

### TC-SCIM-FILTER-047: Sorting by userName descending
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.2.3
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?sortBy=userName&sortOrder=descending
  ```
- **Expected Output**: Resources sorted by email DESC

### TC-SCIM-FILTER-048: Sorting by displayName
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.2.3
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?sortBy=displayName
  ```
- **Expected Output**: Resources sorted by display_name ASC (default order when no sortOrder specified)

### TC-SCIM-FILTER-049: Sorting by unsupported attribute defaults to created_at
- **Category**: Edge Case
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?sortBy=unknownField
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: Resources sorted by created_at ASC (default fallback)
  ```

### TC-SCIM-FILTER-050: Filter combined with pagination
- **Category**: Edge Case
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. 20 active users, 5 inactive users
- **Input**:
  ```
  GET /scim/v2/Users?filter=active eq true&startIndex=1&count=10
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: totalResults=20, itemsPerPage=10, Resources contains 10 active users
  ```

### TC-SCIM-FILTER-051: Filter combined with sorting
- **Category**: Edge Case
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=active eq true&sortBy=userName&sortOrder=descending
  ```
- **Expected Output**: Only active users, sorted by email descending

### TC-SCIM-FILTER-052: Case-insensitive filter operators
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.2.2
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=userName EQ "alice@example.com"
  ```
- **Expected Output**: Status 200; operators are case-insensitive per spec
- **Verification**: Parser lowercases operator before matching

### TC-SCIM-FILTER-053: emails.value attribute mapping
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.4.2.2
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=emails.value eq "alice@example.com"
  ```
- **Expected Output**: Status 200; maps to `email` column in DB

### TC-SCIM-FILTER-054: Filter by name.familyName
- **Category**: Edge Case
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=name.familyName eq "Smith"
  ```
- **Expected Output**: Status 200; maps to `last_name` column

---

## Security Cases

### TC-SCIM-FILTER-060: SQL injection via filter value
- **Category**: Security
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=userName eq "'; DROP TABLE users; --"
  ```
- **Expected Output**:
  ```
  Status: 200 OK (empty result set)
  ```
- **Verification**: Filter values are bound as parameterized query parameters (`$N`), not concatenated into SQL

### TC-SCIM-FILTER-061: SQL injection via attribute name
- **Category**: Security
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=id; DROP TABLE users;-- eq "test"
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: SCIM error with scimType "invalidFilter"
  ```
- **Verification**: Attribute names are validated against the whitelist mapper; unknown attributes rejected. Column names in SQL are double-quoted for defense-in-depth

### TC-SCIM-FILTER-062: Filter does not bypass tenant isolation
- **Category**: Security
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. Tenant A has user `alice@a.com`; Bearer token for Tenant B
- **Input**:
  ```
  GET /scim/v2/Users?filter=userName eq "alice@a.com"
  Authorization: Bearer xscim_<tenant-B-token>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: totalResults=0 (Tenant B cannot see Tenant A users)
  ```
- **Verification**: Filter SQL always includes `WHERE tenant_id = $1` as the base condition

### TC-SCIM-FILTER-063: Oversized filter string
- **Category**: Security
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**: Filter string with 10,000+ characters (potential DoS via complex parsing)
- **Expected Output**:
  ```
  Status: 400 Bad Request
  ```
- **Verification**: Parser handles without excessive memory/CPU consumption

### TC-SCIM-FILTER-064: Filter with escaped quotes in value
- **Category**: Security
- **Standard**: RFC 7644 Section 3.4.2.2
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. SCIM token authenticated
- **Input**:
  ```
  GET /scim/v2/Users?filter=displayName eq "O\"Brien"
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: Users with displayName matching the escaped value
  ```
- **Verification**: Parser correctly handles backslash-escaped quotes within string values
