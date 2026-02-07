# SCIM 2.0 Bulk Operations Functional Tests

**API Endpoint**: `POST /scim/v2/Bulk`
**Authentication**: Bearer token (SCIM token via `Authorization: Bearer xscim_...`)
**Required Headers**: `Content-Type: application/scim+json`, `Authorization: Bearer <token>`
**Applicable Standards**: RFC 7644 Section 3.7 (Bulk Operations)

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `SCIM_TOKEN`, `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: SCIM bearer token provisioned for the test tenant; existing users and groups for PUT/PATCH/DELETE operations

---

## Nominal Cases

### TC-SCIM-BULK-001: Create multiple users in a single bulk request
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.7
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. Valid SCIM Bearer token; no existing users with the given emails
- **Input**:
  ```json
  POST /scim/v2/Bulk
  Content-Type: application/scim+json
  Authorization: Bearer xscim_<token>

  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
    "Operations": [
      {
        "method": "POST",
        "path": "/Users",
        "bulkId": "user-1",
        "data": {
          "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
          "userName": "bulk-alice@example.com",
          "displayName": "Alice Bulk"
        }
      },
      {
        "method": "POST",
        "path": "/Users",
        "bulkId": "user-2",
        "data": {
          "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
          "userName": "bulk-bob@example.com",
          "displayName": "Bob Bulk"
        }
      }
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Content-Type: application/scim+json
  Body: {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkResponse"],
    "Operations": [
      {
        "method": "POST",
        "bulkId": "user-1",
        "status": "201",
        "location": "https://<host>/scim/v2/Users/<uuid1>",
        "response": {
          "id": "<uuid1>",
          "userName": "bulk-alice@example.com",
          ...
        }
      },
      {
        "method": "POST",
        "bulkId": "user-2",
        "status": "201",
        "location": "https://<host>/scim/v2/Users/<uuid2>",
        "response": {
          "id": "<uuid2>",
          "userName": "bulk-bob@example.com",
          ...
        }
      }
    ]
  }
  ```
- **Verification**: Both users created in database; HTTP status is 200 (bulk always returns 200)

### TC-SCIM-BULK-002: Mixed operation types (POST, PUT, PATCH, DELETE)
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.7
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. User `<existing-id>` exists; user `<patch-id>` exists; user `<delete-id>` exists
- **Input**:
  ```json
  POST /scim/v2/Bulk
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
    "Operations": [
      {
        "method": "POST",
        "path": "/Users",
        "bulkId": "new-user",
        "data": {
          "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
          "userName": "new@example.com"
        }
      },
      {
        "method": "PUT",
        "path": "/Users/<existing-id>",
        "data": {
          "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
          "userName": "replaced@example.com",
          "displayName": "Replaced User"
        }
      },
      {
        "method": "PATCH",
        "path": "/Users/<patch-id>",
        "data": {
          "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          "Operations": [
            {"op": "replace", "path": "active", "value": false}
          ]
        }
      },
      {
        "method": "DELETE",
        "path": "/Users/<delete-id>"
      }
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: BulkResponse with Operations:
    - POST: status "201"
    - PUT: status "200"
    - PATCH: status "200"
    - DELETE: status "204"
  ```

### TC-SCIM-BULK-003: Bulk with group operations
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.7
- **Input**:
  ```json
  POST /scim/v2/Bulk
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
    "Operations": [
      {
        "method": "POST",
        "path": "/Groups",
        "bulkId": "group-1",
        "data": {
          "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
          "displayName": "Bulk Group"
        }
      }
    ]
  }
  ```
- **Expected Output**: BulkResponse with group creation status "201" and location header

### TC-SCIM-BULK-004: Bulk request with failOnErrors = 0 (continue all)
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.7
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. User `existing@example.com` already exists
- **Input**:
  ```json
  POST /scim/v2/Bulk
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
    "failOnErrors": 0,
    "Operations": [
      {
        "method": "POST",
        "path": "/Users",
        "bulkId": "user-ok",
        "data": {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "unique@example.com"}
      },
      {
        "method": "POST",
        "path": "/Users",
        "bulkId": "user-dup",
        "data": {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "existing@example.com"}
      },
      {
        "method": "POST",
        "path": "/Users",
        "bulkId": "user-ok-2",
        "data": {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "unique2@example.com"}
      }
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: BulkResponse with all 3 operations processed:
    - user-ok: status "201"
    - user-dup: status "409" with SCIM error in response
    - user-ok-2: status "201" (processed despite previous error)
  ```

### TC-SCIM-BULK-005: Bulk request with failOnErrors = 1 (stop after first error)
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.7
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. User `existing@example.com` already exists
- **Input**:
  ```json
  POST /scim/v2/Bulk
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
    "failOnErrors": 1,
    "Operations": [
      {
        "method": "POST",
        "path": "/Users",
        "bulkId": "user-dup",
        "data": {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "existing@example.com"}
      },
      {
        "method": "POST",
        "path": "/Users",
        "bulkId": "user-skipped",
        "data": {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "wont-be-created@example.com"}
      }
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: BulkResponse with:
    - user-dup: status "409"
    - user-skipped: NOT processed (skipped due to failOnErrors threshold)
  ```

### TC-SCIM-BULK-006: Bulk with bulkId cross-reference
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.7.2
- **Input**:
  ```json
  POST /scim/v2/Bulk
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
    "Operations": [
      {
        "method": "POST",
        "path": "/Users",
        "bulkId": "new-user",
        "data": {
          "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
          "userName": "referenced@example.com"
        }
      },
      {
        "method": "PATCH",
        "path": "/Groups/<group-id>",
        "data": {
          "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          "Operations": [
            {
              "op": "add",
              "path": "members",
              "value": [{"value": "bulkId:new-user"}]
            }
          ]
        }
      }
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: BulkResponse where:
    - new-user: status "201" with assigned UUID
    - group patch: status "200", bulkId:new-user resolved to the created user's UUID
  ```
- **Verification**: The newly created user is now a member of the group

### TC-SCIM-BULK-007: Bulk with version/ETag for optimistic concurrency
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.7
- **Input**:
  ```json
  POST /scim/v2/Bulk
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
    "Operations": [
      {
        "method": "PUT",
        "path": "/Users/<user-id>",
        "version": "W/\"abc123\"",
        "data": {
          "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
          "userName": "versioned@example.com"
        }
      }
    ]
  }
  ```
- **Expected Output**: Status 200 OK; version field included in operation for concurrency control

### TC-SCIM-BULK-008: Bulk response schema is correct
- **Category**: Nominal
- **Standard**: RFC 7644 Section 3.7
- **Input**: Any valid bulk request
- **Expected Output**:
  ```
  Body includes: "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkResponse"]
  ```
- **Verification**: Response schema URI is BulkResponse, not BulkRequest

---

## Edge Cases

### TC-SCIM-BULK-020: Empty Operations array
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.7
- **Input**:
  ```json
  POST /scim/v2/Bulk
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
    "Operations": []
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkResponse"],
    "Operations": []
  }
  ```

### TC-SCIM-BULK-021: Operations exceeding maxOperations limit
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.7
- **Input**: Bulk request with 1001+ operations (exceeding maxOperations=1000)
- **Expected Output**:
  ```
  Status: 413 Payload Too Large
  Body: {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
    "detail": "Number of operations exceeds maxOperations limit",
    "status": "413"
  }
  ```

### TC-SCIM-BULK-022: Payload exceeding maxPayloadSize
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.7
- **Input**: Bulk request body exceeding 1 MB (maxPayloadSize=1048576)
- **Expected Output**:
  ```
  Status: 413 Payload Too Large
  ```

### TC-SCIM-BULK-023: Missing BulkRequest schema
- **Category**: Edge Case
- **Input**:
  ```json
  POST /scim/v2/Bulk
  {
    "schemas": ["wrong:schema"],
    "Operations": []
  }
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: SCIM error response
  ```

### TC-SCIM-BULK-024: Invalid HTTP method in operation
- **Category**: Edge Case
- **Input**:
  ```json
  POST /scim/v2/Bulk
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
    "Operations": [
      {
        "method": "GET",
        "path": "/Users/<user-id>"
      }
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: BulkResponse with operation status "400" (GET not allowed in bulk)
  ```
- **Note**: RFC 7644 Section 3.7 does not allow GET in bulk operations

### TC-SCIM-BULK-025: Missing bulkId on POST operation
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.7 (bulkId REQUIRED for POST)
- **Input**:
  ```json
  POST /scim/v2/Bulk
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
    "Operations": [
      {
        "method": "POST",
        "path": "/Users",
        "data": {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "no-bulkid@example.com"}
      }
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: BulkResponse with operation status "400" (bulkId required for POST)
  ```

### TC-SCIM-BULK-026: Duplicate bulkId values in request
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.7
- **Input**:
  ```json
  POST /scim/v2/Bulk
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
    "Operations": [
      {"method": "POST", "path": "/Users", "bulkId": "same-id", "data": {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "dup1@example.com"}},
      {"method": "POST", "path": "/Users", "bulkId": "same-id", "data": {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "dup2@example.com"}}
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: SCIM error indicating duplicate bulkId values
  ```

### TC-SCIM-BULK-027: Invalid resource path in operation
- **Category**: Edge Case
- **Input**:
  ```json
  POST /scim/v2/Bulk
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
    "Operations": [
      {
        "method": "POST",
        "path": "/InvalidResource",
        "bulkId": "bad-path",
        "data": {}
      }
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: BulkResponse with operation status "404" or "400"
  ```

### TC-SCIM-BULK-028: Unresolvable bulkId reference
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.7.2
- **Input**:
  ```json
  POST /scim/v2/Bulk
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
    "Operations": [
      {
        "method": "PATCH",
        "path": "/Groups/<group-id>",
        "data": {
          "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
          "Operations": [
            {"op": "add", "path": "members", "value": [{"value": "bulkId:non-existent"}]}
          ]
        }
      }
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: BulkResponse with operation status "400" (cannot resolve bulkId:non-existent)
  ```

### TC-SCIM-BULK-029: Mixed success and failure responses
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.7
- **Input**: Bulk with 3 operations where 2nd fails (duplicate user)
- **Expected Output**:
  ```
  Status: 200 OK (HTTP level always 200 for bulk)
  Body: individual operations have their own status codes (201, 409, 201)
  ```

### TC-SCIM-BULK-030: DELETE operation with no data field
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.7
- **Input**:
  ```json
  POST /scim/v2/Bulk
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
    "Operations": [
      {"method": "DELETE", "path": "/Users/<user-id>"}
    ]
  }
  ```
- **Expected Output**: Status 200; operation status "204" (DELETE does not require data field)

### TC-SCIM-BULK-031: failOnErrors with exactly threshold errors
- **Category**: Edge Case
- **Standard**: RFC 7644 Section 3.7
- **Input**: failOnErrors=2, with exactly 2 errors among 5 operations
- **Expected Output**: Processing stops after the 2nd error; remaining operations are not executed

### TC-SCIM-BULK-032: Large bulk request at exactly maxOperations limit
- **Category**: Edge Case
- **Input**: Bulk request with exactly 1000 operations (assuming maxOperations=1000)
- **Expected Output**: Status 200; all 1000 operations processed

---

## Security Cases

### TC-SCIM-BULK-050: Unauthenticated bulk request
- **Category**: Security
- **Input**:
  ```json
  POST /scim/v2/Bulk
  (no Authorization header)
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
    "Operations": [
      {"method": "POST", "path": "/Users", "bulkId": "u1", "data": {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "unauth@evil.com"}}
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  ```

### TC-SCIM-BULK-051: Bulk operations respect tenant isolation
- **Category**: Security
- **Preconditions**: Fixtures: `SCIM_TOKEN`, `TEST_TENANT`. Bearer token for Tenant A
- **Input**: Bulk operations referencing Tenant B user IDs in PUT/PATCH/DELETE paths
- **Expected Output**: Operations targeting Tenant B resources return status "404" per operation

### TC-SCIM-BULK-052: Bulk with SQL injection in operation data
- **Category**: Security
- **Input**:
  ```json
  POST /scim/v2/Bulk
  {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
    "Operations": [
      {
        "method": "POST",
        "path": "/Users",
        "bulkId": "sqli",
        "data": {
          "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
          "userName": "'; DROP TABLE users; --@evil.com"
        }
      }
    ]
  }
  ```
- **Expected Output**: Operation creates user or returns 400; no SQL injection occurs

### TC-SCIM-BULK-053: Bulk denial-of-service prevention
- **Category**: Security
- **Input**: Multiple rapid bulk requests each with maxOperations operations
- **Expected Output**: Rate limiter kicks in; returns 429 Too Many Requests after threshold

### TC-SCIM-BULK-054: Bulk error responses do not leak internal state
- **Category**: Security
- **Input**: Bulk operation that triggers an internal error
- **Expected Output**: Operation-level error uses generic message; no stack traces, SQL errors, or file paths exposed
