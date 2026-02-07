# API Key Management Functional Tests

**API Endpoints**:
- `POST /tenants/:tenant_id/api-keys` (create API key)
- `GET /tenants/:tenant_id/api-keys` (list API keys)
- `POST /tenants/:tenant_id/api-keys/:key_id/rotate` (rotate API key)
- `DELETE /tenants/:tenant_id/api-keys/:key_id` (deactivate API key)
**Authentication**: JWT (Bearer token) with admin role
**Applicable Standards**: OWASP API Security Top 10 (API2:2023 Broken Authentication), NIST SP 800-63B

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: None

---

## Nominal Cases

### TC-APIKEY-MGMT-001: Create API key with name and scopes
- **Category**: Nominal
- **Standard**: OWASP API Security API2:2023
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated admin user in tenant
- **Input**:
  ```json
  POST /tenants/:tenant_id/api-keys
  {
    "name": "CI/CD Pipeline Key",
    "scopes": ["read:users", "write:users"],
    "expires_at": "2027-02-07T00:00:00Z"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<uuid>",
    "name": "CI/CD Pipeline Key",
    "key": "xavyo_<random_string>",
    "key_prefix": "xavyo_abc...",
    "scopes": ["read:users", "write:users"],
    "expires_at": "2027-02-07T00:00:00Z",
    "created_at": "2026-02-07T...",
    "is_active": true
  }
  ```
- **Side Effects**:
  - API key stored as hash in database (not plaintext)
  - Audit log: `api_key.created`
- **Note**: The full key value is returned ONLY on creation; subsequent GETs show only the prefix

### TC-APIKEY-MGMT-002: Create API key with minimal fields
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```json
  POST /tenants/:tenant_id/api-keys
  { "name": "Basic Key" }
  ```
- **Expected Output**: Status 201, key created with no scopes (full access) and no expiration

### TC-APIKEY-MGMT-003: List all API keys for tenant
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Tenant has 3 API keys (2 active, 1 deactivated)
- **Input**: `GET /tenants/:tenant_id/api-keys`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "api_keys": [
      { "id": "<uuid>", "name": "Key 1", "key_prefix": "xavyo_abc...", "is_active": true, ... },
      { "id": "<uuid>", "name": "Key 2", "key_prefix": "xavyo_def...", "is_active": true, ... },
      { "id": "<uuid>", "name": "Key 3", "key_prefix": "xavyo_ghi...", "is_active": false, ... }
    ]
  }
  ```
- **Verification**: Full key values are NOT included in list response

### TC-APIKEY-MGMT-004: Rotate API key
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Active API key exists
- **Input**: `POST /tenants/:tenant_id/api-keys/:key_id/rotate`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "id": "<same_uuid>",
    "key": "xavyo_<new_random_string>",
    "key_prefix": "xavyo_xyz...",
    "rotated_at": "2026-02-07T..."
  }
  ```
- **Side Effects**:
  - Old key hash replaced with new key hash
  - Old key immediately stops working
  - Audit log: `api_key.rotated`

### TC-APIKEY-MGMT-005: Deactivate API key
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Active API key exists
- **Input**: `DELETE /tenants/:tenant_id/api-keys/:key_id`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "message": "API key deactivated" }
  ```
- **Side Effects**:
  - `is_active = false` in database
  - Key immediately stops working for authentication
  - Audit log: `api_key.deactivated`

### TC-APIKEY-MGMT-006: Create API key with expiration
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```json
  POST /tenants/:tenant_id/api-keys
  {
    "name": "Temporary Key",
    "expires_at": "2026-02-08T00:00:00Z"
  }
  ```
- **Expected Output**: Status 201, `expires_at` set correctly
- **Verification**: After expiration, key returns 401

### TC-APIKEY-MGMT-007: Authenticate with valid API key
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. API key created and active
- **Input**: API request with `Authorization: Bearer xavyo_<key>` or `X-API-Key: xavyo_<key>`
- **Expected Output**: Status 200, request succeeds with key's permissions

### TC-APIKEY-MGMT-008: Create multiple API keys for same tenant
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**: Create 5 API keys with different names
- **Expected Output**: All 5 created successfully, each with unique ID and key value
- **Verification**: `GET /tenants/:tenant_id/api-keys` returns all 5

### TC-APIKEY-MGMT-009: API key name uniqueness per tenant
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**: Create two keys with different names
- **Expected Output**: Both created successfully

### TC-APIKEY-MGMT-010: Rotated key works immediately
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**:
  1. Create API key, note key value
  2. Rotate the key, note new key value
  3. Authenticate with new key value
- **Expected Output**: New key authenticates successfully

---

## Edge Cases

### TC-APIKEY-MGMT-011: Create API key with duplicate name
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Key named "My Key" exists
- **Input**: Create another key named "My Key"
- **Expected Output**: Status 409 "API key name already exists" OR Status 201 (if duplicates allowed)

### TC-APIKEY-MGMT-012: Create API key with empty name
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: `{ "name": "" }`
- **Expected Output**: Status 400 "Name is required"

### TC-APIKEY-MGMT-013: Create API key with very long name (500 chars)
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: Name with 500 characters
- **Expected Output**: Status 400 (exceeds limit) OR Status 201 (if no limit)

### TC-APIKEY-MGMT-014: Deactivate already deactivated key
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Key already deactivated
- **Input**: `DELETE /tenants/:tenant_id/api-keys/:key_id`
- **Expected Output**: Status 404 OR Status 200 (idempotent)

### TC-APIKEY-MGMT-015: Rotate deactivated key
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Key is deactivated
- **Input**: `POST /tenants/:tenant_id/api-keys/:deactivated_key_id/rotate`
- **Expected Output**: Status 400 "Cannot rotate deactivated key"

### TC-APIKEY-MGMT-016: Deactivate non-existent key
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: `DELETE /tenants/:tenant_id/api-keys/00000000-0000-0000-0000-000000000099`
- **Expected Output**: Status 404 "API key not found"

### TC-APIKEY-MGMT-017: Create API key with past expiration date
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: `{ "name": "Expired", "expires_at": "2020-01-01T00:00:00Z" }`
- **Expected Output**: Status 400 "Expiration date must be in the future"

### TC-APIKEY-MGMT-018: Authenticate with expired API key
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. API key with past `expires_at`
- **Input**: API request with expired key
- **Expected Output**: Status 401 "API key expired"

### TC-APIKEY-MGMT-019: List API keys with pagination
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. 50 API keys exist
- **Input**: `GET /tenants/:tenant_id/api-keys?limit=10&offset=0`
- **Expected Output**: Status 200, returns 10 keys with pagination metadata

### TC-APIKEY-MGMT-020: Create API key with invalid scopes
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: `{ "name": "Bad Scopes", "scopes": ["nonexistent:scope"] }`
- **Expected Output**: Status 400 "Invalid scope: nonexistent:scope"

### TC-APIKEY-MGMT-021: Authenticate with old key after rotation
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Active API key exists
- **Steps**:
  1. Create key, note value
  2. Rotate key
  3. Authenticate with OLD key value
- **Expected Output**: Status 401 (old key no longer valid)

---

## Security Cases

### TC-APIKEY-MGMT-022: API key not stored in plaintext
- **Category**: Security
- **Standard**: OWASP API Security API2:2023
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. API key created
- **Verification**: Database `api_keys` table stores only a hash of the key, never the plaintext value

### TC-APIKEY-MGMT-023: Full key shown only on creation
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**:
  1. Create key, note full `key` field in response
  2. `GET /tenants/:tenant_id/api-keys`
- **Expected Output**: List response shows only `key_prefix`, not the full key

### TC-APIKEY-MGMT-024: Non-admin cannot create API keys
- **Category**: Security
- **Preconditions**: Fixtures: `TEST_TENANT`. Authenticated as regular user (no admin role)
- **Input**: `POST /tenants/:tenant_id/api-keys`
- **Expected Output**: Status 403 Forbidden

### TC-APIKEY-MGMT-025: Cross-tenant API key isolation
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Tenant A has API key K1
- **Input**: Admin of tenant B calls `GET /tenants/:tenant_a_id/api-keys`
- **Expected Output**: Status 403 (cannot access other tenant's keys)

### TC-APIKEY-MGMT-026: API key entropy is sufficient
- **Category**: Security
- **Standard**: NIST SP 800-63B
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. API key created
- **Verification**: Generated key has at least 256 bits of entropy (CSPRNG)

### TC-APIKEY-MGMT-027: Rate limiting on key creation
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: 100 rapid `POST /tenants/:tenant_id/api-keys` requests
- **Expected Output**: Rate limiting kicks in after threshold (429 Too Many Requests)

### TC-APIKEY-MGMT-028: API key scoping enforced
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Key has scope `read:users` only
- **Input**: Use key to `POST /users` (write operation)
- **Expected Output**: Status 403 "Insufficient scope"

### TC-APIKEY-MGMT-029: Audit trail for all key operations
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Key operations performed
- **Verification**: Audit log entries for: creation, rotation, deactivation, authentication attempts (success + failure)

### TC-APIKEY-MGMT-030: SQL injection in key name
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: `{ "name": "'; DROP TABLE api_keys; --" }`
- **Expected Output**: Status 201 (name safely stored) or Status 400 (rejected), no SQL execution
