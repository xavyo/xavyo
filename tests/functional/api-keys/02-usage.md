# API Key Usage Tracking and Introspection Functional Tests

**API Endpoints**:
- `GET /tenants/:tenant_id/api-keys/:key_id/usage` (get usage statistics)
- `GET /api-keys/introspect` (introspect the current API key)
**Authentication**: JWT (usage endpoint), API Key (introspect endpoint)
**Applicable Standards**: API security monitoring, OWASP API Security Top 10

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: API keys must be created and used prior to usage tracking tests

---

## Nominal Cases

### TC-APIKEY-USAGE-001: Get usage statistics for API key
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. API key K1 has been used for 50 requests over 7 days
- **Input**: `GET /tenants/:tenant_id/api-keys/:key_id/usage`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "key_id": "<uuid>",
    "total_requests": 50,
    "last_used_at": "2026-02-07T09:00:00Z",
    "first_used_at": "2026-02-01T10:00:00Z",
    "usage_by_day": [
      { "date": "2026-02-07", "count": 10 },
      { "date": "2026-02-06", "count": 8 },
      ...
    ]
  }
  ```

### TC-APIKEY-USAGE-002: Get usage for never-used key
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. API key created but never used
- **Input**: `GET /tenants/:tenant_id/api-keys/:key_id/usage`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "key_id": "<uuid>",
    "total_requests": 0,
    "last_used_at": null,
    "first_used_at": null
  }
  ```

### TC-APIKEY-USAGE-003: Introspect current API key
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated via API key
- **Input**: `GET /api-keys/introspect` with `X-API-Key: xavyo_<key>` or `Authorization: Bearer xavyo_<key>`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "key_id": "<uuid>",
    "name": "CI/CD Pipeline Key",
    "tenant_id": "<uuid>",
    "scopes": ["read:users", "write:users"],
    "is_active": true,
    "created_at": "2026-02-01T...",
    "expires_at": "2027-02-07T...",
    "last_used_at": "2026-02-07T..."
  }
  ```

### TC-APIKEY-USAGE-004: Usage counter increments on each request
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Active API key exists
- **Steps**:
  1. Note current `total_requests` for key
  2. Make 5 authenticated API calls with the key
  3. Check usage again
- **Expected Output**: `total_requests` increased by 5

### TC-APIKEY-USAGE-005: Usage tracks last_used_at timestamp
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Active API key exists
- **Steps**:
  1. Make API call with key at T1
  2. Wait 2 seconds
  3. Make API call with key at T2
  4. Check usage
- **Expected Output**: `last_used_at` equals T2 (most recent)

### TC-APIKEY-USAGE-006: Introspect returns scopes for scoped key
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. API key with scopes `["read:users"]`
- **Input**: `GET /api-keys/introspect`
- **Expected Output**: Response `scopes` field matches `["read:users"]`

---

## Edge Cases

### TC-APIKEY-USAGE-007: Usage for non-existent key
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: `GET /tenants/:tenant_id/api-keys/00000000-0000-0000-0000-000000000099/usage`
- **Expected Output**: Status 404 "API key not found"

### TC-APIKEY-USAGE-008: Usage for deactivated key
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. API key has been deactivated
- **Input**: `GET /tenants/:tenant_id/api-keys/:deactivated_key_id/usage`
- **Expected Output**: Status 200 (historical usage data still accessible)

### TC-APIKEY-USAGE-009: Introspect with invalid API key
- **Category**: Edge Case
- **Preconditions**: Fixtures: `TEST_TENANT`
- **Input**: `GET /api-keys/introspect` with `X-API-Key: xavyo_invalid_key`
- **Expected Output**: Status 401 "Invalid API key"

### TC-APIKEY-USAGE-010: Introspect with expired API key
- **Category**: Edge Case
- **Preconditions**: Fixtures: `TEST_TENANT`. API key with past expiration
- **Input**: `GET /api-keys/introspect` with expired API key
- **Expected Output**: Status 401 "API key expired"

### TC-APIKEY-USAGE-011: Introspect without API key header
- **Category**: Edge Case
- **Preconditions**: Fixtures: `TEST_TENANT`
- **Input**: `GET /api-keys/introspect` with no authentication
- **Expected Output**: Status 401 "API key required"

### TC-APIKEY-USAGE-012: Usage with invalid key_id format
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: `GET /tenants/:tenant_id/api-keys/not-a-uuid/usage`
- **Expected Output**: Status 400 "Invalid key ID format"

---

## Security Cases

### TC-APIKEY-USAGE-013: Cross-tenant usage access denied
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Key K1 belongs to tenant A
- **Input**: Admin of tenant B calls `GET /tenants/:tenant_a_id/api-keys/:k1_id/usage`
- **Expected Output**: Status 403 Forbidden

### TC-APIKEY-USAGE-014: Introspect does not reveal key hash
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated via API key
- **Input**: `GET /api-keys/introspect`
- **Expected Output**: Response does NOT contain the key hash, key_secret, or full key value

### TC-APIKEY-USAGE-015: Usage data does not leak request payloads
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. API key with usage data
- **Verification**: Usage statistics contain only counts and timestamps, never request/response bodies or headers
