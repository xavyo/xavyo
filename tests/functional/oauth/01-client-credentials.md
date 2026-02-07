# OAuth 2.0 Client Credentials Flow - Functional Test Suite

**Component**: `xavyo-api-oauth` (token endpoint, client credentials grant)
**Standards**: RFC 6749 Section 4.4, RFC 6749 Section 2.3
**API Endpoint**: `POST /oauth/token` with `grant_type=client_credentials`
**Tenant Context**: Requires `X-Tenant-ID` header (UUID)

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `OAUTH_CC_CLIENT`, `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: Confidential client with `client_credentials` grant type, public client, and auth-code-only client needed

All tests assume:
- A valid tenant exists with ID `{TENANT_ID}` (UUID)
- An admin JWT is available for client management via `/admin/oauth/clients`
- `X-Tenant-ID: {TENANT_ID}` header is present on all requests unless noted

### Fixture: Confidential Client (CC-enabled)

Created via `POST /admin/oauth/clients`:
```json
{
  "name": "CC Test Client",
  "client_type": "confidential",
  "redirect_uris": [],
  "grant_types": ["client_credentials"],
  "scopes": ["read", "write", "admin"]
}
```
Response yields `client_id` and `client_secret`.

### Fixture: Public Client (no secret)

```json
{
  "name": "Public Test Client",
  "client_type": "public",
  "redirect_uris": ["https://app.example.com/callback"],
  "grant_types": ["authorization_code"],
  "scopes": ["openid", "profile"]
}
```

### Fixture: Client without CC grant

```json
{
  "name": "AuthCode-Only Client",
  "client_type": "confidential",
  "redirect_uris": ["https://app.example.com/callback"],
  "grant_types": ["authorization_code"],
  "scopes": ["openid", "profile"]
}
```

---

## Nominal Tests (TC-OAUTH-CC-001 through TC-OAUTH-CC-015)

### TC-OAUTH-CC-001: Basic client credentials grant via HTTP Basic Auth
- **Category**: Nominal
- **Standard**: RFC 6749 Section 4.4, Section 2.3.1
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Confidential client with `client_credentials` grant type exists
- **Input**:
  ```
  POST /oauth/token
  Authorization: Basic base64({client_id}:{client_secret})
  Content-Type: application/x-www-form-urlencoded
  X-Tenant-ID: {TENANT_ID}

  grant_type=client_credentials
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Body:
    ```json
    {
      "access_token": "<JWT>",
      "token_type": "Bearer",
      "expires_in": 900,
      "scope": "read write admin"
    }
    ```
  - `refresh_token` MUST NOT be present (RFC 6749 Section 4.4.3)
  - `id_token` MUST NOT be present

### TC-OAUTH-CC-002: Client credentials via body parameters
- **Category**: Nominal
- **Standard**: RFC 6749 Section 2.3.1 (alternative client auth)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Confidential client with `client_credentials` grant exists
- **Input**:
  ```
  POST /oauth/token
  Content-Type: application/x-www-form-urlencoded
  X-Tenant-ID: {TENANT_ID}

  grant_type=client_credentials&client_id={client_id}&client_secret={client_secret}
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Body contains `access_token`, `token_type`, `expires_in`
  - No `refresh_token`

### TC-OAUTH-CC-003: Request specific scope subset
- **Category**: Nominal
- **Standard**: RFC 6749 Section 4.4.2 (scope parameter)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Client has allowed scopes `["read", "write", "admin"]`
- **Input**:
  ```
  POST /oauth/token
  Authorization: Basic base64({client_id}:{client_secret})
  Content-Type: application/x-www-form-urlencoded
  X-Tenant-ID: {TENANT_ID}

  grant_type=client_credentials&scope=read
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Body: `scope` field equals `"read"`

### TC-OAUTH-CC-004: Request multiple scopes
- **Category**: Nominal
- **Standard**: RFC 6749 Section 3.3 (space-delimited scopes)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Client has allowed scopes `["read", "write", "admin"]`
- **Input**:
  ```
  POST /oauth/token
  Authorization: Basic base64({client_id}:{client_secret})
  Content-Type: application/x-www-form-urlencoded
  X-Tenant-ID: {TENANT_ID}

  grant_type=client_credentials&scope=read+write
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Body: `scope` field contains both `read` and `write`

### TC-OAUTH-CC-005: Omit scope (receive default scopes)
- **Category**: Nominal
- **Standard**: RFC 6749 Section 4.4.2 (OPTIONAL scope)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Client has allowed scopes `["read", "write", "admin"]`
- **Input**:
  ```
  POST /oauth/token
  Authorization: Basic base64({client_id}:{client_secret})
  Content-Type: application/x-www-form-urlencoded
  X-Tenant-ID: {TENANT_ID}

  grant_type=client_credentials
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Body: `scope` field contains client's allowed scopes minus `openid` and `offline_access`

### TC-OAUTH-CC-006: Access token is a valid JWT
- **Category**: Nominal
- **Standard**: RFC 9068 (JWT Access Tokens, informational)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Successfully issued token from TC-OAUTH-CC-001
- **Input**: Decode the `access_token` JWT from previous response
- **Expected Output**:
  - JWT header contains `alg` (RS256) and `kid`
  - JWT payload contains `sub` (client identifier), `iss` (issuer URL), `exp`, `iat`
  - JWT payload contains `tid` (tenant_id as UUID)
  - JWT payload contains `jti` (unique token ID)
  - `exp - iat` equals `expires_in` from response

### TC-OAUTH-CC-007: Token type is always "Bearer"
- **Category**: Nominal
- **Standard**: RFC 6749 Section 4.4.3
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Client credentials grant succeeds
- **Input**: Same as TC-OAUTH-CC-001
- **Expected Output**:
  - `token_type` is exactly `"Bearer"` (case-sensitive per RFC 6750)

### TC-OAUTH-CC-008: Consecutive requests yield different tokens
- **Category**: Nominal
- **Standard**: RFC 6749 Section 4.4 (stateless tokens)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid client credentials
- **Input**: Execute TC-OAUTH-CC-001 twice in sequence
- **Expected Output**:
  - Both requests return `200 OK`
  - `access_token` values differ between requests
  - Both tokens have different `jti` claims

### TC-OAUTH-CC-009: Token with single scope
- **Category**: Nominal
- **Standard**: RFC 6749 Section 3.3
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Client has scopes `["read", "write", "admin"]`
- **Input**:
  ```
  POST /oauth/token
  Authorization: Basic base64({client_id}:{client_secret})
  Content-Type: application/x-www-form-urlencoded
  X-Tenant-ID: {TENANT_ID}

  grant_type=client_credentials&scope=admin
  ```
- **Expected Output**:
  - Status: `200 OK`
  - `scope` equals `"admin"` (single scope)

### TC-OAUTH-CC-010: Client credentials with all allowed scopes explicit
- **Category**: Nominal
- **Standard**: RFC 6749 Section 3.3
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Client has scopes `["read", "write", "admin"]`
- **Input**:
  ```
  grant_type=client_credentials&scope=read+write+admin
  ```
- **Expected Output**:
  - Status: `200 OK`
  - `scope` contains all three scopes

### TC-OAUTH-CC-011: HTTP Basic Auth header takes precedence over body
- **Category**: Nominal
- **Standard**: RFC 6749 Section 2.3.1
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `ADMIN_JWT`, `TEST_TENANT`. Two confidential clients exist
- **Input**:
  ```
  POST /oauth/token
  Authorization: Basic base64({client_id_A}:{secret_A})
  Content-Type: application/x-www-form-urlencoded
  X-Tenant-ID: {TENANT_ID}

  grant_type=client_credentials&client_id={client_id_B}&client_secret={secret_B}
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Token `sub` or `aud` identifies `client_id_A` (header credentials used)

### TC-OAUTH-CC-012: Colon in client_secret via Basic Auth
- **Category**: Nominal
- **Standard**: RFC 6749 Section 2.3.1 (base64 of `client_id:client_secret`)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Client with secret containing colons (regenerated)
- **Input**:
  ```
  Authorization: Basic base64({client_id}:{secret_with_colons})
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Secret is parsed correctly using `splitn(2, ':')` — only first colon is separator

### TC-OAUTH-CC-013: Response Content-Type is application/json
- **Category**: Nominal
- **Standard**: RFC 6749 Section 5.1
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid client credentials request
- **Input**: Same as TC-OAUTH-CC-001
- **Expected Output**:
  - Response `Content-Type` header is `application/json`

### TC-OAUTH-CC-014: Cache-Control headers present
- **Category**: Nominal
- **Standard**: RFC 6749 Section 5.1 ("no-store" on token responses)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid client credentials request
- **Input**: Same as TC-OAUTH-CC-001
- **Expected Output**:
  - Response includes `Cache-Control: no-store` (or equivalent with additional directives)

### TC-OAUTH-CC-015: Token issued with correct issuer
- **Category**: Nominal
- **Standard**: RFC 9068 Section 2.2 (JWT iss claim)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Issuer URL configured (e.g., `https://idp.xavyo.com`)
- **Input**: Same as TC-OAUTH-CC-001
- **Expected Output**:
  - JWT `iss` claim matches configured issuer URL

---

## Edge Case Tests (TC-OAUTH-CC-016 through TC-OAUTH-CC-030)

### TC-OAUTH-CC-016: Missing grant_type parameter
- **Category**: Edge Case
- **Standard**: RFC 6749 Section 4.4.2 (REQUIRED)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid client credentials
- **Input**:
  ```
  POST /oauth/token
  Authorization: Basic base64({client_id}:{client_secret})
  Content-Type: application/x-www-form-urlencoded
  X-Tenant-ID: {TENANT_ID}

  (empty body)
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request", "error_description": "..." }`

### TC-OAUTH-CC-017: Missing client_id entirely (no header, no body)
- **Category**: Edge Case
- **Standard**: RFC 6749 Section 2.3
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  POST /oauth/token
  Content-Type: application/x-www-form-urlencoded
  X-Tenant-ID: {TENANT_ID}

  grant_type=client_credentials
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request", "error_description": "client_id is required" }`

### TC-OAUTH-CC-018: Missing X-Tenant-ID header
- **Category**: Edge Case
- **Standard**: Platform-specific (multi-tenant)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid client credentials
- **Input**:
  ```
  POST /oauth/token
  Authorization: Basic base64({client_id}:{client_secret})
  Content-Type: application/x-www-form-urlencoded

  grant_type=client_credentials
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request", "error_description": "X-Tenant-ID header is required" }`

### TC-OAUTH-CC-019: Invalid X-Tenant-ID (not a UUID)
- **Category**: Edge Case
- **Standard**: Platform-specific
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid client credentials
- **Input**:
  ```
  X-Tenant-ID: not-a-uuid
  grant_type=client_credentials
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request", "error_description": "X-Tenant-ID must be a valid UUID" }`

### TC-OAUTH-CC-020: Scope requesting "openid" (user-only scope)
- **Category**: Edge Case
- **Standard**: OIDC Core Section 3.1.2.1 (openid requires user authentication)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Client has scope `openid` in allowed scopes
- **Input**:
  ```
  grant_type=client_credentials&scope=openid
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_scope", "error_description": "..." }`
  - OR: Status `200 OK` but `openid` excluded from default scopes (implementation filters `openid` and `offline_access`)

### TC-OAUTH-CC-021: Scope requesting "offline_access"
- **Category**: Edge Case
- **Standard**: OIDC Core Section 11 (offline_access implies refresh token)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Client has `offline_access` in allowed scopes
- **Input**:
  ```
  grant_type=client_credentials&scope=offline_access
  ```
- **Expected Output**:
  - Status: `400 Bad Request` (no refresh tokens for client_credentials)
  - OR: `200 OK` with `offline_access` excluded from granted scopes

### TC-OAUTH-CC-022: Request scope not allowed for client
- **Category**: Edge Case
- **Standard**: RFC 6749 Section 3.3
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Client has scopes `["read", "write"]` only
- **Input**:
  ```
  grant_type=client_credentials&scope=delete
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_scope", "error_description": "Scope 'delete' is not allowed for this client" }`

### TC-OAUTH-CC-023: Unsupported grant_type
- **Category**: Edge Case
- **Standard**: RFC 6749 Section 4.4.2
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid client auth
- **Input**:
  ```
  grant_type=password
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "unsupported_grant_type", "error_description": "..." }`

### TC-OAUTH-CC-024: Invalid base64 in Authorization header
- **Category**: Edge Case
- **Standard**: RFC 6749 Section 2.3.1
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  Authorization: Basic !!!invalid-base64!!!
  grant_type=client_credentials
  ```
- **Expected Output**:
  - Status: `401 Unauthorized`
  - Body: `{ "error": "invalid_client", "error_description": "Invalid base64 in authorization header" }`

### TC-OAUTH-CC-025: Authorization header without colon separator
- **Category**: Edge Case
- **Standard**: RFC 6749 Section 2.3.1
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  Authorization: Basic base64("client-id-only-no-colon")
  grant_type=client_credentials
  ```
- **Expected Output**:
  - Status: `401 Unauthorized`
  - Body: `{ "error": "invalid_client", "error_description": "Invalid credential format" }`

### TC-OAUTH-CC-026: Empty scope string
- **Category**: Edge Case
- **Standard**: RFC 6749 Section 3.3
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid client credentials
- **Input**:
  ```
  grant_type=client_credentials&scope=
  ```
- **Expected Output**:
  - Status: `200 OK` (treated as omitted scope, server grants default)
  - OR: `400 Bad Request` if implementation rejects empty string

### TC-OAUTH-CC-027: Bearer Auth instead of Basic Auth
- **Category**: Edge Case
- **Standard**: RFC 6749 Section 2.3.1
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  Authorization: Bearer some-token-here
  grant_type=client_credentials
  ```
- **Expected Output**:
  - Status: `400 Bad Request` or `401 Unauthorized`
  - Body: `{ "error": "invalid_request" }` or `{ "error": "invalid_client" }`

### TC-OAUTH-CC-028: Client exists in different tenant
- **Category**: Edge Case
- **Standard**: Platform-specific (tenant isolation)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Client belongs to `TENANT_A`, request uses `TENANT_B`
- **Input**:
  ```
  X-Tenant-ID: {TENANT_B_ID}
  Authorization: Basic base64({client_id_from_tenant_A}:{secret})
  grant_type=client_credentials
  ```
- **Expected Output**:
  - Status: `401 Unauthorized`
  - Body: `{ "error": "invalid_client" }`

### TC-OAUTH-CC-029: Deactivated client
- **Category**: Edge Case
- **Standard**: RFC 6749 Section 2.3 (server decides authentication rules)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `ADMIN_JWT`, `TEST_TENANT`. Client was deactivated via `DELETE /admin/oauth/clients/{id}`
- **Input**:
  ```
  Authorization: Basic base64({deactivated_client_id}:{secret})
  grant_type=client_credentials
  ```
- **Expected Output**:
  - Status: `401 Unauthorized`
  - Body: `{ "error": "invalid_client" }`

### TC-OAUTH-CC-030: Non-existent tenant ID (valid UUID format)
- **Category**: Edge Case
- **Standard**: Platform-specific
- **Preconditions**: Fixtures: `TEST_TENANT`. UUID is valid but not a real tenant
- **Input**:
  ```
  X-Tenant-ID: 00000000-0000-0000-0000-ffffffffffff
  grant_type=client_credentials&client_id=any&client_secret=any
  ```
- **Expected Output**:
  - Status: `401 Unauthorized`
  - Body: `{ "error": "invalid_client" }`

---

## Security Tests (TC-OAUTH-CC-031 through TC-OAUTH-CC-040)

### TC-OAUTH-CC-031: Wrong client_secret
- **Category**: Security
- **Standard**: RFC 6749 Section 2.3 (client authentication)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid client_id, incorrect secret
- **Input**:
  ```
  Authorization: Basic base64({client_id}:wrong-secret)
  grant_type=client_credentials
  ```
- **Expected Output**:
  - Status: `401 Unauthorized`
  - Body: `{ "error": "invalid_client" }`
  - Error description MUST NOT reveal whether client_id or secret is wrong

### TC-OAUTH-CC-032: Public client attempting client_credentials
- **Category**: Security
- **Standard**: RFC 6749 Section 4.4 (MUST authenticate confidential clients)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `ADMIN_JWT`, `TEST_TENANT`. Public client (no secret) exists
- **Input**:
  ```
  grant_type=client_credentials&client_id={public_client_id}
  ```
- **Expected Output**:
  - Status: `401 Unauthorized`
  - Body: `{ "error": "invalid_client", "error_description": "client_secret is required for client_credentials grant" }`

### TC-OAUTH-CC-033: Client not authorized for client_credentials grant
- **Category**: Security
- **Standard**: RFC 6749 Section 4.4.2
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `ADMIN_JWT`, `TEST_TENANT`. Confidential client with `grant_types: ["authorization_code"]`
- **Input**:
  ```
  Authorization: Basic base64({authcode_client_id}:{secret})
  grant_type=client_credentials
  ```
- **Expected Output**:
  - Status: `401 Unauthorized`
  - Body: `{ "error": "unauthorized_client", "error_description": "Client is not authorized for client_credentials grant" }`

### TC-OAUTH-CC-034: Cross-tenant token isolation
- **Category**: Security
- **Standard**: Platform-specific (multi-tenancy)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Token issued for `TENANT_A`
- **Input**: Introspect the token using `TENANT_B` credentials at `/oauth/introspect`
- **Expected Output**:
  - Status: `200 OK`
  - Body: `{ "active": false }` (token not visible cross-tenant)

### TC-OAUTH-CC-035: Token JWT contains tenant_id claim
- **Category**: Security
- **Standard**: Platform-specific (multi-tenant JWT)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Successfully issued token
- **Input**: Decode JWT `access_token`
- **Expected Output**:
  - JWT `tid` claim equals `{TENANT_ID}`
  - Prevents cross-tenant token reuse

### TC-OAUTH-CC-036: Timing attack resistance on client_secret
- **Category**: Security
- **Standard**: OWASP Authentication Cheat Sheet
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid client_id
- **Input**: Send 100 requests with correct secret, 100 with incorrect secret; measure response times
- **Expected Output**:
  - Response time distribution for correct vs. incorrect secrets should be statistically indistinguishable
  - Implementation uses constant-time comparison (bcrypt/argon2)

### TC-OAUTH-CC-037: SQL injection in client_id via body
- **Category**: Security
- **Standard**: OWASP Injection Prevention
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  grant_type=client_credentials&client_id=' OR 1=1 --&client_secret=anything
  ```
- **Expected Output**:
  - Status: `401 Unauthorized`
  - Body: `{ "error": "invalid_client" }`
  - No SQL error leak in response

### TC-OAUTH-CC-038: SQL injection in X-Tenant-ID header
- **Category**: Security
- **Standard**: OWASP Injection Prevention
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  X-Tenant-ID: 00000000-0000-0000-0000-000000000001'; DROP TABLE oauth_clients;--
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request", "error_description": "X-Tenant-ID must be a valid UUID" }`

### TC-OAUTH-CC-039: Response does not leak client_secret
- **Category**: Security
- **Standard**: RFC 6749 Section 2.3.1 (secrets MUST NOT appear in responses)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Successfully issued token
- **Input**: Same as TC-OAUTH-CC-001
- **Expected Output**:
  - Response body does not contain the `client_secret` value
  - JWT payload does not contain the `client_secret`

### TC-OAUTH-CC-040: Error response does not leak internal details
- **Category**: Security
- **Standard**: OWASP Error Handling (information leakage)
- **Preconditions**: Fixtures: `TEST_TENANT`. Various invalid requests
- **Input**: Send requests causing database errors, JWT encoding errors
- **Expected Output**:
  - Error responses use generic messages: `"server_error"` with sanitized description
  - No stack traces, SQL queries, or internal paths exposed
  - No distinction between "client not found" and "wrong secret"
