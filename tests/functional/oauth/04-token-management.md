# OAuth 2.0 Token Management & Client CRUD - Functional Test Suite

**Component**: `xavyo-api-oauth` (introspection, revocation, client admin)
**Standards**: RFC 7662 (Token Introspection), RFC 7009 (Token Revocation)
**API Endpoints**:
- `POST /oauth/introspect` -- RFC 7662 Token Introspection
- `POST /oauth/revoke` -- RFC 7009 Token Revocation
- `POST /admin/oauth/clients` -- Create client
- `GET /admin/oauth/clients` -- List clients
- `GET /admin/oauth/clients/:id` -- Get client
- `PUT /admin/oauth/clients/:id` -- Update client
- `DELETE /admin/oauth/clients/:id` -- Deactivate client (soft delete)
- `POST /admin/oauth/clients/:id/regenerate-secret` -- Regenerate secret
- `POST /admin/oauth/revoke-user` -- Admin revoke all user tokens
- `GET /admin/oauth/active-sessions` -- List active sessions
- `DELETE /admin/oauth/sessions/:token_id` -- Delete session

**Tenant Context**: `X-Tenant-ID` header for OAuth endpoints; JWT with `TenantId` extension for admin endpoints

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `OAUTH_CC_CLIENT`, `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: Confidential client for introspection/revocation, issued access and refresh tokens

All tests assume:
- A valid tenant with ID `{TENANT_ID}`
- Admin JWT for `/admin/oauth/clients` operations
- A confidential client registered for introspection/revocation
- Access tokens and refresh tokens issued via client_credentials or device_code flow

### Fixture: Introspection/Revocation Client

A confidential client capable of authenticating to introspection/revocation endpoints:
```json
{
  "name": "Resource Server",
  "client_type": "confidential",
  "redirect_uris": [],
  "grant_types": ["client_credentials"],
  "scopes": ["read", "write"]
}
```

---

## Part 1: Token Introspection (RFC 7662)

### Nominal Tests (TC-OAUTH-TI-001 through TC-OAUTH-TI-010)

### TC-OAUTH-TI-001: Introspect active access token
- **Category**: Nominal
- **Standard**: RFC 7662 Section 2.2
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid access token (JWT) issued via client_credentials
- **Input**:
  ```
  POST /oauth/introspect
  Content-Type: application/x-www-form-urlencoded
  Authorization: Basic base64({client_id}:{client_secret})
  X-Tenant-ID: {TENANT_ID}

  token={access_token}
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Body:
    ```json
    {
      "active": true,
      "sub": "<client-or-user-id>",
      "scope": "<granted-scopes>",
      "exp": 1706400000,
      "iat": 1706399100,
      "token_type": "Bearer",
      "iss": "https://idp.xavyo.com",
      "jti": "<unique-token-id>",
      "tid": "{TENANT_ID}"
    }
    ```

### TC-OAUTH-TI-002: Introspect active refresh token
- **Category**: Nominal
- **Standard**: RFC 7662 Section 2.2
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid refresh token (opaque) from device code flow
- **Input**:
  ```
  POST /oauth/introspect
  Authorization: Basic base64({client_id}:{client_secret})
  X-Tenant-ID: {TENANT_ID}

  token={refresh_token}&token_type_hint=refresh_token
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Body:
    ```json
    {
      "active": true,
      "sub": "<user-id>",
      "scope": "openid profile",
      "exp": 1706500000,
      "iat": 1706399100,
      "token_type": "refresh_token",
      "tid": "{TENANT_ID}"
    }
    ```

### TC-OAUTH-TI-003: Introspect with access_token hint
- **Category**: Nominal
- **Standard**: RFC 7662 Section 2.1 (token_type_hint)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid access token
- **Input**:
  ```
  token={access_token}&token_type_hint=access_token
  ```
- **Expected Output**:
  - Status: `200 OK`
  - `active: true`
  - Hint optimizes lookup order (access token checked first)

### TC-OAUTH-TI-004: Introspect with refresh_token hint
- **Category**: Nominal
- **Standard**: RFC 7662 Section 2.1 (token_type_hint)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid refresh token
- **Input**:
  ```
  token={refresh_token}&token_type_hint=refresh_token
  ```
- **Expected Output**:
  - Status: `200 OK`
  - `active: true`
  - Hint optimizes lookup order (refresh token checked first)

### TC-OAUTH-TI-005: Introspect with wrong hint still works
- **Category**: Nominal
- **Standard**: RFC 7662 Section 2.1 ("the server SHOULD check other types as well")
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid access token
- **Input**:
  ```
  token={access_token}&token_type_hint=refresh_token
  ```
- **Expected Output**:
  - Status: `200 OK`
  - `active: true`
  - Server falls back to checking other token types

### TC-OAUTH-TI-006: Introspect expired access token
- **Category**: Nominal
- **Standard**: RFC 7662 Section 2.2
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Access token past its `exp` time
- **Input**:
  ```
  token={expired_access_token}
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Body: `{ "active": false }`

### TC-OAUTH-TI-007: Introspect revoked access token
- **Category**: Nominal
- **Standard**: RFC 7662 Section 2.2
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Access token was revoked via `/oauth/revoke`
- **Input**:
  ```
  token={revoked_access_token}
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Body: `{ "active": false }`

### TC-OAUTH-TI-008: Introspect unknown token
- **Category**: Nominal
- **Standard**: RFC 7662 Section 2.2 ("MUST return active=false for unknown tokens")
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  token=completely-random-garbage-token
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Body: `{ "active": false }`
  - No error (always 200 per RFC 7662)

### TC-OAUTH-TI-009: Introspect via body credentials (not Basic Auth)
- **Category**: Nominal
- **Standard**: RFC 7662 Section 2.1 (client authentication)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid client credentials
- **Input**:
  ```
  POST /oauth/introspect
  Content-Type: application/x-www-form-urlencoded
  X-Tenant-ID: {TENANT_ID}

  token={access_token}&client_id={client_id}&client_secret={client_secret}
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Body with `active: true` for valid token

### TC-OAUTH-TI-010: Introspect revoked refresh token
- **Category**: Nominal
- **Standard**: RFC 7662 Section 2.2
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Refresh token was revoked
- **Input**:
  ```
  token={revoked_refresh_token}&token_type_hint=refresh_token
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Body: `{ "active": false }`

---

### Edge Case Tests (TC-OAUTH-TI-011 through TC-OAUTH-TI-020)

### TC-OAUTH-TI-011: Missing token parameter
- **Category**: Edge Case
- **Standard**: RFC 7662 Section 2.1 (REQUIRED)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Authenticated client
- **Input**:
  ```
  POST /oauth/introspect
  Authorization: Basic base64({client_id}:{client_secret})
  X-Tenant-ID: {TENANT_ID}

  (empty body)
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request" }`

### TC-OAUTH-TI-012: Missing client credentials
- **Category**: Edge Case
- **Standard**: RFC 7662 Section 2.1 (client authentication REQUIRED)
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  POST /oauth/introspect
  X-Tenant-ID: {TENANT_ID}

  token={access_token}
  ```
  (no Authorization header, no client_id/client_secret in body)
- **Expected Output**:
  - Status: `401 Unauthorized`
  - Body: `{ "error": "invalid_client" }`

### TC-OAUTH-TI-013: Wrong client_secret for introspection
- **Category**: Edge Case
- **Standard**: RFC 7662 Section 2.1
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid client_id, wrong secret
- **Input**:
  ```
  Authorization: Basic base64({client_id}:wrong-secret)
  token={access_token}
  ```
- **Expected Output**:
  - Status: `401 Unauthorized`
  - Body: `{ "error": "invalid_client" }`

### TC-OAUTH-TI-014: Missing X-Tenant-ID header
- **Category**: Edge Case
- **Standard**: Platform-specific (multi-tenancy)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid client credentials
- **Input**:
  ```
  POST /oauth/introspect
  Authorization: Basic base64({client_id}:{client_secret})

  token={access_token}
  ```
  (no X-Tenant-ID)
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request", "error_description": "Missing X-Tenant-ID header" }`

### TC-OAUTH-TI-015: Invalid token_type_hint value
- **Category**: Edge Case
- **Standard**: RFC 7662 Section 2.1 (server MAY ignore invalid hints)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid client, valid token
- **Input**:
  ```
  token={access_token}&token_type_hint=bearer_token
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Server ignores invalid hint and checks all token types
  - Returns correct `active` status

### TC-OAUTH-TI-016: Empty token string
- **Category**: Edge Case
- **Standard**: RFC 7662 Section 2.1
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Authenticated client
- **Input**:
  ```
  token=
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Body: `{ "active": false }` (empty string is unknown token)

### TC-OAUTH-TI-017: Very long token string (boundary test)
- **Category**: Edge Case
- **Standard**: RFC 7662 Section 2.1
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Authenticated client
- **Input**:
  ```
  token={10000-character-random-string}
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Body: `{ "active": false }` (unknown token, no crash)

### TC-OAUTH-TI-018: Inactive response has no extra fields
- **Category**: Edge Case
- **Standard**: RFC 7662 Section 2.2 ("only `active` is REQUIRED for inactive")
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Unknown token
- **Input**: Introspect garbage token
- **Expected Output**:
  - Serialized JSON is exactly `{"active":false}` (no optional fields)

### TC-OAUTH-TI-019: Introspect token from different tenant
- **Category**: Edge Case
- **Standard**: RFC 7662 Section 2.1, platform-specific (tenant isolation)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Token issued for `TENANT_A`, introspection from `TENANT_B`
- **Input**:
  ```
  Authorization: Basic base64({tenant_B_client_id}:{secret})
  X-Tenant-ID: {TENANT_B_ID}

  token={token_from_tenant_A}
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Body: `{ "active": false }` (cross-tenant tokens appear unknown)

### TC-OAUTH-TI-020: Introspect after user revoke-all
- **Category**: Edge Case
- **Standard**: RFC 7662 Section 2.2, platform-specific (admin revocation)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Access token issued, then admin revokes all user tokens via `POST /admin/oauth/revoke-user`
- **Input**:
  ```
  token={access_token_issued_before_revoke_all}
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Body: `{ "active": false }` (sentinel pattern catches pre-revocation tokens)

---

### Security Tests (TC-OAUTH-TI-021 through TC-OAUTH-TI-030)

### TC-OAUTH-TI-021: Revocation cache fail-closed on error
- **Category**: Security
- **Standard**: OWASP Fail-Closed Principle
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Revocation cache configured, simulate cache failure
- **Input**: Introspect a valid token while cache is unavailable
- **Expected Output**:
  - Status: `200 OK`
  - Body: `{ "active": false }` (fail-closed: treat as revoked)

### TC-OAUTH-TI-022: No information leakage on inactive tokens
- **Category**: Security
- **Standard**: RFC 7662 Section 4 (Security Considerations)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Token is expired, revoked, or unknown
- **Input**: Introspect various inactive tokens
- **Expected Output**:
  - Response is always `{ "active": false }` with no additional fields
  - No distinction between expired, revoked, and unknown tokens
  - Prevents token enumeration

### TC-OAUTH-TI-023: Cross-tenant token introspection isolation
- **Category**: Security
- **Standard**: Platform-specific (multi-tenancy)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Active token for `TENANT_A`
- **Input**: Introspect from `TENANT_B`
- **Expected Output**:
  - Body: `{ "active": false }` (token invisible cross-tenant)
  - JWT `tid` mismatch causes inactive response

### TC-OAUTH-TI-024: SQL injection in token parameter
- **Category**: Security
- **Standard**: OWASP Injection Prevention
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Authenticated client
- **Input**:
  ```
  token=' OR 1=1 --&token_type_hint=refresh_token
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Body: `{ "active": false }`
  - No SQL error, no information leakage

### TC-OAUTH-TI-025: Revoke-all sentinel prevents stale introspection
- **Category**: Security
- **Standard**: Platform-specific (sentinel revocation pattern)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Token issued at time T, revoke-all sentinel at T+1
- **Input**: Introspect token after sentinel created
- **Expected Output**:
  - Body: `{ "active": false }`
  - Sentinel query checks `iat < sentinel.created_at` for the user's tenant

---

## Part 2: Token Revocation (RFC 7009)

### Nominal Tests (TC-OAUTH-TR-001 through TC-OAUTH-TR-005)

### TC-OAUTH-TR-001: Revoke access token
- **Category**: Nominal
- **Standard**: RFC 7009 Section 2.1
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid access token (JWT)
- **Input**:
  ```
  POST /oauth/revoke
  Content-Type: application/x-www-form-urlencoded
  Authorization: Basic base64({client_id}:{client_secret})
  X-Tenant-ID: {TENANT_ID}

  token={access_token}
  ```
- **Expected Output**:
  - Status: `200 OK` (empty body)
  - Subsequent introspection returns `{ "active": false }`
  - JTI added to revocation blacklist

### TC-OAUTH-TR-002: Revoke refresh token
- **Category**: Nominal
- **Standard**: RFC 7009 Section 2.1
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid refresh token (opaque)
- **Input**:
  ```
  POST /oauth/revoke
  Authorization: Basic base64({client_id}:{client_secret})
  X-Tenant-ID: {TENANT_ID}

  token={refresh_token}&token_type_hint=refresh_token
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Refresh token marked as revoked in database
  - Cascade: `revoke-all:{user_id}:{timestamp}` sentinel created
  - All user's access tokens issued before revocation become inactive

### TC-OAUTH-TR-003: Revoke with access_token hint
- **Category**: Nominal
- **Standard**: RFC 7009 Section 2.1
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid access token
- **Input**:
  ```
  token={access_token}&token_type_hint=access_token
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Token revoked efficiently (hint skips refresh token lookup)

### TC-OAUTH-TR-004: Revoke already-revoked token
- **Category**: Nominal
- **Standard**: RFC 7009 Section 2.1 ("no error even if token was already invalidated")
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Token already revoked
- **Input**:
  ```
  token={already_revoked_token}
  ```
- **Expected Output**:
  - Status: `200 OK` (idempotent, no error)

### TC-OAUTH-TR-005: Revoke unknown token
- **Category**: Nominal
- **Standard**: RFC 7009 Section 2.1 ("always respond with 200 OK")
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  token=unknown-garbage-token-abc123
  ```
- **Expected Output**:
  - Status: `200 OK` (per RFC 7009: never leak token existence)

---

### Edge Case Tests (TC-OAUTH-TR-006 through TC-OAUTH-TR-010)

### TC-OAUTH-TR-006: Missing token parameter
- **Category**: Edge Case
- **Standard**: RFC 7009 Section 2.1 (REQUIRED)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Authenticated client
- **Input**: Empty body
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request" }`

### TC-OAUTH-TR-007: Missing client credentials for revocation
- **Category**: Edge Case
- **Standard**: RFC 7009 Section 2.1 (client auth REQUIRED)
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  POST /oauth/revoke
  X-Tenant-ID: {TENANT_ID}

  token={access_token}
  ```
  (no auth)
- **Expected Output**:
  - Status: `401 Unauthorized`
  - Body: `{ "error": "invalid_client" }`

### TC-OAUTH-TR-008: Wrong client_secret for revocation
- **Category**: Edge Case
- **Standard**: RFC 7009 Section 2.1
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid client_id, wrong secret
- **Input**:
  ```
  Authorization: Basic base64({client_id}:wrong-secret)
  token={access_token}
  ```
- **Expected Output**:
  - Status: `401 Unauthorized`
  - Body: `{ "error": "invalid_client" }`

### TC-OAUTH-TR-009: Revoke token from different tenant
- **Category**: Edge Case
- **Standard**: RFC 7009 Section 2.1, platform-specific (isolation)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Token issued in `TENANT_A`, revocation from `TENANT_B`
- **Input**:
  ```
  Authorization: Basic base64({tenant_B_client_id}:{secret})
  X-Tenant-ID: {TENANT_B_ID}

  token={token_from_tenant_A}
  ```
- **Expected Output**:
  - Status: `200 OK` (RFC 7009: always 200)
  - Token from `TENANT_A` is NOT revoked (cross-tenant protection)

### TC-OAUTH-TR-010: Revoke expired token
- **Category**: Edge Case
- **Standard**: RFC 7009 Section 2.1
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Expired access token
- **Input**:
  ```
  token={expired_access_token}&token_type_hint=access_token
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Expired token revoked (JTI blacklisted as defense-in-depth)

---

### Security Tests (TC-OAUTH-TR-011 through TC-OAUTH-TR-015)

### TC-OAUTH-TR-011: Cascade revocation from refresh token
- **Category**: Security
- **Standard**: OAuth 2.0 Security BCP Section 4.14.2
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Refresh token and access token issued for same user
- **Input**: Revoke the refresh token
- **Expected Output**:
  - Refresh token marked revoked
  - `revoke-all:{user_id}:{timestamp}` sentinel created
  - Access token now appears inactive on introspection

### TC-OAUTH-TR-012: Revocation cache invalidation
- **Category**: Security
- **Standard**: Platform-specific (real-time revocation)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. In-memory revocation cache active
- **Input**: Revoke access token
- **Expected Output**:
  - JTI immediately invalidated in cache
  - Subsequent requests with the token are rejected by JWT middleware
  - No delay for cache expiry

### TC-OAUTH-TR-013: Revocation does not affect other users' tokens
- **Category**: Security
- **Standard**: RFC 7009 Section 2.1 (precision)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Tokens for user_A and user_B
- **Input**: Revoke user_A's access token
- **Expected Output**:
  - user_A's token: `active: false` on introspection
  - user_B's token: `active: true` on introspection (unaffected)

### TC-OAUTH-TR-014: Revocation sets RLS tenant context
- **Category**: Security
- **Standard**: Platform-specific (RLS enforcement)
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid client in `TENANT_A`
- **Input**: Revoke a token
- **Expected Output**:
  - `set_config('app.current_tenant', ...)` called before INSERT into `revoked_tokens`
  - RLS ensures revocation records are tenant-isolated

### TC-OAUTH-TR-015: No information leakage from revocation endpoint
- **Category**: Security
- **Standard**: RFC 7009 Section 2.1
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Various inputs
- **Input**: Revoke valid token, invalid token, unknown token, empty token
- **Expected Output**:
  - All return `200 OK`
  - Response body is empty
  - Attacker cannot determine whether a token existed or was valid

---

## Part 3: OAuth Client CRUD (Admin Endpoints)

### Nominal Tests (TC-OAUTH-CL-001 through TC-OAUTH-CL-010)

### TC-OAUTH-CL-001: Create confidential client
- **Category**: Nominal
- **Standard**: RFC 6749 Section 2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Admin JWT with `TenantId` extension
- **Input**:
  ```
  POST /admin/oauth/clients
  Authorization: Bearer {admin_jwt}
  Content-Type: application/json

  {
    "name": "My API Client",
    "client_type": "confidential",
    "redirect_uris": ["https://app.example.com/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "scopes": ["openid", "profile", "email"]
  }
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Body:
    ```json
    {
      "id": "<uuid>",
      "client_id": "<generated-string>",
      "name": "My API Client",
      "client_type": "confidential",
      "redirect_uris": ["https://app.example.com/callback"],
      "grant_types": ["authorization_code", "refresh_token"],
      "scopes": ["openid", "profile", "email"],
      "is_active": true,
      "created_at": "...",
      "updated_at": "...",
      "client_secret": "<only-shown-once>"
    }
    ```
  - `client_secret` present ONLY in creation response

### TC-OAUTH-CL-002: Create public client
- **Category**: Nominal
- **Standard**: RFC 6749 Section 2.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Admin JWT
- **Input**:
  ```json
  {
    "name": "SPA Client",
    "client_type": "public",
    "redirect_uris": ["https://spa.example.com/callback"],
    "grant_types": ["authorization_code"],
    "scopes": ["openid", "profile"]
  }
  ```
- **Expected Output**:
  - Status: `200 OK`
  - `client_secret` is `null` (public clients have no secret)

### TC-OAUTH-CL-003: List all clients
- **Category**: Nominal
- **Standard**: Platform-specific (admin API)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Multiple clients created
- **Input**:
  ```
  GET /admin/oauth/clients
  Authorization: Bearer {admin_jwt}
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Body:
    ```json
    {
      "clients": [...],
      "total": 3
    }
    ```
  - `client_secret` NOT included in list response (never re-exposed)

### TC-OAUTH-CL-004: Get client by ID
- **Category**: Nominal
- **Standard**: Platform-specific
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Client created with known ID
- **Input**:
  ```
  GET /admin/oauth/clients/{id}
  Authorization: Bearer {admin_jwt}
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Body contains full client details (no `client_secret`)

### TC-OAUTH-CL-005: Update client name
- **Category**: Nominal
- **Standard**: Platform-specific
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Client exists
- **Input**:
  ```
  PUT /admin/oauth/clients/{id}
  Authorization: Bearer {admin_jwt}
  Content-Type: application/json

  {
    "name": "Updated Client Name"
  }
  ```
- **Expected Output**:
  - Status: `200 OK`
  - `name` field updated to "Updated Client Name"
  - `updated_at` timestamp changed

### TC-OAUTH-CL-006: Update client redirect_uris
- **Category**: Nominal
- **Standard**: RFC 6749 Section 2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Client exists
- **Input**:
  ```json
  {
    "redirect_uris": ["https://app.example.com/callback", "https://staging.example.com/callback"]
  }
  ```
- **Expected Output**:
  - Status: `200 OK`
  - `redirect_uris` updated with both entries

### TC-OAUTH-CL-007: Update client scopes
- **Category**: Nominal
- **Standard**: RFC 6749 Section 2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Client exists with scopes `["openid", "profile"]`
- **Input**:
  ```json
  {
    "scopes": ["openid", "profile", "email", "read"]
  }
  ```
- **Expected Output**:
  - Status: `200 OK`
  - `scopes` updated to include all four entries

### TC-OAUTH-CL-008: Deactivate (soft delete) client
- **Category**: Nominal
- **Standard**: Platform-specific (soft delete)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Active client
- **Input**:
  ```
  DELETE /admin/oauth/clients/{id}
  Authorization: Bearer {admin_jwt}
  ```
- **Expected Output**:
  - Status: `204 No Content`
  - Subsequent `GET /admin/oauth/clients/{id}` shows `is_active: false`
  - Client can no longer authenticate or issue tokens

### TC-OAUTH-CL-009: Regenerate client secret
- **Category**: Nominal
- **Standard**: Platform-specific (secret rotation)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Confidential client exists
- **Input**:
  ```
  POST /admin/oauth/clients/{id}/regenerate-secret
  Authorization: Bearer {admin_jwt}
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Body:
    ```json
    {
      "client_secret": "<new-secret>"
    }
    ```
  - Old secret no longer works for authentication
  - New secret is different from the old one

### TC-OAUTH-CL-010: Update client grant_types
- **Category**: Nominal
- **Standard**: RFC 6749 Section 2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Client with `grant_types: ["authorization_code"]`
- **Input**:
  ```json
  {
    "grant_types": ["authorization_code", "client_credentials", "refresh_token"]
  }
  ```
- **Expected Output**:
  - Status: `200 OK`
  - `grant_types` updated with all three entries

---

### Edge Case Tests (TC-OAUTH-CL-011 through TC-OAUTH-CL-020)

### TC-OAUTH-CL-011: Create client with empty name
- **Category**: Edge Case
- **Standard**: Platform-specific (validation)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Admin JWT
- **Input**:
  ```json
  {
    "name": "",
    "client_type": "confidential",
    "redirect_uris": [],
    "grant_types": ["client_credentials"],
    "scopes": ["read"]
  }
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request", "error_description": "Client name is required" }`

### TC-OAUTH-CL-012: Create client with empty grant_types
- **Category**: Edge Case
- **Standard**: RFC 6749 Section 2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Admin JWT
- **Input**:
  ```json
  {
    "name": "No Grants Client",
    "client_type": "confidential",
    "redirect_uris": [],
    "grant_types": [],
    "scopes": ["read"]
  }
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request", "error_description": "At least one grant_type is required" }`

### TC-OAUTH-CL-013: Create client with invalid grant_type
- **Category**: Edge Case
- **Standard**: RFC 6749 Section 4
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Admin JWT
- **Input**:
  ```json
  {
    "name": "Invalid Grant Client",
    "client_type": "confidential",
    "redirect_uris": [],
    "grant_types": ["password"],
    "scopes": ["read"]
  }
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request", "error_description": "Invalid grant_type: password" }`

### TC-OAUTH-CL-014: Create authorization_code client without redirect_uris
- **Category**: Edge Case
- **Standard**: RFC 6749 Section 3.1.2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Admin JWT
- **Input**:
  ```json
  {
    "name": "No Redirect Client",
    "client_type": "confidential",
    "redirect_uris": [],
    "grant_types": ["authorization_code"],
    "scopes": ["openid"]
  }
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request", "error_description": "redirect_uris is required for authorization_code grant" }`

### TC-OAUTH-CL-015: Get non-existent client
- **Category**: Edge Case
- **Standard**: Platform-specific
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Admin JWT
- **Input**:
  ```
  GET /admin/oauth/clients/00000000-0000-0000-0000-ffffffffffff
  ```
- **Expected Output**:
  - Status: `404 Not Found`

### TC-OAUTH-CL-016: Update non-existent client
- **Category**: Edge Case
- **Standard**: Platform-specific
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Admin JWT
- **Input**:
  ```
  PUT /admin/oauth/clients/00000000-0000-0000-0000-ffffffffffff
  {"name": "Ghost"}
  ```
- **Expected Output**:
  - Status: `404 Not Found`

### TC-OAUTH-CL-017: Delete non-existent client
- **Category**: Edge Case
- **Standard**: Platform-specific
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Admin JWT
- **Input**:
  ```
  DELETE /admin/oauth/clients/00000000-0000-0000-0000-ffffffffffff
  ```
- **Expected Output**:
  - Status: `404 Not Found`

### TC-OAUTH-CL-018: Regenerate secret for public client
- **Category**: Edge Case
- **Standard**: Platform-specific
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Public client exists
- **Input**:
  ```
  POST /admin/oauth/clients/{public_client_id}/regenerate-secret
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request", "error_description": "Client is not confidential" }`

### TC-OAUTH-CL-019: Update client with invalid grant_type
- **Category**: Edge Case
- **Standard**: RFC 6749 Section 4
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Client exists
- **Input**:
  ```json
  {
    "grant_types": ["implicit"]
  }
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request", "error_description": "Invalid grant_type: implicit" }`

### TC-OAUTH-CL-020: Invalid UUID in path parameter
- **Category**: Edge Case
- **Standard**: Platform-specific
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Admin JWT
- **Input**:
  ```
  GET /admin/oauth/clients/not-a-valid-uuid
  ```
- **Expected Output**:
  - Status: `400 Bad Request`

---

### Security Tests (TC-OAUTH-CL-021 through TC-OAUTH-CL-025)

### TC-OAUTH-CL-021: Client CRUD requires admin authentication
- **Category**: Security
- **Standard**: Platform-specific (admin authorization)
- **Preconditions**: Fixtures: `TEST_TENANT`. No JWT or non-admin JWT
- **Input**:
  ```
  POST /admin/oauth/clients
  Content-Type: application/json

  { "name": "Unauthorized", ... }
  ```
  (no Authorization header)
- **Expected Output**:
  - Status: `401 Unauthorized`

### TC-OAUTH-CL-022: Non-admin user cannot manage clients
- **Category**: Security
- **Standard**: Platform-specific (RBAC)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. JWT for regular user (not admin)
- **Input**:
  ```
  GET /admin/oauth/clients
  Authorization: Bearer {regular_user_jwt}
  ```
- **Expected Output**:
  - Status: `403 Forbidden`

### TC-OAUTH-CL-023: Client list is tenant-isolated
- **Category**: Security
- **Standard**: Platform-specific (multi-tenancy)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Clients in `TENANT_A` and `TENANT_B`
- **Input**: Admin in `TENANT_A` lists clients
- **Expected Output**:
  - Only `TENANT_A` clients returned
  - `TENANT_B` clients not visible

### TC-OAUTH-CL-024: Client secret shown only once
- **Category**: Security
- **Standard**: OWASP Credential Management
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Confidential client created
- **Input**:
  1. `POST /admin/oauth/clients` -- response includes `client_secret`
  2. `GET /admin/oauth/clients/{id}` -- response does NOT include `client_secret`
  3. `GET /admin/oauth/clients` -- response does NOT include `client_secret` in list
- **Expected Output**:
  - `client_secret` only appears in creation response
  - No endpoint re-exposes the secret after creation

### TC-OAUTH-CL-025: Regenerate secret invalidates old secret
- **Category**: Security
- **Standard**: OWASP Credential Rotation
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Confidential client with known secret
- **Input**:
  1. Authenticate with old secret: `200 OK` (success)
  2. Regenerate secret: `POST /admin/oauth/clients/{id}/regenerate-secret`
  3. Authenticate with old secret: should fail
  4. Authenticate with new secret: should succeed
- **Expected Output**:
  - Step 3: `401 Unauthorized` (old secret invalid)
  - Step 4: `200 OK` (new secret works)

---

## Cross-Reference Index

| Test ID | Flow/Feature | RFC | Category |
|---------|-------------|-----|----------|
| TC-OAUTH-CC-001..015 | Client Credentials | RFC 6749 S4.4 | Nominal |
| TC-OAUTH-CC-016..030 | Client Credentials | RFC 6749 S4.4 | Edge Case |
| TC-OAUTH-CC-031..040 | Client Credentials | RFC 6749 S4.4 | Security |
| TC-OAUTH-DC-001..015 | Device Code | RFC 8628 | Nominal |
| TC-OAUTH-DC-016..030 | Device Code | RFC 8628 | Edge Case |
| TC-OAUTH-DC-031..040 | Device Code | RFC 8628 | Security |
| TC-OAUTH-AC-001..010 | Authorization Code | RFC 6749 S4.1, RFC 7636 | Nominal |
| TC-OAUTH-AC-011..025 | Authorization Code | RFC 6749 S4.1, RFC 7636 | Edge Case |
| TC-OAUTH-AC-026..035 | Authorization Code | RFC 6749 S4.1, RFC 7636 | Security |
| TC-OAUTH-TI-001..010 | Introspection | RFC 7662 | Nominal |
| TC-OAUTH-TI-011..020 | Introspection | RFC 7662 | Edge Case |
| TC-OAUTH-TI-021..025 | Introspection | RFC 7662 | Security |
| TC-OAUTH-TR-001..005 | Revocation | RFC 7009 | Nominal |
| TC-OAUTH-TR-006..010 | Revocation | RFC 7009 | Edge Case |
| TC-OAUTH-TR-011..015 | Revocation | RFC 7009 | Security |
| TC-OAUTH-CL-001..010 | Client CRUD | Platform | Nominal |
| TC-OAUTH-CL-011..020 | Client CRUD | Platform | Edge Case |
| TC-OAUTH-CL-021..025 | Client CRUD | Platform | Security |

**Total: 160 test cases**
- Client Credentials: 15 nominal + 15 edge + 10 security = **40**
- Device Code: 15 nominal + 15 edge + 10 security = **40**
- Authorization Code: 10 nominal + 15 edge + 10 security = **35**
- Token Introspection: 10 nominal + 10 edge + 5 security = **25**
- Token Revocation: 5 nominal + 5 edge + 5 security = **15**
- Client CRUD: 10 nominal + 10 edge + 5 security = **25**

### Dependency Map

```
TC-OAUTH-CL-001 --> TC-OAUTH-CC-001 (client needed for CC grant)
TC-OAUTH-CL-001 --> TC-OAUTH-DC-001 (client needed for device code)
TC-OAUTH-CC-001 --> TC-OAUTH-TI-001 (token needed for introspection)
TC-OAUTH-CC-001 --> TC-OAUTH-TR-001 (token needed for revocation)
TC-OAUTH-DC-006 --> TC-OAUTH-TI-002 (refresh token from device flow)
TC-OAUTH-TR-001 --> TC-OAUTH-TI-007 (revoked token for introspection)
TC-OAUTH-AC-004 --> TC-OAUTH-AC-006 (auth code tokens for refresh)
```
