# OIDC UserInfo Endpoint Functional Tests

**API Endpoint**: `GET /oauth/userinfo`
**Authentication**: Bearer token (JWT access token with `openid` scope)
**Required Headers**: `Authorization: Bearer {access_token}`
**Applicable Standards**: OpenID Connect Core 1.0 Section 5.3, RFC 6750 (Bearer Token Usage)

**Implementation Notes**:
- Handler: `userinfo_handler` in `xavyo-api-oauth`
- Service: `UserInfoService::get_user_claims()` performs scope-based claim filtering
- Scopes control which claims are returned:
  - `openid` (required): returns `sub`
  - `email`: returns `email`, `email_verified`
  - `profile`: returns `name`, `given_name`, `family_name` (when available)
- Token must contain `openid` in roles (scopes stored as roles in JWT)
- Tenant isolation enforced via RLS (`SET app.current_tenant`) and explicit `WHERE tenant_id = $N`
- User must be active (`is_active = true`)

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `USER_JWT`, `TEST_TENANT`
- **Special Setup**: Access tokens with various scope combinations (openid, email, profile)

---

## Nominal Cases

### TC-OIDC-UI-001: Successful UserInfo request with openid scope only
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0, Section 5.3
- **Preconditions**:
  - Valid access token with `openid` scope/role
  - User exists, is active, and belongs to the token's tenant
- **Input**:
  ```
  GET /oauth/userinfo
  Authorization: Bearer {valid_access_token}
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Content-Type: application/json
  Body: {
    "sub": "<user-uuid>"
  }
  ```
- **Verification**:
  - Only `sub` claim is returned (no email or profile claims)
  - `sub` matches the `sub` claim from the access token

### TC-OIDC-UI-002: UserInfo with openid and email scope
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0, Sections 5.3 and 5.4
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Access token with scopes/roles: `openid email`
- **Input**:
  ```
  GET /oauth/userinfo
  Authorization: Bearer {access_token_with_email_scope}
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "sub": "<user-uuid>",
    "email": "user@example.com",
    "email_verified": true
  }
  ```
- **Verification**:
  - `email` matches the user's actual email address in the database
  - `email_verified` reflects the database `email_verified` boolean

### TC-OIDC-UI-003: UserInfo with openid and profile scope
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0, Sections 5.3 and 5.4
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Access token with scopes/roles: `openid profile`; user has display_name
- **Input**:
  ```
  GET /oauth/userinfo
  Authorization: Bearer {access_token_with_profile_scope}
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "sub": "<user-uuid>",
    "name": "Jane Doe"
  }
  ```
- **Note**: Current implementation returns `name: null` if user has no display_name; `given_name` and `family_name` are not populated from the user model

### TC-OIDC-UI-004: UserInfo with all scopes (openid email profile)
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0, Section 5.4
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Access token with scopes/roles: `openid email profile`
- **Input**:
  ```
  GET /oauth/userinfo
  Authorization: Bearer {access_token_all_scopes}
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "sub": "<user-uuid>",
    "email": "user@example.com",
    "email_verified": true,
    "name": "Jane Doe"
  }
  ```

### TC-OIDC-UI-005: UserInfo for user with unverified email
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0, Section 5.1
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Access token with `openid email` scope; user's email is NOT verified
- **Input**:
  ```
  GET /oauth/userinfo
  Authorization: Bearer {access_token}
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "sub": "<user-uuid>",
    "email": "unverified@example.com",
    "email_verified": false
  }
  ```

### TC-OIDC-UI-006: UserInfo sub claim is consistent with ID token sub
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0, Section 5.3
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Both an ID token and access token obtained from the same authorization
- **Input**:
  1. Decode the ID token -- extract `sub`
  2. `GET /oauth/userinfo` with the access token -- extract `sub`
- **Expected Output**:
  - The `sub` value from the UserInfo response MUST match the `sub` in the ID token
  - Both represent the same user UUID

### TC-OIDC-UI-007: UserInfo for user with no display_name
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0, Section 5.1
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. User has `display_name = NULL` in database; token has `openid profile` scope
- **Input**:
  ```
  GET /oauth/userinfo
  Authorization: Bearer {access_token}
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "sub": "<user-uuid>",
    "name": null
  }
  ```
- **Note**: `name` is included because `profile` scope is present, but value is null. Alternatively, `name` field may be omitted entirely via `skip_serializing_if = "Option::is_none"`.

### TC-OIDC-UI-008: UserInfo omits claims for scopes not granted
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0, Section 5.4
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Token has only `openid` scope (no `email` or `profile`)
- **Input**:
  ```
  GET /oauth/userinfo
  Authorization: Bearer {access_token}
  ```
- **Expected Output**:
  - Response contains `sub` only
  - `email` field is absent (not present as null)
  - `email_verified` field is absent
  - `name` field is absent
- **Verification**: Uses `#[serde(skip_serializing_if = "Option::is_none")]` to omit null claims

---

## Edge Cases

### TC-OIDC-UI-010: UserInfo without Authorization header
- **Category**: Edge Case
- **Standard**: RFC 6750, Section 3.1
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  GET /oauth/userinfo
  ```
  (no Authorization header)
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  Body: { "error": "invalid_token", "error_description": "Missing Authorization header" }
  ```

### TC-OIDC-UI-011: UserInfo with Basic auth instead of Bearer
- **Category**: Edge Case
- **Standard**: RFC 6750, Section 2.1
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  GET /oauth/userinfo
  Authorization: Basic dXNlcjpwYXNz
  ```
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  Body: { "error": "invalid_token", "error_description": "Authorization header must use Bearer scheme" }
  ```

### TC-OIDC-UI-012: UserInfo with empty Bearer token
- **Category**: Edge Case
- **Standard**: RFC 6750, Section 2.1
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  GET /oauth/userinfo
  Authorization: Bearer
  ```
  (empty token after "Bearer ")
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  Body: { "error": "invalid_token", "error_description": "Bearer token cannot be empty" }
  ```

### TC-OIDC-UI-013: UserInfo with expired access token
- **Category**: Edge Case
- **Standard**: RFC 6750, Section 3.1
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Access token has `exp` in the past
- **Input**:
  ```
  GET /oauth/userinfo
  Authorization: Bearer {expired_token}
  ```
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  Body: { "error": "invalid_token", "error_description": "Invalid access token" }
  ```

### TC-OIDC-UI-014: UserInfo with malformed JWT
- **Category**: Edge Case
- **Standard**: RFC 7519, Section 7.2
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  GET /oauth/userinfo
  Authorization: Bearer not.a.valid.jwt.token
  ```
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  Body: { "error": "invalid_token", "error_description": "Invalid access token" }
  ```

### TC-OIDC-UI-015: UserInfo for non-existent user (deleted after token issued)
- **Category**: Edge Case
- **Standard**: Operational
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Valid token issued, then user deleted from database
- **Input**:
  ```
  GET /oauth/userinfo
  Authorization: Bearer {token_for_deleted_user}
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  Body: { "error": "invalid_request", "error_description": "User not found" }
  ```
- **Note**: Returns `UserNotFound` error from the service layer

### TC-OIDC-UI-016: UserInfo for inactive user
- **Category**: Edge Case
- **Standard**: Operational
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. User account deactivated (`is_active = false`) after token was issued
- **Input**:
  ```
  GET /oauth/userinfo
  Authorization: Bearer {token_for_inactive_user}
  ```
- **Expected Output**:
  ```
  Status: 403 Forbidden
  Body: { "error": "access_denied", "error_description": "User account is inactive" }
  ```

### TC-OIDC-UI-017: POST request to UserInfo endpoint
- **Category**: Edge Case
- **Standard**: OpenID Connect Core 1.0, Section 5.3.1
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  POST /oauth/userinfo
  Authorization: Bearer {valid_token}
  ```
- **Expected Output**:
  - Status: 405 Method Not Allowed (if only GET is registered)
  - Or Status: 200 OK (if POST is also supported per OIDC Core Section 5.3.2)
- **Note**: Current implementation only registers GET route; POST returns 405

### TC-OIDC-UI-018: UserInfo with token missing tenant_id (tid) claim
- **Category**: Edge Case
- **Standard**: Xavyo Multi-Tenancy Architecture
- **Preconditions**: Fixtures: `TEST_TENANT`. Crafted token without `tid` claim
- **Input**:
  ```
  GET /oauth/userinfo
  Authorization: Bearer {token_without_tid}
  ```
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  Body: { "error": "invalid_token", "error_description": "Missing tenant ID in token" }
  ```

### TC-OIDC-UI-019: UserInfo with token having invalid sub (non-UUID)
- **Category**: Edge Case
- **Standard**: Xavyo Implementation
- **Preconditions**: Fixtures: `TEST_TENANT`. Crafted token with `sub: "not-a-uuid"`
- **Input**:
  ```
  GET /oauth/userinfo
  Authorization: Bearer {token_with_invalid_sub}
  ```
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  Body: { "error": "invalid_token", "error_description": "Invalid subject in token" }
  ```

---

## Security Cases

### TC-OIDC-UI-020: UserInfo without openid scope returns 403
- **Category**: Security
- **Standard**: OpenID Connect Core 1.0, Section 5.3
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Access token with roles `["user", "admin"]` but NOT `"openid"`
- **Input**:
  ```
  GET /oauth/userinfo
  Authorization: Bearer {token_without_openid_scope}
  ```
- **Expected Output**:
  ```
  Status: 403 Forbidden
  Body: {
    "error": "insufficient_scope",
    "error_description": "The access token must have openid scope for userinfo"
  }
  ```
- **Rationale**: UserInfo endpoint is an OIDC-specific endpoint requiring `openid` scope

### TC-OIDC-UI-021: Cross-tenant user information isolation
- **Category**: Security
- **Standard**: Xavyo Multi-Tenancy Architecture
- **Preconditions**:
  - User A in tenant 1
  - User B in tenant 2
  - Token issued for user A in tenant 1
- **Input**:
  ```
  GET /oauth/userinfo
  Authorization: Bearer {token_for_user_A_tenant_1}
  ```
- **Expected Output**:
  - Returns only user A's claims from tenant 1
  - Cannot return any data from tenant 2
  - RLS context is set to tenant 1 (`SET app.current_tenant = tenant_1_uuid`)
  - SQL query includes `WHERE tenant_id = $2` as defense-in-depth

### TC-OIDC-UI-022: UserInfo does not leak sensitive fields
- **Category**: Security
- **Standard**: OWASP ASVS 3.6
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Valid access token with all scopes
- **Input**:
  ```
  GET /oauth/userinfo
  Authorization: Bearer {access_token}
  ```
- **Expected Output**:
  - Response does NOT contain `password_hash` or any password-related field
  - Response does NOT contain `tenant_id` (only exposed via `sub` scope-matching)
  - Response does NOT contain `created_at` or `updated_at` internal timestamps
  - Response does NOT contain `is_active` (service checks this internally, not exposed)
  - Only OIDC-standard claims are returned

### TC-OIDC-UI-023: UserInfo with revoked token is rejected
- **Category**: Security
- **Standard**: RFC 7009 / F084
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Token was revoked via `POST /oauth/revoke`
- **Input**:
  ```
  GET /oauth/userinfo
  Authorization: Bearer {revoked_access_token}
  ```
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  ```
- **Note**: If JWT middleware (with RevocationCache) intercepts the request before the handler, the error may come from middleware rather than the userinfo handler itself

### TC-OIDC-UI-024: UserInfo response does not include CORS wildcard
- **Category**: Security
- **Standard**: OWASP ASVS 14.5
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  GET /oauth/userinfo
  Authorization: Bearer {valid_token}
  Origin: https://evil.example.com
  ```
- **Expected Output**:
  - Response does NOT include `Access-Control-Allow-Origin: *`
  - UserInfo contains personally identifiable information and must not be accessible cross-origin without explicit CORS policy

---

## Cross-Reference Matrix

| Test Case | Standard Section | Category | Focus |
|-----------|-----------------|----------|-------|
| UI-001 | Core 1.0 S5.3 | Nominal | Basic sub claim |
| UI-002 | Core 1.0 S5.3, S5.4 | Nominal | Email claims |
| UI-003 | Core 1.0 S5.3, S5.4 | Nominal | Profile claims |
| UI-004 | Core 1.0 S5.4 | Nominal | All scopes |
| UI-005 | Core 1.0 S5.1 | Nominal | Unverified email |
| UI-006 | Core 1.0 S5.3 | Nominal | sub consistency |
| UI-007 | Core 1.0 S5.1 | Nominal | Null profile |
| UI-008 | Core 1.0 S5.4 | Nominal | Claim filtering |
| UI-010 | RFC 6750 S3.1 | Edge | Missing auth |
| UI-011 | RFC 6750 S2.1 | Edge | Wrong auth scheme |
| UI-012 | RFC 6750 S2.1 | Edge | Empty token |
| UI-013 | RFC 6750 S3.1 | Edge | Expired token |
| UI-014 | RFC 7519 S7.2 | Edge | Malformed JWT |
| UI-015 | Operational | Edge | Deleted user |
| UI-016 | Operational | Edge | Inactive user |
| UI-017 | Core 1.0 S5.3.1 | Edge | POST method |
| UI-018 | Multi-Tenancy | Edge | Missing tid |
| UI-019 | Implementation | Edge | Invalid sub |
| UI-020 | Core 1.0 S5.3 | Security | openid required |
| UI-021 | Multi-Tenancy | Security | Tenant isolation |
| UI-022 | OWASP ASVS 3.6 | Security | Data leakage |
| UI-023 | RFC 7009 / F084 | Security | Revoked token |
| UI-024 | OWASP ASVS 14.5 | Security | CORS |
