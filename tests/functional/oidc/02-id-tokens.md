# OIDC ID Token Functional Tests

**API Endpoint**: `POST /oauth/token` (token issuance)
**Token Format**: JWT (RFC 7519), signed with RS256
**Authentication**: Client credentials (Basic or POST body)
**Applicable Standards**: OpenID Connect Core 1.0, RFC 7519 (JWT), RFC 7515 (JWS), RFC 7518 (JWA)

**Implementation Notes**:
- Xavyo issues ID tokens via `TokenService::issue_authorization_code_tokens()`
- Tokens are signed with RS256 using the active signing key
- Token includes custom claims: `tid` (tenant_id), `roles`, `email`, `jti`
- PKCE (S256) is mandatory for authorization code grants
- Key rotation supported via F069-S5 (multiple kids in JWKS)

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`
- **Special Setup**: OAuth client with authorization_code grant and openid scope

---

## Nominal Cases

### TC-OIDC-IDT-001: ID token issued on authorization_code grant with openid scope
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0, Section 3.1.3.3
- **Preconditions**:
  - Valid OAuth2 client registered (confidential, grant_type includes authorization_code)
  - User authenticated and authorization code issued with scope `openid`
- **Input**:
  ```
  POST /oauth/token
  Content-Type: application/x-www-form-urlencoded
  Authorization: Basic {base64(client_id:client_secret)}

  grant_type=authorization_code&code={auth_code}&redirect_uri={uri}&code_verifier={pkce_verifier}
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Content-Type: application/json
  Body: {
    "access_token": "<jwt>",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "<opaque-token>",
    "id_token": "<jwt>",
    "scope": "openid"
  }
  ```
- **Verification**: `id_token` is present in the response when `openid` scope was requested

### TC-OIDC-IDT-002: ID token contains required OIDC claims
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0, Section 2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. ID token obtained from TC-OIDC-IDT-001
- **Input**: Decode the JWT payload of the `id_token`
- **Expected Output**: Decoded payload contains:
  ```json
  {
    "iss": "https://idp.xavyo.com",
    "sub": "<user-uuid>",
    "aud": ["<client_id>"],
    "exp": <unix-timestamp>,
    "iat": <unix-timestamp>,
    "jti": "<unique-uuid>"
  }
  ```
- **Verification**:
  - `iss` matches the configured issuer URL
  - `sub` is a valid UUID matching the authenticated user
  - `aud` contains the client_id used in the request
  - `exp` > `iat` (token has a future expiration)
  - `jti` is a unique UUID (not reused across issuance)

### TC-OIDC-IDT-003: ID token includes nonce when provided in authorization request
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0, Section 3.1.3.7 (item 11)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Authorization request included `nonce=test-nonce-value-123`
- **Input**: Decode the JWT payload of the `id_token`
- **Expected Output**:
  - `nonce` claim is present in the ID token
  - `nonce` value exactly matches `test-nonce-value-123`
- **Rationale**: Nonce mitigates replay attacks; MUST be included when sent in auth request

### TC-OIDC-IDT-004: ID token includes email claims with email scope
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0, Section 5.4
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Token issued with scope `openid email`
- **Input**: Decode the JWT payload of the `id_token`
- **Expected Output**:
  - `email` claim is present with the user's email address
  - `email_verified` claim is present (boolean)

### TC-OIDC-IDT-005: ID token includes profile claims with profile scope
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0, Section 5.4
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Token issued with scope `openid profile`; user has display_name set
- **Input**: Decode the JWT payload of the `id_token`
- **Expected Output**:
  - `name` claim is present (if user has display_name)
  - `given_name` and `family_name` are present (if derivable from user data)

### TC-OIDC-IDT-006: ID token signature verifiable with JWKS public key
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0, Section 3.1.3.7 (item 6)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. ID token obtained and JWKS fetched
- **Input**:
  1. `GET /.well-known/jwks.json` -- extract the key matching the token's `kid` header
  2. Verify the RS256 signature of the `id_token` using the extracted public key
- **Expected Output**:
  - JWT header has `alg: "RS256"` and `kid: "<key-id>"`
  - Signature verification succeeds using the JWKS public key with matching `kid`
  - The header `typ` is `"JWT"`

### TC-OIDC-IDT-007: ID token includes Xavyo custom claims (tenant_id, roles)
- **Category**: Nominal
- **Standard**: RFC 7519, Section 4.2 (Private Claims)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Token issued for a user in a specific tenant with roles
- **Input**: Decode the JWT payload
- **Expected Output**:
  - `tid` claim is present as a UUID (tenant_id)
  - `roles` claim is an array of role strings (e.g., `["user", "admin"]`)
  - `tid` matches the tenant the user belongs to

### TC-OIDC-IDT-008: ID token not issued for client_credentials grant
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0, Section 3.1.3.3
- **Preconditions**: Fixtures: `OAUTH_CC_CLIENT`, `TEST_TENANT`. Valid confidential client with client_credentials grant type
- **Input**:
  ```
  POST /oauth/token
  Content-Type: application/x-www-form-urlencoded
  Authorization: Basic {base64(client_id:client_secret)}
  X-Tenant-ID: {tenant_uuid}

  grant_type=client_credentials
  ```
- **Expected Output**:
  ```json
  {
    "access_token": "<jwt>",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "..."
  }
  ```
  - `id_token` field is absent or null
  - No `refresh_token` for client_credentials grant
- **Rationale**: ID tokens represent user identity; client_credentials has no user context

### TC-OIDC-IDT-009: ID token exp is in the future relative to iat
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0, Section 2 / RFC 7519, Section 4.1.4
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Fresh ID token obtained
- **Input**: Decode the JWT payload
- **Expected Output**:
  - `exp` > `iat`
  - `exp - iat` is a reasonable lifetime (e.g., 3600 seconds = 1 hour)
  - `iat` is within a few seconds of the current server time

### TC-OIDC-IDT-010: ID token issued with device_code grant includes id_token
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0, Section 3.1.3.3 / RFC 8628
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Device code flow completed (user authorized)
- **Input**:
  ```
  POST /oauth/token
  Content-Type: application/x-www-form-urlencoded
  X-Tenant-ID: {tenant_uuid}

  grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={code}&client_id={id}
  ```
- **Expected Output**:
  - `id_token` is present if original device authorization included `openid` scope
  - ID token contains standard OIDC claims

---

## Edge Cases

### TC-OIDC-IDT-020: ID token without openid scope is not issued
- **Category**: Edge Case
- **Standard**: OpenID Connect Core 1.0, Section 3.1.2.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Authorization code issued with scope `profile email` (no `openid`)
- **Input**: Exchange the authorization code at `/oauth/token`
- **Expected Output**:
  - `id_token` is absent from the response
  - `access_token` is still issued
- **Rationale**: ID token MUST only be issued when `openid` scope is requested

### TC-OIDC-IDT-021: ID token with multiple audience values
- **Category**: Edge Case
- **Standard**: OpenID Connect Core 1.0, Section 2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Client configured with multiple audiences
- **Input**: Exchange authorization code
- **Expected Output**:
  - `aud` claim is an array containing all intended audiences
  - When `aud` is multi-valued, an `azp` claim SHOULD be present per OIDC Core Section 2

### TC-OIDC-IDT-022: Expired authorization code rejects token issuance
- **Category**: Edge Case
- **Standard**: RFC 6749, Section 4.1.2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Authorization code was issued more than 10 minutes ago
- **Input**:
  ```
  POST /oauth/token
  grant_type=authorization_code&code={expired_code}&...
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: { "error": "invalid_grant", "error_description": "..." }
  ```

### TC-OIDC-IDT-023: Reused authorization code rejects token issuance
- **Category**: Edge Case
- **Standard**: RFC 6749, Section 4.1.2 / OpenID Connect Core 1.0, Section 3.1.3.4
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Authorization code already exchanged successfully
- **Input**: Attempt to exchange the same code again
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: { "error": "invalid_grant", "error_description": "Authorization code not found, expired, or already used" }
  ```
- **Side Effects**: Per RFC, the OP SHOULD revoke all tokens previously issued based on the code

### TC-OIDC-IDT-024: ID token with very long subject claim
- **Category**: Edge Case
- **Standard**: RFC 7519, Section 4.1.2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. User ID is a standard UUID (36 characters)
- **Input**: Exchange authorization code for the user
- **Expected Output**:
  - `sub` claim is the full UUID string (e.g., `550e8400-e29b-41d4-a716-446655440000`)
  - Sub claim is not truncated

### TC-OIDC-IDT-025: Token request with mismatched redirect_uri
- **Category**: Edge Case
- **Standard**: RFC 6749, Section 4.1.3
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Authorization code was issued with `redirect_uri=https://app.example.com/callback`
- **Input**:
  ```
  POST /oauth/token
  grant_type=authorization_code&code={code}&redirect_uri=https://different.example.com/callback&...
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: { "error": "invalid_grant", "error_description": "..." }
  ```

### TC-OIDC-IDT-026: Token request with invalid PKCE code_verifier
- **Category**: Edge Case
- **Standard**: RFC 7636, Section 4.6
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Authorization code issued with PKCE S256 challenge
- **Input**:
  ```
  POST /oauth/token
  grant_type=authorization_code&code={code}&redirect_uri={uri}&code_verifier=wrong_verifier
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: { "error": "invalid_grant", "error_description": "..." }
  ```

### TC-OIDC-IDT-027: Token request missing required code_verifier
- **Category**: Edge Case
- **Standard**: RFC 7636, Section 4.6
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Authorization code issued with PKCE
- **Input**:
  ```
  POST /oauth/token
  grant_type=authorization_code&code={code}&redirect_uri={uri}
  ```
  (no `code_verifier` parameter)
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: { "error": "invalid_request", "error_description": "code_verifier is required" }
  ```

### TC-OIDC-IDT-028: ID token iat claim is close to current server time
- **Category**: Edge Case
- **Standard**: RFC 7519, Section 4.1.6
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Fresh token just issued
- **Input**: Decode the JWT payload; compare `iat` to current time
- **Expected Output**:
  - `|current_time - iat|` < 5 seconds (accounting for processing time)
  - `iat` is a positive integer (Unix timestamp)

### TC-OIDC-IDT-029: Token request with unsupported grant_type
- **Category**: Edge Case
- **Standard**: RFC 6749, Section 4.1.3
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  POST /oauth/token
  grant_type=password&username=user&password=pass&client_id={id}
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: { "error": "unsupported_grant_type", "error_description": "Unsupported grant type: password" }
  ```

### TC-OIDC-IDT-030: Token request with empty grant_type
- **Category**: Edge Case
- **Standard**: RFC 6749, Section 4.1.3
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  POST /oauth/token
  grant_type=&client_id={id}
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: { "error": "unsupported_grant_type", "error_description": "..." }
  ```

### TC-OIDC-IDT-031: Refresh token grant issues new access token but no new ID token
- **Category**: Edge Case
- **Standard**: OpenID Connect Core 1.0, Section 12.2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Valid refresh token obtained from an authorization_code exchange
- **Input**:
  ```
  POST /oauth/token
  Content-Type: application/x-www-form-urlencoded
  X-Tenant-ID: {tenant_uuid}

  grant_type=refresh_token&refresh_token={token}&client_id={id}&client_secret={secret}
  ```
- **Expected Output**:
  - New `access_token` is issued
  - New `refresh_token` is issued (token rotation)
  - `id_token` MAY or MAY NOT be present per spec (implementation-dependent)
  - Old refresh token is invalidated

### TC-OIDC-IDT-032: Token request with client credentials in both header and body
- **Category**: Edge Case
- **Standard**: RFC 6749, Section 2.3
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Valid client
- **Input**:
  ```
  POST /oauth/token
  Authorization: Basic {base64(client_id:client_secret)}

  grant_type=authorization_code&code={code}&client_id={different_id}&client_secret={different_secret}&...
  ```
- **Expected Output**:
  - Server uses the Authorization header credentials (header takes precedence)
  - Body credentials are ignored

### TC-OIDC-IDT-033: Each ID token has a unique jti claim
- **Category**: Edge Case
- **Standard**: RFC 7519, Section 4.1.7
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Same user, same client
- **Input**: Issue two separate ID tokens for the same user in quick succession
- **Expected Output**:
  - Both tokens have `jti` claims
  - The `jti` values are different (UUIDv4, cryptographically random)

### TC-OIDC-IDT-034: ID token with inactive user account
- **Category**: Edge Case
- **Standard**: Operational
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. User account has been deactivated (`is_active = false`)
- **Input**: Attempt to exchange authorization code for this user
- **Expected Output**:
  - Token issuance fails
  - Error indicates the user account is not available
  - No ID token or access token issued

---

## Security Cases

### TC-OIDC-IDT-040: ID token uses RS256 algorithm (not none)
- **Category**: Security
- **Standard**: OpenID Connect Core 1.0, Section 3.1.3.7 (item 6) / CVE-2015-9235
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. ID token obtained
- **Input**: Decode the JWT header of the `id_token`
- **Expected Output**:
  - `alg` is `"RS256"` (never `"none"` or `"HS256"`)
  - `typ` is `"JWT"`
  - `kid` is present and matches a key in the JWKS

### TC-OIDC-IDT-041: Algorithm substitution attack rejected
- **Category**: Security
- **Standard**: RFC 7515, Section 4.1.1 / JWT Algorithm Confusion
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Attacker crafts a token with `alg: "HS256"` signed with the public key
- **Input**: Present the crafted token to any protected endpoint
- **Expected Output**:
  - Token is rejected (401 Unauthorized)
  - Server MUST only accept RS256 signatures verified with the RSA public key
  - Server MUST NOT accept HS256 using the public key as the HMAC secret

### TC-OIDC-IDT-042: Token with tampered payload is rejected
- **Category**: Security
- **Standard**: RFC 7515, Section 5.2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Valid ID token obtained
- **Input**:
  1. Decode the JWT payload
  2. Modify a claim (e.g., change `sub` to a different user ID)
  3. Re-encode the payload (without re-signing)
  4. Present the modified token to `/oauth/userinfo`
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  Body: { "error": "invalid_token", "error_description": "Invalid access token" }
  ```

### TC-OIDC-IDT-043: Token with forged signature is rejected
- **Category**: Security
- **Standard**: RFC 7515, Section 5.2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Attacker generates their own RSA key pair
- **Input**: Create a JWT signed with the attacker's private key but claiming the server's issuer
- **Expected Output**:
  - Token is rejected at all protected endpoints
  - Signature verification fails because the key does not match any key in the server's JWKS

### TC-OIDC-IDT-044: Expired ID token is rejected
- **Category**: Security
- **Standard**: RFC 7519, Section 4.1.4
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Token with `exp` in the past
- **Input**: Present the expired token to a protected endpoint
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  ```
- **Note**: Clock skew tolerance of up to 5 minutes (300 seconds) is acceptable per federation config

### TC-OIDC-IDT-045: Token with future iat is suspicious
- **Category**: Security
- **Standard**: RFC 7519, Section 4.1.6
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Crafted token with `iat` far in the future
- **Input**: Present the crafted token to a protected endpoint
- **Expected Output**:
  - Server MAY reject tokens with `iat` significantly in the future
  - At minimum, the token should be flagged in logs

### TC-OIDC-IDT-046: Cross-tenant ID token rejected
- **Category**: Security
- **Standard**: Xavyo Multi-Tenancy Architecture
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Token issued for tenant A, user attempts to access tenant B resources
- **Input**: Present a valid token from tenant A with an `X-Tenant-ID: {tenant_B_uuid}` header
- **Expected Output**:
  - Request is rejected (403 Forbidden or 401 Unauthorized)
  - Token's `tid` claim does not match the target tenant
  - No cross-tenant data access occurs

### TC-OIDC-IDT-047: Revoked token (via JTI blacklist) is rejected
- **Category**: Security
- **Standard**: RFC 7009 (Token Revocation) / F084 Feature
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Token has been revoked via `POST /oauth/revoke`
- **Input**: Present the revoked token to a protected endpoint
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  ```
- **Note**: RevocationCache (in-memory + DB) checks the `jti` claim against the blacklist

### TC-OIDC-IDT-048: Token with missing kid header is rejected or handled gracefully
- **Category**: Security
- **Standard**: RFC 7515, Section 4.1.4
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Crafted JWT without `kid` in the header
- **Input**: Present the crafted token
- **Expected Output**:
  - If server has only one key, it MAY attempt verification with that key
  - If server has multiple keys, token MUST be rejected (ambiguous key selection)
  - No key confusion attacks possible

### TC-OIDC-IDT-049: Token from a different issuer is rejected
- **Category**: Security
- **Standard**: OpenID Connect Core 1.0, Section 3.1.3.7 (item 2)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Valid JWT from a different OIDC provider (e.g., Google)
- **Input**: Present the foreign token to xavyo's protected endpoints
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  ```
  - Token rejected because `iss` claim does not match the server's issuer
  - Signature cannot be verified with the server's keys

---

## Compliance Cases

### TC-OIDC-IDT-050: ID token conforms to JWT format (3-part base64url-encoded)
- **Category**: Compliance
- **Standard**: RFC 7519, Section 3.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. ID token obtained
- **Input**: Parse the `id_token` string
- **Expected Output**:
  - Token has exactly 3 parts separated by `.` (header.payload.signature)
  - Each part is valid base64url-encoded data
  - Header decodes to a JSON object
  - Payload decodes to a JSON object

### TC-OIDC-IDT-051: ID token header contains required fields
- **Category**: Compliance
- **Standard**: RFC 7515, Section 4.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. ID token obtained
- **Input**: Decode the JWT header
- **Expected Output**:
  ```json
  {
    "alg": "RS256",
    "typ": "JWT",
    "kid": "<non-empty-string>"
  }
  ```

### TC-OIDC-IDT-052: sub claim is a locally unique identifier
- **Category**: Compliance
- **Standard**: OpenID Connect Core 1.0, Section 2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. ID tokens for two different users
- **Input**: Compare `sub` claims
- **Expected Output**:
  - `sub` is a non-empty string
  - `sub` values are different for different users
  - `sub` is stable for the same user across multiple token issuances
  - `sub` MUST NOT exceed 255 ASCII characters

### TC-OIDC-IDT-053: aud claim matches the client_id
- **Category**: Compliance
- **Standard**: OpenID Connect Core 1.0, Section 2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. ID token obtained for a specific client
- **Input**: Decode the JWT payload
- **Expected Output**:
  - `aud` contains the `client_id` used to obtain the token
  - Relying Parties MUST validate that their own `client_id` is in the `aud` array

### TC-OIDC-IDT-054: exp and iat are numeric Unix timestamps
- **Category**: Compliance
- **Standard**: RFC 7519, Sections 4.1.4 and 4.1.6
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. ID token obtained
- **Input**: Decode the JWT payload
- **Expected Output**:
  - `exp` is a JSON number (not a string, not a formatted date)
  - `iat` is a JSON number (not a string, not a formatted date)
  - Both values represent seconds since 1970-01-01T00:00:00Z (Unix epoch)
  - Both values are positive integers

### TC-OIDC-IDT-055: Token response Content-Type is application/json
- **Category**: Compliance
- **Standard**: RFC 6749, Section 5.1
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**: Any successful `POST /oauth/token` request
- **Expected Output**:
  - Response `Content-Type` is `application/json`
  - Response includes `Cache-Control: no-store` (per RFC 6749 Section 5.1)
  - Response includes `Pragma: no-cache`

### TC-OIDC-IDT-056: Error responses follow RFC 6749 Section 5.2 format
- **Category**: Compliance
- **Standard**: RFC 6749, Section 5.2
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**: Any failed `POST /oauth/token` request
- **Expected Output**:
  ```json
  {
    "error": "<error_code>",
    "error_description": "<human-readable-string>"
  }
  ```
  - `error` is one of: `invalid_request`, `invalid_client`, `invalid_grant`, `unauthorized_client`, `unsupported_grant_type`, `invalid_scope`
  - `error_description` is an optional human-readable ASCII string

### TC-OIDC-IDT-057: token_type is always Bearer
- **Category**: Compliance
- **Standard**: RFC 6749, Section 5.1 / RFC 6750
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**: Any successful `POST /oauth/token` request
- **Expected Output**:
  - `token_type` is `"Bearer"` (case-insensitive per RFC 6750, but should be exactly `"Bearer"`)

### TC-OIDC-IDT-058: expires_in matches actual token lifetime
- **Category**: Compliance
- **Standard**: RFC 6749, Section 5.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. Fresh token issued
- **Input**:
  1. Record `expires_in` from the token response
  2. Decode the JWT to get `exp` and `iat`
- **Expected Output**:
  - `expires_in` approximately equals `exp - iat` (within 2 seconds)
  - Both values represent the same intended lifetime

### TC-OIDC-IDT-059: ID token claims use correct JSON types
- **Category**: Compliance
- **Standard**: OpenID Connect Core 1.0, Section 2 / RFC 7519
- **Preconditions**: Fixtures: `ADMIN_JWT`, `USER_JWT`, `TEST_TENANT`. ID token obtained
- **Input**: Decode the JWT payload and validate JSON types
- **Expected Output**:
  - `iss`: JSON string
  - `sub`: JSON string
  - `aud`: JSON string or JSON array of strings
  - `exp`: JSON number (integer)
  - `iat`: JSON number (integer)
  - `nonce`: JSON string (when present)
  - `email`: JSON string (when present)
  - `email_verified`: JSON boolean (when present)
  - `name`: JSON string (when present)
  - `roles`: JSON array of strings (custom claim)
  - `tid`: JSON string (UUID format, custom claim)

---

## Cross-Reference Matrix

| Test Case | Standard Section | Category | Focus |
|-----------|-----------------|----------|-------|
| IDT-001 | Core 1.0 S3.1.3.3 | Nominal | ID token presence |
| IDT-002 | Core 1.0 S2 | Nominal | Required claims |
| IDT-003 | Core 1.0 S3.1.3.7 | Nominal | Nonce claim |
| IDT-004 | Core 1.0 S5.4 | Nominal | Email claims |
| IDT-005 | Core 1.0 S5.4 | Nominal | Profile claims |
| IDT-006 | Core 1.0 S3.1.3.7 | Nominal | Signature verification |
| IDT-007 | RFC 7519 S4.2 | Nominal | Custom claims |
| IDT-008 | Core 1.0 S3.1.3.3 | Nominal | No ID token for CC |
| IDT-009 | RFC 7519 S4.1.4 | Nominal | Expiration validity |
| IDT-010 | Core 1.0 / RFC 8628 | Nominal | Device code ID token |
| IDT-020 | Core 1.0 S3.1.2.1 | Edge | No openid scope |
| IDT-021 | Core 1.0 S2 | Edge | Multiple audiences |
| IDT-022 | RFC 6749 S4.1.2 | Edge | Expired auth code |
| IDT-023 | Core 1.0 S3.1.3.4 | Edge | Reused auth code |
| IDT-024 | RFC 7519 S4.1.2 | Edge | Long sub claim |
| IDT-025 | RFC 6749 S4.1.3 | Edge | redirect_uri mismatch |
| IDT-026 | RFC 7636 S4.6 | Edge | Invalid PKCE verifier |
| IDT-027 | RFC 7636 S4.6 | Edge | Missing PKCE verifier |
| IDT-028 | RFC 7519 S4.1.6 | Edge | iat freshness |
| IDT-029 | RFC 6749 S4.1.3 | Edge | Unsupported grant type |
| IDT-030 | RFC 6749 S4.1.3 | Edge | Empty grant type |
| IDT-031 | Core 1.0 S12.2 | Edge | Refresh token behavior |
| IDT-032 | RFC 6749 S2.3 | Edge | Duplicate credentials |
| IDT-033 | RFC 7519 S4.1.7 | Edge | Unique jti |
| IDT-034 | Operational | Edge | Inactive user |
| IDT-040 | Core 1.0 S3.1.3.7 | Security | Algorithm enforcement |
| IDT-041 | RFC 7515 S4.1.1 | Security | Algorithm substitution |
| IDT-042 | RFC 7515 S5.2 | Security | Payload tampering |
| IDT-043 | RFC 7515 S5.2 | Security | Forged signature |
| IDT-044 | RFC 7519 S4.1.4 | Security | Expired token |
| IDT-045 | RFC 7519 S4.1.6 | Security | Future iat |
| IDT-046 | Multi-Tenancy | Security | Cross-tenant |
| IDT-047 | RFC 7009 / F084 | Security | Revoked token |
| IDT-048 | RFC 7515 S4.1.4 | Security | Missing kid |
| IDT-049 | Core 1.0 S3.1.3.7 | Security | Foreign issuer |
| IDT-050 | RFC 7519 S3.1 | Compliance | JWT format |
| IDT-051 | RFC 7515 S4.1 | Compliance | Header fields |
| IDT-052 | Core 1.0 S2 | Compliance | sub uniqueness |
| IDT-053 | Core 1.0 S2 | Compliance | aud matching |
| IDT-054 | RFC 7519 S4.1.4,6 | Compliance | Numeric timestamps |
| IDT-055 | RFC 6749 S5.1 | Compliance | Content-Type |
| IDT-056 | RFC 6749 S5.2 | Compliance | Error format |
| IDT-057 | RFC 6749/6750 | Compliance | token_type |
| IDT-058 | RFC 6749 S5.1 | Compliance | expires_in accuracy |
| IDT-059 | Core 1.0 S2 / RFC 7519 | Compliance | JSON types |
