# OAuth 2.0 Authorization Code Flow with PKCE - Functional Test Suite

**Component**: `xavyo-api-oauth` (authorize endpoint, consent endpoint, token exchange)
**Standards**: RFC 6749 Section 4.1, RFC 7636 (PKCE), OIDC Core 1.0
**API Endpoints**:
- `GET /oauth/authorize` -- Authorization endpoint (redirect to consent/login)
- `POST /oauth/authorize/consent` -- Consent submission
- `POST /oauth/token` with `grant_type=authorization_code` -- Token exchange
- `POST /oauth/token` with `grant_type=refresh_token` -- Token refresh

**Tenant Context**: Requires `X-Tenant-ID` header (UUID)

**Implementation Note**: The consent handler is currently a placeholder that returns
`"User authentication required"`. Tests marked with `[PLACEHOLDER]` document the
expected behavior once session management integration is complete. The authorization
endpoint (`GET /oauth/authorize`) performs full validation and redirect, so those
tests are fully executable.

---

## Prerequisites

All tests assume:
- A valid tenant exists with ID `{TENANT_ID}` (UUID)
- A user exists with `{USER_ID}`, email `user@example.com`, verified, active
- PKCE: `code_verifier` is a 43-128 character random string
- PKCE: `code_challenge` = `base64url(sha256(code_verifier))`, method = `S256`

### Fixture: Authorization Code Client

Created via `POST /admin/oauth/clients`:
```json
{
  "name": "Web Application",
  "client_type": "confidential",
  "redirect_uris": ["https://app.example.com/callback", "https://app.example.com/auth/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scopes": ["openid", "profile", "email", "read", "write", "offline_access"]
}
```

### Fixture: Public SPA Client

```json
{
  "name": "SPA Application",
  "client_type": "public",
  "redirect_uris": ["https://spa.example.com/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scopes": ["openid", "profile"]
}
```

### PKCE Values (Example)

```
code_verifier  = dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
code_challenge = E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
code_challenge_method = S256
```

---

## Nominal Tests (TC-OAUTH-AC-001 through TC-OAUTH-AC-010)

### TC-OAUTH-AC-001: Initiate authorization code flow
- **Category**: Nominal
- **Standard**: RFC 6749 Section 4.1.1, RFC 7636 Section 4.3
- **Preconditions**: Client with `authorization_code` grant type, registered redirect_uri
- **Input**:
  ```
  GET /oauth/authorize?response_type=code&client_id={client_id}&redirect_uri=https://app.example.com/callback&scope=openid+profile&state=xyz123&code_challenge={code_challenge}&code_challenge_method=S256
  X-Tenant-ID: {TENANT_ID}
  ```
- **Expected Output**:
  - Status: `302 Found`
  - `Location` header redirects to consent/login page with all parameters preserved
  - CSRF token cookie is set (HttpOnly, SameSite=Strict, Path=/oauth, Max-Age=600)
  - Redirect URL includes `csrf_token` and `csrf_sig` parameters

### TC-OAUTH-AC-002: Authorization with OIDC nonce
- **Category**: Nominal
- **Standard**: OIDC Core Section 3.1.2.1 (nonce parameter)
- **Preconditions**: Valid client and PKCE values
- **Input**:
  ```
  GET /oauth/authorize?response_type=code&client_id={client_id}&redirect_uri=https://app.example.com/callback&scope=openid+profile&state=xyz123&code_challenge={code_challenge}&code_challenge_method=S256&nonce=n-0S6_WzA2Mj
  X-Tenant-ID: {TENANT_ID}
  ```
- **Expected Output**:
  - Status: `302 Found`
  - `Location` includes `nonce` parameter (preserved for ID token)

### TC-OAUTH-AC-003: Consent denial redirects with access_denied [PLACEHOLDER]
- **Category**: Nominal
- **Standard**: RFC 6749 Section 4.1.2.1
- **Preconditions**: User authenticated, consent form displayed
- **Input**:
  ```
  POST /oauth/authorize/consent
  Content-Type: application/x-www-form-urlencoded
  Cookie: csrf_token={csrf}

  client_id={client_id}&redirect_uri=https://app.example.com/callback&scope=openid+profile&state=xyz123&code_challenge={code_challenge}&code_challenge_method=S256&approved=false&csrf_token={csrf}&csrf_sig={sig}
  ```
- **Expected Output**:
  - Status: `302 Found`
  - `Location`: `https://app.example.com/callback?error=access_denied&error_description=The+user+denied+the+authorization+request&state=xyz123`

### TC-OAUTH-AC-004: Token exchange with authorization code [PLACEHOLDER]
- **Category**: Nominal
- **Standard**: RFC 6749 Section 4.1.3, RFC 7636 Section 4.5
- **Preconditions**: Authorization code issued after user consent
- **Input**:
  ```
  POST /oauth/token
  Content-Type: application/x-www-form-urlencoded

  grant_type=authorization_code&code={auth_code}&redirect_uri=https://app.example.com/callback&client_id={client_id}&client_secret={client_secret}&code_verifier={code_verifier}
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Body:
    ```json
    {
      "access_token": "<JWT>",
      "token_type": "Bearer",
      "expires_in": 900,
      "refresh_token": "<opaque>",
      "id_token": "<JWT>",
      "scope": "openid profile"
    }
    ```
  - `id_token` present when `openid` scope requested
  - `refresh_token` present when `offline_access` or `refresh_token` grant allowed

### TC-OAUTH-AC-005: Token exchange derives tenant from auth code
- **Category**: Nominal
- **Standard**: Platform-specific (multi-tenant token exchange)
- **Preconditions**: Auth code issued in `TENANT_A`
- **Input**:
  ```
  POST /oauth/token
  Content-Type: application/x-www-form-urlencoded

  grant_type=authorization_code&code={auth_code}&redirect_uri=https://app.example.com/callback&client_id={client_id}&client_secret={client_secret}&code_verifier={code_verifier}
  ```
  (no X-Tenant-ID header needed -- tenant derived from code)
- **Expected Output**:
  - Status: `200 OK`
  - JWT `tid` claim matches `TENANT_A`
  - No X-Tenant-ID header required for this grant type

### TC-OAUTH-AC-006: Refresh token grant [PLACEHOLDER]
- **Category**: Nominal
- **Standard**: RFC 6749 Section 6
- **Preconditions**: Valid refresh_token from previous token exchange
- **Input**:
  ```
  POST /oauth/token
  Content-Type: application/x-www-form-urlencoded
  X-Tenant-ID: {TENANT_ID}

  grant_type=refresh_token&refresh_token={refresh_token}&client_id={client_id}&client_secret={client_secret}
  ```
- **Expected Output**:
  - Status: `200 OK`
  - New `access_token` issued
  - New `refresh_token` issued (rotation)
  - Old refresh_token is invalidated

### TC-OAUTH-AC-007: Refresh token rotation issues new refresh token
- **Category**: Nominal
- **Standard**: OAuth 2.0 Security BCP (refresh token rotation)
- **Preconditions**: Valid refresh_token
- **Input**: Same as TC-OAUTH-AC-006
- **Expected Output**:
  - New `refresh_token` is different from the original
  - Old `refresh_token` cannot be used again

### TC-OAUTH-AC-008: Public client token exchange with PKCE only [PLACEHOLDER]
- **Category**: Nominal
- **Standard**: RFC 7636 Section 4.5 (PKCE for public clients)
- **Preconditions**: Public client, auth code issued
- **Input**:
  ```
  POST /oauth/token
  Content-Type: application/x-www-form-urlencoded

  grant_type=authorization_code&code={auth_code}&redirect_uri=https://spa.example.com/callback&client_id={public_client_id}&code_verifier={code_verifier}
  ```
  (no client_secret -- public client)
- **Expected Output**:
  - Status: `200 OK`
  - Tokens issued based on PKCE verification alone

### TC-OAUTH-AC-009: Authorization code hash uses SHA-256
- **Category**: Nominal
- **Standard**: Platform-specific (secure code storage)
- **Preconditions**: Auth code issued [PLACEHOLDER]
- **Input**: Inspect database `authorization_codes` table
- **Expected Output**:
  - Column `code_hash` contains SHA-256 hex digest (64 characters)
  - Raw authorization code is NOT stored in database

### TC-OAUTH-AC-010: Redirect URI exact match validation
- **Category**: Nominal
- **Standard**: RFC 6749 Section 3.1.2.3 (exact match)
- **Preconditions**: Client has `redirect_uris: ["https://app.example.com/callback"]`
- **Input**:
  ```
  GET /oauth/authorize?...&redirect_uri=https://app.example.com/callback
  ```
- **Expected Output**:
  - Status: `302 Found` (passes validation)
  - No error -- exact match succeeds

---

## Edge Case Tests (TC-OAUTH-AC-011 through TC-OAUTH-AC-025)

### TC-OAUTH-AC-011: Missing response_type parameter
- **Category**: Edge Case
- **Standard**: RFC 6749 Section 4.1.1 (REQUIRED)
- **Preconditions**: Valid client
- **Input**:
  ```
  GET /oauth/authorize?client_id={client_id}&redirect_uri=https://app.example.com/callback&scope=openid&state=xyz&code_challenge={cc}&code_challenge_method=S256
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request" }`

### TC-OAUTH-AC-012: response_type is not "code"
- **Category**: Edge Case
- **Standard**: RFC 6749 Section 4.1.1
- **Preconditions**: Valid client
- **Input**:
  ```
  GET /oauth/authorize?response_type=token&client_id={client_id}&...
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "unsupported_response_type" }`

### TC-OAUTH-AC-013: Missing code_challenge (PKCE required)
- **Category**: Edge Case
- **Standard**: RFC 7636 Section 4.4.1
- **Preconditions**: Valid client, PKCE is mandatory
- **Input**:
  ```
  GET /oauth/authorize?response_type=code&client_id={client_id}&redirect_uri=https://app.example.com/callback&scope=openid&state=xyz&code_challenge_method=S256
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request" }`

### TC-OAUTH-AC-014: Unsupported code_challenge_method
- **Category**: Edge Case
- **Standard**: RFC 7636 Section 4.2 (only S256 recommended)
- **Preconditions**: Valid client
- **Input**:
  ```
  GET /oauth/authorize?...&code_challenge={cc}&code_challenge_method=plain
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request" }` (only S256 supported)

### TC-OAUTH-AC-015: Redirect URI not registered
- **Category**: Edge Case
- **Standard**: RFC 6749 Section 3.1.2.3
- **Preconditions**: Client has `redirect_uris: ["https://app.example.com/callback"]`
- **Input**:
  ```
  GET /oauth/authorize?...&redirect_uri=https://evil.example.com/callback
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request" }`
  - MUST NOT redirect to the unregistered URI

### TC-OAUTH-AC-016: Redirect URI with extra path segment
- **Category**: Edge Case
- **Standard**: RFC 6749 Section 3.1.2.3 (exact match required)
- **Preconditions**: Client has `redirect_uris: ["https://app.example.com/callback"]`
- **Input**:
  ```
  GET /oauth/authorize?...&redirect_uri=https://app.example.com/callback/extra
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request" }`

### TC-OAUTH-AC-017: Redirect URI with query string appended
- **Category**: Edge Case
- **Standard**: RFC 6749 Section 3.1.2 (no fragment, exact match)
- **Preconditions**: Registered URI has no query string
- **Input**:
  ```
  GET /oauth/authorize?...&redirect_uri=https://app.example.com/callback?extra=param
  ```
- **Expected Output**:
  - Status: `400 Bad Request` (does not match registered URI exactly)

### TC-OAUTH-AC-018: Invalid client_id format
- **Category**: Edge Case
- **Standard**: RFC 6749 Section 2.2
- **Preconditions**: None
- **Input**:
  ```
  GET /oauth/authorize?response_type=code&client_id=not-a-uuid&...
  ```
- **Expected Output**:
  - Status: `400 Bad Request` or `401 Unauthorized`
  - Body: `{ "error": "invalid_client", "error_description": "Invalid client_id format" }`

### TC-OAUTH-AC-019: Deactivated client on authorize
- **Category**: Edge Case
- **Standard**: RFC 6749 Section 4.1.2.1
- **Preconditions**: Client deactivated via `DELETE /admin/oauth/clients/{id}`
- **Input**:
  ```
  GET /oauth/authorize?response_type=code&client_id={deactivated_client_id}&...
  ```
- **Expected Output**:
  - Status: `401 Unauthorized`
  - Body: `{ "error": "invalid_client", "error_description": "Client is not active" }`

### TC-OAUTH-AC-020: Client not authorized for authorization_code grant
- **Category**: Edge Case
- **Standard**: RFC 6749 Section 4.1
- **Preconditions**: Client with `grant_types: ["client_credentials"]`
- **Input**:
  ```
  GET /oauth/authorize?response_type=code&client_id={cc_client_id}&...
  ```
- **Expected Output**:
  - Status: `401 Unauthorized`
  - Body: `{ "error": "unauthorized_client" }`

### TC-OAUTH-AC-021: Missing state parameter
- **Category**: Edge Case
- **Standard**: RFC 6749 Section 4.1.1 (RECOMMENDED, enforced as REQUIRED here)
- **Preconditions**: Valid client
- **Input**:
  ```
  GET /oauth/authorize?response_type=code&client_id={client_id}&redirect_uri=...&scope=openid&code_challenge={cc}&code_challenge_method=S256
  ```
  (no state parameter)
- **Expected Output**:
  - Status: `400 Bad Request` (if state is enforced)
  - Body: `{ "error": "invalid_request" }`

### TC-OAUTH-AC-022: Auth code expired before exchange [PLACEHOLDER]
- **Category**: Edge Case
- **Standard**: RFC 6749 Section 4.1.2 (short-lived codes)
- **Preconditions**: Auth code issued, wait beyond expiration (e.g., 10 minutes)
- **Input**:
  ```
  POST /oauth/token
  grant_type=authorization_code&code={expired_code}&...&code_verifier={code_verifier}
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_grant", "error_description": "Authorization code not found, expired, or already used" }`

### TC-OAUTH-AC-023: Auth code replay (used twice) [PLACEHOLDER]
- **Category**: Edge Case
- **Standard**: RFC 6749 Section 4.1.2 ("MUST NOT be used more than once")
- **Preconditions**: Auth code successfully exchanged once
- **Input**: Exchange same auth code again
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_grant" }`
  - Tokens from first exchange SHOULD be revoked (RFC 6749 Section 10.5)

### TC-OAUTH-AC-024: PKCE code_verifier mismatch [PLACEHOLDER]
- **Category**: Edge Case
- **Standard**: RFC 7636 Section 4.6
- **Preconditions**: Auth code issued with code_challenge from verifier_A
- **Input**: Exchange with different code_verifier_B
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_grant" }`

### TC-OAUTH-AC-025: Missing code_verifier on token exchange [PLACEHOLDER]
- **Category**: Edge Case
- **Standard**: RFC 7636 Section 4.5 (REQUIRED when code_challenge was sent)
- **Preconditions**: Auth code issued with PKCE
- **Input**:
  ```
  POST /oauth/token
  grant_type=authorization_code&code={auth_code}&redirect_uri=...&client_id={client_id}&client_secret={client_secret}
  ```
  (no code_verifier)
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request", "error_description": "code_verifier is required" }`

---

## Security Tests (TC-OAUTH-AC-026 through TC-OAUTH-AC-035)

### TC-OAUTH-AC-026: Open redirect prevention
- **Category**: Security
- **Standard**: RFC 6749 Section 10.15, OWASP Open Redirect
- **Preconditions**: Client has registered `redirect_uris`
- **Input**:
  ```
  GET /oauth/authorize?...&redirect_uri=https://attacker.com/steal
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request" }`
  - Server MUST NOT redirect to the attacker-controlled URI

### TC-OAUTH-AC-027: CSRF protection on consent form (F082-US6)
- **Category**: Security
- **Standard**: RFC 6749 Section 10.12, OWASP CSRF Prevention
- **Preconditions**: Authorization flow initiated
- **Input**: Submit consent form without valid CSRF token
  ```
  POST /oauth/authorize/consent
  Content-Type: application/x-www-form-urlencoded

  client_id={client_id}&redirect_uri=...&approved=true
  ```
  (no csrf_token or csrf_sig, no csrf_token cookie)
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request", "error_description": "CSRF validation failed" }`
  - Auth code NOT issued

### TC-OAUTH-AC-028: CSRF token HMAC tampered
- **Category**: Security
- **Standard**: OWASP CSRF Prevention (double-submit with HMAC)
- **Preconditions**: CSRF token obtained from authorize redirect
- **Input**:
  ```
  POST /oauth/authorize/consent
  Cookie: csrf_token={valid_csrf}
  csrf_token={valid_csrf}&csrf_sig=tampered-signature&approved=true&...
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request", "error_description": "CSRF validation failed" }`

### TC-OAUTH-AC-029: CSRF cookie mismatch with form token
- **Category**: Security
- **Standard**: OWASP CSRF Prevention (double-submit cookie)
- **Preconditions**: Two different CSRF tokens
- **Input**:
  ```
  POST /oauth/authorize/consent
  Cookie: csrf_token=cookie-csrf-value
  csrf_token=different-form-csrf&csrf_sig={sig}&approved=true&...
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request", "error_description": "CSRF validation failed" }`

### TC-OAUTH-AC-030: Refresh token replay detection [PLACEHOLDER]
- **Category**: Security
- **Standard**: OAuth 2.0 Security BCP Section 4.14.2
- **Preconditions**: Refresh token rotated (old token invalidated)
- **Input**: Use the old (rotated) refresh token
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_grant" }`
  - SHOULD revoke entire token family (all refresh tokens in the chain)

### TC-OAUTH-AC-031: Missing X-Tenant-ID on authorize
- **Category**: Security
- **Standard**: Platform-specific (tenant isolation)
- **Preconditions**: Valid client
- **Input**:
  ```
  GET /oauth/authorize?response_type=code&client_id={client_id}&...
  ```
  (no X-Tenant-ID header)
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request", "error_description": "Tenant context required..." }`

### TC-OAUTH-AC-032: Cross-tenant client access
- **Category**: Security
- **Standard**: Platform-specific (tenant isolation)
- **Preconditions**: Client registered in `TENANT_A`
- **Input**:
  ```
  GET /oauth/authorize?response_type=code&client_id={client_id_from_tenant_A}&...
  X-Tenant-ID: {TENANT_B_ID}
  ```
- **Expected Output**:
  - Status: `401 Unauthorized` or `404 Not Found`
  - Client from `TENANT_A` is not visible in `TENANT_B`

### TC-OAUTH-AC-033: Authorization code bound to redirect_uri [PLACEHOLDER]
- **Category**: Security
- **Standard**: RFC 6749 Section 4.1.3 (redirect_uri MUST match)
- **Preconditions**: Auth code issued with `redirect_uri=https://app.example.com/callback`
- **Input**: Exchange code with different redirect_uri
  ```
  POST /oauth/token
  grant_type=authorization_code&code={auth_code}&redirect_uri=https://app.example.com/auth/callback&...
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_grant" }`

### TC-OAUTH-AC-034: State parameter echoed in error redirect
- **Category**: Security
- **Standard**: RFC 6749 Section 4.1.2.1 (state MUST be included in error redirect)
- **Preconditions**: Consent denied by user
- **Input**: Same as TC-OAUTH-AC-003 (consent denied)
- **Expected Output**:
  - Redirect URL query contains `state=xyz123`
  - State value is unchanged from the original request

### TC-OAUTH-AC-035: Redirect URI fragment prevention
- **Category**: Security
- **Standard**: RFC 6749 Section 3.1.2 ("MUST NOT include a fragment component")
- **Preconditions**: Valid client
- **Input**:
  ```
  GET /oauth/authorize?...&redirect_uri=https://app.example.com/callback#fragment
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request" }`
