# OIDC Federation (RP) Functional Tests

**API Endpoints**:
- `POST /auth/federation/discover` -- Home Realm Discovery (identify IdP for email domain)
- `GET /auth/federation/authorize` -- Initiate federated authorization (redirect to external IdP)
- `GET /auth/federation/callback` -- Handle callback from external IdP (code exchange + provisioning)
- `POST /auth/federation/logout` -- Federation logout (session cleanup)

**Authentication**:
- `discover`, `authorize`: Requires tenant context (via TenantLayer middleware)
- `callback`: Stateless (session looked up by `state` parameter)
- `logout`: Requires tenant context

**Applicable Standards**: OpenID Connect Core 1.0 (RP behavior), RFC 6749, RFC 7636 (PKCE), RFC 7519 (JWT)

**Implementation Notes**:
- Crate: `xavyo-api-oidc-federation`
- Auth flow uses PKCE S256, nonce, and state parameters
- Sessions stored in `federated_auth_sessions` table with 10-minute TTL
- User provisioning is Just-In-Time (JIT) via `ProvisioningService`
- Client secret encrypted at rest via `EncryptionService` (AES-256-GCM)
- ID token decoded from external IdP; signature verification via `TokenVerifierService`
- JWKS cached with automatic refresh via `JwksCache`
- Token issued by `TokenIssuerService` after successful federation login
- User roles looked up from database (`UserRole::get_user_roles()`)

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: OIDC identity provider configured with domain mapping and client credentials

---

## Nominal Cases

### TC-OIDC-FED-001: Home realm discovery for federated domain
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0, Section 2 (Authentication using Authorization Code Flow)
- **Preconditions**:
  - Tenant has an OIDC IdP configured with domain `example.com`
  - IdP is enabled (`is_enabled = true`)
- **Input**:
  ```
  POST /auth/federation/discover
  Content-Type: application/json
  X-Tenant-ID: {tenant_uuid}

  { "email": "user@example.com" }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "authentication_method": "federated",
    "identity_provider": {
      "id": "<idp-uuid>",
      "name": "Corporate SSO",
      "provider_type": "oidc"
    }
  }
  ```

### TC-OIDC-FED-002: Home realm discovery for non-federated domain
- **Category**: Nominal
- **Standard**: Home Realm Discovery
- **Preconditions**: Fixtures: `TEST_TENANT`. No IdP configured for the email domain `gmail.com`
- **Input**:
  ```
  POST /auth/federation/discover
  Content-Type: application/json
  X-Tenant-ID: {tenant_uuid}

  { "email": "user@gmail.com" }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "authentication_method": "standard",
    "identity_provider": null
  }
  ```

### TC-OIDC-FED-003: Initiate federated authorization flow
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0, Section 3.1.2
- **Preconditions**:
  - OIDC IdP is configured, enabled, and validated
  - IdP's discovery document is reachable
- **Input**:
  ```
  GET /auth/federation/authorize?idp_id={idp_uuid}&redirect_uri=https://app.example.com/callback
  X-Tenant-ID: {tenant_uuid}
  ```
- **Expected Output**:
  ```
  Status: 307 Temporary Redirect
  Location: https://external-idp.example.com/authorize?
    response_type=code&
    client_id={configured_client_id}&
    redirect_uri={callback_base_url}/auth/federation/callback&
    state={random_state}&
    nonce={random_nonce}&
    code_challenge={pkce_challenge}&
    code_challenge_method=S256&
    scope=openid+profile+email
  ```
- **Side Effects**:
  - `federated_auth_sessions` record created with state, nonce, PKCE verifier, redirect_uri, tenant_id, idp_id
  - Session has a TTL of 10 minutes

### TC-OIDC-FED-004: Authorization URL includes PKCE S256 challenge
- **Category**: Nominal
- **Standard**: RFC 7636, Section 4.2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Federated auth initiated (TC-OIDC-FED-003)
- **Input**: Parse the `Location` header from the redirect
- **Expected Output**:
  - `code_challenge` parameter is present (base64url-encoded SHA-256 hash)
  - `code_challenge_method` is `S256`
  - `code_challenge` is derived from a PKCE verifier stored in the session
- **Rationale**: PKCE prevents authorization code interception attacks

### TC-OIDC-FED-005: Authorization URL includes nonce parameter
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0, Section 3.1.2.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Federated auth initiated
- **Input**: Parse the `Location` header from the redirect
- **Expected Output**:
  - `nonce` parameter is present and is a randomly generated value
  - Nonce value is stored in the session for later verification

### TC-OIDC-FED-006: Successful callback with authorization code (new user JIT provisioning)
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0, Section 3.1.3
- **Preconditions**:
  - Federated auth session exists (state matches)
  - External IdP returns valid authorization code
  - No existing user with the IdP subject or email
- **Input**:
  ```
  GET /auth/federation/callback?code={auth_code}&state={session_state}
  ```
- **Expected Output**:
  - New user created in `users` table (JIT provisioning)
  - New entry in `user_identity_links` table (subject, issuer, raw_claims)
  - Response is either:
    - **Redirect**: `307 Temporary Redirect` to `{redirect_uri}#access_token={jwt}&token_type=Bearer&expires_in=3600`
    - **JSON**: `200 OK` with `{ "access_token": "...", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "..." }`
  - Session marked as used (`is_used = true`)

### TC-OIDC-FED-007: Successful callback with authorization code (existing user sync)
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0, Section 3.1.3
- **Preconditions**:
  - User already linked to this IdP (existing `user_identity_links` record)
  - IdP has `sync_on_login = true`
- **Input**:
  ```
  GET /auth/federation/callback?code={auth_code}&state={session_state}
  ```
- **Expected Output**:
  - Existing user is synced (display_name updated if changed)
  - Identity link updated with latest raw_claims
  - Xavyo JWT issued with user's current roles from database
  - User not duplicated

### TC-OIDC-FED-008: Callback performs token exchange with IdP
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0, Section 3.1.3.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Valid session and authorization code
- **Input**: Internal behavior during callback processing
- **Expected Output**: Token exchange request to the IdP includes:
  - `grant_type=authorization_code`
  - `code={auth_code}`
  - `client_id={configured_client_id}`
  - `client_secret={decrypted_secret}` (from encrypted storage)
  - `redirect_uri={callback_url}` (must match the authorize request)
  - `code_verifier={pkce_verifier}` (from session)

### TC-OIDC-FED-009: Callback decodes external IdP's ID token
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0, Section 3.1.3.5
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Token exchange returned an ID token
- **Input**: Internal behavior during callback processing
- **Expected Output**: Decoded ID token claims include:
  - `sub` (subject identifier at the IdP)
  - `iss` (issuer -- the external IdP)
  - `aud` (audience -- should include our client_id)
  - `exp` (expiration)
  - `email` (if scope included email)
  - `name` (if scope included profile)

### TC-OIDC-FED-010: Callback issues Xavyo JWT with user roles from database
- **Category**: Nominal
- **Standard**: Xavyo Implementation
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User provisioned/synced during callback
- **Input**: Xavyo token issuance step of the callback
- **Expected Output**:
  - Access token is a valid Xavyo JWT
  - Token `sub` is the xavyo user ID (not the external IdP subject)
  - Token `tid` is the tenant_id
  - Token `roles` are loaded from `user_roles` table (not hardcoded)
  - Falls back to `["user"]` if role lookup fails

### TC-OIDC-FED-011: Callback with redirect_uri returns fragment-based redirect
- **Category**: Nominal
- **Standard**: OAuth 2.0 Implicit Grant (fragment encoding for security)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Session stored with `redirect_uri` starting with `http`
- **Input**:
  ```
  GET /auth/federation/callback?code={code}&state={state}
  ```
- **Expected Output**:
  ```
  Status: 307 Temporary Redirect
  Location: https://app.example.com/callback#access_token={jwt}&token_type=Bearer&expires_in=3600
  ```
- **Rationale**: Fragment-based redirect is safer than query parameters (not sent to the server on subsequent requests)

### TC-OIDC-FED-012: Federation logout cleans up expired sessions
- **Category**: Nominal
- **Standard**: Operational
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Some expired federation sessions exist
- **Input**:
  ```
  POST /auth/federation/logout
  X-Tenant-ID: {tenant_uuid}
  ```
- **Expected Output**:
  ```
  Status: 204 No Content
  ```
- **Side Effects**: Expired sessions are cleaned up from `federated_auth_sessions` table

---

## Edge Cases

### TC-OIDC-FED-020: Callback with expired session (older than 10 minutes)
- **Category**: Edge Case
- **Standard**: Security (session timeout)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Federation session created more than 10 minutes ago
- **Input**:
  ```
  GET /auth/federation/callback?code={code}&state={expired_session_state}
  ```
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  Body: { "error": "session_expired", "message": "Authentication session has expired" }
  ```
- **Side Effects**: Expired session is deleted from the database

### TC-OIDC-FED-021: Callback with unknown state parameter
- **Category**: Edge Case
- **Standard**: RFC 6749, Section 10.12 (CSRF Protection)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. No session exists for the given state value
- **Input**:
  ```
  GET /auth/federation/callback?code={code}&state=nonexistent-state-value
  ```
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  Body: { "error": "session_expired", "message": "Authentication session not found or expired" }
  ```

### TC-OIDC-FED-022: Callback without authorization code (error from IdP)
- **Category**: Edge Case
- **Standard**: RFC 6749, Section 4.1.2.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User denied consent at the external IdP
- **Input**:
  ```
  GET /auth/federation/callback?state={state}&error=access_denied&error_description=User+denied+consent
  ```
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: { "error": "idp_error", "message": "access_denied: User denied consent" }
  ```

### TC-OIDC-FED-023: Callback without code and without error
- **Category**: Edge Case
- **Standard**: RFC 6749, Section 4.1.2
- **Preconditions**: Fixtures: `TEST_TENANT`. Malformed callback
- **Input**:
  ```
  GET /auth/federation/callback?state={state}
  ```
  (neither `code` nor `error` present)
- **Expected Output**:
  ```
  Status: 400 Bad Request
  Body: { "error": "invalid_callback", "message": "Missing authorization code" }
  ```

### TC-OIDC-FED-024: Authorize with disabled IdP
- **Category**: Edge Case
- **Standard**: Operational
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. IdP exists but `is_enabled = false`
- **Input**:
  ```
  GET /auth/federation/authorize?idp_id={disabled_idp_uuid}
  X-Tenant-ID: {tenant_uuid}
  ```
- **Expected Output**:
  ```
  Status: 403 Forbidden
  Body: { "error": "idp_disabled", "message": "Identity provider {id} is disabled" }
  ```

### TC-OIDC-FED-025: Authorize with non-existent IdP
- **Category**: Edge Case
- **Standard**: Operational
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. IdP UUID does not exist for this tenant
- **Input**:
  ```
  GET /auth/federation/authorize?idp_id={nonexistent_uuid}
  X-Tenant-ID: {tenant_uuid}
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  Body: { "error": "idp_not_found", "message": "Identity provider {id} not found" }
  ```

### TC-OIDC-FED-026: Authorize with IdP whose discovery endpoint is unreachable
- **Category**: Edge Case
- **Standard**: OpenID Connect Discovery 1.0
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. IdP's `issuer_url` points to an unreachable server
- **Input**:
  ```
  GET /auth/federation/authorize?idp_id={idp_uuid}
  X-Tenant-ID: {tenant_uuid}
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  Body: { "error": "discovery_failed", "message": "Discovery failed for {issuer}: ..." }
  ```

### TC-OIDC-FED-027: Callback with token exchange failure (IdP returns error)
- **Category**: Edge Case
- **Standard**: OpenID Connect Core 1.0, Section 3.1.3.4
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Valid session, but external IdP rejects the code exchange (e.g., code expired)
- **Input**:
  ```
  GET /auth/federation/callback?code={invalid_code}&state={state}
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  Body: { "error": "token_exchange_failed", "message": "..." }
  ```

### TC-OIDC-FED-028: Callback with invalid ID token from IdP
- **Category**: Edge Case
- **Standard**: OpenID Connect Core 1.0, Section 3.1.3.5
- **Preconditions**: Fixtures: `TEST_TENANT`. IdP returns a malformed ID token (not valid JWT format)
- **Input**: Callback processing where `decode_id_token` receives `"not.a.jwt"`
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  Body: { "error": "invalid_id_token", "message": "Invalid JWT format" }
  ```

### TC-OIDC-FED-029: Discover with invalid email format
- **Category**: Edge Case
- **Standard**: RFC 5322
- **Preconditions**: Fixtures: `TEST_TENANT`. No specific setup required
- **Input**:
  ```
  POST /auth/federation/discover
  Content-Type: application/json
  X-Tenant-ID: {tenant_uuid}

  { "email": "not-an-email" }
  ```
- **Expected Output**: Either:
  - `400 Bad Request` with validation error
  - Or `200 OK` with `authentication_method: "standard"` (no domain match)

### TC-OIDC-FED-030: Callback links existing user by email (email match JIT)
- **Category**: Edge Case
- **Standard**: Xavyo Implementation (JIT Provisioning)
- **Preconditions**:
  - User with email `user@corp.com` already exists in the tenant
  - No identity link for this user to the IdP
  - IdP returns ID token with `email: "user@corp.com"`
- **Input**:
  ```
  GET /auth/federation/callback?code={code}&state={state}
  ```
- **Expected Output**:
  - Existing user is linked (new `user_identity_links` entry created)
  - No duplicate user created
  - Login succeeds with the existing user's identity

### TC-OIDC-FED-031: Callback with IdP returning no email claim
- **Category**: Edge Case
- **Standard**: OpenID Connect Core 1.0, Section 5.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. IdP ID token has no `email` claim and no email in mapped claims
- **Input**: Callback processing
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  Body: { "error": "provisioning_failed", "message": "Email claim is required" }
  ```

### TC-OIDC-FED-032: Multiple IdPs configured for same domain (priority-based)
- **Category**: Edge Case
- **Standard**: Home Realm Discovery
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Two IdPs configured for `example.com` with different priorities
- **Input**:
  ```
  POST /auth/federation/discover
  Content-Type: application/json
  X-Tenant-ID: {tenant_uuid}

  { "email": "user@example.com" }
  ```
- **Expected Output**:
  - Returns the IdP with the highest priority for the domain
  - Discovery is deterministic

### TC-OIDC-FED-033: Authorize without redirect_uri uses default
- **Category**: Edge Case
- **Standard**: RFC 6749, Section 3.1.2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. IdP configured, no redirect_uri in request
- **Input**:
  ```
  GET /auth/federation/authorize?idp_id={idp_uuid}
  X-Tenant-ID: {tenant_uuid}
  ```
- **Expected Output**:
  - Redirect to external IdP succeeds
  - Session stores default redirect_uri: `{callback_base_url}/`

### TC-OIDC-FED-034: Callback when IdP returns additional unknown claims
- **Category**: Edge Case
- **Standard**: OpenID Connect Core 1.0, Section 5.1 (extensibility)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. IdP ID token contains non-standard claims (e.g., `department`, `employee_id`)
- **Input**: Callback processing
- **Expected Output**:
  - Additional claims are captured in `raw_claims` (via `#[serde(flatten)]` on `additional` field)
  - Login succeeds; unknown claims do not cause errors
  - Claims are stored in `user_identity_links.raw_claims`

---

## Security Cases

### TC-OIDC-FED-040: CSRF protection via state parameter
- **Category**: Security
- **Standard**: RFC 6749, Section 10.12
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Federated auth initiated (session created)
- **Input**:
  1. Attacker crafts a callback URL with their own `state` value: `GET /auth/federation/callback?code={code}&state=attacker-forged-state`
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  Body: { "error": "session_expired", "message": "Authentication session not found or expired" }
  ```
- **Rationale**: State parameter must match a valid session; attacker cannot forge state

### TC-OIDC-FED-041: Nonce verification prevents ID token replay
- **Category**: Security
- **Standard**: OpenID Connect Core 1.0, Section 3.1.3.7 (item 11)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Federation auth uses nonce
- **Input**: Internal verification: session nonce is compared against ID token nonce claim
- **Expected Output**:
  - If nonce in ID token does not match the session nonce, authentication fails
  - Prevents replay of ID tokens from previous authentication sessions

### TC-OIDC-FED-042: Session replay prevention (is_used flag)
- **Category**: Security
- **Standard**: Security best practice
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Session already used (`is_used = true` via `find_by_state` filtering)
- **Input**:
  ```
  GET /auth/federation/callback?code={same_code}&state={same_state}
  ```
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  Body: { "error": "session_expired", "message": "Authentication session not found or expired" }
  ```
- **Note**: `find_by_state` filters `is_used = false`, preventing session replay

### TC-OIDC-FED-043: Client secret encrypted at rest
- **Category**: Security
- **Standard**: OWASP Cryptographic Failures
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. IdP configured with client_secret
- **Input**: Inspect the `tenant_identity_providers.client_secret_encrypted` column
- **Expected Output**:
  - `client_secret_encrypted` is not the plaintext secret
  - Decryption requires the master encryption key (AES-256-GCM)
  - Raw `client_secret` is never stored in the database

### TC-OIDC-FED-044: PKCE verifier protects code exchange
- **Category**: Security
- **Standard**: RFC 7636, Section 1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authorization flow initiated with PKCE
- **Input**: Attacker intercepts the authorization code but does not have the PKCE verifier
- **Expected Output**:
  - Code exchange fails at the external IdP because `code_verifier` does not match `code_challenge`
  - Attacker cannot obtain tokens without the verifier
  - PKCE verifier is stored server-side in the session (not exposed to the client)

### TC-OIDC-FED-045: Cross-tenant IdP access prevented
- **Category**: Security
- **Standard**: Xavyo Multi-Tenancy Architecture
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. IdP belongs to tenant A
- **Input**:
  ```
  GET /auth/federation/authorize?idp_id={tenant_A_idp_uuid}
  X-Tenant-ID: {tenant_B_uuid}
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  Body: { "error": "idp_not_found", "message": "Identity provider {id} not found" }
  ```
- **Rationale**: `find_by_id_and_tenant` ensures IdP is only accessible within its tenant

### TC-OIDC-FED-046: Discovery endpoint uses HTTPS with no redirect following
- **Category**: Security
- **Standard**: SSRF Prevention
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. IdP configured with an HTTPS issuer URL
- **Input**: Internal behavior when `DiscoveryService::discover()` fetches metadata
- **Expected Output**:
  - HTTP client created with `redirect(Policy::none())` (no redirect following)
  - Prevents SSRF via redirect chains to internal networks
  - Only HTTPS issuer URLs are accepted in production

### TC-OIDC-FED-047: Provisioning rejects unverified email from IdP
- **Category**: Security
- **Standard**: OpenID Connect Core 1.0, Section 5.1 / Account takeover prevention
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. IdP ID token has `email_verified: false`
- **Input**: Callback processing with unverified email
- **Expected Output**:
  - Provisioning should reject or flag the user (implementation may vary)
  - At minimum, the user's `email_verified` should reflect the IdP's claim
  - Must not allow account linking to an existing verified user via an unverified email

### TC-OIDC-FED-048: Open redirect prevention on callback redirect_uri
- **Category**: Security
- **Standard**: OWASP Open Redirect
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Attacker sets `redirect_uri` to an external malicious site
- **Input**:
  ```
  GET /auth/federation/authorize?idp_id={uuid}&redirect_uri=https://evil.example.com/steal-token
  X-Tenant-ID: {tenant_uuid}
  ```
- **Expected Output**:
  - Implementation should validate that `redirect_uri` is a trusted/registered URL
  - Known: only relative paths should be allowed (sanitized via `sanitize_redirect_uri`)
  - External URLs should be rejected or restricted to registered callback domains

### TC-OIDC-FED-049: ID token signature verification (JWKS-based)
- **Category**: Security
- **Standard**: OpenID Connect Core 1.0, Section 3.1.3.7 (items 6-7)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. `TokenVerifierService` is wired into the callback flow
- **Input**: ID token from external IdP
- **Expected Output**:
  - Token signature verified using the IdP's JWKS (fetched from `jwks_uri`)
  - `kid` from the token header is matched against the IdP's JWKS keys
  - Tokens with invalid/forged signatures are rejected
  - Tokens signed with unknown keys (not in JWKS) are rejected with `JwksKeyNotFound`

---

## Cross-Reference Matrix

| Test Case | Standard Section | Category | Endpoint |
|-----------|-----------------|----------|----------|
| FED-001 | Core 1.0 S2 | Nominal | POST /auth/federation/discover |
| FED-002 | HRD | Nominal | POST /auth/federation/discover |
| FED-003 | Core 1.0 S3.1.2 | Nominal | GET /auth/federation/authorize |
| FED-004 | RFC 7636 S4.2 | Nominal | GET /auth/federation/authorize |
| FED-005 | Core 1.0 S3.1.2.1 | Nominal | GET /auth/federation/authorize |
| FED-006 | Core 1.0 S3.1.3 | Nominal | GET /auth/federation/callback |
| FED-007 | Core 1.0 S3.1.3 | Nominal | GET /auth/federation/callback |
| FED-008 | Core 1.0 S3.1.3.1 | Nominal | GET /auth/federation/callback |
| FED-009 | Core 1.0 S3.1.3.5 | Nominal | GET /auth/federation/callback |
| FED-010 | Implementation | Nominal | GET /auth/federation/callback |
| FED-011 | OAuth 2.0 | Nominal | GET /auth/federation/callback |
| FED-012 | Operational | Nominal | POST /auth/federation/logout |
| FED-020 | Security | Edge | GET /auth/federation/callback |
| FED-021 | RFC 6749 S10.12 | Edge | GET /auth/federation/callback |
| FED-022 | RFC 6749 S4.1.2.1 | Edge | GET /auth/federation/callback |
| FED-023 | RFC 6749 S4.1.2 | Edge | GET /auth/federation/callback |
| FED-024 | Operational | Edge | GET /auth/federation/authorize |
| FED-025 | Operational | Edge | GET /auth/federation/authorize |
| FED-026 | Discovery 1.0 | Edge | GET /auth/federation/authorize |
| FED-027 | Core 1.0 S3.1.3.4 | Edge | GET /auth/federation/callback |
| FED-028 | Core 1.0 S3.1.3.5 | Edge | GET /auth/federation/callback |
| FED-029 | RFC 5322 | Edge | POST /auth/federation/discover |
| FED-030 | Implementation (JIT) | Edge | GET /auth/federation/callback |
| FED-031 | Core 1.0 S5.1 | Edge | GET /auth/federation/callback |
| FED-032 | HRD | Edge | POST /auth/federation/discover |
| FED-033 | RFC 6749 S3.1.2 | Edge | GET /auth/federation/authorize |
| FED-034 | Core 1.0 S5.1 | Edge | GET /auth/federation/callback |
| FED-040 | RFC 6749 S10.12 | Security | GET /auth/federation/callback |
| FED-041 | Core 1.0 S3.1.3.7 | Security | GET /auth/federation/callback |
| FED-042 | Best practice | Security | GET /auth/federation/callback |
| FED-043 | OWASP Crypto | Security | Configuration |
| FED-044 | RFC 7636 S1 | Security | GET /auth/federation/callback |
| FED-045 | Multi-Tenancy | Security | GET /auth/federation/authorize |
| FED-046 | SSRF Prevention | Security | Discovery |
| FED-047 | Core 1.0 S5.1 | Security | GET /auth/federation/callback |
| FED-048 | OWASP Open Redirect | Security | GET /auth/federation/authorize |
| FED-049 | Core 1.0 S3.1.3.7 | Security | GET /auth/federation/callback |

---

## Federation Flow Sequence (Reference)

```
User                    Xavyo (RP)                     External IdP
 |                         |                                |
 |--POST /discover-------->|                                |
 |<--{federated, idp_id}---|                                |
 |                         |                                |
 |--GET /authorize-------->|                                |
 |   ?idp_id={uuid}       |--Discover OIDC endpoints------>|
 |                         |<--.well-known/openid-config----|
 |                         |                                |
 |                         |  Create session (state, nonce, |
 |                         |  PKCE verifier, redirect_uri)  |
 |                         |                                |
 |<--307 Redirect----------|                                |
 |   Location: {idp}/authorize?                             |
 |     response_type=code&                                  |
 |     client_id=...&                                       |
 |     state=...&nonce=...&                                 |
 |     code_challenge=...&                                  |
 |     code_challenge_method=S256                           |
 |                         |                                |
 |------User authenticates at IdP----->|                    |
 |<-----Redirect to callback-----------|                    |
 |   ?code={auth_code}&state={state}                        |
 |                         |                                |
 |--GET /callback--------->|                                |
 |   ?code=...&state=...   |--Lookup session by state       |
 |                         |--Validate session (< 10 min)   |
 |                         |--Verify state matches          |
 |                         |                                |
 |                         |--POST {idp}/token------------->|
 |                         |  grant_type=authorization_code  |
 |                         |  code={auth_code}               |
 |                         |  client_id, client_secret       |
 |                         |  redirect_uri, code_verifier    |
 |                         |<--{access_token, id_token}------|
 |                         |                                |
 |                         |--Decode & verify ID token       |
 |                         |--Verify nonce matches session   |
 |                         |--Provision or sync user (JIT)   |
 |                         |--Lookup user roles from DB      |
 |                         |--Issue Xavyo JWT                |
 |                         |--Mark session as used           |
 |                         |                                |
 |<--307 Redirect----------|                                |
 |   Location: {redirect_uri}                               |
 |   #access_token={xavyo_jwt}                              |
 |   &token_type=Bearer                                     |
 |   &expires_in=3600                                       |
```
