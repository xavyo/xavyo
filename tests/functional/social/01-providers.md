# Social Login Provider Functional Tests

**API Endpoints**:
- `GET /auth/social/available` (list available social providers)
- `GET /auth/social/:provider/authorize` (initiate OAuth flow)
- `GET /auth/social/:provider/callback` (handle OAuth callback)
- `POST /auth/social/apple/callback` (Apple form_post callback)
- `GET /auth/social/connections` (list linked accounts, authenticated)
- `GET /auth/social/link/:provider/authorize` (initiate account linking)
- `POST /auth/social/link/:provider` (complete account linking)
- `DELETE /auth/social/unlink/:provider` (unlink social account)
- Admin: `GET /admin/social-providers/` (list providers)
- Admin: `PUT /admin/social-providers/:provider` (configure provider)
- Admin: `DELETE /admin/social-providers/:provider` (disable provider)
**Authentication**: Public (authorize/callback), JWT (linking/admin)
**Applicable Standards**: OAuth 2.0 (RFC 6749), OpenID Connect Core 1.0, OWASP ASVS 2.5

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`, `SOCIAL_GOOGLE`
- **Special Setup**: Social provider (Google) must be configured and enabled for the test tenant; OAuth callback tests require valid state tokens

---

## Nominal Cases

### TC-SOCIAL-PROV-001: List available social login providers
- **Category**: Nominal
- **Preconditions**: Fixtures: `TEST_TENANT`, `SOCIAL_GOOGLE`. Tenant has Google and Microsoft configured and enabled
- **Input**: `GET /auth/social/available`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "providers": [
      { "name": "google", "enabled": true },
      { "name": "microsoft", "enabled": true }
    ]
  }
  ```

### TC-SOCIAL-PROV-002: Initiate Google OAuth flow
- **Category**: Nominal
- **Standard**: OAuth 2.0 (RFC 6749 Section 4.1)
- **Preconditions**: Fixtures: `TEST_TENANT`, `SOCIAL_GOOGLE`. Google provider configured for tenant
- **Input**: `GET /auth/social/google/authorize?tenant_id=<tid>`
- **Expected Output**:
  ```
  Status: 302 Found
  Location: https://accounts.google.com/o/oauth2/v2/auth?
    client_id=<google_client_id>&
    redirect_uri=<callback_url>&
    response_type=code&
    scope=openid+email+profile&
    state=<encrypted_state>&
    nonce=<nonce>
  ```
- **Verification**: State token contains tenant_id, nonce, timestamp

### TC-SOCIAL-PROV-003: Successful Google callback creates user
- **Category**: Nominal
- **Standard**: OpenID Connect Core 1.0 Section 3.1.3
- **Preconditions**: Fixtures: `TEST_TENANT`, `SOCIAL_GOOGLE`. Google provider configured, user does not exist
- **Input**: `GET /auth/social/google/callback?code=<auth_code>&state=<valid_state>`
- **Expected Output**: Redirect to frontend with tokens OR JSON response:
  ```
  {
    "access_token": "<jwt>",
    "refresh_token": "<token>",
    "user": { "id": "<uuid>", "email": "user@gmail.com", "display_name": "Google User" }
  }
  ```
- **Side Effects**:
  - User record created with `email_verified = true` (from Google)
  - Social connection record created (provider=google, provider_user_id=...)
  - Audit log: `social.login.google`

### TC-SOCIAL-PROV-004: Google callback logs in existing user
- **Category**: Nominal
- **Preconditions**: Fixtures: `TEST_TENANT`, `SOCIAL_GOOGLE`. User with matching email already exists and has Google connection
- **Input**: `GET /auth/social/google/callback?code=<auth_code>&state=<valid_state>`
- **Expected Output**: Tokens returned, no new user created
- **Verification**: Existing user record used (same user_id)

### TC-SOCIAL-PROV-005: Initiate Microsoft OAuth flow
- **Category**: Nominal
- **Standard**: OAuth 2.0, Microsoft Identity Platform
- **Preconditions**: Fixtures: `TEST_TENANT`. Microsoft provider configured for tenant.
- **Input**: `GET /auth/social/microsoft/authorize?tenant_id=<tid>`
- **Expected Output**: Status 302 redirect to `https://login.microsoftonline.com/.../authorize`

### TC-SOCIAL-PROV-006: Initiate GitHub OAuth flow
- **Category**: Nominal
- **Preconditions**: Fixtures: `TEST_TENANT`. GitHub provider configured for tenant.
- **Input**: `GET /auth/social/github/authorize?tenant_id=<tid>`
- **Expected Output**: Status 302 redirect to `https://github.com/login/oauth/authorize`

### TC-SOCIAL-PROV-007: Apple callback via form_post
- **Category**: Nominal
- **Standard**: Sign in with Apple (Apple uses POST for callback)
- **Preconditions**: Fixtures: `TEST_TENANT`. Apple provider configured for tenant.
- **Input**: `POST /auth/social/apple/callback` with form body: `code=<code>&state=<state>&id_token=<jwt>`
- **Expected Output**: Redirect to frontend with tokens
- **Verification**: Apple ID token validated (RS256 against Apple's JWKS)

### TC-SOCIAL-PROV-008: Link social account to existing user
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SOCIAL_GOOGLE`. Authenticated user without Google connection
- **Steps**:
  1. `GET /auth/social/link/google/authorize` (authenticated)
  2. Complete OAuth flow
  3. `POST /auth/social/link/google` with authorization code
- **Expected Output**: Status 200, Google account linked
- **Side Effects**: Social connection record created

### TC-SOCIAL-PROV-009: List linked social accounts
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SOCIAL_GOOGLE`. User has Google and GitHub linked
- **Input**: `GET /auth/social/connections` (authenticated)
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "connections": [
      { "provider": "google", "email": "user@gmail.com", "linked_at": "2026-01-01T..." },
      { "provider": "github", "email": "user@github.com", "linked_at": "2026-01-15T..." }
    ]
  }
  ```

### TC-SOCIAL-PROV-010: Unlink social account
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SOCIAL_GOOGLE`. User has Google linked and a password set (alternative login method)
- **Input**: `DELETE /auth/social/unlink/google` (authenticated)
- **Expected Output**: Status 200, Google connection removed
- **Side Effects**: Social connection deleted, audit log: `social.unlinked.google`

---

## Edge Cases

### TC-SOCIAL-PROV-011: Callback with invalid state token
- **Category**: Edge Case / Security
- **Preconditions**: Fixtures: `TEST_TENANT`, `SOCIAL_GOOGLE`.
- **Input**: `GET /auth/social/google/callback?code=<code>&state=tampered_state`
- **Expected Output**: Status 400 "Invalid OAuth state"
- **Verification**: No user created, no session issued

### TC-SOCIAL-PROV-012: Callback with expired state token
- **Category**: Edge Case
- **Preconditions**: Fixtures: `TEST_TENANT`, `SOCIAL_GOOGLE`.
- **Input**: State token older than TTL (e.g., 10 minutes)
- **Expected Output**: Status 400 "OAuth state expired"

### TC-SOCIAL-PROV-013: Callback with authorization error from provider
- **Category**: Edge Case
- **Preconditions**: Fixtures: `TEST_TENANT`, `SOCIAL_GOOGLE`.
- **Input**: `GET /auth/social/google/callback?error=access_denied&state=<state>`
- **Expected Output**: Redirect to frontend with error parameter OR Status 400

### TC-SOCIAL-PROV-014: Login with disabled provider
- **Category**: Edge Case
- **Preconditions**: Fixtures: `TEST_TENANT`, `SOCIAL_GOOGLE`. Google provider is disabled for this tenant
- **Input**: `GET /auth/social/google/authorize?tenant_id=<tid>`
- **Expected Output**: Status 404 "Provider not configured" OR Status 400

### TC-SOCIAL-PROV-015: Login with unconfigured provider
- **Category**: Edge Case
- **Preconditions**: Fixtures: `TEST_TENANT`.
- **Input**: `GET /auth/social/twitter/authorize?tenant_id=<tid>` (Twitter not supported)
- **Expected Output**: Status 400 "Unsupported provider"

### TC-SOCIAL-PROV-016: Callback with email already linked to another user
- **Category**: Edge Case
- **Preconditions**: Fixtures: `TEST_TENANT`, `SOCIAL_GOOGLE`. User A exists with email user@example.com
- **Input**: Google callback returns email user@example.com for a different Google account
- **Expected Output**: Status 409 "Email already associated with another account" OR auto-link

### TC-SOCIAL-PROV-017: Link provider already linked
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SOCIAL_GOOGLE`. User already has Google linked
- **Input**: Attempt to link Google again
- **Expected Output**: Status 409 "Provider already linked"

### TC-SOCIAL-PROV-018: Unlink last authentication method
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SOCIAL_GOOGLE`. User has only Google linked, no password set
- **Input**: `DELETE /auth/social/unlink/google`
- **Expected Output**: Status 400 "Cannot unlink last authentication method"

### TC-SOCIAL-PROV-019: Provider returns email_verified=false
- **Category**: Edge Case
- **Standard**: OpenID Connect Core 1.0
- **Preconditions**: Fixtures: `TEST_TENANT`, `SOCIAL_GOOGLE`.
- **Input**: Provider callback returns user profile with `email_verified: false`
- **Expected Output**: User created with `email_verified = false`; verification email sent

### TC-SOCIAL-PROV-020: Provider returns no email (GitHub private email)
- **Category**: Edge Case
- **Preconditions**: Fixtures: `TEST_TENANT`.
- **Input**: GitHub callback where user has private email
- **Expected Output**: User created with null email OR error requiring email permission

### TC-SOCIAL-PROV-021: Callback with missing code parameter
- **Category**: Edge Case
- **Preconditions**: Fixtures: `TEST_TENANT`, `SOCIAL_GOOGLE`.
- **Input**: `GET /auth/social/google/callback?state=<valid_state>` (no code)
- **Expected Output**: Status 400 "Missing authorization code"

---

## Security Cases

### TC-SOCIAL-PROV-022: CSRF protection via state parameter
- **Category**: Security
- **Standard**: OAuth 2.0 (RFC 6749 Section 10.12)
- **Preconditions**: Fixtures: `TEST_TENANT`, `SOCIAL_GOOGLE`.
- **Verification**: Every authorize request generates a unique state token; callback validates it matches

### TC-SOCIAL-PROV-023: Open redirect prevention on callback
- **Category**: Security
- **Standard**: OWASP ASVS 5.1.5
- **Preconditions**: Fixtures: `TEST_TENANT`, `SOCIAL_GOOGLE`.
- **Verification**: Callback redirect_uri is validated against registered URIs only. Arbitrary URLs are rejected.

### TC-SOCIAL-PROV-024: Social login tokens are not leaked in URL
- **Category**: Security
- **Preconditions**: Fixtures: `TEST_TENANT`, `SOCIAL_GOOGLE`.
- **Verification**: Access tokens are NOT placed in URL fragments or query parameters of redirects to frontend. Use POST or secure cookies.

### TC-SOCIAL-PROV-025: Cross-tenant social login isolation
- **Category**: Security
- **Preconditions**: Fixtures: `TEST_TENANT`, `SOCIAL_GOOGLE`. Google configured for tenant A only
- **Input**: Attempt social login with tenant B's context
- **Expected Output**: Status 404 "Provider not configured for this tenant"
- **Verification**: Tenant B cannot use tenant A's social provider configuration
