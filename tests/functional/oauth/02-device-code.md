# OAuth 2.0 Device Code Flow - Functional Test Suite

**Component**: `xavyo-api-oauth` (device authorization endpoint, token polling)
**Standards**: RFC 8628 (Device Authorization Grant), RFC 6749 Section 5.2
**API Endpoints**:
- `POST /oauth/device/code` -- Request device authorization
- `POST /oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code` -- Poll for tokens
- `GET /device` -- Verification page (HTML)
- `POST /device/verify` -- Verify user code
- `POST /device/authorize` -- Approve/deny authorization
- `POST /device/login` -- Authenticate during device flow (F112)
- `POST /device/login/mfa` -- MFA during device flow (F112)
- `GET /device/confirm/:token` -- Email confirmation (F117 Storm-2372)
- `POST /device/resend-confirmation` -- Resend confirmation (F117)

**Tenant Context**: Requires `X-Tenant-ID` header (UUID)

---

## Prerequisites

All tests assume:
- A valid tenant exists with ID `{TENANT_ID}` (UUID)
- A user exists with `{USER_ID}`, email `user@example.com`, verified, active
- A session cookie for the user is available (for authorization step)

### Fixture: Device Code Client

Created via `POST /admin/oauth/clients`:
```json
{
  "name": "CLI Application",
  "client_type": "public",
  "redirect_uris": [],
  "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"],
  "scopes": ["openid", "profile", "read", "write"]
}
```

### Fixture: Confidential Device Code Client

```json
{
  "name": "IoT Device",
  "client_type": "confidential",
  "redirect_uris": [],
  "grant_types": ["urn:ietf:params:oauth:grant-type:device_code", "client_credentials"],
  "scopes": ["read", "write"]
}
```

---

## Nominal Tests (TC-OAUTH-DC-001 through TC-OAUTH-DC-015)

### TC-OAUTH-DC-001: Request device authorization code
- **Category**: Nominal
- **Standard**: RFC 8628 Section 3.1
- **Preconditions**: Public client with `device_code` grant type exists
- **Input**:
  ```
  POST /oauth/device/code
  Content-Type: application/x-www-form-urlencoded
  X-Tenant-ID: {TENANT_ID}

  client_id={client_id}
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Body:
    ```json
    {
      "device_code": "<opaque-string>",
      "user_code": "<XXXX-XXXX>",
      "verification_uri": "https://{issuer}/device",
      "verification_uri_complete": "https://{issuer}/device?code=<XXXX-XXXX>",
      "expires_in": 600,
      "interval": 5
    }
    ```

### TC-OAUTH-DC-002: Request device authorization with scopes
- **Category**: Nominal
- **Standard**: RFC 8628 Section 3.1 (scope parameter)
- **Preconditions**: Client has scopes `["openid", "profile", "read", "write"]`
- **Input**:
  ```
  POST /oauth/device/code
  Content-Type: application/x-www-form-urlencoded
  X-Tenant-ID: {TENANT_ID}

  client_id={client_id}&scope=openid+profile
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Response includes all RFC 8628 required fields
  - Scopes are stored with the device code for later token issuance

### TC-OAUTH-DC-003: User code format is XXXX-XXXX
- **Category**: Nominal
- **Standard**: RFC 8628 Section 6.1 (user-friendly codes)
- **Preconditions**: Device authorization issued
- **Input**: Inspect `user_code` from TC-OAUTH-DC-001 response
- **Expected Output**:
  - `user_code` matches pattern `[A-Z0-9]{4}-[A-Z0-9]{4}` (8 characters + dash)
  - No ambiguous characters (0/O, 1/I/L) per RFC 8628 Section 6.1 recommendation

### TC-OAUTH-DC-004: Poll with pending authorization (authorization_pending)
- **Category**: Nominal
- **Standard**: RFC 8628 Section 3.5
- **Preconditions**: Device code issued, user has NOT yet authorized
- **Input**:
  ```
  POST /oauth/token
  Content-Type: application/x-www-form-urlencoded
  X-Tenant-ID: {TENANT_ID}

  grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={device_code}&client_id={client_id}
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body:
    ```json
    {
      "error": "authorization_pending",
      "error_description": "The authorization request is still pending"
    }
    ```

### TC-OAUTH-DC-005: Poll too frequently (slow_down)
- **Category**: Nominal
- **Standard**: RFC 8628 Section 3.5
- **Preconditions**: Device code issued with `interval=5`, client polls faster
- **Input**: Send two poll requests within 5 seconds
- **Expected Output** (second request):
  - Status: `400 Bad Request`
  - Body:
    ```json
    {
      "error": "slow_down",
      "error_description": "Polling too frequently, slow down. New interval: <N> seconds"
    }
    ```
  - New interval is increased (e.g., previous + 5 seconds)

### TC-OAUTH-DC-006: User approves device -- token issued
- **Category**: Nominal
- **Standard**: RFC 8628 Section 3.5 (successful response)
- **Preconditions**: Device code issued, user approves via `/device/authorize`
- **Input**:
  1. User approves: `POST /device/authorize` with `action=approve&user_code={user_code}`
  2. Client polls: `POST /oauth/token` with `device_code={device_code}`
- **Expected Output**:
  - Status: `200 OK`
  - Body:
    ```json
    {
      "access_token": "<JWT>",
      "token_type": "Bearer",
      "expires_in": 900,
      "refresh_token": "<opaque>",
      "scope": "openid profile"
    }
    ```

### TC-OAUTH-DC-007: User denies device authorization
- **Category**: Nominal
- **Standard**: RFC 8628 Section 3.5 (access_denied)
- **Preconditions**: Device code issued, user denies
- **Input**:
  1. User denies: `POST /device/authorize` with `action=deny&user_code={user_code}`
  2. Client polls: `POST /oauth/token` with `device_code={device_code}`
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body:
    ```json
    {
      "error": "access_denied",
      "error_description": "User denied the authorization request"
    }
    ```

### TC-OAUTH-DC-008: Device code expires
- **Category**: Nominal
- **Standard**: RFC 8628 Section 3.5 (expired_token)
- **Preconditions**: Device code issued with `expires_in=600`, wait until expired
- **Input**: Poll after expiration:
  ```
  grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={expired_device_code}&client_id={client_id}
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body:
    ```json
    {
      "error": "expired_token",
      "error_description": "Device code has expired"
    }
    ```

### TC-OAUTH-DC-009: Verification page renders correctly
- **Category**: Nominal
- **Standard**: RFC 8628 Section 3.3 (end-user verification)
- **Preconditions**: Device code issued
- **Input**:
  ```
  GET /device
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Content-Type: `text/html`
  - HTML contains input field for user code
  - HTML contains CSRF token in hidden field
  - CSRF cookie is set in response headers

### TC-OAUTH-DC-010: Verification page with pre-filled code
- **Category**: Nominal
- **Standard**: RFC 8628 Section 3.3.1 (verification_uri_complete)
- **Preconditions**: Device code issued with `verification_uri_complete`
- **Input**:
  ```
  GET /device?code=ABCD-1234
  ```
- **Expected Output**:
  - Status: `200 OK`
  - HTML input field pre-filled with `ABCD-1234`

### TC-OAUTH-DC-011: Verify valid user code
- **Category**: Nominal
- **Standard**: RFC 8628 Section 3.3
- **Preconditions**: Device code issued with valid user_code, user authenticated
- **Input**:
  ```
  POST /device/verify
  Content-Type: application/x-www-form-urlencoded
  Cookie: xavyo_session={session_token}; csrf_token={csrf}
  X-Tenant-ID: {TENANT_ID}

  user_code={user_code}&csrf_token={csrf}
  ```
- **Expected Output**:
  - Status: `200 OK`
  - HTML shows approval page with client name, scopes, approve/deny buttons

### TC-OAUTH-DC-012: Device login flow (F112) -- unauthenticated user
- **Category**: Nominal
- **Standard**: F112 (platform-specific login integration)
- **Preconditions**: Device code issued, user NOT authenticated
- **Input**:
  ```
  POST /device/verify
  Content-Type: application/x-www-form-urlencoded
  X-Tenant-ID: {TENANT_ID}

  user_code={user_code}&csrf_token={csrf}
  ```
- **Expected Output**:
  - Status: `200 OK`
  - HTML shows login form with email/password fields
  - Form preserves `user_code` context

### TC-OAUTH-DC-013: Device login with credentials (F112)
- **Category**: Nominal
- **Standard**: F112 (device flow login)
- **Preconditions**: Device code issued, user not yet authenticated
- **Input**:
  ```
  POST /device/login
  Content-Type: application/x-www-form-urlencoded
  X-Tenant-ID: {TENANT_ID}

  email=user@example.com&password=MyP@ssw0rd_2026&user_code={user_code}&csrf_token={csrf}
  ```
- **Expected Output**:
  - Status: `200 OK` (redirect to approval page)
  - Session cookie set
  - If MFA enabled: shows MFA page instead

### TC-OAUTH-DC-014: Device MFA verification (F112)
- **Category**: Nominal
- **Standard**: F112 (device flow MFA)
- **Preconditions**: Login returned `mfa_required=true` with `mfa_session_id`
- **Input**:
  ```
  POST /device/login/mfa
  Content-Type: application/x-www-form-urlencoded
  X-Tenant-ID: {TENANT_ID}

  mfa_session_id={mfa_session_id}&code=123456&user_code={user_code}&csrf_token={csrf}
  ```
- **Expected Output**:
  - Status: `200 OK`
  - Redirect to device approval page

### TC-OAUTH-DC-015: Token response includes refresh_token for device flow
- **Category**: Nominal
- **Standard**: RFC 8628 Section 3.5 (token response)
- **Preconditions**: User approved device code
- **Input**: Poll for tokens after approval
- **Expected Output**:
  - Status: `200 OK`
  - `refresh_token` IS present (unlike client_credentials)
  - `access_token` is a valid JWT with `tid`, `sub` (user_id), `jti`

---

## Edge Case Tests (TC-OAUTH-DC-016 through TC-OAUTH-DC-030)

### TC-OAUTH-DC-016: Invalid user code on verify
- **Category**: Edge Case
- **Standard**: RFC 8628 Section 3.3
- **Preconditions**: No matching device code
- **Input**:
  ```
  POST /device/verify
  user_code=ZZZZ-ZZZZ&csrf_token={csrf}
  ```
- **Expected Output**:
  - Status: `200 OK` (HTML page)
  - HTML shows error: "Invalid or expired code"

### TC-OAUTH-DC-017: Poll with non-existent device_code
- **Category**: Edge Case
- **Standard**: RFC 8628 Section 3.5
- **Preconditions**: None
- **Input**:
  ```
  grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=non-existent-code&client_id={client_id}
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "expired_token" }` or `{ "error": "invalid_grant" }`

### TC-OAUTH-DC-018: Poll with mismatched client_id
- **Category**: Edge Case
- **Standard**: RFC 8628 Section 3.4 (client_id binding)
- **Preconditions**: Device code issued for `client_A`, polling with `client_B`
- **Input**:
  ```
  grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code={device_code}&client_id={client_B_id}
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: error indicating device code not found for this client

### TC-OAUTH-DC-019: Missing device_code in token request
- **Category**: Edge Case
- **Standard**: RFC 8628 Section 3.4
- **Preconditions**: Valid client_id
- **Input**:
  ```
  grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id={client_id}
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request", "error_description": "device_code is required" }`

### TC-OAUTH-DC-020: Missing client_id in device authorization request
- **Category**: Edge Case
- **Standard**: RFC 8628 Section 3.1 (REQUIRED)
- **Preconditions**: None
- **Input**:
  ```
  POST /oauth/device/code
  Content-Type: application/x-www-form-urlencoded
  X-Tenant-ID: {TENANT_ID}

  (empty body)
  ```
- **Expected Output**:
  - Status: `400 Bad Request`

### TC-OAUTH-DC-021: Client without device_code grant type
- **Category**: Edge Case
- **Standard**: RFC 8628 Section 3.1
- **Preconditions**: Confidential client with `grant_types: ["client_credentials"]`
- **Input**:
  ```
  POST /oauth/device/code
  client_id={non_device_client_id}
  ```
- **Expected Output**:
  - Status: `401 Unauthorized`
  - Body: `{ "error": "unauthorized_client", "error_description": "Client is not authorized for device_code grant" }`

### TC-OAUTH-DC-022: Invalid scope in device authorization
- **Category**: Edge Case
- **Standard**: RFC 8628 Section 3.1 (scope validation)
- **Preconditions**: Client has scopes `["read", "write"]`
- **Input**:
  ```
  POST /oauth/device/code
  client_id={client_id}&scope=admin
  ```
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_scope", "error_description": "Scope 'admin' is not allowed for this client" }`

### TC-OAUTH-DC-023: Poll after code already exchanged (replay)
- **Category**: Edge Case
- **Standard**: RFC 8628 Section 3.5
- **Preconditions**: Device code was already successfully exchanged for tokens
- **Input**: Poll again with same device_code
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_grant" }` or `{ "error": "expired_token" }`

### TC-OAUTH-DC-024: Missing X-Tenant-ID on device authorization
- **Category**: Edge Case
- **Standard**: Platform-specific (multi-tenant)
- **Preconditions**: Valid client_id
- **Input**:
  ```
  POST /oauth/device/code
  client_id={client_id}
  ```
  (no X-Tenant-ID header)
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_request", "error_description": "X-Tenant-ID header is required" }`

### TC-OAUTH-DC-025: CSRF validation failure on verify
- **Category**: Edge Case
- **Standard**: OWASP CSRF Prevention
- **Preconditions**: Device code issued
- **Input**:
  ```
  POST /device/verify
  user_code={user_code}&csrf_token=wrong-token
  ```
  (cookie has different CSRF token)
- **Expected Output**:
  - Status: `200 OK` (HTML)
  - HTML shows error: "Session expired. Please try again."

### TC-OAUTH-DC-026: CSRF validation failure on authorize
- **Category**: Edge Case
- **Standard**: OWASP CSRF Prevention
- **Preconditions**: User verified code, CSRF token mismatch on approve
- **Input**:
  ```
  POST /device/authorize
  user_code={user_code}&action=approve&csrf_token=wrong-token
  ```
- **Expected Output**:
  - Status: `200 OK` (HTML)
  - HTML shows error: "Session expired"
  - Authorization NOT granted

### TC-OAUTH-DC-027: Invalid action value on authorize
- **Category**: Edge Case
- **Standard**: Platform-specific
- **Preconditions**: Valid user code and CSRF
- **Input**:
  ```
  POST /device/authorize
  user_code={user_code}&action=maybe&csrf_token={csrf}
  ```
- **Expected Output**:
  - Status: `200 OK` (HTML)
  - HTML shows error: "Invalid action"

### TC-OAUTH-DC-028: Device login with invalid credentials (F112)
- **Category**: Edge Case
- **Standard**: F112 (device flow login)
- **Preconditions**: Device code issued
- **Input**:
  ```
  POST /device/login
  email=user@example.com&password=wrong-password&user_code={user_code}
  ```
- **Expected Output**:
  - Status: `200 OK` (HTML)
  - HTML shows login form with error message
  - Generic error: "Invalid email or password" (no user enumeration)

### TC-OAUTH-DC-029: Device login with locked account (F112)
- **Category**: Edge Case
- **Standard**: F112 (device flow login)
- **Preconditions**: User account is locked
- **Input**:
  ```
  POST /device/login
  email=locked@example.com&password=anything&user_code={user_code}
  ```
- **Expected Output**:
  - Status: `200 OK` (HTML)
  - HTML shows error about locked account with unlock time

### TC-OAUTH-DC-030: Concurrent device codes for same client
- **Category**: Edge Case
- **Standard**: RFC 8628 Section 3.1
- **Preconditions**: Same client requests multiple device codes
- **Input**: Issue 3 device codes for the same `client_id`
- **Expected Output**:
  - All 3 requests succeed with `200 OK`
  - Each returns a unique `device_code` and `user_code`
  - Each can be independently approved/denied

---

## Security Tests (TC-OAUTH-DC-031 through TC-OAUTH-DC-040)

### TC-OAUTH-DC-031: Device code brute-force resistance
- **Category**: Security
- **Standard**: RFC 8628 Section 5.1 (user code entropy)
- **Preconditions**: Device code issued
- **Input**: Attempt to guess `user_code` with 1000 random codes via `POST /device/verify`
- **Expected Output**:
  - All attempts fail (statistically negligible collision probability)
  - User code space is large enough (8 characters from limited alphabet)
  - Rate limiting or lockout after excessive attempts

### TC-OAUTH-DC-032: Device code not leaked in verification_uri
- **Category**: Security
- **Standard**: RFC 8628 Section 5.4
- **Preconditions**: Device authorization response
- **Input**: Inspect `verification_uri` and `verification_uri_complete`
- **Expected Output**:
  - `verification_uri` does NOT contain `device_code`
  - `verification_uri_complete` contains only `user_code`, NOT `device_code`
  - `device_code` is only returned to the requesting client

### TC-OAUTH-DC-033: Cross-tenant device code isolation
- **Category**: Security
- **Standard**: Platform-specific (multi-tenancy)
- **Preconditions**: Device code issued in `TENANT_A`
- **Input**: Attempt to verify user_code via `POST /device/verify` with `X-Tenant-ID: {TENANT_B}`
- **Expected Output**:
  - HTML shows "Invalid or expired code"
  - Device code from `TENANT_A` is not accessible in `TENANT_B`

### TC-OAUTH-DC-034: Authorize without authentication
- **Category**: Security
- **Standard**: RFC 8628 Section 3.3 (user identification)
- **Preconditions**: Valid user_code verified, but no session cookie
- **Input**:
  ```
  POST /device/authorize
  user_code={user_code}&action=approve&csrf_token={csrf}
  ```
  (no session cookie)
- **Expected Output**:
  - HTML shows "Authentication Required" page
  - Authorization NOT granted

### TC-OAUTH-DC-035: Storm-2372 remediation -- IP mismatch warning (F117)
- **Category**: Security
- **Standard**: F117 (Storm-2372 mitigation)
- **Preconditions**: Device code requested from IP `10.0.0.1`, user approving from IP `192.168.1.1`
- **Input**: User verifies code and sees approval page
- **Expected Output**:
  - Approval page shows info banner about different origin IP
  - Displays origin IP address and country
  - Does not block but informs the user

### TC-OAUTH-DC-036: Storm-2372 remediation -- stale code warning (F117)
- **Category**: Security
- **Standard**: F117 (Storm-2372 mitigation)
- **Preconditions**: Device code older than 5 minutes
- **Input**: User verifies the stale code
- **Expected Output**:
  - Approval page shows warning banner about code age
  - Warning mentions the code is "older than 5 minutes"
  - User can still approve or deny

### TC-OAUTH-DC-037: Storm-2372 remediation -- unknown application warning (F117)
- **Category**: Security
- **Standard**: F117 (Storm-2372 mitigation)
- **Preconditions**: Client has no `client_name` in database (or name is null)
- **Input**: User verifies user code for unknown application
- **Expected Output**:
  - Approval page shows warning: "Unknown Application"
  - Displays client_id as fallback identifier
  - Warns user to only approve if they initiated the request

### TC-OAUTH-DC-038: Device code single-use enforcement
- **Category**: Security
- **Standard**: RFC 8628 Section 5.3 (one-time use)
- **Preconditions**: Device code already exchanged for tokens
- **Input**: Attempt to exchange the same device_code again
- **Expected Output**:
  - Status: `400 Bad Request`
  - Body: `{ "error": "invalid_grant" }` or `{ "error": "expired_token" }`
  - Previously issued tokens remain valid

### TC-OAUTH-DC-039: XSS protection in HTML pages
- **Category**: Security
- **Standard**: OWASP XSS Prevention
- **Preconditions**: Device verification flow
- **Input**:
  ```
  GET /device?code=<script>alert('xss')</script>
  ```
- **Expected Output**:
  - Status: `200 OK`
  - HTML output has the script tag escaped: `&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;`
  - No executable JavaScript in rendered HTML

### TC-OAUTH-DC-040: Email confirmation token validation (F117)
- **Category**: Security
- **Standard**: F117 (Storm-2372 email confirmation)
- **Preconditions**: Confirmation email sent with token
- **Input**:
  ```
  GET /device/confirm/{valid_token}
  ```
- **Expected Output** (valid token):
  - Status: `200 OK`
  - HTML shows "Email Confirmed" success page
- **Input** (expired token):
  ```
  GET /device/confirm/{expired_token}
  ```
- **Expected Output** (expired):
  - Status: `200 OK`
  - HTML shows "Confirmation Failed" with "link has expired" message
- **Input** (invalid token):
  ```
  GET /device/confirm/totally-fake-token
  ```
- **Expected Output** (invalid):
  - Status: `200 OK`
  - HTML shows "Confirmation Failed" with "invalid or already used" message
