# Login Functional Tests

**API Endpoint**: `POST /auth/login`
**Authentication**: Public
**Required Headers**: `Content-Type: application/json`, `X-Tenant-ID: <uuid>`
**Applicable Standards**: NIST SP 800-63B, OWASP ASVS 2.2, ISO 27001 A.9.4.2

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `REGULAR_USER`, `USER_JWT`, `TEST_TENANT`
- **Special Setup**: User must have verified email before login tests

## Nominal Cases

### TC-AUTH-LOGIN-001: Successful login with valid credentials
- **Category**: Nominal
- **Standard**: NIST SP 800-63B AAL1
- **Preconditions**: Fixtures: `REGULAR_USER`, `TEST_TENANT`. User exists with verified email
- **Input**:
  ```json
  POST /auth/login
  X-Tenant-ID: 00000000-0000-0000-0000-000000000001
  { "email": "user@example.com", "password": "MyP@ssw0rd_2026" }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "access_token": "<jwt>",
    "refresh_token": "<opaque>",
    "token_type": "Bearer",
    "expires_in": 3600
  }
  ```
- **Side Effects**:
  - Session record created in `sessions` table
  - Audit log: `user.login.success`
  - `last_login_at` updated on user record

### TC-AUTH-LOGIN-002: Login returns tokens with correct claims
- **Category**: Nominal
- **Input**: Valid login
- **Expected Output**: JWT `access_token` contains:
  - `sub`: user_id (UUID)
  - `tid`: tenant_id (UUID)
  - `email`: user's email
  - `roles`: array of role names
  - `iat`: issued at (Unix timestamp)
  - `exp`: expiration (iat + expires_in)

### TC-AUTH-LOGIN-003: Login with case-insensitive email
- **Category**: Nominal
- **Preconditions**: Fixtures: `REGULAR_USER`, `TEST_TENANT`. User registered as `user@example.com`
- **Input**: `"email": "USER@Example.COM"`
- **Expected Output**: Status 200 (login succeeds)

### TC-AUTH-LOGIN-004: Login creates refresh token
- **Category**: Nominal
- **Input**: Valid login
- **Expected Output**: `refresh_token` is returned, stored in `sessions` table with expiry

### TC-AUTH-LOGIN-005: Login with tenant-scoped user
- **Category**: Nominal
- **Preconditions**: Fixtures: `REGULAR_USER`, `TEST_TENANT`. User belongs to specific tenant
- **Input**: Login with correct `X-Tenant-ID`
- **Expected Output**: JWT `tid` claim matches the tenant_id

---

## Edge Cases

### TC-AUTH-LOGIN-010: Wrong password
- **Category**: Edge Case
- **Standard**: NIST SP 800-63B
- **Input**: Valid email, wrong password
- **Expected Output**:
  ```
  Status: 401 Unauthorized
  Body: { "error": "Invalid credentials" }
  ```
- **Note**: Must NOT say "wrong password" — use generic error (anti-enumeration)

### TC-AUTH-LOGIN-011: Non-existent email
- **Category**: Edge Case
- **Standard**: NIST SP 800-63B (anti-enumeration)
- **Input**: `"email": "nobody@example.com"`
- **Expected Output**: Status 401 with SAME error message as wrong password

### TC-AUTH-LOGIN-012: Timing consistency for invalid user vs wrong password
- **Category**: Edge Case / Security
- **Standard**: OWASP ASVS 2.2.1
- **Input**: Compare response time of non-existent user vs wrong password
- **Expected Output**: Response times should be comparable (constant-time comparison)

### TC-AUTH-LOGIN-013: Unverified email login attempt
- **Category**: Edge Case
- **Preconditions**: Fixtures: `TEST_TENANT`. User signed up but email not verified
- **Input**: Valid credentials
- **Expected Output**: Status 401 or 403 with message about email verification required

### TC-AUTH-LOGIN-014: Disabled/suspended account login
- **Category**: Edge Case
- **Preconditions**: Fixtures: `TEST_TENANT`. User account is suspended
- **Input**: Valid credentials
- **Expected Output**: Status 401 (generic "Invalid credentials" — no account status leak)

### TC-AUTH-LOGIN-015: Deleted account login
- **Category**: Edge Case
- **Preconditions**: Fixtures: `TEST_TENANT`. User account soft-deleted
- **Input**: Valid credentials for deleted account
- **Expected Output**: Status 401

### TC-AUTH-LOGIN-016: Missing X-Tenant-ID header
- **Category**: Edge Case
- **Input**: Login request without `X-Tenant-ID`
- **Expected Output**: Status 400 or uses system tenant as default

### TC-AUTH-LOGIN-017: Invalid X-Tenant-ID (not a UUID)
- **Category**: Edge Case
- **Input**: `X-Tenant-ID: not-a-uuid`
- **Expected Output**: Status 400

### TC-AUTH-LOGIN-018: X-Tenant-ID for non-existent tenant
- **Category**: Edge Case
- **Input**: `X-Tenant-ID: 99999999-9999-9999-9999-999999999999`
- **Expected Output**: Status 401 (don't reveal tenant doesn't exist)

### TC-AUTH-LOGIN-019: Empty password
- **Category**: Edge Case
- **Input**: `"password": ""`
- **Expected Output**: Status 400

### TC-AUTH-LOGIN-020: Null email
- **Category**: Edge Case
- **Input**: `"email": null`
- **Expected Output**: Status 400

### TC-AUTH-LOGIN-021: Login with expired but existing credentials
- **Category**: Edge Case
- **Preconditions**: Fixtures: `REGULAR_USER`, `TEST_TENANT`. User's password_changed_at is older than password policy max_age
- **Input**: Correct credentials
- **Expected Output**: Status 401 or 403 with message to change password

### TC-AUTH-LOGIN-022: Very long password (10,000 chars)
- **Category**: Edge Case
- **Input**: Password with 10,000 characters
- **Expected Output**: Status 400 (DoS protection — max password length enforced before hashing)

---

## Security Cases

### TC-AUTH-LOGIN-030: Account lockout after failed attempts
- **Category**: Security
- **Standard**: NIST SP 800-63B, OWASP ASVS 2.2.1
- **Preconditions**: Fixtures: `REGULAR_USER`, `TEST_TENANT`. Clean login state
- **Input**: 5 consecutive failed login attempts
- **Expected Output**: 6th attempt returns 429 Too Many Requests
- **Verification**: Rate limit window is documented (e.g., 60 seconds)

### TC-AUTH-LOGIN-031: Lockout counter resets after successful login
- **Category**: Security
- **Input**: 4 failed attempts, then 1 successful login, then 1 failed
- **Expected Output**: The last failed attempt should NOT trigger lockout

### TC-AUTH-LOGIN-032: Lockout is per-user, not global
- **Category**: Security
- **Input**: 5 failed attempts for user A, then login attempt for user B
- **Expected Output**: User B's login is not affected by user A's lockout

### TC-AUTH-LOGIN-033: Brute force with credential stuffing
- **Category**: Security
- **Input**: Rapid login attempts with different email/password pairs from same IP
- **Expected Output**: IP-level rate limiting kicks in after threshold

### TC-AUTH-LOGIN-034: SQL injection in email
- **Category**: Security
- **Input**: `"email": "' OR 1=1 --"`
- **Expected Output**: Status 400 or 401, no SQL execution

### TC-AUTH-LOGIN-035: No password hash in error responses
- **Category**: Security
- **Input**: Any failed login
- **Expected Output**: Response contains no hash, salt, or internal user data

### TC-AUTH-LOGIN-036: Login audit log captures IP and user agent
- **Category**: Security
- **Standard**: SOC 2 CC6.1, ISO 27001 A.12.4
- **Input**: Login from known IP with specific User-Agent
- **Verification**: Audit log entry contains source IP and user agent string

### TC-AUTH-LOGIN-037: Concurrent session limit enforcement
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Tenant policy limits concurrent sessions to 3
- **Input**: Login 4 times (4 different sessions)
- **Expected Output**: 4th login either revokes oldest session or is rejected

### TC-AUTH-LOGIN-038: Cross-tenant login isolation
- **Category**: Security
- **Preconditions**: Fixtures: `REGULAR_USER`, `TEST_TENANT`. User in tenant A
- **Input**: Login with `X-Tenant-ID` of tenant B
- **Expected Output**: Status 401 (user not found in tenant B)

---

## Compliance Cases

### TC-AUTH-LOGIN-040: ISO 27001 A.9.4.2 — Secure log-on procedure
- **Category**: Compliance
- **Standard**: ISO 27001 A.9.4.2
- **Verification**:
  - No valid user ID or password displayed until log-on input complete
  - Error message does not indicate which part is incorrect
  - Failed attempts are logged
  - Successful login is logged with timestamp

### TC-AUTH-LOGIN-041: SOC 2 CC6.1 — Logical access security
- **Category**: Compliance
- **Standard**: SOC 2 CC6.1
- **Verification**:
  - Authentication uses encrypted channel (HTTPS)
  - Credentials validated against stored hashes
  - Session token returned upon successful auth
  - Failed login events audited

### TC-AUTH-LOGIN-042: NIST SP 800-63B — AAL1 requirements
- **Category**: Compliance
- **Standard**: NIST SP 800-63B Section 4.1.1
- **Verification**:
  - Single-factor authentication (password)
  - Passwords compared using approved hash (Argon2id)
  - Rate limiting present on authentication endpoint

### TC-AUTH-LOGIN-043: OWASP ASVS 2.2 — General authenticator requirements
- **Category**: Compliance
- **Standard**: OWASP ASVS v4.0 Section 2.2
- **Verification**:
  - Anti-automation controls (rate limiting)
  - Credential recovery does not reveal existence of account
  - Default credentials not present
  - Authentication decisions logged
