# User Profile Self-Service Functional Tests

**API Endpoints**:
- `GET /me/profile` -- Get current user's profile
- `PUT /me/profile` -- Update current user's profile
- `PUT /me/password` -- Change own password
- `POST /me/email/change` -- Initiate email change
- `POST /me/email/verify` -- Verify email change with token

**Authentication**: JWT Bearer token (any authenticated user, no admin role required)
**Required Headers**: `Content-Type: application/json`, `Authorization: Bearer <jwt>`
**Applicable Standards**: NIST SP 800-63B (Authentication), ISO 27001 Annex A.9.4 (System and Application Access Control), SOC 2 CC6.1, GDPR Article 16 (Right to Rectification)

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `USER_JWT`, `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: Profile tests use self-service endpoints (`/me/*`) that operate on the authenticated user; password and email change tests require known credentials

---

## Nominal Cases

### TC-USER-PROFILE-001: Get own profile
- **Category**: Nominal
- **Standard**: ISO 27001 A.9.4.1
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated user `U1` in tenant `T1`
- **Input**:
  ```
  GET /me/profile
  Authorization: Bearer <user-jwt-U1>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "id": "<U1-uuid>",
    "email": "user@example.com",
    "display_name": "John Doe",
    "first_name": "John",
    "last_name": "Doe",
    "avatar_url": "https://example.com/avatar.png",
    "email_verified": true,
    "created_at": "<iso8601>"
  }
  ```

### TC-USER-PROFILE-002: Get profile with minimal data
- **Category**: Nominal
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. User `U1` has no display_name, first_name, last_name, or avatar_url set
- **Input**: `GET /me/profile`
- **Expected Output**: Status 200; optional fields are `null`

### TC-USER-PROFILE-003: Update display name
- **Category**: Nominal
- **Standard**: GDPR Article 16 (Right to Rectification)
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user
- **Input**:
  ```json
  PUT /me/profile
  {
    "display_name": "Johnny D"
  }
  ```
- **Expected Output**: Status 200; `"display_name": "Johnny D"`

### TC-USER-PROFILE-004: Update first and last name
- **Category**: Nominal
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user
- **Input**:
  ```json
  PUT /me/profile
  {
    "first_name": "Jonathan",
    "last_name": "Davis"
  }
  ```
- **Expected Output**: Status 200; both fields updated

### TC-USER-PROFILE-005: Update avatar URL
- **Category**: Nominal
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user
- **Input**:
  ```json
  PUT /me/profile
  {
    "avatar_url": "https://gravatar.com/avatar/abc123"
  }
  ```
- **Expected Output**: Status 200; `"avatar_url": "https://gravatar.com/avatar/abc123"`

### TC-USER-PROFILE-006: Update all profile fields at once
- **Category**: Nominal
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user
- **Input**:
  ```json
  PUT /me/profile
  {
    "display_name": "J. Davis",
    "first_name": "Jonathan",
    "last_name": "Davis",
    "avatar_url": "https://cdn.example.com/avatar.jpg"
  }
  ```
- **Expected Output**: Status 200; all four fields updated in response

### TC-USER-PROFILE-007: Change password successfully
- **Category**: Nominal
- **Standard**: NIST SP 800-63B Section 5.1.1.2
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. User with current password `OldP@ssw0rd_2026`
- **Input**:
  ```json
  PUT /me/password
  {
    "current_password": "OldP@ssw0rd_2026",
    "new_password": "NewP@ssw0rd_2026!",
    "revoke_other_sessions": false
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "message": "Password changed successfully", "sessions_revoked": 0 }
  ```

### TC-USER-PROFILE-008: Change password and revoke other sessions
- **Category**: Nominal
- **Standard**: NIST SP 800-63B
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. User has 3 active sessions
- **Input**:
  ```json
  PUT /me/password
  {
    "current_password": "OldP@ssw0rd_2026",
    "new_password": "NewP@ssw0rd_2026!",
    "revoke_other_sessions": true
  }
  ```
- **Expected Output**: Status 200; `"sessions_revoked": 3` (or however many were active)
- **Side Effects**: All other refresh tokens revoked; only current session remains valid

### TC-USER-PROFILE-009: Initiate email change
- **Category**: Nominal
- **Standard**: NIST SP 800-63B
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. User authenticated with email `old@example.com`
- **Input**:
  ```json
  POST /me/email/change
  {
    "new_email": "new@example.com",
    "current_password": "MyP@ssw0rd_2026"
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "message": "Verification email sent to new address",
    "expires_at": "<iso8601>"
  }
  ```
- **Side Effects**: Verification email sent to `new@example.com` with a time-limited token

### TC-USER-PROFILE-010: Verify email change with valid token
- **Category**: Nominal
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Email change initiated; verification token received
- **Input**:
  ```json
  POST /me/email/verify
  {
    "token": "<43-char-verification-token>"
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "message": "Email changed successfully",
    "new_email": "new@example.com"
  }
  ```
- **Side Effects**: User's email updated in database

### TC-USER-PROFILE-011: Profile update is scoped to own user
- **Category**: Nominal
- **Standard**: ISO 27001 A.9.4.1
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Users U1 and U2 in same tenant
- **Input**: `PUT /me/profile { "display_name": "Updated" }` with U1's JWT
- **Verification**: Only U1's profile is modified; U2's profile is unchanged

---

## Edge Cases

### TC-USER-PROFILE-020: Update profile with empty display_name
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user
- **Input**: `PUT /me/profile { "display_name": "" }`
- **Expected Output**: Status 400 with validation error: "Display name must be 1-100 characters"

### TC-USER-PROFILE-021: Update profile with display_name exceeding 100 chars
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user
- **Input**: `PUT /me/profile { "display_name": "<101 characters>" }`
- **Expected Output**: Status 400 with validation error

### TC-USER-PROFILE-022: Update profile with first_name exceeding 100 chars
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user
- **Input**: `PUT /me/profile { "first_name": "<101 characters>" }`
- **Expected Output**: Status 400

### TC-USER-PROFILE-023: Update profile with invalid avatar URL
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user
- **Input**: `PUT /me/profile { "avatar_url": "not-a-valid-url" }`
- **Expected Output**: Status 400 with validation error: "Invalid avatar URL format"

### TC-USER-PROFILE-024: Update profile with avatar URL exceeding 2048 chars
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user
- **Input**: `PUT /me/profile { "avatar_url": "https://example.com/<very long path>" }` (>2048 chars)
- **Expected Output**: Status 400 with validation error

### TC-USER-PROFILE-025: Update profile with no fields (empty object)
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user
- **Input**: `PUT /me/profile {}`
- **Expected Output**: Status 200; profile unchanged (all fields optional, no-op update)

### TC-USER-PROFILE-026: Change password with wrong current password
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user
- **Input**:
  ```json
  PUT /me/password
  { "current_password": "WrongPassword!", "new_password": "NewP@ssw0rd_2026" }
  ```
- **Expected Output**: Status 401 (InvalidCredentials)

### TC-USER-PROFILE-027: Change password with same old and new password
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user
- **Input**:
  ```json
  PUT /me/password
  { "current_password": "MyP@ssw0rd_2026", "new_password": "MyP@ssw0rd_2026" }
  ```
- **Expected Output**: Status 400 (password history check rejects reuse) OR Status 200 (if no history configured)

### TC-USER-PROFILE-028: Change password that violates tenant password policy
- **Category**: Edge Case
- **Standard**: NIST SP 800-63B
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Tenant policy requires min 12 chars
- **Input**:
  ```json
  PUT /me/password
  { "current_password": "OldP@ssw0rd_2026", "new_password": "Short1!" }
  ```
- **Expected Output**: Status 400 (WeakPassword error with specific policy violations)

### TC-USER-PROFILE-029: Initiate email change to same email
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user
- **Input**:
  ```json
  POST /me/email/change
  { "new_email": "<current-email>", "current_password": "MyP@ssw0rd_2026" }
  ```
- **Expected Output**: Status 400 ("New email is same as current email" or similar)

### TC-USER-PROFILE-030: Initiate email change to already-taken email
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. `taken@example.com` belongs to another user in the same tenant
- **Input**:
  ```json
  POST /me/email/change
  { "new_email": "taken@example.com", "current_password": "MyP@ssw0rd_2026" }
  ```
- **Expected Output**: Status 409 Conflict

### TC-USER-PROFILE-031: Verify email change with expired token
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Email change token has expired
- **Input**: `POST /me/email/verify { "token": "<expired-token>" }`
- **Expected Output**: Status 400 ("Invalid or expired token")

### TC-USER-PROFILE-032: Verify email change with invalid token format
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user
- **Input**: `POST /me/email/verify { "token": "short" }`
- **Expected Output**: Status 400 (token must be exactly 43 characters)

### TC-USER-PROFILE-033: Initiate email change with invalid email format
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user
- **Input**: `POST /me/email/change { "new_email": "not-an-email", "current_password": "..." }`
- **Expected Output**: Status 400 with email validation error

### TC-USER-PROFILE-034: Initiate email change with wrong password
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user
- **Input**:
  ```json
  POST /me/email/change
  { "new_email": "new@example.com", "current_password": "WrongPassword!" }
  ```
- **Expected Output**: Status 401

### TC-USER-PROFILE-035: Password change respects minimum age policy
- **Category**: Edge Case
- **Standard**: NIST SP 800-63B
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Tenant has min_age_hours = 24; user changed password 1 hour ago
- **Input**: `PUT /me/password { "current_password": "...", "new_password": "..." }`
- **Expected Output**: Status 400 (minimum password age not met)

### TC-USER-PROFILE-036: Password change adds to history
- **Category**: Edge Case
- **Standard**: NIST SP 800-63B
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Tenant has `history_count = 5`
- **Input**: Change password successfully
- **Verification**: Old password hash added to `password_history` table; attempting to reuse it fails

### TC-USER-PROFILE-037: Unicode in profile fields
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user
- **Input**:
  ```json
  PUT /me/profile
  { "display_name": "Jean-Pierre", "first_name": "Jean-Pierre", "last_name": "Lefevre" }
  ```
- **Expected Output**: Status 200; Unicode characters stored and returned correctly

---

## Security Cases

### TC-USER-PROFILE-040: Unauthenticated access to GET /me/profile
- **Category**: Security
- **Standard**: ISO 27001 A.9.4.1
- **Preconditions**: Fixtures: `TEST_TENANT`. No authentication token provided
- **Input**: `GET /me/profile` with no Authorization header
- **Expected Output**: Status 401

### TC-USER-PROFILE-041: Unauthenticated access to PUT /me/profile
- **Category**: Security
- **Preconditions**: Fixtures: `TEST_TENANT`. No authentication token provided
- **Input**: `PUT /me/profile { "display_name": "Hacker" }` with no auth
- **Expected Output**: Status 401

### TC-USER-PROFILE-042: Profile endpoint does not allow modifying other users
- **Category**: Security
- **Standard**: ISO 27001 A.9.4.1
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. User U1 authenticated; user U2 exists in same tenant
- **Input**: `PUT /me/profile` with U1's JWT -- no way to specify U2's ID
- **Verification**: The `/me` endpoints ALWAYS operate on the authenticated user (derived from JWT `sub` claim); there is no `user_id` parameter to manipulate

### TC-USER-PROFILE-043: Profile endpoint tenant isolation
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. User U1 in tenant T1; user U2 in tenant T2
- **Input**: `GET /me/profile` with U1's JWT
- **Verification**: Query uses `WHERE id = $1 AND tenant_id = $2` ensuring even if user_id existed in another tenant, it would not match

### TC-USER-PROFILE-044: Password not returned in profile response
- **Category**: Security
- **Standard**: OWASP ASVS 2.4.1
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user
- **Input**: `GET /me/profile`
- **Expected Output**: Response contains NO password-related fields (no `password`, `password_hash`, or similar)

### TC-USER-PROFILE-045: Password change requires current password verification
- **Category**: Security
- **Standard**: NIST SP 800-63B
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user
- **Input**: `PUT /me/password` with missing `current_password`
- **Expected Output**: Status 400 (validation error)
- **Verification**: Cannot change password without proving knowledge of current password

### TC-USER-PROFILE-046: Email change requires password verification
- **Category**: Security
- **Standard**: NIST SP 800-63B
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user
- **Input**: `POST /me/email/change` with wrong `current_password`
- **Expected Output**: Status 401 (must prove account ownership before changing email)

### TC-USER-PROFILE-047: XSS in profile fields
- **Category**: Security
- **Standard**: OWASP ASVS 5.3.3
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user
- **Input**:
  ```json
  PUT /me/profile
  { "display_name": "<script>alert('xss')</script>" }
  ```
- **Expected Output**: Status 200 (stored safely; API returns JSON with proper Content-Type); no script execution

### TC-USER-PROFILE-048: SQL injection in profile fields
- **Category**: Security
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user
- **Input**:
  ```json
  PUT /me/profile
  { "display_name": "'; DROP TABLE users; --" }
  ```
- **Expected Output**: Status 200 (parameterized queries prevent injection); value stored as literal string

### TC-USER-PROFILE-049: Password change generates security alert
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user with known password
- **Input**: Successful password change
- **Verification**: `AlertService.generate_password_change_alert()` called with tenant_id, user_id, and IP address

### TC-USER-PROFILE-050: Email change token is cryptographically random
- **Category**: Security
- **Standard**: NIST SP 800-63B
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user with known password
- **Input**: Initiate email change
- **Verification**: Token is 43 characters (base64url-encoded, ~32 bytes of entropy); generated using CSPRNG

### TC-USER-PROFILE-051: Expired JWT on profile endpoint
- **Category**: Security
- **Preconditions**: Fixtures: `TEST_TENANT`. Expired JWT token available
- **Input**: `GET /me/profile` with expired JWT
- **Expected Output**: Status 401

### TC-USER-PROFILE-052: Suspended user profile access
- **Category**: Security
- **Standard**: ISO 27001 A.9.2.6
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User account suspended via admin
- **Input**: `GET /me/profile` with suspended user's (still valid) JWT
- **Expected Output**: Status 401 or 403 (suspended account check in middleware)

---

## Compliance Cases

### TC-USER-PROFILE-060: Audit trail for password change
- **Category**: Compliance
- **Standard**: SOC 2 CC6.1, ISO 27001 A.12.4.1
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user with known password
- **Input**: Change password via `PUT /me/password`
- **Verification**: Audit log records: user_id, tenant_id, action type (password_change), timestamp, source IP, user agent

### TC-USER-PROFILE-061: Password policy enforcement
- **Category**: Compliance
- **Standard**: NIST SP 800-63B Section 5.1.1
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user; tenant has password policy configured
- **Input**: Attempt password change
- **Verification**: Tenant password policy is fetched and applied: min length, complexity, history check, minimum age

### TC-USER-PROFILE-062: Email change verification flow
- **Category**: Compliance
- **Standard**: NIST SP 800-63A (Email verification)
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user with known password
- **Input**: Complete email change flow (initiate + verify)
- **Verification**: Email is NOT changed until verification token is confirmed; two-step process ensures control of new email address

### TC-USER-PROFILE-063: GDPR right to rectification
- **Category**: Compliance
- **Standard**: GDPR Article 16
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated as regular user
- **Input**: Update profile via `PUT /me/profile`
- **Verification**: Users can update their own personal data (display_name, first_name, last_name, avatar) without admin intervention
