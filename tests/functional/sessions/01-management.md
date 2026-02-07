# Session Management Functional Tests

**API Endpoints**:
- `GET /me/sessions` (list active sessions)
- `DELETE /me/sessions/:id` (revoke a specific session)
- `DELETE /me/sessions` (revoke all sessions)
- `POST /auth/logout` (logout / destroy current session)
- `GET /me/security` (security overview including session info)
**Authentication**: JWT (Bearer token)
**Applicable Standards**: OWASP ASVS 3.3 (Session Logout & Timeout), NIST SP 800-63B Section 7

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `USER_JWT`, `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: Session tests require authenticated users with active sessions; some tests require multiple concurrent sessions from different devices

---

## Nominal Cases

### TC-SESSION-MGMT-001: List active sessions
- **Category**: Nominal
- **Standard**: OWASP ASVS 3.3.1
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated user with at least one active session
- **Input**: `GET /me/sessions` (authenticated)
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "sessions": [
      {
        "id": "<uuid>",
        "ip_address": "192.168.1.1",
        "user_agent": "Mozilla/5.0...",
        "created_at": "2026-02-07T10:00:00Z",
        "last_active_at": "2026-02-07T10:05:00Z",
        "is_current": true
      }
    ]
  }
  ```
- **Verification**: Response includes the current session marked with `is_current: true`

### TC-SESSION-MGMT-002: List multiple sessions across devices
- **Category**: Nominal
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. User logged in from two different devices/browsers
- **Input**: `GET /me/sessions`
- **Expected Output**: Status 200, array contains exactly 2 sessions with different `user_agent` values
- **Verification**: Each session has unique ID, one marked `is_current: true`

### TC-SESSION-MGMT-003: Revoke a specific session by ID
- **Category**: Nominal
- **Standard**: OWASP ASVS 3.3.1
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. User has two active sessions (session A = current, session B = other device)
- **Input**: `DELETE /me/sessions/:session_b_id`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "message": "Session revoked" }
  ```
- **Side Effects**:
  - Session B invalidated in database
  - Audit log entry: `session.revoked`
  - Subsequent requests with session B's token return 401

### TC-SESSION-MGMT-004: Revoke all sessions except current
- **Category**: Nominal
- **Standard**: OWASP ASVS 3.3.4
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. User has 3 active sessions
- **Input**: `DELETE /me/sessions`
- **Expected Output**: Status 200, all sessions except current are revoked
- **Verification**: `GET /me/sessions` returns only 1 session (the current one)

### TC-SESSION-MGMT-005: Logout destroys current session
- **Category**: Nominal
- **Standard**: OWASP ASVS 3.3.1
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated user with valid session
- **Input**: `POST /auth/logout`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "message": "Logged out" }
  ```
- **Side Effects**:
  - Session marked as revoked in database
  - Refresh token invalidated
  - Subsequent requests with this token return 401
  - Audit log entry: `user.logout`

### TC-SESSION-MGMT-006: Session contains accurate metadata
- **Category**: Nominal
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. User logs in from known IP and User-Agent
- **Input**: `GET /me/sessions`
- **Expected Output**: Session entry contains:
  - `ip_address` matching the login request origin
  - `user_agent` matching the login request User-Agent header
  - `created_at` within seconds of login time

### TC-SESSION-MGMT-007: Session last_active_at updates on activity
- **Category**: Nominal
- **Standard**: NIST SP 800-63B 7.2
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated session exists
- **Steps**:
  1. Note `last_active_at` from `GET /me/sessions`
  2. Wait 5 seconds, make an authenticated API call
  3. Check `GET /me/sessions` again
- **Expected Output**: `last_active_at` has been updated to reflect recent activity

### TC-SESSION-MGMT-008: Security overview includes session count
- **Category**: Nominal
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. User has 2 active sessions
- **Input**: `GET /me/security`
- **Expected Output**: Status 200, response includes active session count

### TC-SESSION-MGMT-009: Login creates new session record
- **Category**: Nominal
- **Preconditions**: Fixtures: `TEST_TENANT`. User account exists with known credentials
- **Steps**:
  1. `POST /auth/login` with valid credentials
  2. `GET /me/sessions`
- **Expected Output**: New session appears in the list with correct `created_at`
- **Side Effects**: Session record created in `sessions` table with tenant_id

### TC-SESSION-MGMT-010: Token refresh does not create duplicate session
- **Category**: Nominal
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated user with active session and refresh token
- **Steps**:
  1. Login and note session count
  2. `POST /auth/refresh` with refresh_token
  3. `GET /me/sessions`
- **Expected Output**: Session count remains the same; session `last_active_at` updated

---

## Edge Cases

### TC-SESSION-MGMT-011: Revoke non-existent session ID
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated user
- **Input**: `DELETE /me/sessions/00000000-0000-0000-0000-000000000099`
- **Expected Output**: Status 404 "Session not found"

### TC-SESSION-MGMT-012: Revoke the current session via session endpoint
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated user with known current session ID
- **Input**: `DELETE /me/sessions/:current_session_id`
- **Expected Output**: Status 200 (session revoked) OR Status 400 "Cannot revoke current session, use logout"
- **Verification**: Behavior is documented and consistent

### TC-SESSION-MGMT-013: Revoke session belonging to another user
- **Category**: Edge Case / Security
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. User A and User B each have sessions
- **Input**: User A calls `DELETE /me/sessions/:user_b_session_id`
- **Expected Output**: Status 404 (session not found for this user, no cross-user access)

### TC-SESSION-MGMT-014: List sessions with no active sessions
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Somehow all sessions are expired (should not happen if currently authenticated)
- **Input**: `GET /me/sessions`
- **Expected Output**: Status 200, array with at least the current session

### TC-SESSION-MGMT-015: Revoke session with invalid UUID format
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated user
- **Input**: `DELETE /me/sessions/not-a-uuid`
- **Expected Output**: Status 400 "Invalid session ID format"

### TC-SESSION-MGMT-016: Concurrent session revocation
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Session B exists
- **Input**: Two simultaneous `DELETE /me/sessions/:session_b_id`
- **Expected Output**: First succeeds (200), second returns 404 (already revoked). No error.

### TC-SESSION-MGMT-017: Session limit enforcement
- **Category**: Edge Case
- **Standard**: OWASP ASVS 3.7.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Tenant has max_sessions_per_user = 5
- **Steps**: Login 6 times from different devices
- **Expected Output**: Oldest session is automatically revoked OR 6th login is rejected
- **Verification**: At most 5 active sessions exist

### TC-SESSION-MGMT-018: Session after password change
- **Category**: Edge Case
- **Standard**: OWASP ASVS 3.3.3
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. User has sessions on multiple devices
- **Steps**:
  1. User has sessions on device A and device B
  2. User changes password on device A
- **Expected Output**: All other sessions (device B) are revoked
- **Verification**: Device B receives 401 on next request

### TC-SESSION-MGMT-019: Logout with expired token
- **Category**: Edge Case
- **Preconditions**: Fixtures: `TEST_TENANT`. Expired JWT token available
- **Input**: `POST /auth/logout` with an expired JWT
- **Expected Output**: Status 401 Unauthorized

### TC-SESSION-MGMT-020: Logout with revoked token
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Token has been revoked via session revocation
- **Input**: `POST /auth/logout` with the revoked token
- **Expected Output**: Status 401 Unauthorized

### TC-SESSION-MGMT-021: Session persists across API calls
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated user with active session
- **Steps**:
  1. Login, get access_token
  2. Make 10 sequential API calls
  3. `GET /me/sessions`
- **Expected Output**: Still exactly 1 session (no session duplication)

### TC-SESSION-MGMT-022: Revoke all sessions when only one exists
- **Category**: Edge Case
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. User has only the current session
- **Input**: `DELETE /me/sessions`
- **Expected Output**: Status 200, current session is preserved (no sessions to revoke)

---

## Security Cases

### TC-SESSION-MGMT-023: Session tokens are not predictable
- **Category**: Security
- **Standard**: OWASP ASVS 3.2.1
- **Preconditions**: Fixtures: `TEST_TENANT`. User account exists with known credentials
- **Steps**: Create 100 sessions, collect all session IDs
- **Verification**: Session IDs are UUIDs v4 (random), no sequential pattern

### TC-SESSION-MGMT-024: Session fixation prevention
- **Category**: Security
- **Standard**: OWASP ASVS 3.2.3
- **Preconditions**: Fixtures: `TEST_TENANT`. User account exists with known credentials
- **Steps**:
  1. Login, note session ID
  2. Logout
  3. Login again with same credentials
- **Expected Output**: New session has a different ID (not reusing old session)

### TC-SESSION-MGMT-025: Cross-tenant session isolation
- **Category**: Security
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. User in tenant A, sessions exist in tenant B
- **Input**: `GET /me/sessions`
- **Expected Output**: Only sessions belonging to the authenticated user's tenant are returned
- **Verification**: SQL query filters by tenant_id

### TC-SESSION-MGMT-026: Session data does not leak sensitive information
- **Category**: Security
- **Standard**: OWASP ASVS 3.1.1
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated user with active session
- **Input**: `GET /me/sessions`
- **Expected Output**: Response does NOT contain:
  - Access tokens or refresh tokens
  - Password hashes
  - Internal server details

### TC-SESSION-MGMT-027: Idle session timeout
- **Category**: Security
- **Standard**: NIST SP 800-63B 7.2 (AAL2: 30 min idle timeout)
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated user with active session
- **Steps**:
  1. Login, note session
  2. Wait beyond idle timeout period (e.g., 30 minutes)
  3. Make authenticated request
- **Expected Output**: Status 401 (session expired due to inactivity)

### TC-SESSION-MGMT-028: Absolute session timeout
- **Category**: Security
- **Standard**: OWASP ASVS 3.3.2
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Authenticated user with active session
- **Steps**:
  1. Login, note session
  2. Keep session active with periodic requests
  3. Wait beyond absolute session lifetime
- **Expected Output**: Session expires regardless of activity

### TC-SESSION-MGMT-029: Audit trail for session events
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `USER_JWT`, `ADMIN_JWT`, `TEST_TENANT`. Authenticated users with sessions
- **Verification**: Audit log contains entries for:
  - `session.created` (on login)
  - `session.revoked` (on explicit revocation)
  - `session.expired` (on timeout)
  - Each entry includes: user_id, tenant_id, session_id, IP, timestamp

### TC-SESSION-MGMT-030: Session revocation is immediate
- **Category**: Security
- **Standard**: OWASP ASVS 3.3.1
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. User has multiple active sessions
- **Steps**:
  1. Revoke session B via `DELETE /me/sessions/:id`
  2. Immediately use session B's token for an API call
- **Expected Output**: The API call with session B's token returns 401 (no grace period)
