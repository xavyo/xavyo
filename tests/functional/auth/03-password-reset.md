# Password Reset Functional Tests

**API Endpoints**:
- `POST /auth/forgot-password` (request reset)
- `POST /auth/reset-password` (execute reset)
**Authentication**: Public
**Applicable Standards**: NIST SP 800-63B Section 5.1.1.2, OWASP ASVS 2.5

---

## Nominal Cases

### TC-AUTH-RESET-001: Request password reset for existing user
- **Category**: Nominal
- **Input**:
  ```json
  POST /auth/forgot-password
  X-Tenant-ID: <tenant_id>
  { "email": "user@example.com" }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "message": "If an account exists, a reset link has been sent." }
  ```
- **Side Effects**: Password reset token created in DB, email sent

### TC-AUTH-RESET-002: Execute password reset with valid token
- **Category**: Nominal
- **Preconditions**: Reset token generated via TC-AUTH-RESET-001
- **Input**:
  ```json
  POST /auth/reset-password
  { "token": "<reset_token>", "new_password": "NewP@ssw0rd_2026" }
  ```
- **Expected Output**: Status 200
- **Side Effects**:
  - Password hash updated in DB
  - Reset token invalidated
  - All existing sessions revoked
  - Audit log: `user.password_reset`

### TC-AUTH-RESET-003: Login with new password after reset
- **Category**: Nominal
- **Preconditions**: Password reset completed
- **Input**: Login with new password
- **Expected Output**: Status 200 (login succeeds)

### TC-AUTH-RESET-004: Old password rejected after reset
- **Category**: Nominal
- **Preconditions**: Password reset completed
- **Input**: Login with old password
- **Expected Output**: Status 401

---

## Edge Cases

### TC-AUTH-RESET-010: Request reset for non-existent email
- **Category**: Edge Case
- **Standard**: OWASP ASVS 2.5.2 (anti-enumeration)
- **Input**: `"email": "nonexistent@example.com"`
- **Expected Output**: Status 200 with SAME success message (no email existence leak)

### TC-AUTH-RESET-011: Request reset for unverified email
- **Category**: Edge Case
- **Input**: Email exists but not verified
- **Expected Output**: Status 200 (same generic message). No reset email sent.

### TC-AUTH-RESET-012: Expired reset token
- **Category**: Edge Case
- **Preconditions**: Reset token older than expiry window (e.g., 1 hour)
- **Input**: `POST /auth/reset-password` with expired token
- **Expected Output**: Status 400 "Token expired or invalid"

### TC-AUTH-RESET-013: Already-used reset token (replay)
- **Category**: Edge Case
- **Standard**: OWASP ASVS 2.5.6
- **Preconditions**: Token used once successfully
- **Input**: Same token used again
- **Expected Output**: Status 400 "Token expired or invalid"

### TC-AUTH-RESET-014: Invalid reset token format
- **Category**: Edge Case
- **Input**: `"token": "not-a-valid-token"`
- **Expected Output**: Status 400

### TC-AUTH-RESET-015: Multiple reset requests — only latest token valid
- **Category**: Edge Case
- **Input**: Request reset twice for same email
- **Expected Output**: Only the second token works; first is invalidated

### TC-AUTH-RESET-016: New password same as old password
- **Category**: Edge Case
- **Input**: Reset with same password as current
- **Expected Output**: Status 400 (if password history enforced) OR Status 200

### TC-AUTH-RESET-017: New password fails complexity requirements
- **Category**: Edge Case
- **Input**: `"new_password": "weak"`
- **Expected Output**: Status 400 with password policy violation message

### TC-AUTH-RESET-018: Reset for suspended account
- **Category**: Edge Case
- **Input**: Reset request for suspended user
- **Expected Output**: Status 200 (same generic message — no status leak)

---

## Security Cases

### TC-AUTH-RESET-020: Reset token is cryptographically random
- **Category**: Security
- **Standard**: NIST SP 800-63B
- **Verification**: Token has sufficient entropy (min 128 bits)

### TC-AUTH-RESET-021: Reset token is single-use
- **Category**: Security
- **Standard**: OWASP ASVS 2.5.6
- **Verification**: Token marked as `used` in DB after successful reset

### TC-AUTH-RESET-022: Reset token has bounded lifetime
- **Category**: Security
- **Standard**: OWASP ASVS 2.5.5
- **Verification**: Token expires within 1 hour (or configured TTL)

### TC-AUTH-RESET-023: Rate limiting on reset requests
- **Category**: Security
- **Input**: 10 rapid reset requests for same email
- **Expected Output**: Rate limiting after threshold

### TC-AUTH-RESET-024: Reset revokes all active sessions
- **Category**: Security
- **Standard**: OWASP ASVS 2.5.4
- **Preconditions**: User has active sessions
- **Input**: Successful password reset
- **Verification**: All sessions for user are revoked in DB

### TC-AUTH-RESET-025: Reset token not logged in plaintext
- **Category**: Security
- **Verification**: Application logs do not contain reset token values

### TC-AUTH-RESET-026: Reset email does not leak user information
- **Category**: Security
- **Verification**: Email content doesn't include password, user ID, or internal data
