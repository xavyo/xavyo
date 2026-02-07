# Email Verification Functional Tests

**API Endpoints**:
- `POST /auth/resend-verification` (resend verification email)
- `POST /auth/verify-email` (verify with token)
- `GET /me/profile` (check verification status)
**Applicable Standards**: NIST SP 800-63A, SOC 2 CC6.1

---

## Nominal Cases

### TC-AUTH-VERIFY-001: Verification email sent on signup
- **Category**: Nominal
- **Preconditions**: Fresh signup
- **Verification**: Email sent with verification link containing token

### TC-AUTH-VERIFY-002: Verify email with valid token
- **Category**: Nominal
- **Input**:
  ```json
  POST /auth/verify-email
  { "token": "<verification_token>" }
  ```
- **Expected Output**: Status 200
- **Side Effects**: `email_verified = true` in users table, audit log entry

### TC-AUTH-VERIFY-003: Profile reflects verified status
- **Category**: Nominal
- **Preconditions**: Email verified
- **Input**: `GET /me/profile` (authenticated)
- **Expected Output**: `"email_verified": true`

### TC-AUTH-VERIFY-004: Resend verification email
- **Category**: Nominal
- **Input**:
  ```json
  POST /auth/resend-verification
  X-Tenant-ID: <tenant_id>
  { "email": "unverified@example.com" }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "message": "If an unverified account exists, a verification email will be sent." }
  ```

### TC-AUTH-VERIFY-005: Login blocked until email verified
- **Category**: Nominal
- **Preconditions**: Email not verified
- **Input**: `POST /auth/login` with valid credentials
- **Expected Output**: Status 401 or 403 (email verification required)

---

## Edge Cases

### TC-AUTH-VERIFY-010: Expired verification token
- **Category**: Edge Case
- **Input**: Token older than TTL
- **Expected Output**: Status 400 "Token expired"

### TC-AUTH-VERIFY-011: Already-used verification token
- **Category**: Edge Case
- **Input**: Token used twice
- **Expected Output**: Status 400 (second use rejected)

### TC-AUTH-VERIFY-012: Resend for already-verified email
- **Category**: Edge Case
- **Input**: Resend for email that's already verified
- **Expected Output**: Status 200 (same generic message, no email sent)

### TC-AUTH-VERIFY-013: Resend for non-existent email
- **Category**: Edge Case
- **Input**: `"email": "nobody@example.com"`
- **Expected Output**: Status 200 (same generic message — anti-enumeration)

### TC-AUTH-VERIFY-014: Multiple resend requests — token rotation
- **Category**: Edge Case
- **Input**: Resend 3 times
- **Expected Output**: Only the latest token is valid

### TC-AUTH-VERIFY-015: Verify token with wrong format
- **Category**: Edge Case
- **Input**: `"token": "abc123"`
- **Expected Output**: Status 400

### TC-AUTH-VERIFY-016: Rate limiting on resend
- **Category**: Edge Case / Security
- **Input**: 10 rapid resend requests
- **Expected Output**: 429 after threshold

---

## CLI Tests

### TC-AUTH-VERIFY-020: CLI verify status (verified)
- **Category**: Nominal
- **Preconditions**: Logged in, email verified
- **Input**: `xavyo verify status`
- **Expected Output**: `Email <email> is verified.` (exit code 0)

### TC-AUTH-VERIFY-021: CLI verify status (unverified)
- **Category**: Nominal
- **Preconditions**: Logged in, email not verified
- **Input**: `xavyo verify status`
- **Expected Output**: `Email <email> is NOT verified.` (exit code 0)

### TC-AUTH-VERIFY-022: CLI verify status --json
- **Category**: Nominal
- **Input**: `xavyo verify --json status`
- **Expected Output**: `{ "email": "...", "email_verified": true/false }`

### TC-AUTH-VERIFY-023: CLI verify resend
- **Category**: Nominal
- **Preconditions**: Logged in
- **Input**: `xavyo verify resend`
- **Expected Output**: Success message, email inferred from session

### TC-AUTH-VERIFY-024: CLI verify resend --email
- **Category**: Nominal
- **Input**: `xavyo verify resend --email other@example.com`
- **Expected Output**: Success message for specified email

### TC-AUTH-VERIFY-025: CLI verify resend not logged in
- **Category**: Edge Case
- **Preconditions**: Not logged in, no --email
- **Input**: `xavyo verify resend`
- **Expected Output**: Error: "No email specified and not logged in" (exit code 4)

### TC-AUTH-VERIFY-026: CLI verify status not logged in
- **Category**: Edge Case
- **Input**: `xavyo verify status` (no credentials)
- **Expected Output**: Error: "Not logged in" (exit code 2)
