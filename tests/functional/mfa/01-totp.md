# TOTP Multi-Factor Authentication Functional Tests

**API Endpoints**:
- `POST /auth/mfa/totp/setup` (initiate TOTP enrollment)
- `POST /auth/mfa/totp/verify` (verify TOTP code)
- `POST /auth/mfa/totp/disable` (disable TOTP)
- `POST /auth/mfa/verify` (verify MFA during login)
**Authentication**: JWT (Bearer token)
**Applicable Standards**: RFC 6238 (TOTP), NIST SP 800-63B AAL2, OWASP ASVS 2.8

---

## Nominal Cases

### TC-MFA-TOTP-001: Initiate TOTP setup
- **Category**: Nominal
- **Preconditions**: Authenticated user, no MFA enrolled
- **Input**: `POST /auth/mfa/totp/setup` (authenticated)
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "secret": "<base32_secret>",
    "qr_code_uri": "otpauth://totp/xavyo:user@example.com?secret=...&issuer=xavyo",
    "recovery_codes": ["code1", "code2", ..., "code10"]
  }
  ```

### TC-MFA-TOTP-002: Verify TOTP code to complete enrollment
- **Category**: Nominal
- **Preconditions**: TOTP setup initiated
- **Input**:
  ```json
  POST /auth/mfa/totp/verify
  { "code": "<valid_6_digit_totp>" }
  ```
- **Expected Output**: Status 200, MFA now active for user
- **Side Effects**: `mfa_enabled = true` in user record, audit log `mfa.totp.enrolled`

### TC-MFA-TOTP-003: Login flow with MFA challenge
- **Category**: Nominal
- **Preconditions**: User has TOTP enrolled
- **Input**:
  1. `POST /auth/login` → Status 200 with `mfa_required: true`, `mfa_token: "<temp>"`
  2. `POST /auth/mfa/verify` with `{ "mfa_token": "<temp>", "code": "<totp>" }`
- **Expected Output**: Full access_token + refresh_token returned after step 2

### TC-MFA-TOTP-004: TOTP code accepted within time window
- **Category**: Nominal
- **Standard**: RFC 6238 (30-second window)
- **Input**: Valid TOTP code generated within current 30-second period
- **Expected Output**: Status 200

### TC-MFA-TOTP-005: Disable TOTP
- **Category**: Nominal
- **Preconditions**: TOTP enrolled, tenant policy allows disabling
- **Input**:
  ```json
  POST /auth/mfa/totp/disable
  { "code": "<valid_totp>" }
  ```
- **Expected Output**: Status 200, MFA disabled
- **Side Effects**: `mfa_enabled = false`, audit log `mfa.totp.disabled`

### TC-MFA-TOTP-006: Recovery codes generated on setup
- **Category**: Nominal
- **Verification**: Exactly 10 recovery codes, each 8+ characters, unique

### TC-MFA-TOTP-007: Login with recovery code
- **Category**: Nominal
- **Preconditions**: TOTP enrolled, user has recovery codes
- **Input**: MFA verify with recovery code instead of TOTP
- **Expected Output**: Status 200, recovery code marked as used

---

## Edge Cases

### TC-MFA-TOTP-010: Wrong TOTP code
- **Category**: Edge Case
- **Input**: `"code": "000000"`
- **Expected Output**: Status 401 "Invalid MFA code"

### TC-MFA-TOTP-011: Expired TOTP code (previous window)
- **Category**: Edge Case
- **Standard**: RFC 6238
- **Input**: TOTP code from 60+ seconds ago
- **Expected Output**: Status 401 (if no time-step tolerance) or 200 (if ±1 step tolerance)

### TC-MFA-TOTP-012: TOTP code reuse within same window
- **Category**: Edge Case / Security
- **Input**: Same valid code submitted twice within 30 seconds
- **Expected Output**: First succeeds, second fails (replay prevention)

### TC-MFA-TOTP-013: MFA token expired
- **Category**: Edge Case
- **Preconditions**: MFA challenge issued, wait > token TTL
- **Input**: Verify with expired mfa_token
- **Expected Output**: Status 401 "MFA session expired"

### TC-MFA-TOTP-014: MFA token for different user
- **Category**: Edge Case / Security
- **Input**: Use user A's mfa_token with user B's TOTP code
- **Expected Output**: Status 401

### TC-MFA-TOTP-015: Disable TOTP when tenant policy requires MFA
- **Category**: Edge Case
- **Preconditions**: Tenant MFA policy = required
- **Input**: `POST /auth/mfa/totp/disable`
- **Expected Output**: Status 403 "MFA required by tenant policy"

### TC-MFA-TOTP-016: Recovery code already used
- **Category**: Edge Case
- **Input**: Same recovery code used twice
- **Expected Output**: Second use returns 401

### TC-MFA-TOTP-017: All recovery codes exhausted
- **Category**: Edge Case
- **Preconditions**: All 10 recovery codes used
- **Input**: Login with TOTP device lost
- **Expected Output**: No recovery possible, must contact admin

### TC-MFA-TOTP-018: Non-numeric TOTP code
- **Category**: Edge Case
- **Input**: `"code": "abcdef"`
- **Expected Output**: Status 400

### TC-MFA-TOTP-019: TOTP code with wrong length
- **Category**: Edge Case
- **Input**: `"code": "12345"` (5 digits) or `"code": "1234567"` (7 digits)
- **Expected Output**: Status 400

### TC-MFA-TOTP-020: Brute force TOTP (many wrong codes)
- **Category**: Edge Case / Security
- **Input**: 10 consecutive wrong codes
- **Expected Output**: Rate limiting or temporary lockout after threshold

---

## Security Cases

### TC-MFA-TOTP-030: TOTP secret not returned after enrollment
- **Category**: Security
- **Verification**: After TOTP is enrolled, `GET /me/profile` does not include the TOTP secret

### TC-MFA-TOTP-031: Recovery codes shown only once
- **Category**: Security
- **Verification**: Recovery codes returned during setup, never retrievable again

### TC-MFA-TOTP-032: TOTP secret stored encrypted
- **Category**: Security
- **Verification**: `totp_secret` column is encrypted in database

### TC-MFA-TOTP-033: MFA token is short-lived
- **Category**: Security
- **Verification**: MFA token expires within 5 minutes

### TC-MFA-TOTP-034: MFA bypass not possible via API
- **Category**: Security
- **Preconditions**: User has MFA enabled
- **Input**: Try to access protected resource with only password auth (no MFA verify step)
- **Expected Output**: Access denied

### TC-MFA-TOTP-035: TOTP enrollment audit trail
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Verification**: Audit logs for: enrollment, verification, disable, recovery code use
