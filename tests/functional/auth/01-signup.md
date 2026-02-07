# Signup Functional Tests

**API Endpoint**: `POST /auth/signup`
**Authentication**: Public (no JWT required)
**Required Headers**: `Content-Type: application/json`
**Applicable Standards**: NIST SP 800-63A (Identity Proofing), OWASP ASVS 2.1

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `SYS_TENANT`
- **Special Setup**: None (public endpoint, no authentication needed)

## Nominal Cases

### TC-AUTH-SIGNUP-001: Successful signup with valid credentials
- **Category**: Nominal
- **Standard**: NIST SP 800-63A IAL1
- **Preconditions**: Fixtures: `SYS_TENANT`. No existing account with the given email
- **Input**:
  ```json
  POST /auth/signup
  {
    "email": "newuser@example.com",
    "password": "MyP@ssw0rd_2026",
    "display_name": "New User"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "user_id": "<uuid>",
    "email": "newuser@example.com",
    "email_verified": false,
    "access_token": "<jwt>",
    "expires_in": 3600
  }
  ```
- **Side Effects**:
  - User record created in `users` table
  - Verification email sent
  - `email_verified = false` in database
  - Audit log entry created (event: `user.signup`)

### TC-AUTH-SIGNUP-002: Signup without display_name
- **Category**: Nominal
- **Standard**: NIST SP 800-63A
- **Preconditions**: Fixtures: `SYS_TENANT`. No existing account
- **Input**:
  ```json
  POST /auth/signup
  { "email": "minimal@example.com", "password": "MyP@ssw0rd_2026" }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: { "user_id": "<uuid>", "email": "minimal@example.com", ... }
  ```
- **Side Effects**: display_name is NULL in database

### TC-AUTH-SIGNUP-003: Signup creates user in system tenant
- **Category**: Nominal
- **Preconditions**: Fixtures: `SYS_TENANT`. API server running
- **Input**:
  ```json
  POST /auth/signup
  { "email": "tenant-test@example.com", "password": "MyP@ssw0rd_2026" }
  ```
- **Expected Output**: Status 201
- **Verification**: User's tenant_id in DB = system tenant (`00000000-0000-0000-0000-000000000001`)

### TC-AUTH-SIGNUP-004: Signup returns valid JWT
- **Category**: Nominal
- **Input**: Valid signup request
- **Expected Output**: `access_token` is a valid JWT with:
  - `sub` claim = user_id
  - `email` claim = submitted email
  - `exp` claim > current time
  - `iat` claim <= current time

---

## Edge Cases

### TC-AUTH-SIGNUP-010: Duplicate email address
- **Category**: Edge Case
- **Preconditions**: Fixtures: `SYS_TENANT`. Account exists with `existing@example.com`
- **Input**:
  ```json
  POST /auth/signup
  { "email": "existing@example.com", "password": "MyP@ssw0rd_2026" }
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  Body: { "error": "Account already exists" }
  ```
- **Note**: Must NOT reveal whether the email exists (anti-enumeration). Some implementations return 200 with a generic message instead.

### TC-AUTH-SIGNUP-011: Duplicate email with different case
- **Category**: Edge Case
- **Input**:
  ```json
  POST /auth/signup
  { "email": "Existing@Example.COM", "password": "MyP@ssw0rd_2026" }
  ```
- **Expected Output**: Same as TC-AUTH-SIGNUP-010 (email comparison is case-insensitive per RFC 5321)

### TC-AUTH-SIGNUP-012: Email with valid but unusual format
- **Category**: Edge Case
- **Input**: `"email": "user+tag@sub.example.co.uk"`
- **Expected Output**: Status 201 (valid per RFC 5322)

### TC-AUTH-SIGNUP-013: Email with leading/trailing whitespace
- **Category**: Edge Case
- **Input**: `"email": "  spaces@example.com  "`
- **Expected Output**: Status 201 (whitespace trimmed) OR Status 400 (strict validation)

### TC-AUTH-SIGNUP-014: Very long email address (254 chars)
- **Category**: Edge Case
- **Input**: Email at exactly 254 characters (RFC 5321 max)
- **Expected Output**: Status 201

### TC-AUTH-SIGNUP-015: Email exceeding 254 characters
- **Category**: Edge Case
- **Input**: Email at 255+ characters
- **Expected Output**: Status 400 (validation error)

### TC-AUTH-SIGNUP-016: Empty request body
- **Category**: Edge Case
- **Input**: `POST /auth/signup` with empty body
- **Expected Output**: Status 400

### TC-AUTH-SIGNUP-017: Missing email field
- **Category**: Edge Case
- **Input**: `{ "password": "MyP@ssw0rd_2026" }`
- **Expected Output**: Status 400 with field-level error

### TC-AUTH-SIGNUP-018: Missing password field
- **Category**: Edge Case
- **Input**: `{ "email": "test@example.com" }`
- **Expected Output**: Status 400 with field-level error

### TC-AUTH-SIGNUP-019: Extra unknown fields in request
- **Category**: Edge Case
- **Input**: `{ "email": "...", "password": "...", "admin": true, "role": "super_admin" }`
- **Expected Output**: Status 201 (unknown fields ignored, no privilege escalation)

### TC-AUTH-SIGNUP-020: Unicode in display_name
- **Category**: Edge Case
- **Input**: `"display_name": "用户名 Ψ αβγ 🎉"`
- **Expected Output**: Status 201, display_name stored correctly

### TC-AUTH-SIGNUP-021: SQL injection in email
- **Category**: Edge Case / Security
- **Input**: `"email": "'; DROP TABLE users; --@example.com"`
- **Expected Output**: Status 400 (invalid email format), no SQL execution

### TC-AUTH-SIGNUP-022: Very long display_name (1000+ chars)
- **Category**: Edge Case
- **Input**: display_name with 1000 characters
- **Expected Output**: Status 400 (validation limit) OR Status 201 (if no limit defined)

### TC-AUTH-SIGNUP-023: Null values for required fields
- **Category**: Edge Case
- **Input**: `{ "email": null, "password": null }`
- **Expected Output**: Status 400

### TC-AUTH-SIGNUP-024: Concurrent signup with same email
- **Category**: Edge Case
- **Input**: Two simultaneous `POST /auth/signup` with identical email
- **Expected Output**: Exactly one succeeds (201), the other fails (409). No duplicate user records.

---

## Security Cases

### TC-AUTH-SIGNUP-030: Password below minimum length
- **Category**: Security
- **Standard**: NIST SP 800-63B (min 8 chars)
- **Input**: `"password": "short"`
- **Expected Output**: Status 400 with clear error message about password requirements

### TC-AUTH-SIGNUP-031: Password without special characters
- **Category**: Security
- **Input**: `"password": "NoSpecialChars123"`
- **Expected Output**: Status 400 (if policy requires special chars)

### TC-AUTH-SIGNUP-032: Password matching common passwords list
- **Category**: Security
- **Standard**: NIST SP 800-63B (breached password check)
- **Input**: `"password": "P@ssword123!"`
- **Expected Output**: Status 400 (if breached password check enabled)

### TC-AUTH-SIGNUP-033: Password same as email
- **Category**: Security
- **Input**: `"email": "test@example.com", "password": "test@example.com"`
- **Expected Output**: Status 400

### TC-AUTH-SIGNUP-034: XSS in display_name
- **Category**: Security
- **Standard**: OWASP ASVS 5.3.3
- **Input**: `"display_name": "<script>alert('xss')</script>"`
- **Expected Output**: Status 201 (stored safely, output-encoded when rendered) OR Status 400 (rejected)

### TC-AUTH-SIGNUP-035: Rate limiting on signup
- **Category**: Security
- **Standard**: OWASP ASVS 11.1.4
- **Input**: 20 rapid signup requests from same IP
- **Expected Output**: First N succeed, subsequent return 429 Too Many Requests

### TC-AUTH-SIGNUP-036: Response does not leak internal errors
- **Category**: Security
- **Standard**: OWASP ASVS 7.4.1
- **Input**: Any failed signup
- **Expected Output**: Error messages must NOT contain stack traces, SQL errors, or internal paths

### TC-AUTH-SIGNUP-037: Password not returned in response
- **Category**: Security
- **Input**: Valid signup
- **Expected Output**: Response body does NOT contain the password in any field

### TC-AUTH-SIGNUP-038: Password stored as hash (not plaintext)
- **Category**: Security
- **Standard**: NIST SP 800-63B, OWASP ASVS 2.4.1
- **Input**: Valid signup
- **Verification**: Database `password_hash` column contains Argon2id hash, not the plaintext password

---

## Compliance Cases

### TC-AUTH-SIGNUP-040: NIST SP 800-63B password length (min 8)
- **Category**: Compliance
- **Standard**: NIST SP 800-63B Section 5.1.1.2
- **Input**: Password with exactly 8 characters including special char
- **Expected Output**: Status 201

### TC-AUTH-SIGNUP-041: NIST SP 800-63B password max length (at least 64)
- **Category**: Compliance
- **Standard**: NIST SP 800-63B Section 5.1.1.2
- **Input**: Password with 64 characters
- **Expected Output**: Status 201 (system must accept at least 64 chars)

### TC-AUTH-SIGNUP-042: NIST SP 800-63B all unicode allowed
- **Category**: Compliance
- **Standard**: NIST SP 800-63B Section 5.1.1.2
- **Input**: `"password": "我的密码很安全!123"`
- **Expected Output**: Status 201 (Unicode passwords must be accepted)

### TC-AUTH-SIGNUP-043: SOC 2 audit trail for signup
- **Category**: Compliance
- **Standard**: SOC 2 CC6.1
- **Input**: Valid signup
- **Verification**: Audit log contains: timestamp, event type, user_id, IP address, user agent
