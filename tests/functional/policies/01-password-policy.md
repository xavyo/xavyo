# Password Policy Configuration and Enforcement Functional Tests

**API Endpoints**:
- `PATCH /system/tenants/:id/settings` (update password policy via settings)
- `GET /system/tenants/:id/settings` (get current password policy)
- `POST /auth/signup` (password validated on signup)
- `PUT /auth/password` (password validated on change)
- `POST /auth/reset-password` (password validated on reset)
**Authentication**: JWT (admin for policy config), varies for enforcement
**Applicable Standards**: NIST SP 800-63B Section 5.1.1, OWASP ASVS 2.1

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: Password policy enforcement tests require user signup/password change flows

---

## Nominal Cases

### TC-POLICY-PWD-001: Get current password policy
- **Category**: Nominal
- **Standard**: NIST SP 800-63B
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: `GET /system/tenants/:id/settings`
- **Expected Output**: Status 200, password_policy section with all configured rules:
  ```json
  {
    "password_policy": {
      "min_length": 8,
      "max_length": 128,
      "require_uppercase": true,
      "require_lowercase": true,
      "require_digits": true,
      "require_special": true,
      "max_age_days": 90,
      "history_count": 5,
      "lockout_threshold": 5,
      "lockout_duration_minutes": 30
    }
  }
  ```

### TC-POLICY-PWD-002: Set minimum password length
- **Category**: Nominal
- **Standard**: NIST SP 800-63B Section 5.1.1.2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```json
  PATCH /system/tenants/:id/settings
  { "password_policy": { "min_length": 12 } }
  ```
- **Expected Output**: Status 200
- **Verification**: New signups with < 12 char passwords are rejected

### TC-POLICY-PWD-003: Enforce minimum length on signup
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Password policy min_length = 12
- **Input**:
  ```json
  POST /auth/signup
  { "email": "test@example.com", "password": "Short1@" }
  ```
- **Expected Output**: Status 400 "Password must be at least 12 characters"

### TC-POLICY-PWD-004: Accept password meeting all requirements
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. All requirements enabled (uppercase, lowercase, digits, special)
- **Input**: Password `MyStr0ng@Pass2026`
- **Expected Output**: Password accepted (Status 201 on signup)

### TC-POLICY-PWD-005: Enforce uppercase requirement
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. `require_uppercase: true`
- **Input**: Password `mystrongpass@123` (no uppercase)
- **Expected Output**: Status 400 "Password must contain at least one uppercase letter"

### TC-POLICY-PWD-006: Enforce lowercase requirement
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. `require_lowercase: true`
- **Input**: Password `MYSTRONGPASS@123` (no lowercase)
- **Expected Output**: Status 400 "Password must contain at least one lowercase letter"

### TC-POLICY-PWD-007: Enforce digit requirement
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. `require_digits: true`
- **Input**: Password `MyStrongPass@abc` (no digits)
- **Expected Output**: Status 400 "Password must contain at least one digit"

### TC-POLICY-PWD-008: Enforce special character requirement
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. `require_special: true`
- **Input**: Password `MyStrongPass123` (no special)
- **Expected Output**: Status 400 "Password must contain at least one special character"

### TC-POLICY-PWD-009: Enforce password on change
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Policy requires 12+ chars, user authenticated
- **Input**:
  ```json
  PUT /auth/password
  { "current_password": "OldP@ssw0rd_2026", "new_password": "Short1@" }
  ```
- **Expected Output**: Status 400 with password policy error

### TC-POLICY-PWD-010: Enforce password on reset
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Valid reset token, policy requires special chars
- **Input**:
  ```json
  POST /auth/reset-password
  { "token": "<reset_token>", "new_password": "NoSpecialChars123" }
  ```
- **Expected Output**: Status 400 with password policy error

---

## Edge Cases

### TC-POLICY-PWD-011: Set min_length below NIST minimum (8)
- **Category**: Edge Case
- **Standard**: NIST SP 800-63B
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: `{ "password_policy": { "min_length": 4 } }`
- **Expected Output**: Status 400 "Minimum password length cannot be less than 8"

### TC-POLICY-PWD-012: Set min_length above max_length
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: `{ "password_policy": { "min_length": 200, "max_length": 128 } }`
- **Expected Output**: Status 400 "min_length cannot exceed max_length"

### TC-POLICY-PWD-013: Password at exact minimum length
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. min_length = 8
- **Input**: Password with exactly 8 characters meeting all requirements
- **Expected Output**: Accepted

### TC-POLICY-PWD-014: Password at exact maximum length
- **Category**: Edge Case
- **Standard**: NIST SP 800-63B (must accept at least 64 chars)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. max_length = 128
- **Input**: Password with exactly 128 characters
- **Expected Output**: Accepted

### TC-POLICY-PWD-015: Password exceeding maximum length
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. max_length = 128
- **Input**: Password with 129 characters
- **Expected Output**: Status 400 "Password exceeds maximum length"

### TC-POLICY-PWD-016: Password history enforcement
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. `history_count: 5`, user has changed password 5 times
- **Input**: Change password to one of the last 5 passwords
- **Expected Output**: Status 400 "Password was recently used"

### TC-POLICY-PWD-017: Account lockout after failed attempts
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. `lockout_threshold: 5`
- **Input**: 5 consecutive failed login attempts
- **Expected Output**: Account locked for `lockout_duration_minutes`

### TC-POLICY-PWD-018: Unicode characters in password
- **Category**: Edge Case
- **Standard**: NIST SP 800-63B (all Unicode accepted)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: Password with Unicode: `Str0ng!Passe_wort`
- **Expected Output**: Accepted

### TC-POLICY-PWD-019: Disable all optional requirements
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```json
  { "password_policy": { "require_uppercase": false, "require_lowercase": false, "require_digits": false, "require_special": false } }
  ```
- **Expected Output**: Status 200, only min_length enforced

---

## Security Cases

### TC-POLICY-PWD-020: Password same as email rejected
- **Category**: Security
- **Standard**: NIST SP 800-63B
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: Password identical to the user's email address
- **Expected Output**: Status 400 "Password cannot be the same as your email"
