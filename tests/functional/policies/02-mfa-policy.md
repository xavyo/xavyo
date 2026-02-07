# MFA Policy Configuration and Enforcement Functional Tests

**API Endpoints**:
- `PATCH /system/tenants/:id/settings` (update MFA policy via settings)
- `GET /system/tenants/:id/settings` (get current MFA policy)
- `POST /auth/login` (MFA enforcement on login)
- `POST /auth/mfa/totp/disable` (MFA disable blocked by policy)
**Authentication**: JWT (admin for policy config), varies for enforcement
**Applicable Standards**: NIST SP 800-63B AAL2, OWASP ASVS 2.8

---

## Nominal Cases

### TC-POLICY-MFA-001: Get current MFA policy
- **Category**: Nominal
- **Standard**: NIST SP 800-63B
- **Input**: `GET /system/tenants/:id/settings`
- **Expected Output**: Status 200, mfa_policy section:
  ```json
  {
    "mfa_policy": {
      "required": false,
      "allowed_methods": ["totp", "webauthn"],
      "grace_period_days": 0,
      "remember_device_days": 30
    }
  }
  ```

### TC-POLICY-MFA-002: Set MFA as required for all users
- **Category**: Nominal
- **Standard**: NIST SP 800-63B AAL2
- **Input**:
  ```json
  PATCH /system/tenants/:id/settings
  {
    "mfa_policy": {
      "required": true,
      "allowed_methods": ["totp", "webauthn"]
    }
  }
  ```
- **Expected Output**: Status 200, MFA now required
- **Side Effects**: Users without MFA prompted on next login

### TC-POLICY-MFA-003: Login with MFA required - user has TOTP enrolled
- **Category**: Nominal
- **Preconditions**: MFA required by policy, user has TOTP set up
- **Steps**:
  1. `POST /auth/login` with valid credentials
  2. Response: `mfa_required: true`
  3. Submit TOTP code
- **Expected Output**: Full tokens returned after MFA verification

### TC-POLICY-MFA-004: Login with MFA required - user has no MFA enrolled
- **Category**: Nominal
- **Preconditions**: MFA required by policy, user has NOT enrolled MFA
- **Input**: `POST /auth/login` with valid credentials
- **Expected Output**: Login response indicates MFA enrollment required:
  ```json
  {
    "mfa_required": true,
    "mfa_enrollment_required": true,
    "allowed_methods": ["totp", "webauthn"]
  }
  ```

### TC-POLICY-MFA-005: Disable MFA blocked by tenant policy
- **Category**: Nominal
- **Preconditions**: MFA required by tenant policy, user has TOTP enrolled
- **Input**: `POST /auth/mfa/totp/disable` with valid TOTP code
- **Expected Output**: Status 403 "MFA required by tenant policy"

### TC-POLICY-MFA-006: Set MFA as optional
- **Category**: Nominal
- **Input**:
  ```json
  PATCH /system/tenants/:id/settings
  { "mfa_policy": { "required": false } }
  ```
- **Expected Output**: Status 200, users can login without MFA
- **Verification**: Users can also disable their MFA enrollment

### TC-POLICY-MFA-007: Configure allowed MFA methods
- **Category**: Nominal
- **Input**:
  ```json
  PATCH /system/tenants/:id/settings
  { "mfa_policy": { "allowed_methods": ["webauthn"] } }
  ```
- **Expected Output**: Status 200, only WebAuthn allowed
- **Verification**: TOTP setup endpoint returns 403 "Method not allowed by policy"

### TC-POLICY-MFA-008: Set MFA grace period
- **Category**: Nominal
- **Input**:
  ```json
  PATCH /system/tenants/:id/settings
  { "mfa_policy": { "required": true, "grace_period_days": 7 } }
  ```
- **Expected Output**: Status 200
- **Verification**: Users have 7 days to enroll MFA before enforcement begins

---

## Edge Cases

### TC-POLICY-MFA-009: Set MFA required with empty allowed_methods
- **Category**: Edge Case
- **Input**:
  ```json
  { "mfa_policy": { "required": true, "allowed_methods": [] } }
  ```
- **Expected Output**: Status 400 "At least one MFA method must be allowed when MFA is required"

### TC-POLICY-MFA-010: Grace period login within window
- **Category**: Edge Case
- **Preconditions**: MFA required, grace_period_days = 7, user created 3 days ago, no MFA enrolled
- **Input**: `POST /auth/login` with valid credentials
- **Expected Output**: Login succeeds WITHOUT MFA (within grace period), warning returned

### TC-POLICY-MFA-011: Grace period login after window
- **Category**: Edge Case
- **Preconditions**: MFA required, grace_period_days = 7, user created 10 days ago, no MFA enrolled
- **Input**: `POST /auth/login` with valid credentials
- **Expected Output**: Login returns MFA enrollment required (grace period expired)

### TC-POLICY-MFA-012: Set invalid MFA method
- **Category**: Edge Case
- **Input**: `{ "mfa_policy": { "allowed_methods": ["sms"] } }` (SMS not supported)
- **Expected Output**: Status 400 "Unsupported MFA method: sms"

### TC-POLICY-MFA-013: Set negative grace period
- **Category**: Edge Case
- **Input**: `{ "mfa_policy": { "grace_period_days": -1 } }`
- **Expected Output**: Status 400 "Grace period must be non-negative"

---

## Security Cases

### TC-POLICY-MFA-014: Non-admin cannot change MFA policy
- **Category**: Security
- **Input**: Regular user calls `PATCH /system/tenants/:id/settings` with MFA changes
- **Expected Output**: Status 403 Forbidden

### TC-POLICY-MFA-015: Audit trail for MFA policy changes
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Verification**: Audit log records: who changed MFA policy, old value, new value, timestamp
