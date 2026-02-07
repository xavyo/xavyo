# Tenant Settings and Security Policies Functional Tests

**API Endpoints**:
- `GET /system/tenants/:id/settings` (get tenant settings)
- `PATCH /system/tenants/:id/settings` (update tenant settings)
- `GET /tenants/:tenant_id/settings` (get tenant user-facing settings)
- `PATCH /tenants/:tenant_id/settings` (update tenant user-facing settings)
- `GET /organizations/:org_id/security-policies` (list security policies)
- `POST /organizations/:org_id/security-policies` (create security policy)
- `GET /organizations/:org_id/security-policies/:policy_type` (get specific policy)
- `PUT /organizations/:org_id/security-policies/:policy_type` (upsert policy)
- `DELETE /organizations/:org_id/security-policies/:policy_type` (delete policy)
- `POST /organizations/:org_id/security-policies/validate` (validate policy)
**Authentication**: JWT (Bearer token) with admin role
**Applicable Standards**: ISO 27001 Annex A.9 (Access Control), NIST SP 800-63B

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: Organization must exist for security policy tests

---

## Nominal Cases

### TC-TENANT-SET-001: Get tenant settings
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated system admin
- **Input**: `GET /system/tenants/:id/settings`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "tenant_id": "<uuid>",
    "settings": {
      "password_policy": {
        "min_length": 8,
        "require_uppercase": true,
        "require_lowercase": true,
        "require_digits": true,
        "require_special": true,
        "max_age_days": 90
      },
      "mfa_policy": {
        "required": false,
        "allowed_methods": ["totp", "webauthn"]
      },
      "session_policy": {
        "max_sessions": 5,
        "idle_timeout_minutes": 30,
        "absolute_timeout_hours": 24
      },
      "branding": { ... }
    }
  }
  ```

### TC-TENANT-SET-002: Update password policy settings
- **Category**: Nominal
- **Standard**: NIST SP 800-63B Section 5.1.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```json
  PATCH /system/tenants/:id/settings
  {
    "password_policy": {
      "min_length": 12,
      "require_special": true,
      "max_age_days": 60
    }
  }
  ```
- **Expected Output**: Status 200, settings updated
- **Side Effects**: New password policy applied to future password changes, audit log: `tenant.settings.updated`

### TC-TENANT-SET-003: Update MFA policy to required
- **Category**: Nominal
- **Standard**: NIST SP 800-63B AAL2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
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
- **Expected Output**: Status 200, MFA now required for all users in tenant
- **Side Effects**: Users without MFA prompted on next login

### TC-TENANT-SET-004: Update session timeout settings
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```json
  PATCH /system/tenants/:id/settings
  {
    "session_policy": {
      "idle_timeout_minutes": 15,
      "absolute_timeout_hours": 8
    }
  }
  ```
- **Expected Output**: Status 200, session timeouts updated

### TC-TENANT-SET-005: Get tenant user-facing settings
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Tenant admin authenticated
- **Input**: `GET /tenants/:tenant_id/settings`
- **Expected Output**: Status 200, settings visible to tenant admin

### TC-TENANT-SET-006: Create organization security policy
- **Category**: Nominal
- **Standard**: ISO 27001 Annex A.9
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Organization exists
- **Input**:
  ```json
  POST /organizations/:org_id/security-policies
  {
    "policy_type": "password",
    "config": {
      "min_length": 14,
      "require_special": true,
      "max_age_days": 45,
      "history_count": 10
    }
  }
  ```
- **Expected Output**: Status 201, policy created
- **Side Effects**: Overrides tenant-level password policy for this organization

### TC-TENANT-SET-007: Get specific security policy
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Security policy exists
- **Input**: `GET /organizations/:org_id/security-policies/password`
- **Expected Output**: Status 200, password policy configuration

### TC-TENANT-SET-008: Update security policy (upsert)
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Organization exists
- **Input**:
  ```json
  PUT /organizations/:org_id/security-policies/mfa
  {
    "config": {
      "required": true,
      "grace_period_days": 7
    }
  }
  ```
- **Expected Output**: Status 200, policy created or updated

### TC-TENANT-SET-009: List all security policies for organization
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Organization exists with policies
- **Input**: `GET /organizations/:org_id/security-policies`
- **Expected Output**: Status 200, list of all policy types and their configurations

### TC-TENANT-SET-010: Delete security policy
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Security policy exists
- **Input**: `DELETE /organizations/:org_id/security-policies/password`
- **Expected Output**: Status 200, policy deleted, tenant-level defaults apply

### TC-TENANT-SET-011: Validate security policy for conflicts
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Organization exists
- **Input**:
  ```json
  POST /organizations/:org_id/security-policies/validate
  {
    "policy_type": "session",
    "config": {
      "idle_timeout_minutes": 5,
      "absolute_timeout_hours": 1
    }
  }
  ```
- **Expected Output**: Status 200, validation result (conflicts or OK)

---

## Edge Cases

### TC-TENANT-SET-012: Update settings with invalid password min_length
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: `{ "password_policy": { "min_length": 3 } }` (below NIST minimum)
- **Expected Output**: Status 400 "Minimum password length must be at least 8"

### TC-TENANT-SET-013: Update settings with negative timeout
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: `{ "session_policy": { "idle_timeout_minutes": -1 } }`
- **Expected Output**: Status 400 "Timeout must be positive"

### TC-TENANT-SET-014: Update settings with zero max sessions
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: `{ "session_policy": { "max_sessions": 0 } }`
- **Expected Output**: Status 400 "Max sessions must be at least 1"

### TC-TENANT-SET-015: Delete non-existent security policy
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: `DELETE /organizations/:org_id/security-policies/nonexistent`
- **Expected Output**: Status 404

### TC-TENANT-SET-016: Create policy for non-existent organization
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: `POST /organizations/00000000-0000-0000-0000-000000000099/security-policies`
- **Expected Output**: Status 404 "Organization not found"

### TC-TENANT-SET-017: Partial settings update preserves other fields
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Settings with known initial values
- **Steps**:
  1. Note current settings (password min_length=8, require_special=true)
  2. `PATCH` only `{ "password_policy": { "min_length": 12 } }`
  3. Get settings
- **Expected Output**: `min_length` is 12, `require_special` remains true (not reset)

---

## Security Cases

### TC-TENANT-SET-018: Non-admin cannot modify settings
- **Category**: Security
- **Preconditions**: Fixtures: `TEST_TENANT`. Authenticated as regular (non-admin) user
- **Input**: Regular user calls `PATCH /system/tenants/:id/settings`
- **Expected Output**: Status 403 Forbidden

### TC-TENANT-SET-019: Cross-tenant settings isolation
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Two tenants exist
- **Input**: Admin of tenant A tries to modify tenant B's settings
- **Expected Output**: Status 403 Forbidden

### TC-TENANT-SET-020: Audit trail for settings changes
- **Category**: Security
- **Standard**: SOC 2 CC6.1, ISO 27001
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Settings changes performed
- **Verification**: All settings changes logged with: who changed, what changed (before/after), when
