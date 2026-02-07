# GDPR Data Subject Rights Functional Tests

**API Endpoints**:
- `GET /governance/gdpr/report` (generate GDPR data subject access report)
- `GET /governance/gdpr/users/:user_id/data-protection` (get user data protection status)
**Authentication**: JWT (Bearer token)
**Applicable Standards**: GDPR Articles 15-20 (Data Subject Rights), ISO 27701 (PIMS), SOC 2

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `USER_JWT`, `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: Test users with various data records (sessions, audit logs, group memberships) for comprehensive report generation

---

## Nominal Cases

### TC-GDPR-DSR-001: Generate data subject access report
- **Category**: Nominal
- **Standard**: GDPR Article 15 (Right of Access)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated admin, user exists with multiple data records
- **Input**: `GET /governance/gdpr/report?user_id=<uuid>`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "user_id": "<uuid>",
    "report_generated_at": "2026-02-07T10:00:00Z",
    "personal_data": {
      "profile": {
        "email": "user@example.com",
        "display_name": "Test User",
        "created_at": "2025-01-01T..."
      },
      "sessions": [ ... ],
      "audit_logs": [ ... ],
      "group_memberships": [ ... ],
      "entitlements": [ ... ],
      "consent_records": [ ... ]
    },
    "processing_purposes": [ ... ],
    "data_categories": ["identity", "authentication", "authorization"]
  }
  ```
- **Side Effects**: Audit log: `gdpr.report.generated`

### TC-GDPR-DSR-002: Report includes all personal data categories
- **Category**: Nominal
- **Standard**: GDPR Article 15(1)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User with data across all categories
- **Verification**: Report includes ALL data held about the user:
  - Profile information (email, name, phone)
  - Authentication data (login history, MFA enrollment)
  - Authorization data (roles, groups, entitlements)
  - Session data (active sessions, device info)
  - Audit trail (actions performed)
  - Social connections (linked accounts)

### TC-GDPR-DSR-003: Get user data protection status
- **Category**: Nominal
- **Standard**: GDPR Article 17 (Right to Erasure)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User exists
- **Input**: `GET /governance/gdpr/users/:user_id/data-protection`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "user_id": "<uuid>",
    "data_protection_status": {
      "data_retention_policy": "90_days",
      "erasure_eligible": true,
      "erasure_blockers": [],
      "consent_records": [
        { "purpose": "authentication", "granted_at": "2025-01-01T...", "expires_at": null }
      ],
      "processing_activities": [ ... ]
    }
  }
  ```

### TC-GDPR-DSR-004: Report for user with minimal data
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User just created, no sessions or audit history
- **Input**: `GET /governance/gdpr/report?user_id=<uuid>`
- **Expected Output**: Status 200, report with profile data only, empty arrays for other categories

### TC-GDPR-DSR-005: Report includes data processing purposes
- **Category**: Nominal
- **Standard**: GDPR Article 15(1)(a)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Report generated for user
- **Verification**: Report includes the purposes of processing for each data category

### TC-GDPR-DSR-006: Report includes data retention periods
- **Category**: Nominal
- **Standard**: GDPR Article 15(1)(d)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Report generated for user
- **Verification**: Report includes retention period or criteria for each data category

### TC-GDPR-DSR-007: Data protection status shows erasure blockers
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User has active entitlements that prevent immediate erasure
- **Input**: `GET /governance/gdpr/users/:user_id/data-protection`
- **Expected Output**: `erasure_eligible: false`, `erasure_blockers` lists the blocking reasons

### TC-GDPR-DSR-008: Report generated in machine-readable format
- **Category**: Nominal
- **Standard**: GDPR Article 20 (Right to Data Portability)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Report generated for user
- **Verification**: Report is in structured JSON format suitable for data portability

---

## Edge Cases

### TC-GDPR-DSR-009: Report for non-existent user
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: `GET /governance/gdpr/report?user_id=00000000-0000-0000-0000-000000000099`
- **Expected Output**: Status 404 "User not found"

### TC-GDPR-DSR-010: Report without user_id parameter
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: `GET /governance/gdpr/report`
- **Expected Output**: Status 400 "user_id is required"

### TC-GDPR-DSR-011: Report for user with extensive data
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User with 1000+ audit log entries, 50+ sessions
- **Input**: `GET /governance/gdpr/report?user_id=<uuid>`
- **Expected Output**: Status 200, paginated or complete report within reasonable time

### TC-GDPR-DSR-012: Data protection status for deleted user
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User has been soft-deleted
- **Input**: `GET /governance/gdpr/users/:deleted_user_id/data-protection`
- **Expected Output**: Status 200 with retention countdown OR Status 404

### TC-GDPR-DSR-013: Report with invalid user_id format
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: `GET /governance/gdpr/report?user_id=not-a-uuid`
- **Expected Output**: Status 400 "Invalid user_id format"

---

## Security Cases

### TC-GDPR-DSR-014: Cross-tenant report isolation
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User belongs to tenant A
- **Input**: Admin of tenant B requests report for tenant A's user
- **Expected Output**: Status 404 (user not visible to other tenants)

### TC-GDPR-DSR-015: Non-admin access to own data only
- **Category**: Security
- **Standard**: GDPR Article 15
- **Preconditions**: Fixtures: `USER_JWT`, `TEST_TENANT`. Regular user (non-admin)
- **Input**: `GET /governance/gdpr/report?user_id=<own_user_id>`
- **Expected Output**: Status 200 (users can access their own data) OR Status 403 (admin-only)
- **Verification**: User cannot request report for other users

### TC-GDPR-DSR-016: Report does not include other users' data
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Multiple users in same tenant/groups
- **Verification**: Report for user A contains ONLY user A's data, not data of other users even if they share groups or entitlements

### TC-GDPR-DSR-017: Audit trail for report generation
- **Category**: Security
- **Standard**: GDPR Article 30 (Records of Processing Activities)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Report generated
- **Verification**: Every report generation is logged with: who requested, for which user, when, from what IP

### TC-GDPR-DSR-018: Report does not expose internal system details
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Report generated
- **Verification**: Report does NOT contain:
  - Database table names or column names
  - Internal service names
  - Server IP addresses
  - Password hashes

### TC-GDPR-DSR-019: Password hashes excluded from report
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Report generated for user with password
- **Verification**: User's password hash is NEVER included in the GDPR report

### TC-GDPR-DSR-020: Report rate limiting
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: 50 rapid report generation requests
- **Expected Output**: Rate limited after threshold (429 Too Many Requests)
