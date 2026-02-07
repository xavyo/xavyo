# Service Account Management Functional Tests

**API Endpoints**:
- `POST /nhi/service-accounts` - Create service account
- `GET /nhi/service-accounts` - List service accounts
- `GET /nhi/service-accounts/summary` - Summary statistics
- `GET /nhi/service-accounts/:id` - Get service account
- `PUT /nhi/service-accounts/:id` - Update service account
- `DELETE /nhi/service-accounts/:id` - Delete service account
- `POST /nhi/service-accounts/:id/suspend` - Suspend
- `POST /nhi/service-accounts/:id/reactivate` - Reactivate
- `POST /nhi/service-accounts/:id/transfer-ownership` - Transfer ownership
- `POST /nhi/service-accounts/:id/certify` - Certify ownership
- `POST /nhi/service-accounts/:id/credentials/rotate` - Rotate credentials
- `GET /nhi/service-accounts/:id/credentials` - List credentials
- `POST /nhi/service-accounts/:nhi_id/credentials/:credential_id/revoke` - Revoke credential
- `POST /nhi/service-accounts/:id/usage` - Record usage
- `GET /nhi/service-accounts/:id/usage` - List usage
- `GET /nhi/service-accounts/:id/risk` - Get risk score
- `POST /nhi/service-accounts/:id/risk/calculate` - Recalculate risk

**Authentication**: Bearer JWT (admin role required for mutations)
**Required Headers**: `Content-Type: application/json`, `Authorization: Bearer <jwt>`
**Applicable Standards**: NIST SP 800-53 AC-2(6) (Automated Account Management), SOC 2 CC6.1, SOC 2 CC6.3

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: Some test cases require a pre-existing service account (created via TC-NHI-SA-001 or equivalent)

---

## Nominal Cases

### TC-NHI-SA-001: Create service account with all required fields
- **Category**: Nominal
- **Standard**: NIST SP 800-53 AC-2(6)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated admin user
- **Input**:
  ```json
  POST /nhi/service-accounts
  {
    "name": "billing-sync-service",
    "purpose": "Synchronize billing data between CRM and ERP",
    "owner_id": "<user-uuid>",
    "nhi_type": "service_account",
    "risk_level": "medium",
    "environment": "production",
    "requested_permissions": ["billing:read", "billing:write"],
    "expiration_date": "2027-01-01T00:00:00Z",
    "rotation_interval_days": 90
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<uuid>",
    "name": "billing-sync-service",
    "purpose": "Synchronize billing data between CRM and ERP",
    "status": "active",
    "nhi_type": "service_account",
    "owner_id": "<user-uuid>",
    "risk_level": "medium",
    "created_at": "<ISO8601>",
    "updated_at": "<ISO8601>"
  }
  ```

### TC-NHI-SA-002: List service accounts with pagination
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. 8 service accounts exist
- **Input**: `GET /nhi/service-accounts?limit=3&offset=0`
- **Expected Output**:
  ```json
  Status: 200 OK
  {
    "items": [ {...}, {...}, {...} ],
    "total": 8,
    "limit": 3,
    "offset": 0
  }
  ```

### TC-NHI-SA-003: List service accounts with status filter
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Mix of active and suspended service accounts exist
- **Input**: `GET /nhi/service-accounts?status=active`
- **Expected Output**: Status 200, only active service accounts

### TC-NHI-SA-004: Get service account summary statistics
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Service accounts exist in tenant
- **Input**: `GET /nhi/service-accounts/summary`
- **Expected Output**:
  ```json
  Status: 200 OK
  {
    "total": 8,
    "active": 5,
    "suspended": 2,
    "expired": 1,
    ...
  }
  ```

### TC-NHI-SA-005: Get service account by ID
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_SA`. Service account exists
- **Input**: `GET /nhi/service-accounts/<sa-id>`
- **Expected Output**: Status 200, full service account object

### TC-NHI-SA-006: Update service account purpose and risk level
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_SA`. Service account exists
- **Input**:
  ```json
  PUT /nhi/service-accounts/<sa-id>
  {
    "purpose": "Updated purpose description",
    "risk_level": "high"
  }
  ```
- **Expected Output**: Status 200, updated fields reflected

### TC-NHI-SA-007: Delete service account
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_SA`. Service account exists
- **Input**: `DELETE /nhi/service-accounts/<sa-id>`
- **Expected Output**: Status 204 No Content
- **Verification**: Subsequent GET returns 404

### TC-NHI-SA-008: Suspend service account with reason
- **Category**: Nominal
- **Standard**: NIST SP 800-53 AC-2(6)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_SA`. Active service account exists
- **Input**:
  ```json
  POST /nhi/service-accounts/<sa-id>/suspend
  {
    "reason": "Security review required",
    "details": "Anomalous activity detected in billing API calls"
  }
  ```
- **Expected Output**:
  ```json
  Status: 200 OK
  { "status": "suspended", ... }
  ```

### TC-NHI-SA-009: Reactivate suspended service account
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_SA`. Service account is suspended
- **Input**:
  ```json
  POST /nhi/service-accounts/<sa-id>/reactivate
  { "reason": "Security review completed, no issues found" }
  ```
- **Expected Output**: Status 200, `status=active`

### TC-NHI-SA-010: Transfer ownership of service account
- **Category**: Nominal
- **Standard**: SOC 2 CC6.3 (Role-based access)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_SA`. Service account exists with current owner
- **Input**:
  ```json
  POST /nhi/service-accounts/<sa-id>/transfer-ownership
  {
    "new_owner_id": "<new-user-uuid>",
    "reason": "Team restructuring"
  }
  ```
- **Expected Output**: Status 200, `owner_id` updated to new owner

### TC-NHI-SA-011: Certify service account ownership
- **Category**: Nominal
- **Standard**: SOC 2 CC6.1 (Periodic access review)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_SA`. Service account exists
- **Input**: `POST /nhi/service-accounts/<sa-id>/certify`
- **Expected Output**:
  ```json
  Status: 200 OK
  {
    "nhi": { ... },
    "message": "Service account ownership and purpose confirmed"
  }
  ```

### TC-NHI-SA-012: Record usage event for service account
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_SA`. Service account exists
- **Input**:
  ```json
  POST /nhi/service-accounts/<sa-id>/usage
  {
    "action": "api_call",
    "resource": "billing-api",
    "details": { "endpoint": "/invoices", "method": "GET" }
  }
  ```
- **Expected Output**: Status 201

### TC-NHI-SA-013: List usage events for service account
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_SA`. Service account has usage events
- **Input**: `GET /nhi/service-accounts/<sa-id>/usage`
- **Expected Output**: Status 200, paginated list of usage events

### TC-NHI-SA-014: Get risk score for service account
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_SA`. Service account exists
- **Input**: `GET /nhi/service-accounts/<sa-id>/risk`
- **Expected Output**:
  ```json
  Status: 200 OK
  {
    "nhi_id": "<sa-id>",
    "risk_score": 45,
    "risk_level": "medium",
    "factors": { ... },
    "calculated_at": "<ISO8601>"
  }
  ```

### TC-NHI-SA-015: Recalculate risk score
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_SA`. Service account exists
- **Input**: `POST /nhi/service-accounts/<sa-id>/risk/calculate`
- **Expected Output**: Status 200, freshly calculated risk score

---

## Edge Cases

### TC-NHI-SA-020: Create service account with duplicate name
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Service account "billing-sync-service" exists
- **Input**: Create with same name
- **Expected Output**: Status 409 Conflict

### TC-NHI-SA-021: Get non-existent service account
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: `GET /nhi/service-accounts/<nonexistent-uuid>`
- **Expected Output**: Status 404

### TC-NHI-SA-022: Suspend already-suspended service account
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_SA`. Service account is already suspended
- **Input**: Suspend an already-suspended account
- **Expected Output**: Status 400 ("Already suspended")

### TC-NHI-SA-023: Reactivate service account that is not suspended
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_SA`. Service account is active (not suspended)
- **Input**: Reactivate an active service account
- **Expected Output**: Status 400 ("Not suspended")

### TC-NHI-SA-024: Transfer ownership to non-existent user
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_SA`. Service account exists
- **Input**: `{ "new_owner_id": "<nonexistent-user>", "reason": "test" }`
- **Expected Output**: Status 400 or 404

### TC-NHI-SA-025: Delete service account with active credentials
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_SA`. Service account has active credentials
- **Input**: `DELETE /nhi/service-accounts/<sa-id>`
- **Expected Output**: Status 204 (credentials should be revoked as part of deletion)
- **Verification**: All associated credentials are revoked

### TC-NHI-SA-026: List service accounts with offset beyond total
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Service accounts exist in tenant
- **Input**: `GET /nhi/service-accounts?offset=1000`
- **Expected Output**: Status 200, empty items array, total reflects actual count

### TC-NHI-SA-027: Create service account with empty name
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: `{ "name": "", "purpose": "test", "nhi_type": "service_account" }`
- **Expected Output**: Status 400 (name required)

### TC-NHI-SA-028: Get usage summary with custom period
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_SA`. Service account has usage events
- **Input**: `GET /nhi/service-accounts/<sa-id>/usage/summary?period_days=7`
- **Expected Output**: Status 200, summary for last 7 days

### TC-NHI-SA-029: Risk score for newly created account (no usage data)
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_SA`. Newly created service account with no usage
- **Input**: Calculate risk for account with zero usage events
- **Expected Output**: Status 200, risk score based on configuration factors only

---

## Security Cases

### TC-NHI-SA-030: Create service account without admin role
- **Category**: Security
- **Standard**: NIST SP 800-53 AC-2(6)
- **Preconditions**: Fixtures: `TEST_TENANT`. Authenticated non-admin user
- **Input**: Non-admin attempts `POST /nhi/service-accounts { ... }`
- **Expected Output**: Status 403 Forbidden ("Admin role required")

### TC-NHI-SA-031: Update service account without admin role
- **Category**: Security
- **Preconditions**: Fixtures: `TEST_TENANT`, `TEST_SA`. Authenticated non-admin user
- **Input**: Non-admin attempts `PUT /nhi/service-accounts/<id> { ... }`
- **Expected Output**: Status 403 Forbidden

### TC-NHI-SA-032: Delete service account without admin role
- **Category**: Security
- **Preconditions**: Fixtures: `TEST_TENANT`, `TEST_SA`. Authenticated non-admin user
- **Input**: Non-admin attempts `DELETE /nhi/service-accounts/<id>`
- **Expected Output**: Status 403 Forbidden

### TC-NHI-SA-033: Suspend service account without admin role
- **Category**: Security
- **Preconditions**: Fixtures: `TEST_TENANT`, `TEST_SA`. Authenticated non-admin user
- **Input**: Non-admin attempts suspend
- **Expected Output**: Status 403 Forbidden

### TC-NHI-SA-034: Cross-tenant service account isolation
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Service account in Tenant A; second tenant JWT available
- **Input**: Tenant B admin attempts `GET /nhi/service-accounts/<tenant-a-sa-id>`
- **Expected Output**: Status 404 (tenant isolation)

### TC-NHI-SA-035: Cross-tenant ownership transfer attempt
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Second tenant JWT available
- **Input**: Tenant B admin attempts to transfer Tenant A service account
- **Expected Output**: Status 404

### TC-NHI-SA-036: Service account without authentication
- **Category**: Security
- **Preconditions**: Fixtures: `TEST_TENANT`. No authentication header provided
- **Input**: Any endpoint without Authorization header
- **Expected Output**: Status 401 Unauthorized

### TC-NHI-SA-037: Credential secret not retrievable after creation
- **Category**: Security
- **Standard**: NIST SP 800-63B
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_SA`. Service account has credentials
- **Verification**: `GET /nhi/service-accounts/<id>/credentials/<cred-id>` never returns the plaintext secret

### TC-NHI-SA-038: SQL injection in service account name
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: `{ "name": "'; DROP TABLE gov_nhi_credentials; --", ... }`
- **Expected Output**: Status 400 or 201 (parameterized queries), no SQL execution

### TC-NHI-SA-039: Response sanitization (no internal errors)
- **Category**: Security
- **Standard**: OWASP ASVS 7.4.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Verification**: Error responses contain sanitized messages, no stack traces, SQL fragments, or internal paths

### TC-NHI-SA-040: Service account request workflow (request-approve-provision)
- **Category**: Security
- **Standard**: NIST SP 800-53 AC-2(6)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Non-admin user and admin user available
- **Input**:
  1. Non-admin submits: `POST /nhi/service-accounts/requests { "name": "new-svc", "purpose": "CI/CD pipeline" }`
  2. Admin approves: `POST /nhi/service-accounts/requests/<req-id>/approve { "comments": "Approved" }`
- **Expected Output**:
  - Step 1: Status 201, request in `pending` status
  - Step 2: Status 200, request `approved`, secret returned once
- **Verification**: Non-admin cannot bypass the approval workflow

### TC-NHI-SA-041: Reject service account request
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Pending service account request exists
- **Input**: `POST /nhi/service-accounts/requests/<req-id>/reject { "reason": "Not justified" }`
- **Expected Output**: Status 200, request status = `rejected`

### TC-NHI-SA-042: Cancel own request
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Pending request created by current user
- **Input**: Original requester cancels: `POST /nhi/service-accounts/requests/<req-id>/cancel`
- **Expected Output**: Status 200, request status = `cancelled`

### TC-NHI-SA-043: Cancel another user's request
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Pending request created by a different user
- **Input**: Different user attempts cancel
- **Expected Output**: Status 403 ("Only requester can cancel")

### TC-NHI-SA-044: Approve already-decided request
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Request has already been rejected
- **Input**: Approve a request that was already rejected
- **Expected Output**: Status 400 ("Already decided")

### TC-NHI-SA-045: Revoke credential records actor identity
- **Category**: Security
- **Standard**: SOC 2 CC7.2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_SA`. Service account has active credentials
- **Input**: Revoke credential
- **Verification**: `revoked_by` field contains the actor_id from JWT, not a hardcoded "system" value
