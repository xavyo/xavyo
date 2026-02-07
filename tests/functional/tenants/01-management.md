# Tenant Management Functional Tests

**API Endpoints**:
- `POST /tenants/provision` (provision new tenant)
- `GET /system/tenants/:id` (get tenant status)
- `POST /system/tenants/:id/suspend` (suspend tenant)
- `POST /system/tenants/:id/reactivate` (reactivate suspended tenant)
- `POST /system/tenants/:id/delete` (soft delete tenant)
- `POST /system/tenants/:id/restore` (restore soft-deleted tenant)
- `GET /system/tenants/deleted` (list deleted tenants)
- `GET /system/tenants/:id/usage` (get usage metrics)
- `GET /system/tenants/:id/usage/history` (get usage history)
- Plan Management:
  - `POST /system/tenants/:id/plan/upgrade` (upgrade plan)
  - `POST /system/tenants/:id/plan/downgrade` (downgrade plan)
  - `DELETE /system/tenants/:id/plan/pending` (cancel pending downgrade)
  - `GET /system/tenants/:id/plan/history` (get plan history)
  - `GET /system/plans` (list available plans)
**Authentication**: Public (provision, rate-limited), JWT (system admin for management)
**Applicable Standards**: Multi-tenancy isolation, SOC 2 Type II

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `SYS_TENANT`
- **Special Setup**: System admin JWT required for management endpoints; provisioning endpoint is public

---

## Nominal Cases

### TC-TENANT-MGMT-001: Provision new tenant
- **Category**: Nominal
- **Standard**: Multi-tenancy isolation
- **Preconditions**: Fixtures: `SYS_TENANT`. None (public endpoint, rate-limited)
- **Input**:
  ```json
  POST /tenants/provision
  {
    "name": "Acme Corp",
    "slug": "acme-corp",
    "admin_email": "admin@acme.com",
    "admin_password": "MyP@ssw0rd_2026"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "tenant_id": "<uuid>",
    "name": "Acme Corp",
    "slug": "acme-corp",
    "status": "active",
    "admin_user_id": "<uuid>",
    "api_key": "xavyo_<key>"
  }
  ```
- **Side Effects**:
  - Tenant record created in database
  - Admin user created with `admin` role
  - Default API key generated
  - Default tenant settings applied
  - Audit log: `tenant.provisioned`

### TC-TENANT-MGMT-002: Get tenant status
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `SYS_TENANT`. System admin authenticated
- **Input**: `GET /system/tenants/:id`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "id": "<uuid>",
    "name": "Acme Corp",
    "slug": "acme-corp",
    "status": "active",
    "plan": "free",
    "created_at": "2026-02-07T...",
    "user_count": 5,
    "group_count": 2
  }
  ```

### TC-TENANT-MGMT-003: Suspend tenant
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `SYS_TENANT`. Tenant is active
- **Input**: `POST /system/tenants/:id/suspend`
- **Expected Output**: Status 200, tenant status changes to "suspended"
- **Side Effects**:
  - All tenant users cannot login
  - API keys for tenant stop working
  - Audit log: `tenant.suspended`

### TC-TENANT-MGMT-004: Reactivate suspended tenant
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `SYS_TENANT`. Tenant is suspended
- **Input**: `POST /system/tenants/:id/reactivate`
- **Expected Output**: Status 200, tenant status changes to "active"
- **Side Effects**: Users can login again, API keys work again

### TC-TENANT-MGMT-005: Soft delete tenant
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `SYS_TENANT`. Tenant exists
- **Input**: `POST /system/tenants/:id/delete`
- **Expected Output**: Status 200, tenant soft-deleted
- **Side Effects**:
  - `deleted_at` timestamp set
  - Tenant no longer appears in normal queries
  - Data retained for grace period

### TC-TENANT-MGMT-006: Restore soft-deleted tenant
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `SYS_TENANT`. Tenant is soft-deleted within grace period
- **Input**: `POST /system/tenants/:id/restore`
- **Expected Output**: Status 200, tenant restored to active status

### TC-TENANT-MGMT-007: List soft-deleted tenants
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `SYS_TENANT`
- **Input**: `GET /system/tenants/deleted`
- **Expected Output**: Status 200, list of all soft-deleted tenants with `deleted_at` timestamps

### TC-TENANT-MGMT-008: Get tenant usage metrics
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `SYS_TENANT`
- **Input**: `GET /system/tenants/:id/usage`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "tenant_id": "<uuid>",
    "user_count": 50,
    "group_count": 10,
    "api_key_count": 3,
    "connector_count": 2,
    "storage_bytes": 1048576
  }
  ```

### TC-TENANT-MGMT-009: Get usage history
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `SYS_TENANT`
- **Input**: `GET /system/tenants/:id/usage/history`
- **Expected Output**: Status 200, array of daily usage snapshots

### TC-TENANT-MGMT-010: List available plans
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `SYS_TENANT`
- **Input**: `GET /system/plans`
- **Expected Output**: Status 200, list of plans with features and limits

### TC-TENANT-MGMT-011: Upgrade tenant plan
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `SYS_TENANT`. Tenant on a lower plan
- **Input**:
  ```json
  POST /system/tenants/:id/plan/upgrade
  { "plan": "enterprise" }
  ```
- **Expected Output**: Status 200, plan upgraded immediately
- **Side Effects**: New plan limits take effect, audit log: `tenant.plan.upgraded`

### TC-TENANT-MGMT-012: Downgrade tenant plan
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `SYS_TENANT`. Tenant on a higher plan
- **Input**:
  ```json
  POST /system/tenants/:id/plan/downgrade
  { "plan": "free" }
  ```
- **Expected Output**: Status 200, downgrade scheduled (takes effect at end of billing period)

### TC-TENANT-MGMT-013: Cancel pending downgrade
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `SYS_TENANT`. Downgrade is pending
- **Input**: `DELETE /system/tenants/:id/plan/pending`
- **Expected Output**: Status 200, downgrade cancelled

### TC-TENANT-MGMT-014: Get plan change history
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `SYS_TENANT`
- **Input**: `GET /system/tenants/:id/plan/history`
- **Expected Output**: Status 200, chronological list of plan changes

---

## Edge Cases

### TC-TENANT-MGMT-015: Provision tenant with duplicate slug
- **Category**: Edge Case
- **Preconditions**: Fixtures: `SYS_TENANT`. Tenant with slug "acme-corp" already exists
- **Input**: `POST /tenants/provision` with same slug
- **Expected Output**: Status 409 "Slug already taken"

### TC-TENANT-MGMT-016: Provision tenant with invalid slug
- **Category**: Edge Case
- **Preconditions**: Fixtures: `SYS_TENANT`
- **Input**: `{ "name": "Test", "slug": "INVALID SLUG!", ... }`
- **Expected Output**: Status 400 "Slug must contain only lowercase alphanumeric and hyphens"

### TC-TENANT-MGMT-017: Provision tenant with missing required fields
- **Category**: Edge Case
- **Preconditions**: Fixtures: `SYS_TENANT`
- **Input**: `{ "name": "Test" }` (missing slug, admin_email, admin_password)
- **Expected Output**: Status 400 with validation errors

### TC-TENANT-MGMT-018: Suspend already suspended tenant
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `SYS_TENANT`. Tenant is already suspended
- **Input**: `POST /system/tenants/:suspended_id/suspend`
- **Expected Output**: Status 400 "Tenant already suspended" OR Status 200 (idempotent)

### TC-TENANT-MGMT-019: Reactivate non-suspended tenant
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `SYS_TENANT`. Tenant is active
- **Input**: `POST /system/tenants/:active_id/reactivate`
- **Expected Output**: Status 400 "Tenant is not suspended"

### TC-TENANT-MGMT-020: Restore non-deleted tenant
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `SYS_TENANT`. Tenant is active
- **Input**: `POST /system/tenants/:active_id/restore`
- **Expected Output**: Status 400 "Tenant is not deleted"

### TC-TENANT-MGMT-021: Get non-existent tenant
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `SYS_TENANT`
- **Input**: `GET /system/tenants/00000000-0000-0000-0000-000000000099`
- **Expected Output**: Status 404

### TC-TENANT-MGMT-022: Upgrade to current plan
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `SYS_TENANT`. Tenant on a specific plan
- **Input**: Upgrade to the plan the tenant is already on
- **Expected Output**: Status 400 "Already on this plan" OR Status 200 (no-op)

### TC-TENANT-MGMT-023: Downgrade when usage exceeds lower plan limits
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `SYS_TENANT`. Enterprise plan with 500 users, free plan limit is 50
- **Input**: Downgrade to free plan
- **Expected Output**: Status 400 "Current usage exceeds target plan limits" OR Warning

### TC-TENANT-MGMT-024: Provision with very long tenant name
- **Category**: Edge Case
- **Preconditions**: Fixtures: `SYS_TENANT`
- **Input**: Tenant name with 500 characters
- **Expected Output**: Status 400 (validation limit)

---

## Security Cases

### TC-TENANT-MGMT-025: Provisioning rate limiting
- **Category**: Security
- **Standard**: OWASP ASVS 11.1.4
- **Preconditions**: Fixtures: `SYS_TENANT`
- **Input**: 20 rapid `POST /tenants/provision` from same IP
- **Expected Output**: Rate limited after 10 requests per hour (429 Too Many Requests)

### TC-TENANT-MGMT-026: Non-system-admin cannot access system endpoints
- **Category**: Security
- **Preconditions**: Fixtures: `SYS_TENANT`. Authenticated as regular tenant admin (not system admin)
- **Input**: `GET /system/tenants/:id`
- **Expected Output**: Status 403 Forbidden

### TC-TENANT-MGMT-027: Tenant isolation in data access
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `SYS_TENANT`. Tenant A and Tenant B exist
- **Verification**: Users in tenant A cannot see or access tenant B's data via any API endpoint

### TC-TENANT-MGMT-028: Suspended tenant blocks all API access
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `SYS_TENANT`. Tenant is suspended
- **Input**: Any authenticated API call from a user in the suspended tenant
- **Expected Output**: Status 403 "Tenant is suspended"

### TC-TENANT-MGMT-029: Provisioning password follows policy
- **Category**: Security
- **Standard**: NIST SP 800-63B
- **Preconditions**: Fixtures: `SYS_TENANT`
- **Input**: `POST /tenants/provision` with weak admin password
- **Expected Output**: Status 400 "Password does not meet requirements"

### TC-TENANT-MGMT-030: Audit trail for all tenant lifecycle events
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `SYS_TENANT`. Tenant lifecycle operations performed
- **Verification**: Audit log entries for: provision, suspend, reactivate, delete, restore, plan change
