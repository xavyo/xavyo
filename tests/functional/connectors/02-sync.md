# Connector Sync Operations Functional Tests

**API Endpoints**:
- `POST /connectors/:id/sync/trigger` (trigger manual sync)
- `GET /connectors/:id/sync/status` (get sync status)
- `GET /connectors/:id/sync/config` (get sync configuration)
- `PUT /connectors/:id/sync/config` (update sync configuration)
- `POST /connectors/:id/sync/enable` (enable periodic sync)
- `POST /connectors/:id/sync/disable` (disable periodic sync)
- `GET /connectors/:id/sync/token` (get sync token / watermark)
- `DELETE /connectors/:id/sync/token` (reset sync token)
- `GET /connectors/:id/sync/changes` (list inbound changes)
- `GET /connectors/:id/sync/changes/:change_id` (get change details)
- `POST /connectors/:id/sync/changes/:change_id/retry` (retry failed change)
- `GET /connectors/:id/sync/conflicts` (list sync conflicts)
- `POST /connectors/:id/sync/conflicts/:conflict_id/resolve` (resolve conflict)
**Authentication**: JWT (Bearer token) with admin role
**Applicable Standards**: Identity lifecycle provisioning, SCIM 2.0 sync

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`, `TEST_CONNECTOR`
- **Special Setup**: Active connector with reachable remote system for sync operations

---

## Nominal Cases

### TC-CONN-SYNC-001: Trigger manual sync
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_CONNECTOR`. Active connector with valid credentials
- **Input**: `POST /connectors/:id/sync/trigger`
- **Expected Output**:
  ```
  Status: 202 Accepted
  Body: {
    "sync_id": "<uuid>",
    "status": "pending",
    "started_at": "2026-02-07T10:00:00Z"
  }
  ```
- **Side Effects**: Sync job queued, audit log: `connector.sync.triggered`

### TC-CONN-SYNC-002: Get sync status
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_CONNECTOR`. Sync has been triggered and completed
- **Input**: `GET /connectors/:id/sync/status`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "last_sync": {
      "sync_id": "<uuid>",
      "status": "completed",
      "started_at": "2026-02-07T10:00:00Z",
      "completed_at": "2026-02-07T10:02:30Z",
      "records_processed": 150,
      "records_created": 10,
      "records_updated": 5,
      "records_failed": 0
    },
    "sync_enabled": true,
    "next_sync_at": "2026-02-07T11:00:00Z"
  }
  ```

### TC-CONN-SYNC-003: Get sync configuration
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_CONNECTOR`
- **Input**: `GET /connectors/:id/sync/config`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "sync_interval_minutes": 60,
    "sync_type": "delta",
    "object_classes": ["user", "group"],
    "filters": { "user": "(objectClass=person)" }
  }
  ```

### TC-CONN-SYNC-004: Update sync configuration
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_CONNECTOR`
- **Input**:
  ```json
  PUT /connectors/:id/sync/config
  {
    "sync_interval_minutes": 30,
    "sync_type": "full",
    "object_classes": ["user"]
  }
  ```
- **Expected Output**: Status 200, config updated
- **Side Effects**: Next sync uses new configuration

### TC-CONN-SYNC-005: Enable periodic sync
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_CONNECTOR`. Sync is disabled
- **Input**: `POST /connectors/:id/sync/enable`
- **Expected Output**: Status 200, sync enabled
- **Verification**: `GET /connectors/:id/sync/status` shows `sync_enabled: true`

### TC-CONN-SYNC-006: Disable periodic sync
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_CONNECTOR`. Sync is enabled
- **Input**: `POST /connectors/:id/sync/disable`
- **Expected Output**: Status 200, sync disabled, no future automatic syncs

### TC-CONN-SYNC-007: List inbound changes from sync
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_CONNECTOR`. Delta sync completed with 3 changes detected
- **Input**: `GET /connectors/:id/sync/changes`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "changes": [
      { "id": "...", "change_type": "create", "object_type": "user", "status": "applied", ... },
      { "id": "...", "change_type": "update", "object_type": "user", "status": "applied", ... },
      { "id": "...", "change_type": "delete", "object_type": "user", "status": "pending", ... }
    ]
  }
  ```

### TC-CONN-SYNC-008: Retry a failed change
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_CONNECTOR`. Change failed with transient error
- **Input**: `POST /connectors/:id/sync/changes/:change_id/retry`
- **Expected Output**: Status 200, change reprocessed

### TC-CONN-SYNC-009: Get sync token (watermark)
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_CONNECTOR`
- **Input**: `GET /connectors/:id/sync/token`
- **Expected Output**: Status 200, current sync watermark for delta sync

### TC-CONN-SYNC-010: Reset sync token for full re-sync
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_CONNECTOR`
- **Input**: `DELETE /connectors/:id/sync/token`
- **Expected Output**: Status 200, next sync will perform full import

---

## Edge Cases

### TC-CONN-SYNC-011: Trigger sync on inactive connector
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_CONNECTOR`. Connector is deactivated
- **Input**: `POST /connectors/:id/sync/trigger`
- **Expected Output**: Status 400 "Connector is not active"

### TC-CONN-SYNC-012: Trigger sync while another sync is running
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_CONNECTOR`. Sync currently in progress
- **Input**: `POST /connectors/:id/sync/trigger`
- **Expected Output**: Status 409 "Sync already in progress"

### TC-CONN-SYNC-013: Sync with unreachable remote system
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_CONNECTOR`. Remote LDAP server is down
- **Input**: `POST /connectors/:id/sync/trigger`
- **Expected Output**: Sync starts but fails with connection error; status shows `"failed"`

### TC-CONN-SYNC-014: List sync conflicts
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_CONNECTOR`. User modified in both xavyo and remote system since last sync
- **Input**: `GET /connectors/:id/sync/conflicts`
- **Expected Output**: Status 200, conflict record with both versions

### TC-CONN-SYNC-015: Resolve sync conflict
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_CONNECTOR`. Existing sync conflict
- **Input**:
  ```json
  POST /connectors/:id/sync/conflicts/:conflict_id/resolve
  { "resolution": "keep_local" }
  ```
- **Expected Output**: Status 200, conflict resolved

### TC-CONN-SYNC-016: Sync with invalid configuration
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_CONNECTOR`
- **Input**: `PUT /connectors/:id/sync/config` with `{ "sync_interval_minutes": -1 }`
- **Expected Output**: Status 400 "Invalid sync interval"

---

## Security Cases

### TC-CONN-SYNC-017: Non-admin cannot trigger sync
- **Category**: Security
- **Preconditions**: Fixtures: `TEST_TENANT`, `TEST_CONNECTOR`. Authenticated as regular (non-admin) user
- **Input**: Regular user calls `POST /connectors/:id/sync/trigger`
- **Expected Output**: Status 403 Forbidden

### TC-CONN-SYNC-018: Cross-tenant sync isolation
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_CONNECTOR`. Connector belongs to tenant A
- **Input**: Admin of tenant B calls `POST /connectors/:id/sync/trigger`
- **Expected Output**: Status 404 (connector not found for tenant B)

### TC-CONN-SYNC-019: Sync does not import users into wrong tenant
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_CONNECTOR`. Sync completed with imported users
- **Verification**: All imported/synced user records have `tenant_id` matching the connector's tenant

### TC-CONN-SYNC-020: Audit trail for sync operations
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `TEST_CONNECTOR`. Sync operations have been performed
- **Verification**: Audit logs for: sync triggered, sync completed, sync failed, conflict resolved
