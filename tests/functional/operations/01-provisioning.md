# Provisioning Operation Tracking Functional Tests

**API Endpoints**:
- `POST /operations` (trigger provisioning operation)
- `GET /operations` (list operations)
- `GET /operations/:id` (get operation details)
- `GET /operations/stats` (get queue statistics)
- `GET /operations/dlq` (list dead letter queue)
- `POST /operations/:id/retry` (retry failed operation)
- `POST /operations/:id/cancel` (cancel pending operation)
- `POST /operations/:id/resolve` (manually resolve operation)
- `GET /operations/:id/logs` (get operation logs)
- `GET /operations/:id/attempts` (get operation attempts)
- `GET /operations/conflicts` (list provisioning conflicts)
- `GET /operations/conflicts/:conflict_id` (get conflict details)
- `POST /operations/conflicts/:conflict_id/resolve` (resolve conflict)
**Authentication**: JWT (Bearer token) with admin role
**Applicable Standards**: IGA provisioning lifecycle, SOC 2 CC6.1

---

## Nominal Cases

### TC-OPS-PROV-001: Trigger provisioning operation
- **Category**: Nominal
- **Preconditions**: Authenticated admin, target connector configured
- **Input**:
  ```json
  POST /operations
  {
    "operation_type": "create_user",
    "target_connector_id": "<uuid>",
    "payload": {
      "email": "newuser@example.com",
      "display_name": "New User",
      "department": "Engineering"
    }
  }
  ```
- **Expected Output**:
  ```
  Status: 202 Accepted
  Body: {
    "id": "<uuid>",
    "operation_type": "create_user",
    "status": "pending",
    "target_connector_id": "<uuid>",
    "created_at": "2026-02-07T..."
  }
  ```
- **Side Effects**: Operation queued for async processing, audit log: `operation.triggered`

### TC-OPS-PROV-002: List all operations
- **Category**: Nominal
- **Preconditions**: Multiple operations in various states
- **Input**: `GET /operations`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "operations": [
      { "id": "...", "operation_type": "create_user", "status": "completed", ... },
      { "id": "...", "operation_type": "update_user", "status": "pending", ... },
      { "id": "...", "operation_type": "delete_user", "status": "failed", ... }
    ]
  }
  ```

### TC-OPS-PROV-003: Get operation details
- **Category**: Nominal
- **Input**: `GET /operations/:id`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "id": "<uuid>",
    "operation_type": "create_user",
    "status": "completed",
    "target_connector_id": "<uuid>",
    "payload": { ... },
    "result": { "remote_id": "cn=newuser,dc=example,dc=com" },
    "created_at": "2026-02-07T10:00:00Z",
    "started_at": "2026-02-07T10:00:01Z",
    "completed_at": "2026-02-07T10:00:05Z",
    "attempt_count": 1
  }
  ```

### TC-OPS-PROV-004: Get queue statistics
- **Category**: Nominal
- **Input**: `GET /operations/stats`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "total": 100,
    "pending": 5,
    "in_progress": 2,
    "completed": 85,
    "failed": 8,
    "dlq_count": 3,
    "avg_processing_time_ms": 2500
  }
  ```

### TC-OPS-PROV-005: Retry failed operation
- **Category**: Nominal
- **Preconditions**: Operation failed with transient error
- **Input**: `POST /operations/:id/retry`
- **Expected Output**: Status 200, operation re-queued with `status: "pending"`
- **Side Effects**: Attempt counter incremented, audit log: `operation.retried`

### TC-OPS-PROV-006: Cancel pending operation
- **Category**: Nominal
- **Preconditions**: Operation in "pending" state
- **Input**: `POST /operations/:id/cancel`
- **Expected Output**: Status 200, `status: "cancelled"`
- **Side Effects**: Audit log: `operation.cancelled`

### TC-OPS-PROV-007: Manually resolve operation
- **Category**: Nominal
- **Preconditions**: Operation failed, admin investigated and resolved manually
- **Input**:
  ```json
  POST /operations/:id/resolve
  { "resolution": "Manually created account in LDAP" }
  ```
- **Expected Output**: Status 200, `status: "resolved"`

### TC-OPS-PROV-008: Get operation logs
- **Category**: Nominal
- **Input**: `GET /operations/:id/logs`
- **Expected Output**: Status 200, chronological log entries for the operation

### TC-OPS-PROV-009: Get operation attempts
- **Category**: Nominal
- **Preconditions**: Operation retried 3 times
- **Input**: `GET /operations/:id/attempts`
- **Expected Output**: Status 200, list of 3 attempt records with timestamps and results

### TC-OPS-PROV-010: List dead letter queue
- **Category**: Nominal
- **Input**: `GET /operations/dlq`
- **Expected Output**: Status 200, list of operations that exhausted all retries

---

## Edge Cases

### TC-OPS-PROV-011: Get non-existent operation
- **Category**: Edge Case
- **Input**: `GET /operations/00000000-0000-0000-0000-000000000099`
- **Expected Output**: Status 404

### TC-OPS-PROV-012: Retry completed operation
- **Category**: Edge Case
- **Input**: `POST /operations/:completed_id/retry`
- **Expected Output**: Status 400 "Cannot retry completed operation"

### TC-OPS-PROV-013: Cancel in-progress operation
- **Category**: Edge Case
- **Input**: `POST /operations/:in_progress_id/cancel`
- **Expected Output**: Status 400 "Cannot cancel in-progress operation" OR Status 200 (graceful cancel)

### TC-OPS-PROV-014: List operations with filters
- **Category**: Edge Case
- **Input**: `GET /operations?status=failed&operation_type=create_user`
- **Expected Output**: Status 200, only failed create_user operations

### TC-OPS-PROV-015: List provisioning conflicts
- **Category**: Edge Case
- **Preconditions**: Operation attempted to create user that already exists remotely
- **Input**: `GET /operations/conflicts`
- **Expected Output**: Status 200, conflict records with both local and remote state

### TC-OPS-PROV-016: Resolve provisioning conflict
- **Category**: Edge Case
- **Input**:
  ```json
  POST /operations/conflicts/:conflict_id/resolve
  { "resolution": "keep_remote" }
  ```
- **Expected Output**: Status 200, conflict resolved

---

## Security Cases

### TC-OPS-PROV-017: Non-admin cannot trigger operations
- **Category**: Security
- **Input**: Regular user calls `POST /operations`
- **Expected Output**: Status 403 Forbidden

### TC-OPS-PROV-018: Cross-tenant operation isolation
- **Category**: Security
- **Preconditions**: Operation O1 belongs to tenant A
- **Input**: Admin of tenant B calls `GET /operations/:o1_id`
- **Expected Output**: Status 404

### TC-OPS-PROV-019: Operation logs do not leak credentials
- **Category**: Security
- **Input**: `GET /operations/:id/logs`
- **Expected Output**: Logs do NOT contain connector credentials, passwords, or API keys

### TC-OPS-PROV-020: Audit trail for operation lifecycle
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Verification**: Audit log entries for: triggered, started, completed, failed, retried, cancelled, resolved
