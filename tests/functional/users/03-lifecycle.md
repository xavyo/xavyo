# User Lifecycle State Functional Tests

**API Endpoints**:
- `PUT /users/:id` -- Update user (including `is_active` toggle)
- `DELETE /users/:id` -- Soft delete (deactivate) user
- `GET /users/:id` -- Verify lifecycle state in response

**Lifecycle States**: Active, Suspended (via `is_active = false`), Governed lifecycle states (Draft, Active, Suspended, Archived via `gov_lifecycle_states`)

**Authentication**: JWT Bearer token with `admin` role required
**Applicable Standards**: NIST SP 800-63A (Identity Lifecycle), ISO 27001 Annex A.9.2.6 (Removal/Adjustment of Access Rights), SOC 2 CC6.1, CC6.2

---

## Nominal Cases

### TC-USER-LIFECYCLE-001: New user starts as active
- **Category**: Nominal
- **Standard**: NIST SP 800-63A
- **Input**:
  ```json
  POST /users
  { "email": "newlife@example.com", "password": "MyP@ssw0rd_2026", "roles": ["user"] }
  ```
- **Expected Output**: Status 201; `"is_active": true`, `"email_verified": false`

### TC-USER-LIFECYCLE-002: Suspend user (set is_active to false)
- **Category**: Nominal
- **Standard**: ISO 27001 A.9.2.6
- **Preconditions**: User `U1` is active in tenant `T1`
- **Input**:
  ```json
  PUT /users/<U1-uuid>
  { "is_active": false }
  ```
- **Expected Output**: Status 200; `"is_active": false`
- **Side Effects**: Webhook event `user.disabled` published

### TC-USER-LIFECYCLE-003: Reactivate suspended user
- **Category**: Nominal
- **Standard**: ISO 27001 A.9.2.6
- **Preconditions**: User `U1` has `is_active = false`
- **Input**:
  ```json
  PUT /users/<U1-uuid>
  { "is_active": true }
  ```
- **Expected Output**: Status 200; `"is_active": true`
- **Side Effects**: Webhook event `user.enabled` published

### TC-USER-LIFECYCLE-004: Soft delete user via DELETE endpoint
- **Category**: Nominal
- **Standard**: ISO 27001 A.9.2.6, SOC 2 CC6.1
- **Preconditions**: User `U1` is active
- **Input**: `DELETE /users/<U1-uuid>`
- **Expected Output**: Status 204 No Content
- **Verification**:
  - `GET /users/<U1-uuid>` returns `"is_active": false`
  - User record still exists in database (soft delete, not hard delete)
  - Webhook event `user.deleted` published

### TC-USER-LIFECYCLE-005: Soft delete preserves user data
- **Category**: Nominal
- **Standard**: SOC 2 CC6.1 (Access revocation, data retention)
- **Preconditions**: User `U1` with roles, email, custom attributes
- **Input**: `DELETE /users/<U1-uuid>` then `GET /users/<U1-uuid>`
- **Expected Output**: All user data (email, roles, custom_attributes, created_at) is preserved; only `is_active = false`

### TC-USER-LIFECYCLE-006: Suspended user appears in list with is_active=false
- **Category**: Nominal
- **Preconditions**: Tenant has active and suspended users
- **Input**: `GET /users`
- **Expected Output**: Both active and suspended users appear in the list; each has correct `is_active` value

### TC-USER-LIFECYCLE-007: Lifecycle state returned when governed
- **Category**: Nominal
- **Standard**: ISO 27001 A.9.2.6
- **Preconditions**: User `U1` has `lifecycle_state_id` referencing a `gov_lifecycle_states` row named "Active"
- **Input**: `GET /users/<U1-uuid>`
- **Expected Output**:
  ```json
  {
    "lifecycle_state": {
      "id": "<state-uuid>",
      "name": "Active",
      "is_terminal": false
    },
    ...
  }
  ```

### TC-USER-LIFECYCLE-008: User without lifecycle state returns null
- **Category**: Nominal
- **Preconditions**: User `U1` has no `lifecycle_state_id`
- **Input**: `GET /users/<U1-uuid>`
- **Expected Output**: `lifecycle_state` field is absent (skipped via `skip_serializing_if = "Option::is_none"`)

### TC-USER-LIFECYCLE-009: Lifecycle state in list response
- **Category**: Nominal
- **Preconditions**: Some users have lifecycle states, others do not
- **Input**: `GET /users`
- **Expected Output**: Users with lifecycle states include the `lifecycle_state` object; users without have it omitted

### TC-USER-LIFECYCLE-010: Terminal lifecycle state indicator
- **Category**: Nominal
- **Preconditions**: User in terminal lifecycle state (e.g., "Deleted" with `is_terminal = true`)
- **Input**: `GET /users/<U1-uuid>`
- **Expected Output**: `"lifecycle_state": { "is_terminal": true, ... }`

### TC-USER-LIFECYCLE-011: Transition active to suspended preserves timestamps
- **Category**: Nominal
- **Preconditions**: User `U1` created at time T0
- **Input**: `PUT /users/<U1-uuid> { "is_active": false }`
- **Expected Output**: `created_at` unchanged (equals T0); `updated_at` is newer than T0

### TC-USER-LIFECYCLE-012: Multiple state transitions in sequence
- **Category**: Nominal
- **Preconditions**: User `U1` starts active
- **Steps**:
  1. `PUT /users/<U1> { "is_active": false }` -- suspend
  2. `PUT /users/<U1> { "is_active": true }` -- reactivate
  3. `DELETE /users/<U1>` -- soft delete
  4. `PUT /users/<U1> { "is_active": true }` -- reactivate from deleted
- **Expected Output**: Each step succeeds with correct state; `updated_at` advances at each step

---

## Edge Cases

### TC-USER-LIFECYCLE-020: Suspend already-suspended user (idempotent)
- **Category**: Edge Case
- **Preconditions**: User `U1` already has `is_active = false`
- **Input**: `PUT /users/<U1-uuid> { "is_active": false }`
- **Expected Output**: Status 200; `is_active` remains false; `updated_at` does NOT change (no actual update occurred)

### TC-USER-LIFECYCLE-021: Activate already-active user (idempotent)
- **Category**: Edge Case
- **Preconditions**: User `U1` already has `is_active = true`
- **Input**: `PUT /users/<U1-uuid> { "is_active": true }`
- **Expected Output**: Status 200; `is_active` remains true; `updated_at` does NOT change

### TC-USER-LIFECYCLE-022: Delete already-deleted user (idempotent)
- **Category**: Edge Case
- **Preconditions**: User `U1` already deactivated via `DELETE`
- **Input**: `DELETE /users/<U1-uuid>`
- **Expected Output**: Status 204 (idempotent success)

### TC-USER-LIFECYCLE-023: Update email on suspended user
- **Category**: Edge Case
- **Preconditions**: User `U1` is suspended (`is_active = false`)
- **Input**: `PUT /users/<U1-uuid> { "email": "new@example.com" }`
- **Expected Output**: Status 200; email updated even while suspended (admin can still manage suspended users)

### TC-USER-LIFECYCLE-024: Update roles on suspended user
- **Category**: Edge Case
- **Preconditions**: User `U1` is suspended
- **Input**: `PUT /users/<U1-uuid> { "roles": ["admin"] }`
- **Expected Output**: Status 200; roles updated (admin prerogative to manage access before reactivation)

### TC-USER-LIFECYCLE-025: Simultaneous is_active and email update
- **Category**: Edge Case
- **Input**:
  ```json
  PUT /users/<U1-uuid>
  { "is_active": false, "email": "newemail@example.com" }
  ```
- **Expected Output**: Status 200; both changes applied atomically

### TC-USER-LIFECYCLE-026: Simultaneous is_active and roles update
- **Category**: Edge Case
- **Input**:
  ```json
  PUT /users/<U1-uuid>
  { "is_active": true, "roles": ["admin", "editor"] }
  ```
- **Expected Output**: Status 200; both state change and role update applied

### TC-USER-LIFECYCLE-027: Lifecycle state persists through is_active toggles
- **Category**: Edge Case
- **Preconditions**: User has `lifecycle_state_id` pointing to "Active" state
- **Input**: `PUT /users/<U1-uuid> { "is_active": false }` then `GET /users/<U1-uuid>`
- **Expected Output**: `lifecycle_state` still present in response (suspension does not clear governance state)

### TC-USER-LIFECYCLE-028: Multiple users transitioning concurrently
- **Category**: Edge Case
- **Input**: Simultaneously `PUT /users/<U1> { "is_active": false }` and `PUT /users/<U2> { "is_active": false }`
- **Expected Output**: Both succeed independently; no deadlocks or race conditions

---

## Security Cases

### TC-USER-LIFECYCLE-030: Cross-tenant lifecycle manipulation
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: User `U1` belongs to tenant `T1`; admin JWT for tenant `T2`
- **Input**: `PUT /users/<U1-uuid> { "is_active": false }` with `T2` JWT
- **Expected Output**: Status 404 (cannot suspend user in another tenant)

### TC-USER-LIFECYCLE-031: Cross-tenant soft delete
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: User `U1` belongs to tenant `T1`; admin JWT for tenant `T2`
- **Input**: `DELETE /users/<U1-uuid>` with `T2` JWT
- **Expected Output**: Status 404

### TC-USER-LIFECYCLE-032: Non-admin cannot suspend users
- **Category**: Security
- **Standard**: ISO 27001 A.9.2.6
- **Preconditions**: JWT with `["user"]` role only
- **Input**: `PUT /users/<U1-uuid> { "is_active": false }`
- **Expected Output**: Status 403 Forbidden

### TC-USER-LIFECYCLE-033: Non-admin cannot delete users
- **Category**: Security
- **Standard**: ISO 27001 A.9.2.6
- **Preconditions**: JWT with `["user"]` role only
- **Input**: `DELETE /users/<U1-uuid>`
- **Expected Output**: Status 403 Forbidden

### TC-USER-LIFECYCLE-034: Suspended user cannot authenticate
- **Category**: Security
- **Standard**: ISO 27001 A.9.2.6
- **Preconditions**: Suspend user via `PUT /users/<U1> { "is_active": false }`
- **Input**: `POST /auth/login { "email": "...", "password": "..." }` as the suspended user
- **Expected Output**: Status 401 (account is inactive)

### TC-USER-LIFECYCLE-035: Soft-deleted user cannot authenticate
- **Category**: Security
- **Standard**: ISO 27001 A.9.2.6
- **Preconditions**: Soft delete user via `DELETE /users/<U1>`
- **Input**: `POST /auth/login` as the soft-deleted user
- **Expected Output**: Status 401 (generic "Invalid credentials" -- does not reveal account exists but is disabled)

### TC-USER-LIFECYCLE-036: Webhook events include correct tenant context
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Input**: Suspend user in tenant `T1`
- **Verification**: `user.disabled` webhook event has `tenant_id = T1`, NOT any other tenant's ID

### TC-USER-LIFECYCLE-037: State transition audit trail
- **Category**: Security
- **Standard**: SOC 2 CC6.1, ISO 27001 A.12.4.1
- **Input**: Suspend then reactivate a user
- **Verification**: Audit log records both transitions with actor (admin), action, timestamp, and new state

---

## Compliance Cases

### TC-USER-LIFECYCLE-040: Access removal within SLA
- **Category**: Compliance
- **Standard**: ISO 27001 A.9.2.6, SOC 2 CC6.2
- **Input**: `DELETE /users/<U1>` or `PUT /users/<U1> { "is_active": false }`
- **Verification**: Access revocation is immediate (synchronous database update); user cannot authenticate on subsequent attempt

### TC-USER-LIFECYCLE-041: Data retention after soft delete
- **Category**: Compliance
- **Standard**: SOC 2 CC6.1 (Retention policies)
- **Input**: `DELETE /users/<U1>`
- **Verification**: User record retained in database; `is_active = false`; no data loss. Hard deletion is a separate process (if implemented)

### TC-USER-LIFECYCLE-042: Lifecycle state transitions auditable
- **Category**: Compliance
- **Standard**: SOC 2 CC6.1
- **Input**: Perform all lifecycle transitions (create, suspend, reactivate, delete)
- **Verification**: Complete audit trail exists for each transition; no gaps in the history

### TC-USER-LIFECYCLE-043: NIST compliant identity deactivation
- **Category**: Compliance
- **Standard**: NIST SP 800-63A Section 4.2
- **Input**: Deactivate a user
- **Verification**: Deactivation prevents authentication, prevents API access, and is recorded in audit logs
