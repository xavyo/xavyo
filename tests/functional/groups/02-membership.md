# Group Membership Management Functional Tests

**API Endpoints**:
- `POST /groups/:id/members` -- Add member(s) to a group
- `DELETE /groups/:id/members` -- Remove member(s) from a group
- `GET /groups/:id/members` -- List group members

**Underlying Operations**:
- `GroupMembership::add_member(tenant_id, group_id, user_id)` -- Add single member (idempotent via ON CONFLICT DO NOTHING)
- `GroupMembership::remove_member(tenant_id, group_id, user_id)` -- Remove single member
- `GroupMembership::get_group_members(tenant_id, group_id)` -- List members with user info
- `GroupMembership::set_members(tenant_id, group_id, user_ids)` -- Replace all members (transactional)
- `GroupMembership::remove_all_members(tenant_id, group_id)` -- Clear all members
- `GroupMembership::count_members(tenant_id, group_id)` -- Count members
- `GroupMembership::is_member(tenant_id, group_id, user_id)` -- Check membership
- `GroupMembership::get_user_groups(tenant_id, user_id)` -- List groups for a user

**Authentication**: JWT Bearer token with `admin` role OR SCIM Bearer token
**Applicable Standards**: ISO 27001 Annex A.9.2.2 (User Access Provisioning), ISO 27001 A.9.2.6 (Removal of Access Rights), SOC 2 CC6.1, CC6.3

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`, `REGULAR_USER`
- **Special Setup**: Membership tests require pre-existing groups and users; the `REGULAR_USER` fixture provides a user to add/remove from groups

---

## Nominal Cases

### TC-GROUP-MEMBERSHIP-001: Add a user to a group
- **Category**: Nominal
- **Standard**: ISO 27001 A.9.2.2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `REGULAR_USER`. Group `G1` and user `U1` exist in tenant `T1`; `U1` is not a member of `G1`
- **Input**:
  ```json
  POST /groups/<G1-uuid>/members
  {
    "user_id": "<U1-uuid>"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<membership-uuid>",
    "tenant_id": "<T1-uuid>",
    "group_id": "<G1-uuid>",
    "user_id": "<U1-uuid>",
    "created_at": "<iso8601>"
  }
  ```
- **Side Effects**: Row inserted into `group_memberships` table

### TC-GROUP-MEMBERSHIP-002: Add multiple users to a group
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `REGULAR_USER`. Group `G1` and users `U1`, `U2`, `U3` exist in tenant `T1`
- **Input**: Add members one by one or via batch
- **Expected Output**: Status 201 for each; all three memberships created
- **Verification**: `GET /groups/<G1>/members` returns all three users

### TC-GROUP-MEMBERSHIP-003: List group members
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group `G1` has 3 members
- **Input**: `GET /groups/<G1-uuid>/members`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: [
    { "user_id": "<uuid>", "display_name": "Alice Smith", "email": "alice@example.com" },
    { "user_id": "<uuid>", "display_name": "Bob Jones", "email": "bob@example.com" },
    { "user_id": "<uuid>", "display_name": null, "email": "charlie@example.com" }
  ]
  ```
- **Verification**: Members ordered by email; tenant isolation enforced (JOIN includes `u.tenant_id = $1`)

### TC-GROUP-MEMBERSHIP-004: Remove a user from a group
- **Category**: Nominal
- **Standard**: ISO 27001 A.9.2.6
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `REGULAR_USER`. User `U1` is a member of group `G1`
- **Input**:
  ```json
  DELETE /groups/<G1-uuid>/members
  {
    "user_id": "<U1-uuid>"
  }
  ```
- **Expected Output**: Status 200 or 204
- **Verification**: Membership row deleted; `GET /groups/<G1>/members` no longer includes `U1`

### TC-GROUP-MEMBERSHIP-005: Replace all group members (set_members)
- **Category**: Nominal
- **Standard**: ISO 27001 A.9.2.2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group `G1` has members U1, U2; want to set to U3, U4
- **Input**: SCIM PATCH or direct set_members call with `[U3, U4]`
- **Expected Output**: Success
- **Verification**: After operation, members are exactly U3 and U4; U1 and U2 removed atomically (transaction)

### TC-GROUP-MEMBERSHIP-006: Count group members
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group `G1` has 5 members
- **Input**: `count_members(tenant_id, G1)`
- **Expected Output**: Returns `5`

### TC-GROUP-MEMBERSHIP-007: Check if user is member (positive)
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `REGULAR_USER`. User `U1` is a member of group `G1`
- **Input**: `is_member(tenant_id, G1, U1)`
- **Expected Output**: Returns `true`

### TC-GROUP-MEMBERSHIP-008: Check if user is member (negative)
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `REGULAR_USER`. User `U1` is NOT a member of group `G1`
- **Input**: `is_member(tenant_id, G1, U1)`
- **Expected Output**: Returns `false`

### TC-GROUP-MEMBERSHIP-009: Get user's groups
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `REGULAR_USER`. User `U1` belongs to groups G1 ("Engineering") and G2 ("Platform")
- **Input**: `get_user_groups(tenant_id, U1)`
- **Expected Output**:
  ```json
  [
    { "group_id": "<G1-uuid>", "display_name": "Engineering" },
    { "group_id": "<G2-uuid>", "display_name": "Platform" }
  ]
  ```
- **Verification**: Ordered by `display_name`; JOIN includes `g.tenant_id = $1`

### TC-GROUP-MEMBERSHIP-010: Remove all members from a group
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group `G1` has 5 members
- **Input**: `remove_all_members(tenant_id, G1)`
- **Expected Output**: Returns `5` (rows affected)
- **Verification**: `count_members(tenant_id, G1)` returns `0`

### TC-GROUP-MEMBERSHIP-011: Add member on group creation
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `REGULAR_USER`. Users U1 and U2 exist in tenant
- **Input**:
  ```json
  POST /groups
  {
    "display_name": "New Team",
    "members": ["<U1-uuid>", "<U2-uuid>"]
  }
  ```
- **Expected Output**: Status 201; group created with 2 members

### TC-GROUP-MEMBERSHIP-012: Members list returns display_name and email
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `REGULAR_USER`. User `U1` has `display_name = "Alice"` and `email = "alice@example.com"`
- **Input**: `GET /groups/<G1>/members`
- **Expected Output**: Member entry includes both `display_name` and `email` from the `users` table

---

## Edge Cases

### TC-GROUP-MEMBERSHIP-020: Add user who is already a member (idempotent)
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `REGULAR_USER`. User `U1` is already in group `G1`
- **Input**: `POST /groups/<G1>/members { "user_id": "<U1-uuid>" }`
- **Expected Output**: Succeeds (ON CONFLICT DO NOTHING) or returns existing membership; no duplicate created
- **Verification**: `count_members(tenant_id, G1)` unchanged

### TC-GROUP-MEMBERSHIP-021: Remove user who is not a member
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `REGULAR_USER`. User `U1` is NOT in group `G1`
- **Input**: `DELETE /groups/<G1>/members { "user_id": "<U1-uuid>" }`
- **Expected Output**: Returns false (0 rows affected) or Status 404

### TC-GROUP-MEMBERSHIP-022: Add member to non-existent group
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `REGULAR_USER`. User U1 exists in tenant
- **Input**: `POST /groups/<non-existent-uuid>/members { "user_id": "<U1-uuid>" }`
- **Expected Output**: Status 404 ("Group not found")

### TC-GROUP-MEMBERSHIP-023: Add non-existent user to group
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group G1 exists in tenant
- **Input**: `POST /groups/<G1>/members { "user_id": "<non-existent-uuid>" }`
- **Expected Output**: Status 404 ("User not found") or database FK violation error

### TC-GROUP-MEMBERSHIP-024: List members of empty group
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group `G1` has no members
- **Input**: `GET /groups/<G1>/members`
- **Expected Output**: Status 200; empty array `[]`

### TC-GROUP-MEMBERSHIP-025: List members of non-existent group
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `GET /groups/<non-existent-uuid>/members`
- **Expected Output**: Status 404 or empty array (depending on implementation)

### TC-GROUP-MEMBERSHIP-026: Set members with empty array (clear all)
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group `G1` has 3 members
- **Input**: `set_members(tenant_id, G1, [])` (empty user_ids)
- **Expected Output**: All members removed; count = 0

### TC-GROUP-MEMBERSHIP-027: Set members with duplicate user IDs
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `REGULAR_USER`. Group G1 and users U1, U2 exist
- **Input**: `set_members(tenant_id, G1, [U1, U1, U2])`
- **Expected Output**: Only 2 unique members added (U1, U2); no duplicate rows

### TC-GROUP-MEMBERSHIP-028: Add member with invalid UUID format
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group G1 exists in tenant
- **Input**: `POST /groups/<G1>/members { "user_id": "not-a-uuid" }`
- **Expected Output**: Status 400

### TC-GROUP-MEMBERSHIP-029: Concurrent add and remove of same member
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `REGULAR_USER`. Group G1 and user U1 exist
- **Input**: Simultaneously add and remove `U1` from `G1`
- **Expected Output**: One operation wins; no database corruption; final state is consistent

### TC-GROUP-MEMBERSHIP-030: Add inactive (suspended) user to group
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. User `U1` has `is_active = false`
- **Input**: `POST /groups/<G1>/members { "user_id": "<U1-uuid>" }`
- **Expected Output**: Status 201 (membership is a data relationship; admin may want to pre-assign for reactivation)

### TC-GROUP-MEMBERSHIP-031: Delete group cascades membership removal
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group `G1` has 5 members
- **Input**: `DELETE /groups/<G1>`
- **Expected Output**: Status 204; all 5 group_memberships rows also deleted
- **Verification**: No orphan memberships remain

### TC-GROUP-MEMBERSHIP-032: Large group (100+ members)
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group `G1` has 150 members
- **Input**: `GET /groups/<G1>/members`
- **Expected Output**: Status 200; all 150 members returned (check if pagination is needed)

### TC-GROUP-MEMBERSHIP-033: User in many groups (50+)
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `REGULAR_USER`. User `U1` is a member of 50 groups
- **Input**: `get_user_groups(tenant_id, U1)`
- **Expected Output**: All 50 groups returned

---

## Security Cases

### TC-GROUP-MEMBERSHIP-040: Cross-tenant membership manipulation
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group `G1` in tenant `T1`; user `U2` in tenant `T2`; admin JWT for `T2`
- **Input**: `POST /groups/<G1>/members { "user_id": "<U2>" }` with T2 JWT
- **Expected Output**: Status 404 (cannot access group from another tenant)

### TC-GROUP-MEMBERSHIP-041: Add cross-tenant user to group
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group `G1` in tenant `T1`; user `U_OTHER` in tenant `T2`; admin JWT for `T1`
- **Input**: `POST /groups/<G1>/members { "user_id": "<U_OTHER>" }` with T1 JWT
- **Expected Output**: Failure (user not found in T1) or FK violation; membership NOT created
- **Verification**: Cannot add user from different tenant to a group

### TC-GROUP-MEMBERSHIP-042: Cross-tenant member listing
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group `G1` with members in T1; admin JWT for T2
- **Input**: `GET /groups/<G1>/members` with T2 JWT
- **Expected Output**: Status 404 (group not visible to T2)

### TC-GROUP-MEMBERSHIP-043: Member list JOIN enforces tenant isolation
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group with members exists in tenant
- **Verification**: SQL query uses `JOIN users u ON gm.user_id = u.id AND u.tenant_id = $1` -- the user JOIN side also filters by tenant_id, preventing data leakage even if group_memberships were somehow shared

### TC-GROUP-MEMBERSHIP-044: User groups query enforces tenant isolation
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `REGULAR_USER`. User belongs to groups in tenant
- **Verification**: `get_user_groups` SQL uses `JOIN groups g ON gm.group_id = g.id AND g.tenant_id = $1` -- both sides of the JOIN include tenant_id

### TC-GROUP-MEMBERSHIP-045: Unauthenticated membership operations
- **Category**: Security
- **Preconditions**: Fixtures: `TEST_TENANT`. No authentication token provided
- **Input**: `POST /groups/<G1>/members` without Authorization header
- **Expected Output**: Status 401

### TC-GROUP-MEMBERSHIP-046: Non-admin membership operations
- **Category**: Security
- **Preconditions**: Fixtures: `TEST_TENANT`. JWT with `["user"]` role only
- **Input**: `POST /groups/<G1>/members { "user_id": "<U1>" }`
- **Expected Output**: Status 403

### TC-GROUP-MEMBERSHIP-047: SQL injection via user_id in membership request
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group G1 exists in tenant
- **Input**: `POST /groups/<G1>/members { "user_id": "'; DELETE FROM group_memberships; --" }`
- **Expected Output**: Status 400 (invalid UUID format)

### TC-GROUP-MEMBERSHIP-048: SQL injection via group_id in path
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated as admin
- **Input**: `GET /groups/'; DELETE FROM groups; --/members`
- **Expected Output**: Status 400 (invalid UUID format)

### TC-GROUP-MEMBERSHIP-049: Remove_all_members enforces tenant_id
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group with members exists in tenant
- **Verification**: `remove_all_members` query uses `WHERE tenant_id = $1 AND group_id = $2` -- cannot clear memberships in another tenant's groups

### TC-GROUP-MEMBERSHIP-050: Set_members uses transaction for atomicity
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Group with members exists in tenant
- **Verification**: `set_members` wraps DELETE + INSERT in a transaction; partial failure does not leave inconsistent state

---

## Compliance Cases

### TC-GROUP-MEMBERSHIP-060: Audit trail for membership changes
- **Category**: Compliance
- **Standard**: SOC 2 CC6.1, CC6.3, ISO 27001 A.12.4.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `REGULAR_USER`. Group and user exist in tenant
- **Input**: Add and remove a member
- **Verification**: Both operations logged with: actor, tenant_id, group_id, user_id, operation type, timestamp

### TC-GROUP-MEMBERSHIP-061: Access provisioning audit (add member)
- **Category**: Compliance
- **Standard**: ISO 27001 A.9.2.2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `REGULAR_USER`. Group and user exist in tenant
- **Input**: Add user to group
- **Verification**: Auditable record that a specific admin granted group access to a specific user at a specific time

### TC-GROUP-MEMBERSHIP-062: Access de-provisioning audit (remove member)
- **Category**: Compliance
- **Standard**: ISO 27001 A.9.2.6
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `REGULAR_USER`. User is a member of group
- **Input**: Remove user from group
- **Verification**: Auditable record that group access was revoked, with actor and timestamp

### TC-GROUP-MEMBERSHIP-063: Membership changes are immediate
- **Category**: Compliance
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `REGULAR_USER`. Group and user exist in tenant
- **Input**: Add or remove member
- **Verification**: Change is effective immediately (synchronous database operation); no eventual consistency delay

### TC-GROUP-MEMBERSHIP-064: Group membership integrity after user deletion
- **Category**: Compliance
- **Standard**: ISO 27001 A.9.2.6
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `REGULAR_USER`. User `U1` is a member of groups G1, G2, G3; user is soft-deleted
- **Input**: Soft delete user U1 via `DELETE /users/<U1>`
- **Verification**: Membership rows remain (soft delete); but user appears as inactive. If user is hard-deleted, membership rows should cascade delete.
