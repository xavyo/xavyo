# Access Certification Campaign Functional Tests

**API Base Path**: `/governance/certification-campaigns`, `/governance/certification-items`, `/governance/my-certifications`
**Authentication**: JWT Bearer token; admin role for campaign management, reviewer role for decisions
**Required Headers**: `Content-Type: application/json`, `Authorization: Bearer <jwt>`
**Applicable Standards**: SOC 2 CC6.1, ISO 27001 A.9.2.5 (Review of User Access Rights), SOX Section 404

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: Some tests require existing entitlements, assignments, certification campaigns, and reviewer users

---

## Nominal Cases

### TC-GOV-CERT-001: Create certification campaign
- **Category**: Nominal
- **Standard**: SOC 2 CC6.1 (Logical Access Controls)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Entitlements and assignments exist
- **Input**:
  ```json
  POST /governance/certification-campaigns
  {
    "name": "Q1 2026 Access Review",
    "description": "Quarterly access certification for SOC 2 compliance",
    "campaign_type": "user_access",
    "scope": { "application_ids": ["<app-id>"] },
    "due_date": "2026-03-31T23:59:59Z",
    "reviewer_strategy": "entitlement_owner"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<uuid>",
    "name": "Q1 2026 Access Review",
    "status": "draft",
    "campaign_type": "user_access",
    "created_at": "<iso8601>"
  }
  ```

### TC-GOV-CERT-002: List certification campaigns
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Multiple campaigns exist
- **Input**:
  ```
  GET /governance/certification-campaigns?limit=10&offset=0
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [...], "total": <count> }
  ```

### TC-GOV-CERT-003: Get campaign by ID
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Campaign exists with known ID
- **Input**:
  ```
  GET /governance/certification-campaigns/<campaign-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "id": "<campaign-id>", "name": "Q1 2026 Access Review", "status": "draft", ... }
  ```

### TC-GOV-CERT-004: Update campaign (draft status)
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Campaign in "draft" status
- **Input**:
  ```json
  PUT /governance/certification-campaigns/<campaign-id>
  {
    "name": "Q1 2026 Full Access Review",
    "due_date": "2026-04-15T23:59:59Z"
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "name": "Q1 2026 Full Access Review", ... }
  ```

### TC-GOV-CERT-005: Launch certification campaign
- **Category**: Nominal
- **Standard**: ISO 27001 A.9.2.5
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Campaign in "draft" status with valid scope
- **Input**:
  ```
  POST /governance/certification-campaigns/<campaign-id>/launch
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "status": "active", "items_generated": <count>, ... }
  ```
- **Side Effects**: Certification items generated for each user-entitlement pair in scope

### TC-GOV-CERT-006: Get campaign progress
- **Category**: Nominal
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Active campaign with some decisions made
- **Input**:
  ```
  GET /governance/certification-campaigns/<campaign-id>/progress
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "total_items": <count>,
    "decided_items": <count>,
    "pending_items": <count>,
    "approved_count": <count>,
    "revoked_count": <count>,
    "completion_percentage": <float>
  }
  ```

### TC-GOV-CERT-007: List campaign certification items
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Active campaign
- **Input**:
  ```
  GET /governance/certification-campaigns/<campaign-id>/items?limit=50&offset=0
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [{ "id": "<item-id>", "user_id": "...", "entitlement_id": "...", "status": "pending", ... }] }
  ```

### TC-GOV-CERT-008: Get single certification item
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Certification item exists
- **Input**:
  ```
  GET /governance/certification-items/<item-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "id": "<item-id>", "status": "pending", "reviewer_id": "<reviewer>", ... }
  ```

### TC-GOV-CERT-009: Approve certification item (certify access)
- **Category**: Nominal
- **Standard**: ISO 27001 A.9.2.5 (Review of User Access Rights)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Reviewer is authenticated; item is pending
- **Input**:
  ```json
  POST /governance/certification-items/<item-id>/decide
  {
    "decision": "approve",
    "comment": "Access confirmed as required for role"
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "status": "approved", "decided_by": "<reviewer-id>", "decided_at": "<iso8601>" }
  ```

### TC-GOV-CERT-010: Revoke certification item
- **Category**: Nominal
- **Standard**: ISO 27001 A.9.2.5
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Reviewer is authenticated; item is pending
- **Input**:
  ```json
  POST /governance/certification-items/<item-id>/decide
  {
    "decision": "revoke",
    "comment": "User no longer in this department"
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "status": "revoked", ... }
  ```
- **Side Effects**: Entitlement assignment revoked or marked for revocation

### TC-GOV-CERT-011: Reassign certification item to different reviewer
- **Category**: Nominal
- **Standard**: IGA Workflow Delegation
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Item is pending; new reviewer is valid user
- **Input**:
  ```json
  POST /governance/certification-items/<item-id>/reassign
  { "new_reviewer_id": "<new-reviewer-id>" }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "reviewer_id": "<new-reviewer-id>", ... }
  ```

### TC-GOV-CERT-012: Get my pending certifications (reviewer view)
- **Category**: Nominal
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated user is reviewer with pending items
- **Input**:
  ```
  GET /governance/my-certifications
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [<pending-item-1>, <pending-item-2>] }
  ```

### TC-GOV-CERT-013: Get my certifications summary
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Reviewer has items across campaigns
- **Input**:
  ```
  GET /governance/my-certifications/summary
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "total_pending": <count>, "total_decided": <count>, "campaigns": [...] }
  ```

### TC-GOV-CERT-014: Cancel certification campaign
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Active campaign
- **Input**:
  ```
  POST /governance/certification-campaigns/<campaign-id>/cancel
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "status": "cancelled", ... }
  ```

### TC-GOV-CERT-015: Delete draft campaign
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Campaign in draft status
- **Input**:
  ```
  DELETE /governance/certification-campaigns/<campaign-id>
  ```
- **Expected Output**:
  ```
  Status: 204 No Content
  ```

---

## Edge Cases

### TC-GOV-CERT-020: Launch campaign with empty scope
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Campaign has scope that matches no users/entitlements
- **Input**:
  ```
  POST /governance/certification-campaigns/<campaign-id>/launch
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  Body: { "error": "Campaign scope matches no items to certify" }
  ```

### TC-GOV-CERT-021: Update campaign after launch
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Campaign is "active" (already launched)
- **Input**:
  ```json
  PUT /governance/certification-campaigns/<campaign-id>
  { "name": "Modified Active Campaign" }
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  Body: { "error": "Cannot modify campaign after launch" }
  ```

### TC-GOV-CERT-022: Decide on already-decided item
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Item already has a decision
- **Input**:
  ```json
  POST /governance/certification-items/<item-id>/decide
  { "decision": "approve", "comment": "Second decision" }
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  Body: { "error": "Item already decided" }
  ```

### TC-GOV-CERT-023: Non-reviewer attempts to decide item
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated user is NOT the assigned reviewer
- **Input**:
  ```json
  POST /governance/certification-items/<item-id>/decide
  { "decision": "approve" }
  ```
- **Expected Output**:
  ```
  Status: 403 Forbidden
  ```

### TC-GOV-CERT-024: Delete active campaign
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Campaign is active
- **Input**:
  ```
  DELETE /governance/certification-campaigns/<campaign-id>
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  Body: { "error": "Cannot delete active campaign; cancel it first" }
  ```

### TC-GOV-CERT-025: Launch already-launched campaign
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Campaign is already active
- **Input**:
  ```
  POST /governance/certification-campaigns/<campaign-id>/launch
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  ```

---

## Security Tests

### TC-GOV-CERT-030: Create campaign without admin role
- **Category**: Security
- **Standard**: NIST SP 800-53 AC-6
- **Preconditions**: Fixtures: `TEST_TENANT`. JWT with non-admin role
- **Input**:
  ```json
  POST /governance/certification-campaigns
  { "name": "Unauthorized Campaign" }
  ```
- **Expected Output**:
  ```
  Status: 403 Forbidden
  ```

### TC-GOV-CERT-031: Access campaign from different tenant
- **Category**: Security
- **Standard**: Multi-tenancy isolation
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Campaign in tenant A; JWT for tenant B (second tenant required)
- **Input**:
  ```
  GET /governance/certification-campaigns/<tenant-a-campaign-id>
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-GOV-CERT-032: Decide item from different tenant
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Item in tenant A; JWT for tenant B admin (second tenant required)
- **Input**:
  ```json
  POST /governance/certification-items/<tenant-a-item>/decide
  { "decision": "approve" }
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

---

## Compliance Tests

### TC-GOV-CERT-040: SOC 2 CC6.1 - Periodic access review execution
- **Category**: Compliance
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Existing users and entitlement assignments
- **Steps**:
  1. Create quarterly certification campaign scoped to all applications
  2. Launch campaign
  3. Verify items generated for all user-entitlement assignments
  4. Review all items (approve or revoke)
  5. Verify campaign completion at 100%
- **Expected Output**: Complete access review cycle suitable for SOC 2 Type II evidence

### TC-GOV-CERT-041: ISO 27001 A.9.2.5 - Manager-based review
- **Category**: Compliance
- **Standard**: ISO 27001 A.9.2.5 (Review of User Access Rights)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Existing users with managers and entitlement assignments
- **Steps**:
  1. Create campaign with `reviewer_strategy: "manager"`
  2. Launch campaign
  3. Verify each user's manager is assigned as reviewer
  4. Manager makes decisions on all items
- **Expected Output**: Access review delegated to user managers per ISO 27001

### TC-GOV-CERT-042: SOX Section 404 - Campaign with remediation tracking
- **Category**: Compliance
- **Standard**: SOX Section 404
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Existing users with entitlement assignments
- **Steps**:
  1. Launch certification campaign
  2. Reviewer revokes access for non-compliant users
  3. Verify revocation is executed (entitlement removed)
  4. Verify audit trail captures reviewer, decision, timestamp
- **Expected Output**: End-to-end remediation from certification through access removal

### TC-GOV-CERT-043: Campaign progress reporting for auditors
- **Category**: Compliance
- **Standard**: SOC 2 CC7.2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**:
  1. Launch campaign
  2. Partially complete reviews
  3. Check progress endpoint
  4. Verify metrics: total, pending, decided, approved, revoked, completion %
- **Expected Output**: Real-time progress metrics for auditor oversight

### TC-GOV-CERT-044: Micro-certification triggered by high-risk event
- **Category**: Compliance
- **Standard**: SOC 2 CC6.1 (Continuous Monitoring)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Micro-certification trigger rule configured for "role_change" events
- **Steps**:
  1. Create trigger rule for high-risk entitlement changes
  2. Assign high-risk entitlement to user
  3. Verify micro-certification created automatically
  4. Reviewer decides on the micro-certification
- **Expected Output**: Just-in-time certification for high-risk access changes
