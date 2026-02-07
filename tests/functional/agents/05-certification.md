# NHI Certification Campaign Functional Tests

**API Endpoints**:
- `POST /nhi/certifications/campaigns` - Create certification campaign
- `GET /nhi/certifications/campaigns` - List campaigns
- `GET /nhi/certifications/campaigns/:id` - Get campaign with item counts
- `POST /nhi/certifications/campaigns/:id/launch` - Launch campaign
- `POST /nhi/certifications/campaigns/:id/cancel` - Cancel campaign
- `GET /nhi/certifications/campaigns/:id/items` - List campaign items
- `GET /nhi/certifications/campaigns/:id/summary` - Campaign summary statistics
- `POST /nhi/certifications/items/:id/decide` - Make certification decision
- `POST /nhi/certifications/items/bulk-decide` - Bulk certification decisions
- `GET /nhi/certifications/my-pending` - My pending certification items

**Authentication**: Bearer JWT (admin for campaign management)
**Required Headers**: `Content-Type: application/json`, `Authorization: Bearer <jwt>`
**Applicable Standards**: SOC 2 CC6.1 (Logical Access), SOC 2 CC6.2 (Access Reviews), ISO 27001 A.9.2.5 (Review of User Access Rights)

---

## Nominal Cases

### TC-NHI-CERT-001: Create certification campaign for service accounts
- **Category**: Nominal
- **Standard**: SOC 2 CC6.1, CC6.2
- **Preconditions**: Authenticated admin, service accounts exist in tenant
- **Input**:
  ```json
  POST /nhi/certifications/campaigns
  {
    "name": "Q1 2026 Service Account Review",
    "description": "Quarterly review of all service account access",
    "nhi_types": ["service_account"],
    "reviewer_id": "<reviewer-user-uuid>",
    "due_date": "2026-04-01T00:00:00Z"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<uuid>",
    "tenant_id": "<tenant-uuid>",
    "name": "Q1 2026 Service Account Review",
    "description": "Quarterly review of all service account access",
    "nhi_types": ["service_account"],
    "status": "draft",
    "reviewer_id": "<reviewer-uuid>",
    "due_date": "2026-04-01T00:00:00Z",
    "created_at": "<ISO8601>"
  }
  ```
- **Verification**: Campaign created in `draft` status, not yet active

### TC-NHI-CERT-002: Create campaign for both NHI types
- **Category**: Nominal
- **Input**:
  ```json
  POST /nhi/certifications/campaigns
  {
    "name": "Full NHI Review",
    "nhi_types": ["service_account", "ai_agent"],
    "reviewer_id": "<uuid>",
    "due_date": "2026-06-01T00:00:00Z"
  }
  ```
- **Expected Output**: Status 201, `nhi_types` contains both types

### TC-NHI-CERT-003: Create campaign with filter criteria
- **Category**: Nominal
- **Standard**: Risk-based access review
- **Input**:
  ```json
  POST /nhi/certifications/campaigns
  {
    "name": "High-Risk NHI Review",
    "nhi_types": ["service_account", "ai_agent"],
    "filter": {
      "risk_min": 50,
      "inactive_days": 30
    },
    "reviewer_id": "<uuid>",
    "due_date": "2026-03-15T00:00:00Z"
  }
  ```
- **Expected Output**: Status 201, only NHIs matching filter included when launched

### TC-NHI-CERT-004: Create campaign with owner filter
- **Category**: Nominal
- **Input**:
  ```json
  POST /nhi/certifications/campaigns
  {
    "name": "Team A Review",
    "nhi_types": ["service_account"],
    "filter": { "owner_id": "<team-lead-uuid>" },
    "reviewer_id": "<uuid>",
    "due_date": "2026-05-01T00:00:00Z"
  }
  ```
- **Expected Output**: Status 201

### TC-NHI-CERT-005: Launch a draft campaign
- **Category**: Nominal
- **Standard**: SOC 2 CC6.2 (initiate review)
- **Preconditions**: Campaign in `draft` status, matching NHIs exist
- **Input**: `POST /nhi/certifications/campaigns/<campaign-id>/launch`
- **Expected Output**:
  ```json
  Status: 200 OK
  {
    "status": "active",
    "launched_at": "<ISO8601>",
    "item_counts": {
      "total": 15,
      "pending": 15,
      "certified": 0,
      "revoked": 0
    }
  }
  ```
- **Side Effects**: Certification items created for each matching NHI

### TC-NHI-CERT-006: List campaigns with pagination
- **Category**: Nominal
- **Input**: `GET /nhi/certifications/campaigns?page=1&per_page=10`
- **Expected Output**:
  ```json
  Status: 200 OK
  {
    "items": [ {...}, ... ],
    "total": 5,
    "page": 1,
    "per_page": 10
  }
  ```

### TC-NHI-CERT-007: List campaigns filtered by status
- **Category**: Nominal
- **Input**: `GET /nhi/certifications/campaigns?status=active`
- **Expected Output**: Status 200, only active campaigns

### TC-NHI-CERT-008: Get campaign details with item counts
- **Category**: Nominal
- **Input**: `GET /nhi/certifications/campaigns/<campaign-id>`
- **Expected Output**:
  ```json
  Status: 200 OK
  {
    "id": "<campaign-id>",
    "name": "...",
    "status": "active",
    "item_counts": {
      "total": 15,
      "pending": 10,
      "certified": 3,
      "revoked": 2
    }
  }
  ```

### TC-NHI-CERT-009: List items in a campaign with filters
- **Category**: Nominal
- **Input**: `GET /nhi/certifications/campaigns/<id>/items?status=pending&nhi_type=service_account`
- **Expected Output**:
  ```json
  Status: 200 OK
  {
    "items": [
      {
        "id": "<item-uuid>",
        "campaign_id": "<campaign-id>",
        "nhi_id": "<nhi-uuid>",
        "nhi_type": "service_account",
        "nhi_name": "billing-sync-service",
        "reviewer_id": "<uuid>",
        "status": "pending",
        "decision": null,
        "created_at": "<ISO8601>"
      },
      ...
    ],
    "total": 10,
    "page": 1,
    "per_page": 20
  }
  ```

### TC-NHI-CERT-010: Certify an NHI item (approve access)
- **Category**: Nominal
- **Standard**: SOC 2 CC6.2 (certify continued need)
- **Input**:
  ```json
  POST /nhi/certifications/items/<item-id>/decide
  {
    "decision": "certify",
    "comment": "Access still required for billing integration"
  }
  ```
- **Expected Output**:
  ```json
  Status: 200 OK
  {
    "id": "<item-id>",
    "status": "certified",
    "decision": "certify",
    "decided_by": "<reviewer-uuid>",
    "decided_at": "<ISO8601>",
    "comment": "Access still required for billing integration"
  }
  ```

### TC-NHI-CERT-011: Revoke an NHI item (deny continued access)
- **Category**: Nominal
- **Standard**: SOC 2 CC6.2 (revoke unnecessary access)
- **Input**:
  ```json
  POST /nhi/certifications/items/<item-id>/decide
  {
    "decision": "revoke",
    "comment": "Service account no longer needed, project completed"
  }
  ```
- **Expected Output**:
  ```json
  Status: 200 OK
  { "status": "revoked", "decision": "revoke", ... }
  ```
- **Side Effects**: NHI status updated to reflect revocation

### TC-NHI-CERT-012: Get campaign summary statistics
- **Category**: Nominal
- **Input**: `GET /nhi/certifications/campaigns/<id>/summary`
- **Expected Output**:
  ```json
  Status: 200 OK
  {
    "campaign_id": "<uuid>",
    "campaign_name": "Q1 Review",
    "status": "active",
    "due_date": "<ISO8601>",
    "item_counts": { "total": 15, "pending": 5, "certified": 8, "revoked": 2 },
    "by_type": [
      { "nhi_type": "service_account", "pending": 3, "certified": 5, "revoked": 1 },
      { "nhi_type": "ai_agent", "pending": 2, "certified": 3, "revoked": 1 }
    ],
    "progress_percent": 66
  }
  ```

### TC-NHI-CERT-013: Bulk certify multiple items
- **Category**: Nominal
- **Input**:
  ```json
  POST /nhi/certifications/items/bulk-decide
  {
    "item_ids": ["<uuid-1>", "<uuid-2>", "<uuid-3>"],
    "decision": "certify",
    "comment": "Bulk approval - all reviewed and confirmed"
  }
  ```
- **Expected Output**:
  ```json
  Status: 200 OK
  {
    "succeeded": [ {...}, {...}, {...} ],
    "failed": [],
    "total_succeeded": 3,
    "total_failed": 0
  }
  ```

### TC-NHI-CERT-014: Get my pending certification items
- **Category**: Nominal
- **Preconditions**: Current user is assigned as reviewer for multiple items
- **Input**: `GET /nhi/certifications/my-pending?page=1&per_page=20`
- **Expected Output**:
  ```json
  Status: 200 OK
  {
    "items": [ { "status": "pending", "reviewer_id": "<current-user>", ... }, ... ],
    "total": 7,
    "page": 1,
    "per_page": 20
  }
  ```

### TC-NHI-CERT-015: Cancel a campaign
- **Category**: Nominal
- **Input**: `POST /nhi/certifications/campaigns/<campaign-id>/cancel`
- **Expected Output**:
  ```json
  Status: 200 OK
  { "status": "cancelled", ... }
  ```

---

## Edge Cases

### TC-NHI-CERT-020: Create campaign with due date in the past
- **Category**: Edge Case
- **Input**: `{ "name": "Past Due", "nhi_types": ["service_account"], "due_date": "2020-01-01T00:00:00Z", ... }`
- **Expected Output**: Status 400 ("Due date must be in the future")

### TC-NHI-CERT-021: Create campaign with empty nhi_types
- **Category**: Edge Case
- **Input**: `{ "name": "No Types", "nhi_types": [], "reviewer_id": "<uuid>", "due_date": "2027-01-01T00:00:00Z" }`
- **Expected Output**: Status 400 ("At least one NHI type must be selected")

### TC-NHI-CERT-022: Launch campaign that is not in draft status
- **Category**: Edge Case
- **Preconditions**: Campaign already active or completed
- **Input**: `POST /nhi/certifications/campaigns/<active-campaign>/launch`
- **Expected Output**: Status 400 ("Campaign is not in draft status")

### TC-NHI-CERT-023: Launch campaign with no matching NHIs
- **Category**: Edge Case
- **Preconditions**: Campaign filter matches zero NHIs
- **Input**: Launch campaign
- **Expected Output**: Status 400 ("No matching NHIs found for campaign")

### TC-NHI-CERT-024: Decide on already-decided item
- **Category**: Edge Case
- **Preconditions**: Item already has decision = "certify"
- **Input**: `POST /nhi/certifications/items/<id>/decide { "decision": "revoke" }`
- **Expected Output**: Status 400 ("Item has already been decided")

### TC-NHI-CERT-025: Decide with invalid decision value
- **Category**: Edge Case
- **Input**: `{ "decision": "maybe" }`
- **Expected Output**: Status 400 ("Decision must be 'certify' or 'revoke'")

### TC-NHI-CERT-026: Cancel already-completed campaign
- **Category**: Edge Case
- **Input**: Cancel a campaign with status = "completed"
- **Expected Output**: Status 400 ("Campaign cannot be cancelled")

### TC-NHI-CERT-027: Get non-existent campaign
- **Category**: Edge Case
- **Input**: `GET /nhi/certifications/campaigns/<nonexistent-uuid>`
- **Expected Output**: Status 404

### TC-NHI-CERT-028: Bulk decide with mix of valid and already-decided items
- **Category**: Edge Case
- **Input**: `{ "item_ids": ["<pending>", "<already-decided>", "<pending>"], "decision": "certify" }`
- **Expected Output**:
  ```json
  Status: 200 OK
  {
    "total_succeeded": 2,
    "total_failed": 1,
    "failed": [{ "item_id": "<already-decided>", "error": "Item already decided" }]
  }
  ```

### TC-NHI-CERT-029: List items with pagination beyond total
- **Category**: Edge Case
- **Input**: `GET /nhi/certifications/campaigns/<id>/items?page=100`
- **Expected Output**: Status 200, empty items, total reflects actual count

### TC-NHI-CERT-030: Create campaign with invalid nhi_type value
- **Category**: Edge Case
- **Input**: `{ "nhi_types": ["robot", "service_account"], ... }`
- **Expected Output**: Status 400 (invalid NHI type) OR ignored (only valid types processed)

### TC-NHI-CERT-031: Bulk decide with empty item_ids array
- **Category**: Edge Case
- **Input**: `{ "item_ids": [], "decision": "certify" }`
- **Expected Output**: Status 400 ("At least one item ID required")

---

## Security Cases

### TC-NHI-CERT-040: Cross-tenant campaign isolation
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Campaign created in Tenant A
- **Input**: Tenant B attempts `GET /nhi/certifications/campaigns/<tenant-a-campaign>`
- **Expected Output**: Status 404

### TC-NHI-CERT-041: Cross-tenant item decision
- **Category**: Security
- **Preconditions**: Certification item belongs to Tenant A campaign
- **Input**: Tenant B attempts to decide on Tenant A item
- **Expected Output**: Status 404

### TC-NHI-CERT-042: Campaign creation without authentication
- **Category**: Security
- **Input**: `POST /nhi/certifications/campaigns` without Authorization header
- **Expected Output**: Status 401

### TC-NHI-CERT-043: Decision records actor identity
- **Category**: Security
- **Standard**: SOC 2 CC7.2 (audit trail)
- **Input**: Make a certification decision
- **Verification**: `decided_by` field matches the JWT subject (user_id), not a system default

### TC-NHI-CERT-044: Missing tenant_id in JWT
- **Category**: Security
- **Input**: JWT without `tid` claim attempts campaign creation
- **Expected Output**: Status 400 ("Tenant ID is required")

### TC-NHI-CERT-045: Invalid user_id in JWT
- **Category**: Security
- **Input**: JWT with non-UUID `sub` claim
- **Expected Output**: Status 400 ("Invalid user ID in token")

### TC-NHI-CERT-046: Pagination per_page clamped to 100
- **Category**: Security
- **Input**: `GET /nhi/certifications/campaigns/<id>/items?per_page=5000`
- **Expected Output**: Status 200, at most 100 items returned (clamped to 1..100)

### TC-NHI-CERT-047: SQL injection in campaign name
- **Category**: Security
- **Input**: `{ "name": "'; DROP TABLE nhi_certification_campaigns; --", ... }`
- **Expected Output**: Status 201 or 400, no SQL execution

### TC-NHI-CERT-048: Bulk decide with non-existent item IDs
- **Category**: Security
- **Input**: `{ "item_ids": ["<nonexistent-uuid>"], "decision": "certify" }`
- **Expected Output**:
  ```json
  {
    "total_succeeded": 0,
    "total_failed": 1,
    "failed": [{ "item_id": "<nonexistent-uuid>", "error": "Item not found" }]
  }
  ```

### TC-NHI-CERT-049: Campaign auto-completes when all items decided
- **Category**: Security
- **Standard**: SOC 2 CC6.2 (completeness of review)
- **Preconditions**: Active campaign with 3 pending items
- **Input**: Decide all 3 items (mix of certify/revoke)
- **Verification**: Campaign status transitions to `completed`, `completed_at` is set

### TC-NHI-CERT-050: My-pending only shows items assigned to current user
- **Category**: Security
- **Preconditions**: Items assigned to User A and User B
- **Input**: User A calls `GET /nhi/certifications/my-pending`
- **Expected Output**: Only items where `reviewer_id` matches User A's ID
