# Access Request Catalog and Workflow Functional Tests

**API Base Path**: `/governance/admin/catalog/categories`, `/governance/admin/catalog/items`, `/governance/catalog/*`, `/governance/access-requests`, `/governance/approval-workflows`
**Authentication**: JWT Bearer token; admin for catalog management, authenticated for requests
**Required Headers**: `Content-Type: application/json`, `Authorization: Bearer <jwt>`
**Applicable Standards**: ITIL Service Request Management, ISO 27001 A.9.2.2, NIST SP 800-53 AC-2

---

## Nominal Cases

### TC-GOV-REQ-001: Create catalog category (admin)
- **Category**: Nominal
- **Standard**: ITIL Service Catalog Management
- **Preconditions**: Authenticated as admin
- **Input**:
  ```json
  POST /governance/admin/catalog/categories
  {
    "name": "IT Applications",
    "description": "Application access requests",
    "icon": "laptop",
    "display_order": 1
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: { "id": "<uuid>", "name": "IT Applications", "parent_id": null, ... }
  ```

### TC-GOV-REQ-002: Create nested catalog category
- **Category**: Nominal
- **Standard**: ITIL Service Catalog Hierarchy
- **Preconditions**: Parent category "IT Applications" exists
- **Input**:
  ```json
  POST /governance/admin/catalog/categories
  {
    "name": "Financial Systems",
    "parent_id": "<it-apps-category-id>",
    "display_order": 1
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: { "parent_id": "<it-apps-category-id>", ... }
  ```

### TC-GOV-REQ-003: Create catalog item linked to entitlement
- **Category**: Nominal
- **Standard**: ITIL Service Request Management
- **Preconditions**: Category and entitlement exist
- **Input**:
  ```json
  POST /governance/admin/catalog/items
  {
    "name": "SAP Financial Reporting Access",
    "description": "Grants read access to financial reports in SAP",
    "category_id": "<financial-systems-category-id>",
    "item_type": "entitlement",
    "entitlement_id": "<entitlement-id>",
    "approval_required": true,
    "requestability_rules": {
      "max_duration_days": 365,
      "requires_justification": true
    }
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: { "id": "<uuid>", "name": "SAP Financial Reporting Access", "is_enabled": true, ... }
  ```

### TC-GOV-REQ-004: Browse catalog categories (self-service)
- **Category**: Nominal
- **Standard**: ITIL Self-Service Portal
- **Preconditions**: Categories and items exist
- **Input**:
  ```
  GET /governance/catalog/categories
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [{ "id": "...", "name": "IT Applications", "children_count": 1, ... }] }
  ```

### TC-GOV-REQ-005: Browse catalog items in category
- **Category**: Nominal
- **Input**:
  ```
  GET /governance/catalog/items?category_id=<category-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [{ "id": "...", "name": "SAP Financial Reporting Access", ... }] }
  ```

### TC-GOV-REQ-006: Add items to request cart
- **Category**: Nominal
- **Standard**: ITIL Request Fulfillment
- **Preconditions**: Catalog items exist
- **Input**:
  ```json
  POST /governance/catalog/cart/items
  {
    "catalog_item_id": "<item-id>",
    "justification": "Need access for quarterly report preparation",
    "duration_days": 90
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  ```

### TC-GOV-REQ-007: Get current cart
- **Category**: Nominal
- **Preconditions**: User has items in cart
- **Input**:
  ```
  GET /governance/catalog/cart
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [{ "catalog_item_id": "...", "justification": "...", ... }], "total_items": 1 }
  ```

### TC-GOV-REQ-008: Validate cart before submission
- **Category**: Nominal
- **Standard**: IGA Pre-validation
- **Preconditions**: Cart has items
- **Input**:
  ```
  POST /governance/catalog/cart/validate
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "valid": true, "warnings": [], "sod_conflicts": [] }
  ```

### TC-GOV-REQ-009: Submit cart (creates access requests)
- **Category**: Nominal
- **Standard**: ITIL Request Fulfillment
- **Preconditions**: Cart is valid
- **Input**:
  ```
  POST /governance/catalog/cart/submit
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: { "requests": [{ "id": "<request-id>", "status": "pending_approval", ... }] }
  ```
- **Side Effects**: Cart cleared; access requests created; approval workflow triggered

### TC-GOV-REQ-010: List my access requests
- **Category**: Nominal
- **Preconditions**: User has submitted requests
- **Input**:
  ```
  GET /governance/access-requests?limit=50&offset=0
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [...], "total": <count> }
  ```

### TC-GOV-REQ-011: Get access request details
- **Category**: Nominal
- **Input**:
  ```
  GET /governance/access-requests/<request-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "id": "<request-id>", "status": "pending_approval", "requested_by": "<user-id>", ... }
  ```

### TC-GOV-REQ-012: Cancel pending access request
- **Category**: Nominal
- **Preconditions**: Request is pending
- **Input**:
  ```
  POST /governance/access-requests/<request-id>/cancel
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "status": "cancelled" }
  ```

### TC-GOV-REQ-013: Approve access request
- **Category**: Nominal
- **Standard**: ITIL Change Authorization
- **Preconditions**: Request pending; authenticated as approver
- **Input**:
  ```json
  POST /governance/access-requests/<request-id>/approve
  { "comment": "Approved per manager review" }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "status": "approved", ... }
  ```
- **Side Effects**: Entitlement provisioned to requesting user

### TC-GOV-REQ-014: Reject access request
- **Category**: Nominal
- **Preconditions**: Request pending; authenticated as approver
- **Input**:
  ```json
  POST /governance/access-requests/<request-id>/reject
  { "comment": "Not justified for this role" }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "status": "rejected", ... }
  ```

### TC-GOV-REQ-015: List pending approvals (approver view)
- **Category**: Nominal
- **Preconditions**: Authenticated user has pending approvals
- **Input**:
  ```
  GET /governance/my-approvals
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [<pending-request-1>, <pending-request-2>] }
  ```

### TC-GOV-REQ-016: Create approval workflow
- **Category**: Nominal
- **Standard**: ITIL Change Management
- **Preconditions**: Admin authenticated
- **Input**:
  ```json
  POST /governance/approval-workflows
  {
    "name": "Standard Two-Level Approval",
    "steps": [
      { "approver_type": "manager", "order": 1 },
      { "approver_type": "application_owner", "order": 2 }
    ]
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  ```

### TC-GOV-REQ-017: Set default approval workflow
- **Category**: Nominal
- **Input**:
  ```
  POST /governance/approval-workflows/<workflow-id>/set-default
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  ```

### TC-GOV-REQ-018: Enable/disable catalog item
- **Category**: Nominal
- **Preconditions**: Catalog item exists
- **Steps**:
  1. Disable: `POST /governance/admin/catalog/items/<id>/disable` -> 200 OK
  2. Enable: `POST /governance/admin/catalog/items/<id>/enable` -> 200 OK
- **Verification**: Disabled items hidden from self-service browse

### TC-GOV-REQ-019: Update cart item quantity/parameters
- **Category**: Nominal
- **Preconditions**: Item in cart
- **Input**:
  ```json
  PUT /governance/catalog/cart/items/<item-id>
  { "justification": "Updated justification", "duration_days": 180 }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  ```

### TC-GOV-REQ-020: Clear entire cart
- **Category**: Nominal
- **Input**:
  ```
  DELETE /governance/catalog/cart
  ```
- **Expected Output**:
  ```
  Status: 204 No Content
  ```

---

## Edge Cases

### TC-GOV-REQ-025: Submit empty cart
- **Category**: Edge Case
- **Preconditions**: Cart is empty
- **Input**:
  ```
  POST /governance/catalog/cart/submit
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  Body: { "error": "Cart is empty" }
  ```

### TC-GOV-REQ-026: Cart validation detects SoD conflict
- **Category**: Edge Case
- **Standard**: SOX Section 404
- **Preconditions**: Cart contains item that conflicts with user's existing access per SoD rule
- **Input**:
  ```
  POST /governance/catalog/cart/validate
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "valid": false, "sod_conflicts": [{ "rule_id": "...", "severity": "critical", ... }] }
  ```

### TC-GOV-REQ-027: Cancel already-approved request
- **Category**: Edge Case
- **Preconditions**: Request is already approved
- **Input**:
  ```
  POST /governance/access-requests/<request-id>/cancel
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  Body: { "error": "Cannot cancel request in current state" }
  ```

### TC-GOV-REQ-028: Request disabled catalog item
- **Category**: Edge Case
- **Preconditions**: Catalog item is disabled
- **Input**:
  ```json
  POST /governance/catalog/cart/items
  { "catalog_item_id": "<disabled-item-id>" }
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  ```

---

## Security Tests

### TC-GOV-REQ-030: Create catalog item without admin role
- **Category**: Security
- **Standard**: NIST SP 800-53 AC-6
- **Input**:
  ```json
  POST /governance/admin/catalog/items
  { "name": "Unauthorized Item" }
  ```
  (JWT with user role)
- **Expected Output**:
  ```
  Status: 403 Forbidden
  ```

### TC-GOV-REQ-031: Approve request as non-approver
- **Category**: Security
- **Preconditions**: User is not the designated approver
- **Input**:
  ```json
  POST /governance/access-requests/<request-id>/approve
  { "comment": "Self-approval attempt" }
  ```
- **Expected Output**:
  ```
  Status: 403 Forbidden
  ```

### TC-GOV-REQ-032: Access another user's cart
- **Category**: Security
- **Standard**: Multi-tenancy / user isolation
- **Verification**: Cart endpoint returns only authenticated user's cart; no way to specify another user's cart

---

## Compliance Tests

### TC-GOV-REQ-040: ITIL - Complete request fulfillment lifecycle
- **Category**: Compliance
- **Standard**: ITIL Service Request Management
- **Steps**:
  1. Admin creates catalog categories and items
  2. User browses catalog
  3. User adds items to cart
  4. User validates and submits cart
  5. Approver approves request
  6. Access provisioned
- **Expected Output**: End-to-end self-service access request with approval workflow

### TC-GOV-REQ-041: ISO 27001 A.9.2.2 - Formal access request process
- **Category**: Compliance
- **Standard**: ISO 27001 A.9.2.2 (User Access Provisioning)
- **Steps**:
  1. Verify justification is required for catalog items
  2. Verify approval is required before provisioning
  3. Verify audit trail captures requester, approver, timestamp
- **Expected Output**: Formal access provisioning process per ISO 27001
