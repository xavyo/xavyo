# Separation of Duties (SoD) Functional Tests

**API Base Path**: `/governance/sod-rules`, `/governance/sod-check`, `/governance/sod-violations`, `/governance/sod-exemptions`
**Authentication**: JWT Bearer token with `admin` role required for rule management
**Required Headers**: `Content-Type: application/json`, `Authorization: Bearer <jwt>`
**Applicable Standards**: SOX Section 404, SOC 2 CC6.3, ISACA COBIT DSS05, ISO 27001 A.6.1.2

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: Some tests require existing entitlements, SoD rules, violations, exemptions, and user-entitlement assignments

---

## Nominal Cases

### TC-GOV-SOD-001: Create SoD rule between two entitlements
- **Category**: Nominal
- **Standard**: SOX Section 404 (Internal Controls)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Two entitlements exist (e.g., "Create Purchase Order", "Approve Purchase Order")
- **Input**:
  ```json
  POST /governance/sod-rules
  {
    "name": "PO Create vs Approve",
    "description": "Prevents same person from creating and approving purchase orders",
    "first_entitlement_id": "<create-po-ent-id>",
    "second_entitlement_id": "<approve-po-ent-id>",
    "severity": "critical",
    "business_rationale": "Required by SOX Section 404 internal controls for financial transactions"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<uuid>",
    "name": "PO Create vs Approve",
    "first_entitlement_id": "<create-po-ent-id>",
    "second_entitlement_id": "<approve-po-ent-id>",
    "severity": "critical",
    "status": "active",
    "business_rationale": "Required by SOX Section 404...",
    "created_at": "<iso8601>"
  }
  ```

### TC-GOV-SOD-002: List SoD rules with filters
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Multiple SoD rules exist
- **Input**:
  ```
  GET /governance/sod-rules?severity=critical&status=active&limit=50&offset=0
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [...], "total": <count> }
  ```

### TC-GOV-SOD-003: Get SoD rule by ID
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. SoD rule exists
- **Input**:
  ```
  GET /governance/sod-rules/<rule-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "id": "<rule-id>", "name": "PO Create vs Approve", ... }
  ```

### TC-GOV-SOD-004: Update SoD rule
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. SoD rule exists
- **Input**:
  ```json
  PUT /governance/sod-rules/<rule-id>
  {
    "name": "PO Create vs Approve - Updated",
    "severity": "high",
    "business_rationale": "Updated per audit finding #2026-Q1-042"
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "name": "PO Create vs Approve - Updated", "severity": "high", ... }
  ```

### TC-GOV-SOD-005: Enable SoD rule
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Disabled SoD rule exists
- **Input**:
  ```
  POST /governance/sod-rules/<rule-id>/enable
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "status": "active", ... }
  ```

### TC-GOV-SOD-006: Disable SoD rule
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Active SoD rule exists
- **Input**:
  ```
  POST /governance/sod-rules/<rule-id>/disable
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "status": "disabled", ... }
  ```

### TC-GOV-SOD-007: Delete SoD rule
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. SoD rule exists
- **Input**:
  ```
  DELETE /governance/sod-rules/<rule-id>
  ```
- **Expected Output**:
  ```
  Status: 204 No Content
  ```

### TC-GOV-SOD-008: Pre-flight SoD check (no conflict)
- **Category**: Nominal
- **Standard**: SOX Section 404 (Preventive Controls)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. SoD rule exists between entitlements A and B; user has only entitlement A
- **Input**:
  ```json
  POST /governance/sod-check
  {
    "user_id": "<user-id>",
    "entitlement_id": "<entitlement-c>"
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "conflicts": [], "has_conflicts": false }
  ```

### TC-GOV-SOD-009: Pre-flight SoD check (conflict detected)
- **Category**: Nominal
- **Standard**: SOX Section 404 (Preventive Controls)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. SoD rule between A and B; user has A; checking assignment of B
- **Input**:
  ```json
  POST /governance/sod-check
  {
    "user_id": "<user-id>",
    "entitlement_id": "<entitlement-b>"
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "has_conflicts": true,
    "conflicts": [{
      "rule_id": "<rule-id>",
      "rule_name": "PO Create vs Approve",
      "severity": "critical",
      "conflicting_entitlement_id": "<entitlement-a>",
      "conflicting_entitlement_name": "Create Purchase Order"
    }]
  }
  ```

### TC-GOV-SOD-010: Scan rule for existing violations
- **Category**: Nominal
- **Standard**: SOC 2 CC6.3 (Logical Access)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. SoD rule exists; some users have both conflicting entitlements
- **Input**:
  ```
  POST /governance/sod-rules/<rule-id>/scan
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "violations_found": <count>,
    "violations": [{
      "user_id": "<user-id>",
      "first_entitlement_id": "<ent-a>",
      "second_entitlement_id": "<ent-b>"
    }]
  }
  ```

### TC-GOV-SOD-011: List SoD violations
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Violations exist from prior scan
- **Input**:
  ```
  GET /governance/sod-violations?limit=50&offset=0
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [...], "total": <count> }
  ```

### TC-GOV-SOD-012: Get violation details
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Violation exists
- **Input**:
  ```
  GET /governance/sod-violations/<violation-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "id": "<violation-id>", "rule_id": "<rule-id>", "user_id": "<user-id>", ... }
  ```

### TC-GOV-SOD-013: Remediate violation
- **Category**: Nominal
- **Standard**: ISACA COBIT DSS05
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Violation exists
- **Input**:
  ```json
  POST /governance/sod-violations/<violation-id>/remediate
  { "action": "revoke", "entitlement_to_revoke": "<ent-id>" }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "status": "remediated", ... }
  ```

### TC-GOV-SOD-014: Create SoD exemption
- **Category**: Nominal
- **Standard**: SOX Section 404 (Compensating Controls)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. SoD rule exists; user has a violation
- **Input**:
  ```json
  POST /governance/sod-exemptions
  {
    "rule_id": "<rule-id>",
    "user_id": "<user-id>",
    "justification": "Approved by CFO - compensating control: weekly audit review of all POs",
    "approved_by": "<approver-id>",
    "expires_at": "2026-12-31T23:59:59Z"
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: { "id": "<exemption-id>", "status": "active", ... }
  ```

### TC-GOV-SOD-015: List SoD exemptions
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Exemptions exist
- **Input**:
  ```
  GET /governance/sod-exemptions?limit=50&offset=0
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [...], "total": <count> }
  ```

### TC-GOV-SOD-016: Get exemption details
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Exemption exists
- **Input**:
  ```
  GET /governance/sod-exemptions/<exemption-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  ```

### TC-GOV-SOD-017: Revoke exemption
- **Category**: Nominal
- **Standard**: SOX Section 404 (Periodic Review)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Active exemption exists
- **Input**:
  ```
  POST /governance/sod-exemptions/<exemption-id>/revoke
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "status": "revoked", ... }
  ```

### TC-GOV-SOD-018: Filter SoD rules by entitlement
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Rules involving specific entitlement exist
- **Input**:
  ```
  GET /governance/sod-rules?entitlement_id=<ent-id>
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "items": [...] }  // All rules involving the entitlement
  ```

---

## Edge Cases

### TC-GOV-SOD-020: Create SoD rule with same entitlement on both sides
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Entitlement exists
- **Input**:
  ```json
  POST /governance/sod-rules
  {
    "name": "Self-conflict",
    "first_entitlement_id": "<ent-a>",
    "second_entitlement_id": "<ent-a>",
    "severity": "high"
  }
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  Body: { "error": "First and second entitlements must be different" }
  ```

### TC-GOV-SOD-021: Create duplicate SoD rule for same entitlement pair
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Rule between A and B already exists
- **Input**:
  ```json
  POST /governance/sod-rules
  { "name": "Duplicate", "first_entitlement_id": "<ent-a>", "second_entitlement_id": "<ent-b>", "severity": "low" }
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  ```

### TC-GOV-SOD-022: Create SoD rule with reversed entitlement pair
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Rule between A and B already exists
- **Input**:
  ```json
  POST /governance/sod-rules
  { "name": "Reversed", "first_entitlement_id": "<ent-b>", "second_entitlement_id": "<ent-a>", "severity": "low" }
  ```
- **Expected Output**:
  ```
  Status: 409 Conflict
  ```
- **Verification**: System treats A-B and B-A as the same conflict pair

### TC-GOV-SOD-023: SoD check with non-existent user
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```json
  POST /governance/sod-check
  { "user_id": "00000000-0000-0000-0000-000000000099", "entitlement_id": "<ent>" }
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-GOV-SOD-024: Exemption with past expiry date
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. SoD rule and user exist
- **Input**:
  ```json
  POST /governance/sod-exemptions
  {
    "rule_id": "<rule-id>",
    "user_id": "<user-id>",
    "justification": "Already expired",
    "expires_at": "2020-01-01T00:00:00Z"
  }
  ```
- **Expected Output**:
  ```
  Status: 422 Unprocessable Entity
  Body: { "error": "Expiry date must be in the future" }
  ```

### TC-GOV-SOD-025: Create rule with non-existent entitlement
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**:
  ```json
  POST /governance/sod-rules
  {
    "name": "Ghost Rule",
    "first_entitlement_id": "00000000-0000-0000-0000-000000000099",
    "second_entitlement_id": "<valid-ent>",
    "severity": "low"
  }
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

---

## Security Tests

### TC-GOV-SOD-030: Create SoD rule without admin role
- **Category**: Security
- **Standard**: ISACA COBIT (Governance)
- **Preconditions**: Fixtures: `TEST_TENANT`. JWT with non-admin role
- **Input**:
  ```json
  POST /governance/sod-rules
  { "name": "Unauthorized", "first_entitlement_id": "<a>", "second_entitlement_id": "<b>", "severity": "low" }
  ```
- **Expected Output**:
  ```
  Status: 403 Forbidden
  ```

### TC-GOV-SOD-031: Cross-tenant SoD rule access
- **Category**: Security
- **Standard**: Multi-tenancy isolation
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. SoD rule in tenant A; JWT for tenant B (second tenant required)
- **Input**:
  ```
  GET /governance/sod-rules/<tenant-a-rule-id>
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-GOV-SOD-032: Cross-tenant violation access
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Violation in tenant A; JWT for tenant B (second tenant required)
- **Input**:
  ```
  GET /governance/sod-violations/<tenant-a-violation-id>
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

### TC-GOV-SOD-033: Cross-tenant exemption creation
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Rule in tenant A; JWT for tenant B (second tenant required)
- **Input**:
  ```json
  POST /governance/sod-exemptions
  { "rule_id": "<tenant-a-rule>", "user_id": "<user>", "justification": "Cross-tenant" }
  ```
- **Expected Output**:
  ```
  Status: 404 Not Found
  ```

---

## Compliance Tests

### TC-GOV-SOD-040: SOX Section 404 - Financial transaction SoD enforcement
- **Category**: Compliance
- **Standard**: SOX Section 404
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**:
  1. Create entitlements: "Initiate Payment", "Approve Payment", "Record Payment"
  2. Create SoD rules for all pairwise conflicts with severity "critical"
  3. Assign "Initiate Payment" to User A
  4. Run SoD check for assigning "Approve Payment" to User A
  5. Verify conflict detected
  6. Create exemption with documented compensating control
- **Expected Output**: System prevents unauthorized accumulation of financial duties

### TC-GOV-SOD-041: SOC 2 CC6.3 - Periodic SoD scanning
- **Category**: Compliance
- **Standard**: SOC 2 CC6.3 (Role-Based Access)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**:
  1. Create SoD rules covering sensitive financial entitlements
  2. Run scan on each rule
  3. Verify all violations are surfaced with user identity and entitlement details
  4. Export violations for SOC 2 auditor review
- **Expected Output**: Complete violation report suitable for SOC 2 Type II audit evidence

### TC-GOV-SOD-042: SOX - Exemptions require documented compensating controls
- **Category**: Compliance
- **Standard**: SOX Section 404 (Compensating Controls)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**:
  1. Create exemption with business justification
  2. Verify justification stored and retrievable
  3. Verify exemption has expiry date (time-bounded)
  4. Verify exemption can be revoked
- **Expected Output**: Exemptions are auditable with justification, approver, expiry, and revocation capability

### TC-GOV-SOD-043: ISACA COBIT - SoD rule business rationale
- **Category**: Compliance
- **Standard**: ISACA COBIT DSS05 (Manage Security Services)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**:
  1. Create SoD rule with `business_rationale` field populated
  2. Verify business rationale preserved and returned in API responses
  3. Verify rules without rationale are flagged during audit
- **Expected Output**: Every SoD rule has traceable business justification per COBIT standards

### TC-GOV-SOD-044: SoD violation remediation creates audit trail
- **Category**: Compliance
- **Standard**: SOC 2 CC7.2 (System Monitoring)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Steps**:
  1. Create SoD rule and trigger violation
  2. Remediate the violation
  3. Verify audit log contains: violation ID, remediation action, actor, timestamp
- **Expected Output**: Full audit trail from detection through remediation
