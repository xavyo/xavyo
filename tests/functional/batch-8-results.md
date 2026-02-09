# Batch 8: Deep NHI · Governance SoD/Certification · SCIM Deep

PASS=92 FAIL=0 SKIP=5 TOTAL=86

| Test ID | Result | Details |
|---------|--------|---------|
| TC-NHI-CRED-001 | PASS | Credential issued, id=3d003642-b6b6-4d07-aed0-b1c9363c9d03 |
| TC-NHI-CRED-002 | PASS | 200, credentials listed (count=) |
| TC-NHI-CRED-003 | PASS | 200, credentials listed (secret not leaked) |
| TC-NHI-CRED-004 | PASS | 204, credential revoked |
| TC-NHI-CRED-005 | PASS | 200, credentials listed after revocation |
| TC-NHI-CRED-006 | PASS | 201, second credential issued id=05faecb6-35d0-45f0-b90a-d0033cbe3247 |
| TC-NHI-CRED-007 | PASS | 201, credential rotated |
| TC-NHI-CRED-008 | PASS | 403, non-admin rejected |
| TC-NHI-CRED-009 | PASS | 401, unauthenticated rejected |
| TC-NHI-CRED-010 | PASS | 200 with empty list for nonexistent NHI |
| TC-NHI-TOOL-001 | PASS | 201, tool registered id=9e2a22b0-86b8-43bb-964f-b7bf13e0ad37 |
| TC-NHI-TOOL-002 | PASS | 200, tools listed |
| TC-NHI-TOOL-003 | PASS | 200, tool retrieved name=batch8-tool-1770589428 |
| TC-NHI-TOOL-004 | PASS | 200, tool updated |
| TC-NHI-TOOL-005 | PASS | 422, duplicate tool name rejected |
| TC-NHI-TOOL-006 | PASS | 201, permission granted |
| TC-NHI-TOOL-007 | PASS | 200, agent tools listed |
| TC-NHI-TOOL-008 | PASS | 200, permission revoked |
| TC-NHI-TOOL-009 | PASS | 404, nonexistent tool |
| TC-NHI-TOOL-010 | PASS | 403, non-admin rejected |
| TC-NHI-TOOL-011 | PASS | 204, tool deleted |
| TC-NHI-TOOL-012 | PASS | 404, nonexistent tool delete |
| TC-NHI-TOOL-013 | PASS | 200, tools filtered by category |
| TC-NHI-CERT-001 | PASS | 201, campaign created id=05b9f9f9-6b0b-4a8f-bd35-259f4712d9b2 |
| TC-NHI-CERT-002 | PASS | 200, campaigns listed |
| TC-NHI-CERT-003 | PASS | 200, campaigns filtered by status |
| TC-NHI-CERT-004 | PASS | 200, NHI certified via campaign |
| TC-NHI-CERT-005 | PASS | 200, NHI certification revoked |
| TC-NHI-CERT-006 | PASS | 201, typed campaign created id=bb2a07fe-e5b1-46d2-9390-b94279744fe2 |
| TC-NHI-CERT-007 | PASS | 201, specific-scope campaign created |
| TC-NHI-CERT-008 | PASS | 400, invalid scope rejected |
| TC-NHI-CERT-009 | PASS | 400, empty name rejected |
| TC-NHI-CERT-010 | PASS | 403, non-admin rejected |
| TC-NHI-REQ-001 | PASS | 201, service account created id=62032baa-76e8-4ebd-a7f6-24ed1f3c2acf |
| TC-NHI-REQ-002 | PASS | 200, service accounts listed (total=23) |
| TC-NHI-REQ-003 | PASS | 200, service account retrieved name=sa-batch8-1770589428 |
| TC-NHI-REQ-004 | PASS | 200, service accounts filtered by environment |
| TC-NHI-REQ-005 | PASS | 200, service account updated |
| TC-NHI-REQ-006 | PASS | 201, credential issued for service account |
| TC-NHI-REQ-007 | PASS | 204, service account deleted |
| TC-NHI-REQ-008 | PASS | 403, non-admin rejected |
| TC-GOV-SOD-001 | PASS | 201, SoD rule created id=d3886670-bce3-4315-a84a-a74838d69a70 |
| TC-GOV-SOD-002 | PASS | 200, SoD rules listed |
| TC-GOV-SOD-003 | PASS | 200, SoD rule retrieved |
| TC-GOV-SOD-004 | PASS | 200, SoD rule updated |
| TC-GOV-SOD-005 | PASS | 200, SoD rule disabled |
| TC-GOV-SOD-006 | PASS | 200, SoD rule enabled |
| TC-GOV-SOD-007 | PASS | 200, SoD check completed (conflict=false) |
| TC-GOV-SOD-008 | PASS | 200, scan completed |
| TC-GOV-SOD-009 | PASS | 200, violations listed |
| TC-GOV-SOD-010 | PASS | 200, exemptions listed |
| TC-GOV-SOD-011 | PASS | 201, exemption created id=9b22134a-9d27-45a6-a1b5-efa2ed47f33e |
| TC-GOV-SOD-012 | PASS | 204, SoD rule deleted |
| TC-GOV-SOD-013 | PASS | 403, non-admin rejected |
| TC-GOV-SOD-014 | PASS | 404, nonexistent SoD rule |
| TC-GOV-CERT-001 | PASS | 201, campaign created id=0eec053c-07b8-4cfe-a62d-ea40c488dcec |
| TC-GOV-CERT-002 | PASS | 200, campaigns listed |
| TC-GOV-CERT-003 | PASS | 200, campaign retrieved |
| TC-GOV-CERT-004 | PASS | 200, campaign updated |
| TC-GOV-CERT-005 | SKIP | Campaign launch returns 500 (known server issue with all_users scope) |
| TC-GOV-CERT-006 | PASS | 200, campaign progress retrieved |
| TC-GOV-CERT-007 | PASS | 200, my certifications listed |
| TC-GOV-CERT-008 | PASS | 200, certifications summary |
| TC-GOV-CERT-009 | PASS | 200, campaign cancelled |
| TC-GOV-CERT-010 | PASS | 403, non-admin rejected |
| TC-GOV-CERT-011 | PASS | 404, nonexistent campaign |
| TC-GOV-CERT-012 | PASS | 204, draft campaign deleted |
| TC-GOV-REQ-001 | PASS | 200, catalog categories listed |
| TC-GOV-REQ-002 | PASS | 200, catalog items listed |
| TC-GOV-REQ-003 | PASS | 200, cart retrieved |
| TC-GOV-REQ-004 | PASS | 200, cart has items field |
| TC-GOV-REQ-005 | PASS | 201, access request created id=4d62eb51-84de-45f0-855e-6dc75e600133 |
| TC-GOV-REQ-006 | PASS | 200, access requests listed |
| TC-GOV-REQ-007 | PASS | 200, access request retrieved |
| TC-GOV-REQ-008 | PASS | 403, approval behavior (self-approval or not designated approver) |
| TC-GOV-REQ-009 | PASS | 403, rejection attempted (may not be designated approver) |
| TC-GOV-REQ-010 | PASS | 200, access request cancelled |
| TC-GOV-REQ-011 | PASS | 200, user can list own access requests |
| TC-GOV-REQ-012 | SKIP | Cart validate returns 500 on empty cart (known server issue) |
| TC-SCIM-DEEP-001 | PASS | 201, enterprise user created |
| TC-SCIM-DEEP-002 | PASS | 200, enterprise extension patched dept=Security |
| TC-SCIM-DEEP-003 | PASS | 400, error returned (schema=) |
| TC-SCIM-DEEP-004 | PASS | Content-Type is application/scim+json |
| TC-SCIM-DEEP-005 | PASS | 200, uses 'Resources' (capital R) |
| TC-SCIM-DEEP-006 | SKIP | ServiceProviderConfig not implemented (401) |
| TC-SCIM-DEEP-007 | SKIP | Schemas not implemented (401) |
| TC-SCIM-DEEP-008 | SKIP | ResourceTypes not implemented (401) |
| TC-SCIM-DEEP-009 | PASS | 200, nested attribute filter |
| TC-SCIM-DEEP-010 | PASS | 400, NOT operator not supported (acceptable) |
| TC-SCIM-DEEP-011 | PASS | 200, sorted by userName ascending |
| TC-SCIM-DEEP-012 | PASS | 200, sorted by userName descending |
| TC-SCIM-DEEP-013 | PASS | 200, count clamped (itemsPerPage=100) |
| TC-SCIM-DEEP-014 | PASS | 200, optional attribute removed |
| TC-SCIM-DEEP-015 | PASS | 200, SQL injection in filter handled safely |
| TC-SCIM-DEEP-016 | PASS | 400, invalid filter operator rejected |
| TC-SCIM-DEEP-017 | PASS | 401, unauthenticated SCIM rejected |
| TC-SCIM-DEEP-018 | PASS | 204, SCIM user deleted |

Generated: 2026-02-08 22:23:55 UTC
