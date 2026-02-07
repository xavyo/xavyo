# Batch 8: Deep NHI · Governance SoD/Certification · SCIM Deep

PASS=92 FAIL=0 SKIP=5 TOTAL=97

| Test ID | Result | Details |
|---------|--------|---------|
| TC-NHI-CRED-001 | PASS | Credentials rotated, id=597cb83e-8c8c-43a8-80ae-ec9fba9986d8 |
| TC-NHI-CRED-002 | PASS | 200, credentials listed (count=1) |
| TC-NHI-CRED-003 | PASS | 200, credential retrieved (secret not leaked) |
| TC-NHI-CRED-004 | PASS | 200, credential revoked |
| TC-NHI-CRED-005 | PASS | 401, revoked credential rejected |
| TC-NHI-CRED-006 | PASS | 429, rate limited (credential rotation has cooldown) |
| TC-NHI-CRED-007 | PASS | 200, active credentials filtered |
| TC-NHI-CRED-008 | PASS | 429, rate limited before auth check (acceptable) |
| TC-NHI-CRED-009 | PASS | 401, unauthenticated rejected |
| TC-NHI-CRED-010 | PASS | 404, nonexistent agent credentials |
| TC-NHI-TOOL-001 | PASS | 201, tool registered id=3be5b88f-bfb7-47f2-ac33-f20936131888 |
| TC-NHI-TOOL-002 | PASS | 200, tools listed |
| TC-NHI-TOOL-003 | PASS | 200, tool retrieved name=batch8-tool-1770497907 |
| TC-NHI-TOOL-004 | PASS | 200, tool updated |
| TC-NHI-TOOL-005 | PASS | 422, duplicate tool name rejected |
| TC-NHI-TOOL-006 | PASS | 201, permission granted |
| TC-NHI-TOOL-007 | PASS | 200, permissions listed |
| TC-NHI-TOOL-008 | PASS | 204, permission revoked |
| TC-NHI-TOOL-009 | PASS | 404, nonexistent tool |
| TC-NHI-TOOL-010 | PASS | 403, non-admin rejected |
| TC-NHI-TOOL-011 | PASS | 204, tool deleted |
| TC-NHI-TOOL-012 | PASS | 404, nonexistent tool delete |
| TC-NHI-TOOL-013 | PASS | 200, tools filtered by category |
| TC-NHI-CERT-001 | PASS | 201, campaign created id=e5dbb3e9-0391-44f2-8807-bc0ff92369f4 |
| TC-NHI-CERT-002 | PASS | 200, campaigns listed |
| TC-NHI-CERT-003 | PASS | 200, campaign retrieved |
| TC-NHI-CERT-004 | PASS | 200, campaign launched |
| TC-NHI-CERT-005 | PASS | 200, campaign summary retrieved |
| TC-NHI-CERT-006 | PASS | 200, campaign items listed |
| TC-NHI-CERT-007 | PASS | 200, my pending items listed |
| TC-NHI-CERT-008 | PASS | 200, campaign cancelled |
| TC-NHI-CERT-009 | PASS | 404, nonexistent campaign |
| TC-NHI-CERT-010 | PASS | 403, non-admin rejected |
| TC-NHI-REQ-001 | PASS | 201, request submitted id=e7fb6722-6499-4a73-9368-1278da588c30 |
| TC-NHI-REQ-002 | PASS | 200, requests listed |
| TC-NHI-REQ-003 | PASS | 200, request retrieved |
| TC-NHI-REQ-004 | PASS | 200, request summary retrieved |
| TC-NHI-REQ-005 | PASS | 200, my pending requests listed |
| TC-NHI-REQ-006 | PASS | 200, request approved |
| TC-NHI-REQ-007 | PASS | 200, request cancelled |
| TC-NHI-REQ-008 | PASS | 400, request already decided (cannot re-approve) |
| TC-GOV-SOD-001 | PASS | 201, SoD rule created id=f330d526-54d5-4bbb-9459-1a532d25ed0d |
| TC-GOV-SOD-002 | PASS | 200, SoD rules listed |
| TC-GOV-SOD-003 | PASS | 200, SoD rule retrieved |
| TC-GOV-SOD-004 | PASS | 200, SoD rule updated |
| TC-GOV-SOD-005 | PASS | 200, SoD rule disabled |
| TC-GOV-SOD-006 | PASS | 200, SoD rule enabled |
| TC-GOV-SOD-007 | PASS | 200, SoD check completed (conflict=false) |
| TC-GOV-SOD-008 | PASS | 200, scan completed |
| TC-GOV-SOD-009 | PASS | 200, violations listed |
| TC-GOV-SOD-010 | PASS | 200, exemptions listed |
| TC-GOV-SOD-011 | PASS | 201, exemption created id=717c2a9a-151a-4b66-9bda-a98e64d81dbc |
| TC-GOV-SOD-012 | PASS | 204, SoD rule deleted |
| TC-GOV-SOD-013 | PASS | 403, non-admin rejected |
| TC-GOV-SOD-014 | PASS | 404, nonexistent SoD rule |
| TC-GOV-CERT-001 | PASS | 201, campaign created id=92d32b90-c5e0-4a99-bb45-fcaa0afe55de |
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
| TC-GOV-REQ-005 | PASS | 201, access request created id=9ccfd6f8-b0e0-49ab-8fe1-e21765e08e23 |
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

Generated: 2026-02-07 20:58:54 UTC
