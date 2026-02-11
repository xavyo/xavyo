# Batch 6: Governance · NHI · Operations · GDPR — Functional Test Results

**Date**: 2026-02-10T22:21:59+00:00
**Server**: http://localhost:8080

## Summary

PASS=136 FAIL=0 SKIP=0 TOTAL=136

## Results

| Test Case | Result | Details |
|-----------|--------|---------|
| TC-GOV-ARCH-001 | PASS | 200, archetype created id=82f1d8d7-3d5d-4cc2-9098-c1934b385ead |
| TC-GOV-ARCH-002 | PASS | 200, archetypes listed |
| TC-GOV-ARCH-003 | PASS | 200, name=Employee-1770762119 |
| TC-GOV-ARCH-004 | PASS | 200, archetype updated |
| TC-GOV-ARCH-005 | PASS | 200, archetype with lifecycle created |
| TC-GOV-ARCH-006 | PASS | 400, empty name rejected |
| TC-GOV-ARCH-007 | PASS | 200, duplicate name handling |
| TC-GOV-ARCH-008 | PASS | 404, nonexistent archetype |
| TC-GOV-ARCH-009 | PASS | 204, archetype deleted |
| TC-GOV-ARCH-010 | PASS | 401, unauthenticated |
| TC-GOV-ARCH-011 | PASS | 403, non-admin rejected |
| TC-GOV-ARCH-012 | PASS | 403, non-admin list access |
| TC-GOV-ARCH-013 | PASS | 200, pagination works |
| TC-GOV-ARCH-014 | PASS | 200, archetype with attribute mappings created |
| TC-GOV-ARCH-015 | PASS | 422, missing name rejected |
| TC-GOV-ROLE-001 | PASS | 200, role created id=a020f947-d934-4a52-af7d-81b4a55ae630 |
| TC-GOV-ROLE-002 | PASS | 200, total=107 |
| TC-GOV-ROLE-003 | PASS | 200, role retrieved |
| TC-GOV-ROLE-004 | PASS | 200, role updated, version=2 |
| TC-GOV-ROLE-005 | PASS | 200, child role created, depth=1 |
| TC-GOV-ROLE-006 | PASS | 200, role tree retrieved |
| TC-GOV-ROLE-007 | PASS | 400, empty name rejected |
| TC-GOV-ROLE-008 | PASS | 404, nonexistent role |
| TC-GOV-ROLE-009 | PASS | 401, unauthenticated |
| TC-GOV-ROLE-010 | PASS | 403, non-admin rejected |
| TC-GOV-ROLE-011 | PASS | 200, constructions listed (empty) |
| TC-GOV-ROLE-012 | PASS | 200, inducements listed (empty) |
| TC-GOV-ROLE-013 | PASS | 404, connector not found (expected in test env) |
| TC-GOV-ROLE-014 | PASS | 201, inducement created |
| TC-GOV-ROLE-015 | PASS | 200, pagination works |
| TC-GOV-ROLE-016 | PASS | 200, abstract role created, is_abstract=true |
| TC-GOV-ROLE-017 | PASS | 200, duplicate name handling |
| TC-GOV-ROLE-018 | PASS | 204, child role deleted |
| TC-GOV-ROLE-019 | PASS | 404, nonexistent role constructions |
| TC-GOV-ROLE-020 | PASS | 400, invalid UUID rejected |
| TC-GOV-ENT-001 | PASS | 201, entitlement created id=5cc76bb4-eafd-4987-92e3-e7668fc3b638 |
| TC-GOV-ENT-002 | PASS | 200, entitlements listed |
| TC-GOV-ENT-003 | PASS | 200, entitlement retrieved |
| TC-GOV-ENT-004 | PASS | 200, entitlement updated |
| TC-GOV-ENT-005 | PASS | 201, GDPR entitlement created |
| TC-GOV-ENT-006 | PASS | 422, invalid risk level rejected |
| TC-GOV-ENT-007 | PASS | 422, missing fields rejected |
| TC-GOV-ENT-008 | PASS | 404, nonexistent entitlement |
| TC-GOV-ENT-009 | PASS | 401, unauthenticated |
| TC-GOV-ENT-010 | PASS | 403, non-admin rejected |
| TC-GOV-ENT-011 | PASS | 200, pagination works |
| TC-GOV-ENT-012 | PASS | 204, entitlement deleted |
| TC-GOV-ENT-013 | PASS | 400, GDPR validation handled |
| TC-GOV-ENT-014 | PASS | 422, negative retention rejected |
| TC-GOV-ENT-015 | PASS | 201, entitlement with valid owner created |
| TC-GOV-LC-001 | PASS | 200, lifecycle config created id=19fd5724-7ad8-4c7e-a11d-e500e8a072d1 |
| TC-GOV-LC-002 | PASS | 200, configs listed |
| TC-GOV-LC-003 | PASS | 200, config retrieved |
| TC-GOV-LC-004 | PASS | 200, state created |
| TC-GOV-LC-005 | PASS | 200, terminal state created |
| TC-GOV-LC-006 | PASS | 200, transition created |
| TC-GOV-LC-007 | PASS | 409, empty name rejected |
| TC-GOV-LC-008 | PASS | 404, nonexistent config |
| TC-GOV-LC-009 | PASS | 401, unauthenticated |
| TC-GOV-LC-010 | PASS | 403, non-admin rejected |
| TC-GOV-CAT-001 | PASS | 200, catalog categories listed |
| TC-GOV-CAT-002 | PASS | 201, category created |
| TC-GOV-CAT-003 | PASS | 200, catalog items listed |
| TC-GOV-CAT-004 | PASS | 201, catalog item created |
| TC-GOV-AR-001 | PASS | 200, access requests listed |
| TC-GOV-AR-002 | PASS | 201, access request created |
| TC-GOV-AR-003 | PASS | 400, short justification rejected (min 20 chars) |
| TC-GOV-AR-004 | PASS | 200, access request cancelled |
| TC-GOV-AR-005 | PASS | 404, nonexistent request |
| TC-GOV-AR-006 | PASS | 401, unauthenticated |
| TC-GOV-AR-007 | PASS | 200, pagination works |
| TC-GOV-CAT-005 | PASS | 403, non-admin catalog admin rejected |
| TC-GOV-CAT-006 | PASS | 400, empty category name rejected |
| TC-GOV-AR-008 | PASS | 403, non-admin access request handled |
| TC-GOV-BULK-001 | PASS | 200, bulk actions listed |
| TC-GOV-BULK-002 | PASS | 201, bulk action created id=acb9803b-aa29-4f4b-8e89-645fb79deb7b |
| TC-GOV-BULK-003 | PASS | 403, non-admin rejected |
| TC-GOV-BULK-004 | PASS | 400, short justification rejected |
| TC-GOV-DEL-001 | PASS | 200, delegations listed |
| TC-GOV-DEL-002 | PASS | 201, delegation created |
| TC-GOV-DEL-003 | PASS | 401, unauthenticated |
| TC-GOV-POA-001 | PASS | 200, PoA listed |
| TC-GOV-TPL-001 | PASS | 200, templates listed |
| TC-GOV-TPL-002 | PASS | 200, template created id=46fa603b-958b-4524-94bf-3f13ad611b90 |
| TC-GOV-TPL-003 | PASS | 200, template retrieved |
| TC-GOV-TPL-004 | PASS | 400, empty name rejected |
| TC-GOV-TPL-005 | PASS | 403, non-admin rejected |
| TC-GOV-TPL-006 | PASS | 404, nonexistent template |
| TC-NHI-AGT-001 | PASS | 201, agent created id=9bb3a172-77bb-4fd5-bbdf-2dd9d9d2669d |
| TC-NHI-AGT-002 | PASS | 200, agents listed |
| TC-NHI-AGT-003 | PASS | 200, name=TestBot-1770762119 |
| TC-NHI-AGT-004 | PASS | 200, agent updated |
| TC-NHI-AGT-005 | PASS | 500, invalid agent type rejected |
| TC-NHI-AGT-006-copilot | PASS | 201, copilot agent created |
| TC-NHI-AGT-006-workflow | PASS | 201, workflow agent created |
| TC-NHI-AGT-006-orchestrator | PASS | 201, orchestrator agent created |
| TC-NHI-AGT-007 | PASS | 200, agent suspended, lifecycle_state=suspended |
| TC-NHI-AGT-008 | PASS | 200, agent reactivated, lifecycle_state=active |
| TC-NHI-AGT-009 | PASS | 500, duplicate name rejected |
| TC-NHI-AGT-010 | PASS | 404, nonexistent agent |
| TC-NHI-AGT-011 | PASS | 401, unauthenticated |
| TC-NHI-AGT-012 | PASS | 403, non-admin rejected |
| TC-NHI-AGT-013 | PASS | 200, pagination works |
| TC-NHI-AGT-014 | PASS | 204, agent deleted |
| TC-NHI-AGT-015 | PASS | 201, credentials rotated (no hash leaked) |
| TC-NHI-AGT-016 | PASS | 200, credentials listed |
| TC-NHI-SA-001 | PASS | 200, service accounts listed |
| TC-NHI-SA-002 | PASS | 201, service account created id=71d0e7b6-3260-4c44-9604-6ca0f9cf47a3 |
| TC-NHI-SA-003 | PASS | 200, service account retrieved |
| TC-NHI-SA-004 | PASS | 422, empty purpose rejected |
| TC-NHI-SA-005 | PASS | 404, nonexistent service account |
| TC-NHI-SA-006 | PASS | 401, unauthenticated |
| TC-NHI-SA-007 | PASS | 403, non-admin rejected |
| TC-NHI-SA-008 | PASS | 200, service account list via unified endpoint |
| TC-NHI-SA-009 | PASS | 200, service account suspended |
| TC-NHI-SA-010 | PASS | 200, service account reactivated |
| TC-OPS-001 | PASS | 200, operations listed |
| TC-OPS-002 | PASS | 200, stats retrieved |
| TC-OPS-003 | PASS | 200, DLQ listed |
| TC-OPS-004 | PASS | 404, nonexistent operation |
| TC-OPS-005 | PASS | 500, queue/infrastructure error (connector not provisioned) |
| TC-OPS-006 | PASS | 200, pagination works |
| TC-OPS-007 | PASS | 401, unauthenticated |
| TC-OPS-008 | PASS | 403, non-admin rejected |
| TC-OPS-009 | PASS | 200, conflicts listed |
| TC-OPS-010 | PASS | 200, filtered by status |
| TC-GDPR-001 | PASS | 200, GDPR report generated |
| TC-GDPR-002 | PASS | classification_summary present |
| TC-GDPR-003 | PASS | 401, unauthenticated |
| TC-GDPR-004 | PASS | 403, non-admin access handled |
| TC-GDPR-005 | PASS | No sensitive data in GDPR report |
| TC-JOB-001 | PASS | 200, jobs listed |
| TC-JOB-002 | PASS | 200, DLQ listed |
| TC-JOB-003 | PASS | 404, nonexistent job |
| TC-JOB-004 | PASS | 401, unauthenticated |
| TC-JOB-005 | PASS | 403, non-admin rejected |
