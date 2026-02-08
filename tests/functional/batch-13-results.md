# Batch 13: NHI Feature 201 — Unified Model, Agent CRUD, Lifecycle, Certification

PASS=3 FAIL=29 SKIP=36 TOTAL=68

| Test ID | Result | Details |
|---------|--------|---------|
| TC-201-UNI-001 | FAIL | Expected 200, got 401 |
| TC-201-UNI-002 | FAIL | Expected 200, got 401 |
| TC-201-UNI-003 | SKIP | No agent ID |
| TC-201-UNI-004 | SKIP | No tool ID |
| TC-201-UNI-005 | SKIP | No service account ID |
| TC-201-UNI-006 | FAIL | Expected 404, got 401 |
| TC-201-UNI-007 | PASS | 401, unauthenticated rejected |
| TC-201-UNI-008 | FAIL | Expected 200, got 401 |
| TC-201-AGT-001 | FAIL | Expected 201, got 401 |
| TC-201-AGT-002 | SKIP | No agent ID |
| TC-201-AGT-003 | SKIP | No agent ID |
| TC-201-AGT-004 | FAIL | Expected 200, got 401 |
| TC-201-AGT-005 | FAIL | Expected 201, got 401 |
| TC-201-AGT-006 | FAIL | Expected 201, got 401 |
| TC-201-AGT-007 | FAIL | Expected 403, got 401 (SECURITY: non-admin should not create agents) |
| TC-201-AGT-008 | PASS | 401, unauthenticated rejected |
| TC-201-AGT-009 | FAIL | Expected 404, got 401 |
| TC-201-AGT-010 | SKIP | No agent ID |
| TC-201-LC-001 | SKIP | No lifecycle agent |
| TC-201-LC-002 | SKIP | No lifecycle agent |
| TC-201-LC-003 | SKIP | No lifecycle agent |
| TC-201-LC-004 | SKIP | No lifecycle agent |
| TC-201-LC-005 | SKIP | No lifecycle agent |
| TC-201-LC-006 | SKIP | No lifecycle agent |
| TC-201-LC-007 | SKIP | Could not create test agent |
| TC-201-LC-008 | SKIP | No lifecycle agent |
| TC-201-LC-009 | SKIP | No test agent |
| TC-201-LC-010 | SKIP | No test agent |
| TC-201-LC-011 | FAIL | Expected 404, got 401 |
| TC-201-LC-012 | SKIP | No test agent |
| TC-201-LC-013 | SKIP | No test agent |
| TC-201-CERT-001 | FAIL | Expected 201, got 401 |
| TC-201-CERT-002 | FAIL | Expected 201, got 401 |
| TC-201-CERT-003 | FAIL | Expected 201, got 401 |
| TC-201-CERT-004 | FAIL | Expected 400/422, got 401 |
| TC-201-CERT-005 | FAIL | Expected 400/422, got 401 |
| TC-201-CERT-006 | FAIL | Expected 400/422, got 401 |
| TC-201-CERT-007 | FAIL | Expected 400/422, got 401 |
| TC-201-CERT-008 | SKIP | No campaign or agent ID |
| TC-201-CERT-009 | FAIL | Expected 200, got 401 |
| TC-201-CERT-010 | FAIL | Expected 403, got 401 (SECURITY) |
| TC-201-CERT-011 | SKIP | No campaign ID |
| TC-201-CERT-012 | SKIP | No agent ID |
| TC-201-PERM-001 | SKIP | No agent or tool ID |
| TC-201-PERM-002 | SKIP | No agent ID |
| TC-201-PERM-003 | SKIP | No agent or second tool ID |
| TC-201-PERM-004 | SKIP | No tool ID |
| TC-201-PERM-005 | SKIP | No agent or tool ID |
| TC-201-PERM-006 | SKIP | No agent or tool ID |
| TC-201-PERM-007 | SKIP | No agent or tool ID |
| TC-201-PERM-008 | SKIP | No tool ID |
| TC-201-RISK-001 | FAIL | Expected 200, got 401 |
| TC-201-RISK-002 | SKIP | No agent ID |
| TC-201-RISK-003 | SKIP | No agent ID |
| TC-201-RISK-004 | FAIL | Expected 404, got 401 |
| TC-201-RISK-005 | PASS | 401, unauthenticated risk summary rejected |
| TC-201-INACT-001 | FAIL | Expected 200, got 401 |
| TC-201-INACT-002 | SKIP | No agent ID |
| TC-201-INACT-003 | FAIL | Expected 200, got 401 |
| TC-201-INACT-004 | FAIL | Expected 200/204, got 401 |
| TC-201-INACT-005 | FAIL | Expected 403, got 401 (SECURITY: non-admin should not detect inactive) |
| TC-201-INACT-006 | FAIL | Expected 404, got 401 |
| TC-201-SOD-001 | SKIP | Missing tool IDs for SoD rule creation |
| TC-201-SOD-002 | FAIL | Expected 200, got 401 |
| TC-201-SOD-003 | SKIP | No agent or tool ID for SoD check |
| TC-201-SOD-004 | SKIP | No SoD rule ID |
| TC-201-SOD-005 | SKIP | Missing tool IDs |
| TC-201-SOD-006 | FAIL | Expected 404, got 401 |

Generated: 2026-02-08 15:20:53 UTC
