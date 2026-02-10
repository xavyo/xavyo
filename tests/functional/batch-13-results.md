# Batch 13: NHI Feature 201 — Unified Model, Agent CRUD, Lifecycle, Certification

PASS=68 FAIL=0 SKIP=0 TOTAL=68

| Test ID | Result | Details |
|---------|--------|---------|
| TC-201-UNI-001 | PASS | 200, unified list returned (total=302) |
| TC-201-UNI-002 | PASS | 200, count increased from 302 to 305 (created 3) |
| TC-201-UNI-003 | PASS | 200, agent via unified endpoint (type=agent, has_agent_ext=yes) |
| TC-201-UNI-004 | PASS | 200, tool via unified endpoint (type=tool) |
| TC-201-UNI-005 | PASS | 200, service account via unified endpoint (type=service_account) |
| TC-201-UNI-006 | PASS | 404, nonexistent NHI |
| TC-201-UNI-007 | PASS | 401, unauthenticated rejected |
| TC-201-UNI-008 | PASS | 200, pagination works (limit=2, data_count=2) |
| TC-201-AGT-001 | PASS | 201, agent created without team (id=780720e4-4e5c-4bc4-95d0-9a108509492a) |
| TC-201-AGT-002 | PASS | 200, agent retrieved (name=agt-no-team-1770747103, type=copilot) |
| TC-201-AGT-003 | PASS | 200, agent updated (model=claude-opus-4-6) |
| TC-201-AGT-004 | PASS | 200, agents listed (total=197) |
| TC-201-AGT-005 | PASS | 201, autonomous agent created (id=2b8575b0-081c-43d9-b7b2-d1b517d3bbb7) |
| TC-201-AGT-006 | PASS | 201, orchestrator agent created (id=ddc236f9-65c9-410b-aac1-1de1ae3bb2c7) |
| TC-201-AGT-007 | PASS | 403, non-admin create rejected |
| TC-201-AGT-008 | PASS | 401, unauthenticated rejected |
| TC-201-AGT-009 | PASS | 404, nonexistent agent |
| TC-201-AGT-010 | PASS | 204, agent deleted |
| TC-201-LC-001 | PASS | 200, agent suspended (state=suspended, reason=testing suspension) |
| TC-201-LC-002 | PASS | 200, agent reactivated (state=active) |
| TC-201-LC-003 | PASS | 200, suspension_reason cleared after reactivation |
| TC-201-LC-004 | PASS | 200, agent deprecated (state=deprecated) |
| TC-201-LC-005 | PASS | 200, agent archived (state=archived, terminal) |
| TC-201-LC-006 | PASS | 200, credentials after archive (active_count=0) |
| TC-201-LC-007 | PASS | 400, invalid transition active->archived rejected |
| TC-201-LC-008 | PASS | 400, invalid transition archived->active rejected |
| TC-201-LC-009 | PASS | 200, agent deactivated (state=inactive) |
| TC-201-LC-010 | PASS | 200, agent activated (state=active) |
| TC-201-LC-011 | PASS | 404, nonexistent NHI lifecycle transition |
| TC-201-LC-012 | PASS | 403, non-admin lifecycle transition rejected |
| TC-201-LC-013 | PASS | 401, unauthenticated lifecycle transition rejected |
| TC-201-CERT-001 | PASS | 201, campaign created with scope=all (id=3b9258c7-8013-4eaa-bd8c-53ebd72f62c7) |
| TC-201-CERT-002 | PASS | 201, campaign created with scope=by_type (id=1f91ac18-13e9-441c-a048-8ab8dc610b58) |
| TC-201-CERT-003 | PASS | 201, campaign created with scope=specific (id=3c1175fc-ac1a-4f6c-a11f-56ec3f01a352) |
| TC-201-CERT-004 | PASS | 400, by_type without nhi_type_filter rejected |
| TC-201-CERT-005 | PASS | 400, specific without specific_nhi_ids rejected |
| TC-201-CERT-006 | PASS | 400, invalid scope 'foobar' rejected |
| TC-201-CERT-007 | PASS | 400, empty name rejected |
| TC-201-CERT-008 | PASS | 200, NHI certified in all-scope campaign (at=2026-02-10T18:11:47.495734849Z) |
| TC-201-CERT-009 | PASS | 200, campaigns listed |
| TC-201-CERT-010 | PASS | 403, non-admin create campaign rejected |
| TC-201-CERT-011 | PASS | 404, certify nonexistent NHI |
| TC-201-CERT-012 | PASS | 404, certify in nonexistent campaign |
| TC-201-PERM-001 | PASS | 201, tool permission granted to agent |
| TC-201-PERM-002 | PASS | 200, agent has 1 tool permission(s) |
| TC-201-PERM-003 | PASS | 201, permission granted with expiry (expires=2027-06-15T00:00:00Z) |
| TC-201-PERM-004 | PASS | 200, tool has 1 agent permission(s) |
| TC-201-PERM-005 | PASS | 200, permission revoked (revoked=true) |
| TC-201-PERM-006 | PASS | 201, permission re-granted (upsert) |
| TC-201-PERM-007 | PASS | 403, non-admin grant rejected |
| TC-201-PERM-008 | PASS | 404, grant to nonexistent agent rejected |
| TC-201-RISK-001 | PASS | 200, risk summary retrieved (total_entities=311) |
| TC-201-RISK-002 | PASS | 200, agent risk score=19 level=low |
| TC-201-RISK-003 | PASS | 200, risk has total_score=19, risk_level=low, common_factors=3 |
| TC-201-RISK-004 | PASS | 404, nonexistent NHI risk |
| TC-201-RISK-005 | PASS | 401, unauthenticated risk summary rejected |
| TC-201-INACT-001 | PASS | 200, inactive NHIs detected |
| TC-201-INACT-002 | PASS | 204, grace period initiated for agent |
| TC-201-INACT-003 | PASS | 200, orphan detection completed |
| TC-201-INACT-004 | PASS | 200, auto-suspend executed (suspended=0) |
| TC-201-INACT-005 | PASS | 403, non-admin detect inactive rejected |
| TC-201-INACT-006 | PASS | 404, grace period for nonexistent NHI |
| TC-201-SOD-001 | PASS | 201, SoD rule created id=2ba5815d-db52-41b7-b6f4-b7cb30c9928d |
| TC-201-SOD-002 | PASS | 200, SoD rules listed (count=1) |
| TC-201-SOD-003 | PASS | 200, SoD check done (is_allowed=false, violations=1) |
| TC-201-SOD-004 | PASS | 204, SoD rule deleted |
| TC-201-SOD-005 | PASS | 403, non-admin SoD rule creation rejected |
| TC-201-SOD-006 | PASS | 404, nonexistent SoD rule delete |

Generated: 2026-02-10 18:11:48 UTC
