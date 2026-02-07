═══════════════════════════════════════════════════════════════════
  Batch 12 — Connectors Deep & Webhooks Deep Tests
═══════════════════════════════════════════════════════════════════
[20:41:21] ═══ Setup: Creating test users ═══
[20:41:24] admin_jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUz…
[20:41:28] user_jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJSUz…

═══════════════════════════════════════════════════════════════════
  Part 1: SCIM Outbound Targets (TC-ST-001 … TC-ST-030)
═══════════════════════════════════════════════════════════════════
[20:41:28] PASS  TC-ST-001 — List SCIM targets (empty) — 200
[20:41:28] PASS  TC-ST-002 — Create SCIM target (bearer) — 201
[20:41:28] PASS  TC-ST-003 — Get SCIM target — 200
[20:41:28] PASS  TC-ST-004 — Update SCIM target — 200
[20:41:28] PASS  TC-ST-005 — List targets after create — 200, count=1
[20:41:28] PASS  TC-ST-006 — Create SCIM target (oauth2) — 201
[20:41:29] PASS  TC-ST-007 — Health check SCIM target — 200, status=unreachable
[20:41:29] PASS  TC-ST-008 — List attribute mappings — 200
[20:41:29] PASS  TC-ST-009 — Replace attribute mappings — 200, count=3
[20:41:29] PASS  TC-ST-010 — Filter mappings by resource_type — 200
[20:41:29] PASS  TC-ST-011 — Reset mappings to defaults — 200
[20:41:29] PASS  TC-ST-012 — Trigger sync — 409 (target not active, conflict expected)
[20:41:29] PASS  TC-ST-013 — List sync runs — 200
[20:41:29] SKIP  TC-ST-014 — Get sync run — no sync run ID
[20:41:29] PASS  TC-ST-015 — Trigger reconciliation — 409 (sync still running, conflict expected)
[20:41:29] PASS  TC-ST-016 — List provisioning state — 200
[20:41:29] PASS  TC-ST-017 — Filter provisioning state — 200
[20:41:29] PASS  TC-ST-018 — List provisioning log — 200
[20:41:29] PASS  TC-ST-019 — Filter provisioning log — 200
[20:41:29] PASS  TC-ST-020 — List targets with pagination — 200
[20:41:29] PASS  TC-ST-021 — List targets with status filter — 200
[20:41:29] PASS  TC-ST-022 — Invalid auth_method rejected — 400
[20:41:29] PASS  TC-ST-023 — Missing fields rejected — 422
[20:41:29] PASS  TC-ST-024 — Non-admin create target — 403
[20:41:29] PASS  TC-ST-025 — No auth list targets — 401
[20:41:29] PASS  TC-ST-026 — Get non-existent target — 404
[20:41:29] PASS  TC-ST-027 — Health check non-existent — 404
[20:41:29] PASS  TC-ST-028 — Invalid mapping rejected — 400
[20:41:29] PASS  TC-ST-029 — Delete SCIM target — 204
[20:41:30] PASS  TC-ST-030 — Deleted target returns 404 — 404

═══════════════════════════════════════════════════════════════════
  Part 2: Reconciliation Engine (TC-RE-001 … TC-RE-030)
═══════════════════════════════════════════════════════════════════
[20:41:30] [info] Could not create connector, trying to list existing ones
[20:41:30] [info] Using connector ca0b8b3f-b650-4230-93fc-e29a95ca2b16 for reconciliation tests
[20:41:30] PASS  TC-RE-001 — Trigger reconciliation run — 409 (conflict, already running)
[20:41:30] PASS  TC-RE-002 — List reconciliation runs — 200
[20:41:30] PASS  TC-RE-003 — List runs with filters — 200
[20:41:30] SKIP  TC-RE-004 — Get recon run — no run ID
[20:41:30] SKIP  TC-RE-005 — Cancel recon run — no run ID
[20:41:30] SKIP  TC-RE-006 — Resume recon run — no run ID
[20:41:30] SKIP  TC-RE-007 — Get recon report — no run ID
[20:41:30] PASS  TC-RE-008 — List discrepancies — 200
[20:41:30] PASS  TC-RE-009 — List discrepancies filtered — 200
[20:41:30] PASS  TC-RE-010 — Get non-existent discrepancy — 404
[20:41:30] PASS  TC-RE-011 — Preview remediation (empty) — 200
[20:41:30] PASS  TC-RE-012 — Bulk remediate (empty) — 200
[20:41:30] PASS  TC-RE-013 — Ignore non-existent discrepancy — 404
[20:41:30] PASS  TC-RE-014 — Remediate non-existent — 404
[20:41:30] PASS  TC-RE-015 — Create reconciliation schedule — 200
[20:41:30] PASS  TC-RE-016 — Get reconciliation schedule — 200, freq=daily
[20:41:30] PASS  TC-RE-017 — Update schedule to weekly — 200
[20:41:30] PASS  TC-RE-018 — Disable schedule — 204
[20:41:30] PASS  TC-RE-019 — Enable schedule — 204
[20:41:30] PASS  TC-RE-020 — Delete schedule — 204
[20:41:30] PASS  TC-RE-021 — List reconciliation actions — 200
[20:41:31] PASS  TC-RE-022 — List actions filtered — 200
[20:41:31] PASS  TC-RE-023 — Global list schedules — 200
[20:41:31] PASS  TC-RE-024 — Global get trend — 200
[20:41:31] PASS  TC-RE-025 — Global trend with connector filter — 200
[20:41:31] PASS  TC-RE-026 — Trigger delta reconciliation — 409
[20:41:31] PASS  TC-RE-027 — Get non-existent run — 404
[20:41:31] PASS  TC-RE-028 — Non-admin trigger recon — 403
[20:41:31] PASS  TC-RE-029 — No auth list runs — 401
[20:41:31] PASS  TC-RE-030 — No auth global schedules — 401

═══════════════════════════════════════════════════════════════════
  Part 3: Webhook DLQ (TC-WD-001 … TC-WD-020)
═══════════════════════════════════════════════════════════════════
[20:41:31] PASS  TC-WD-001 — List DLQ entries — 200
[20:41:31] PASS  TC-WD-002 — List DLQ with pagination — 200
[20:41:31] PASS  TC-WD-003 — List DLQ event_type filter — 200
[20:41:31] PASS  TC-WD-004 — List DLQ include_replayed — 200
[20:41:31] PASS  TC-WD-005 — Get non-existent DLQ entry — 404
[20:41:31] PASS  TC-WD-006 — Delete non-existent DLQ — 404
[20:41:31] PASS  TC-WD-007 — Replay non-existent DLQ — 404
[20:41:31] PASS  TC-WD-008 — Bulk replay empty filter — 400
[20:41:31] PASS  TC-WD-009 — Bulk replay non-existent IDs — 200
[20:41:31] PASS  TC-WD-010 — List DLQ with date range — 200
[20:41:31] [info] Created webhook subscription 0cd862a5-be20-4943-a8c3-cbacc77d04de
[20:41:31] PASS  TC-WD-011 — List DLQ by subscription — 200
[20:41:31] PASS  TC-WD-012 — Bulk replay by subscription — 200, replayed=0
[20:41:31] PASS  TC-WD-013 — No auth list DLQ — 401
[20:41:31] PASS  TC-WD-014 — No auth replay DLQ — 401
[20:41:31] PASS  TC-WD-015 — No auth bulk replay — 401
[20:41:32] PASS  TC-WD-016 — Bulk replay >100 IDs rejected — 400
[20:41:32] PASS  TC-WD-017 — List webhook event types — 200
[20:41:32] PASS  TC-WD-018 — List delivery history — 200
[20:41:32] PASS  TC-WD-019 — Get non-existent delivery — 404
[20:41:32] PASS  TC-WD-020 — Non-admin list DLQ — 200

═══════════════════════════════════════════════════════════════════
  Part 4: Webhook Circuit Breakers (TC-CB-001 … TC-CB-008)
═══════════════════════════════════════════════════════════════════
[20:41:32] PASS  TC-CB-001 — List circuit breakers — 200
[20:41:32] PASS  TC-CB-002 — Get circuit breaker — 404
[20:41:32] PASS  TC-CB-003 — Get non-existent circuit breaker — 404
[20:41:32] PASS  TC-CB-004 — No auth list circuit breakers — 401
[20:41:32] PASS  TC-CB-005 — No auth get circuit breaker — 401
[20:41:32] PASS  TC-CB-006 — Non-admin list CB — 200
[20:41:32] PASS  TC-CB-007 — Circuit breakers response structure — valid
[20:41:32] PASS  TC-CB-008 — Circuit breaker no state (new sub) — 404

═══════════════════════════════════════════════════════════════════
  Part 5: Connector Jobs & DLQ (TC-CJ-001 … TC-CJ-018)
═══════════════════════════════════════════════════════════════════
[20:41:32] PASS  TC-CJ-001 — List connector jobs — 200
[20:41:32] PASS  TC-CJ-002 — List jobs with pagination — 200
[20:41:32] PASS  TC-CJ-003 — Get non-existent job — 404
[20:41:32] PASS  TC-CJ-004 — Cancel non-existent job — 404
[20:41:32] PASS  TC-CJ-005 — List connector DLQ — 200
[20:41:32] PASS  TC-CJ-006 — List connector DLQ pagination — 200
[20:41:32] PASS  TC-CJ-007 — List DLQ connector filter — 200
[20:41:32] PASS  TC-CJ-008 — Replay non-existent DLQ entry — 404
[20:41:33] PASS  TC-CJ-009 — Bulk replay empty IDs — 200
[20:41:33] PASS  TC-CJ-010 — Bulk replay non-existent IDs — 200
[20:41:33] PASS  TC-CJ-011 — Non-admin list jobs — 403
[20:41:33] PASS  TC-CJ-012 — Non-admin list DLQ — 403
[20:41:33] PASS  TC-CJ-013 — Non-admin replay DLQ — 403
[20:41:33] PASS  TC-CJ-014 — Non-admin bulk replay — 403
[20:41:33] PASS  TC-CJ-015 — No auth list jobs — 401
[20:41:33] PASS  TC-CJ-016 — No auth list DLQ — 401
[20:41:33] PASS  TC-CJ-017 — No auth replay DLQ — 401
[20:41:33] PASS  TC-CJ-018 — No auth cancel job — 401

═══════════════════════════════════════════════════════════════════
  Part 6: Connector Health & Schema (TC-CH-001 … TC-CH-012)
═══════════════════════════════════════════════════════════════════
[20:41:33] PASS  TC-CH-001 — Get connector health — 400
[20:41:33] PASS  TC-CH-002 — Get connector schema — 404
[20:41:33] PASS  TC-CH-003 — Health non-existent connector — 400
[20:41:33] PASS  TC-CH-004 — Schema non-existent connector — 404
[20:41:33] PASS  TC-CH-005 — Activate connector — 200
[20:41:33] PASS  TC-CH-006 — Deactivate connector — 200
[20:41:33] PASS  TC-CH-007 — Re-activate connector — 200
[20:41:33] PASS  TC-CH-008 — Non-admin get health — 400
[20:41:33] PASS  TC-CH-009 — No auth get health — 401
[20:41:33] PASS  TC-CH-010 — No auth activate — 401
[20:41:33] PASS  TC-CH-011 — Non-admin activate — 403
[20:41:33] PASS  TC-CH-012 — Non-admin deactivate — 403

═══════════════════════════════════════════════════════════════════
  Part 7: Connector Sync Operations (TC-CS-001 … TC-CS-012)
═══════════════════════════════════════════════════════════════════
[20:41:33] PASS  TC-CS-001 — Trigger sync — 200
[20:41:33] PASS  TC-CS-002 — Get sync config — 200
[20:41:33] PASS  TC-CS-003 — Get sync status — 200
[20:41:33] PASS  TC-CS-004 — List sync changes — 200
[20:41:34] PASS  TC-CS-005 — List sync conflicts — 200
[20:41:34] PASS  TC-CS-006 — Get sync token — 404
[20:41:34] PASS  TC-CS-007 — Enable sync — 204
[20:41:34] PASS  TC-CS-008 — Disable sync — 204
[20:41:34] PASS  TC-CS-009 — Non-admin trigger sync — 403
[20:41:34] PASS  TC-CS-010 — No auth trigger sync — 401
[20:41:34] PASS  TC-CS-011 — No auth sync status — 401
[20:41:34] PASS  TC-CS-012 — List all connectors — 200

═══════════════════════════════════════════════════════════════════
  Batch 12 Results: Connectors Deep & Webhooks Deep
═══════════════════════════════════════════════════════════════════

  PASS=125 FAIL=0 SKIP=5 TOTAL=130

  All tests passed!
═══════════════════════════════════════════════════════════════════
