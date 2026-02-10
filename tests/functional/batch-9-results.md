# Batch 9: Governance Deep — Role Mining, Identity Merge, Personas, Risk

**Date**: 2026-02-10T18:10:32+00:00
**Server**: http://localhost:8080

## Summary

PASS=122 FAIL=0 SKIP=0 TOTAL=122

## Results

| Test Case | Result | Details |
|-----------|--------|---------|
| TC-RM-001 | PASS | List mining jobs (empty) — 200 |
| TC-RM-002 | PASS | Create mining job — 201 |
| TC-RM-003 | PASS | Get mining job — 200 |
| TC-RM-004 | PASS | Run mining job — 200 |
| TC-RM-005 | PASS | List jobs status=completed — 200 |
| TC-RM-006 | PASS | List jobs paginated — 200 |
| TC-RM-007 | PASS | Create job with params — 201 |
| TC-RM-008 | PASS | Get job not found — 404 |
| TC-RM-009 | PASS | Cancel mining job — 412 |
| TC-RM-010 | PASS | List jobs no auth — 401 |
| TC-RM-011 | PASS | List candidates — 200 |
| TC-RM-012 | PASS | List candidates filtered — 200 |
| TC-RM-013 | PASS | Get candidate not found — 404 |
| TC-RM-014 | PASS | Promote candidate not found — 404 |
| TC-RM-015 | PASS | Dismiss candidate not found — 404 |
| TC-RM-016 | PASS | List access patterns — 200 |
| TC-RM-017 | PASS | List patterns filtered — 200 |
| TC-RM-018 | PASS | Get pattern not found — 400 |
| TC-RM-019 | PASS | List excessive privs — 200 |
| TC-RM-020 | PASS | List excessive privs filtered — 200 |
| TC-RM-021 | PASS | Get excessive priv not found — 404 |
| TC-RM-022 | PASS | Review excessive priv not found — 404 |
| TC-RM-023 | PASS | List consolidation suggestions — 200 |
| TC-RM-024 | PASS | Get suggestion not found — 404 |
| TC-RM-025 | PASS | Dismiss suggestion not found — 404 |
| TC-RM-026 | PASS | List simulations — 200 |
| TC-RM-027 | PASS | Create simulation — 201 |
| TC-RM-028 | PASS | Get simulation — 200 |
| TC-RM-029 | PASS | Execute simulation — 200 |
| TC-RM-030 | PASS | List simulations filtered — 200 |
| TC-RM-031 | PASS | Get simulation not found — 404 |
| TC-RM-032 | PASS | Cancel simulation — 200 |
| TC-RM-033 | PASS | List role metrics — 200 |
| TC-RM-034 | PASS | List metrics filtered — 200 |
| TC-RM-035 | PASS | Get metrics not found — 404 |
| TC-RM-036 | PASS | Calculate metrics — 200 |
| TC-RM-037 | PASS | Calculate metrics for role — 200 |
| TC-IM-001 | PASS | List duplicates — 200 |
| TC-IM-002 | PASS | List duplicates filtered — 200 |
| TC-IM-003 | PASS | Get duplicate not found — 404 |
| TC-IM-004 | PASS | Dismiss duplicate not found — 404 |
| TC-IM-005 | PASS | Detect duplicates — 200 |
| TC-IM-006 | PASS | Detect duplicates default — 200 |
| TC-IM-007 | PASS | List duplicates no auth — 401 |
| TC-IM-008 | PASS | Preview merge same user — 412 |
| TC-IM-009 | PASS | Preview merge two users — 200 |
| TC-IM-010 | PASS | Preview merge missing source — 404 |
| TC-IM-011 | PASS | List merge ops — 200 |
| TC-IM-012 | PASS | List merge ops filtered — 200 |
| TC-IM-013 | PASS | Get merge op not found — 404 |
| TC-IM-014 | PASS | List merge audits — 200 |
| TC-IM-015 | PASS | List merge audits filtered — 200 |
| TC-IM-016 | PASS | Get merge audit not found — 404 |
| TC-IM-017 | PASS | Preview batch merge — 200 |
| TC-IM-018 | PASS | Batch merge (empty) — 200 |
| TC-IM-019 | PASS | Get batch job 404 (sync-only) — 404 |
| TC-PER-001 | PASS | List archetypes — 200 |
| TC-PER-002 | PASS | Create archetype — 201 |
| TC-PER-003 | PASS | Get archetype — 200 |
| TC-PER-004 | PASS | Update archetype — 200 |
| TC-PER-005 | PASS | Duplicate archetype name — 409 |
| TC-PER-006 | PASS | List archetypes filtered — 200 |
| TC-PER-007 | PASS | Get archetype not found — 404 |
| TC-PER-008 | PASS | Deactivate archetype — 200 |
| TC-PER-009 | PASS | Activate archetype — 200 |
| TC-PER-010 | PASS | List archetypes no auth — 401 |
| TC-PER-011 | PASS | List personas — 200 |
| TC-PER-012 | PASS | Create persona — 201 |
| TC-PER-013 | PASS | Get persona — 200 |
| TC-PER-014 | PASS | Update persona — 200 |
| TC-PER-015 | PASS | Get persona not found — 404 |
| TC-PER-016 | PASS | List personas filtered — 200 |
| TC-PER-017 | PASS | Activate persona — 200 |
| TC-PER-018 | PASS | Propagate attributes — 200 |
| TC-PER-019 | PASS | Extend persona — 200 |
| TC-PER-020 | PASS | Get user personas — 200 |
| TC-PER-021 | PASS | Get user personas +archived — 200 |
| TC-PER-022 | PASS | Get expiring personas — 200 |
| TC-PER-023 | PASS | Get current context — 200 |
| TC-PER-024 | PASS | Switch context — 200 |
| TC-PER-025 | PASS | Switch back — 200 |
| TC-PER-026 | PASS | List context sessions — 200 |
| TC-PER-027 | PASS | Switch to missing persona — 404 |
| TC-PER-028 | PASS | List persona audit — 200 |
| TC-PER-029 | PASS | List persona audit filtered — 200 |
| TC-PER-030 | PASS | Get persona audit trail — 200 |
| TC-PER-031 | PASS | Deactivate persona — 200 |
| TC-PER-032 | PASS | Archive persona — 200 |
| TC-PER-033 | PASS | Create+delete archetype — 204 |
| TC-RISK-001 | PASS | Get user risk score — 200 |
| TC-RISK-002 | PASS | Calculate risk score — 200 |
| TC-RISK-003 | PASS | Risk score history — 200 |
| TC-RISK-004 | PASS | Risk history limit=10 — 200 |
| TC-RISK-005 | PASS | List risk scores — 200 |
| TC-RISK-006 | PASS | List risk scores filtered — 200 |
| TC-RISK-007 | PASS | Risk score summary — 200 |
| TC-RISK-008 | PASS | Calculate all scores — 200 |
| TC-RISK-009 | PASS | Save risk snapshot — 204 |
| TC-RISK-010 | PASS | Get risk enforcement — 200 |
| TC-RISK-011 | PASS | Risk scores no auth — 401 |
| TC-RISK-012 | PASS | Get enforcement policy — 200 |
| TC-RISK-013 | PASS | Upsert enforcement policy — 200 |
| TC-RISK-014 | PASS | Update policy partial — 200 |
| TC-RISK-015 | PASS | List risk factors — 200 |
| TC-RISK-016 | PASS | Create risk factor — 201 |
| TC-RISK-017 | PASS | Get risk factor — 200 |
| TC-RISK-018 | PASS | Update risk factor — 200 |
| TC-RISK-019 | PASS | Disable risk factor — 200 |
| TC-RISK-020 | PASS | Enable risk factor — 200 |
| TC-RISK-021 | PASS | Create factor non-admin — 403 |
| TC-RISK-022 | PASS | Duplicate factor name — 409 |
| TC-RISK-023 | PASS | Get factor not found — 404 |
| TC-RISK-024 | PASS | Delete risk factor — 204 |
| TC-RISK-025 | PASS | Risk factors no auth — 401 |
| TC-RISK-026 | PASS | List risk alerts — 200 |
| TC-RISK-027 | PASS | Risk alert summary — 200 |
| TC-RISK-028 | PASS | Get alert not found — 404 |
| TC-RISK-029 | PASS | Ack alert not found — 404 |
| TC-RISK-030 | PASS | Ack all user alerts — 200 |
| TC-RISK-031 | PASS | Get user latest alert — 200 |
| TC-RISK-032 | PASS | Delete alert not found — 404 |
| TC-RISK-033 | PASS | Risk alerts no auth — 401 |
