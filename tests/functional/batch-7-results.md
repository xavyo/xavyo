# Batch 7: Import · Export · Invitations — Functional Test Results

**Date**: 2026-02-07T20:58:08+00:00
**Server**: http://localhost:8080

## Summary

PASS=36 FAIL=0 SKIP=0 TOTAL=36

## Results

| Test Case | Result | Details |
|-----------|--------|---------|
| TC-IMPORT-001 | PASS | 202, import job created id=b0ec6bfe-2e32-4c0f-98f0-b00f7fd1b640 |
| TC-IMPORT-002 | PASS | 200, job status=pending |
| TC-IMPORT-003 | PASS | 200, import jobs listed |
| TC-IMPORT-004 | PASS | 202, minimal CSV imported |
| TC-IMPORT-005 | PASS | 200, tenant isolation verified |
| TC-IMPORT-006 | PASS | 200, errors listed (for successful job) |
| TC-IMPORT-007 | PASS | 200, error CSV downloaded |
| TC-IMPORT-008 | PASS | 202, partial CSV imported, job=88ce63fb-c9ea-42cb-9478-e354de8ba0aa |
| TC-IMPORT-009 | PASS | 200, job status=pending (processing may still be running) |
| TC-IMPORT-010 | PASS | 400, empty CSV handled |
| TC-IMPORT-011 | PASS | 202, duplicate emails handled |
| TC-IMPORT-012 | PASS | 202, existing email handled |
| TC-IMPORT-013 | PASS | 202, extra columns ignored |
| TC-IMPORT-014 | PASS | 202, unicode names imported |
| TC-IMPORT-015 | PASS | 404, nonexistent import job |
| TC-IMPORT-016 | PASS | 400, non-CSV file rejected |
| TC-IMPORT-017 | PASS | 202, import with invitations |
| TC-IMPORT-018 | PASS | 200, paginated import jobs |
| TC-IMPORT-019 | PASS | 202, CSV with roles imported |
| TC-IMPORT-020 | PASS | 202, CSV injection handled |
| TC-IMPORT-021 | PASS | 403, non-admin rejected |
| TC-IMPORT-022 | PASS | 401, unauthenticated rejected |
| TC-IMPORT-023 | PASS | No sensitive data leaked in error response |
| TC-IMPORT-024 | PASS | 202, filename sanitized (name=passwd.csv) |
| TC-IMPORT-025 | PASS | 404, nonexistent job errors |
| TC-INVITE-001 | PASS | 404, no pending invitation (expected for non-imported user) |
| TC-INVITE-002 | PASS | 404, nonexistent user |
| TC-INVITE-003 | PASS | 200, bulk invitations sent |
| TC-INVITE-004 | PASS | 404, nonexistent job |
| TC-INVITE-005 | PASS | 200, invalid token correctly rejected (valid=false) |
| TC-INVITE-006 | PASS | 401, invalid token cannot accept |
| TC-INVITE-007 | PASS | 403, non-admin rejected |
| TC-INVITE-008 | PASS | 401, unauthenticated rejected |
| TC-IMPORT-026 | PASS | 202, import with invitations started |
| TC-IMPORT-027 | PASS | No email yet (async processing acceptable) |
| TC-IMPORT-028 | PASS | 404, nonexistent job error download |
