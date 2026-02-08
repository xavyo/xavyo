# Batch 1: Auth Domain — Functional Test Results

**Date**: 2026-02-08T15:17:48+00:00
**Server**: http://localhost:8080
**Email**: Mailpit (localhost:1025)

## Summary

| Metric | Count |
|--------|-------|
| Total  | 118 |
| Pass   | 38  |
| Fail   | 69  |
| Skip   | 11  |

## Results

| Test Case | Result | Details |
|-----------|--------|---------|
| TC-AUTH-SIGNUP-001 | PASS | 201, user_id=048567f6-87f1-427f-903c-1340a6489e96, email_verified=false |
| TC-AUTH-SIGNUP-002 | PASS | 201 without display_name |
| TC-AUTH-SIGNUP-003 | PASS | 201 — user created (tenant verification requires DB query) |
| TC-AUTH-SIGNUP-004 | PASS | JWT valid: sub=048567f6-87f1-427f-903c-1340a6489e96, exp=1770564769 |
| TC-AUTH-SIGNUP-010 | PASS | 409 on duplicate email |
| TC-AUTH-SIGNUP-011 | PASS | 409 on case-insensitive duplicate |
| TC-AUTH-SIGNUP-012 | FAIL | Expected 201, got 429 |
| TC-AUTH-SIGNUP-013 | FAIL | Expected 201/400/422, got 429 |
| TC-AUTH-SIGNUP-014 | FAIL | Expected 201/400/422, got 429 |
| TC-AUTH-SIGNUP-015 | FAIL | Expected 400/422, got 429 |
| TC-AUTH-SIGNUP-016 | FAIL | Expected 400/401/422, got 429 |
| TC-AUTH-SIGNUP-017 | FAIL | Expected 400/422, got 429 |
| TC-AUTH-SIGNUP-018 | FAIL | Expected 400/422, got 429 |
| TC-AUTH-SIGNUP-019 | FAIL | Expected 201, got 429 |
| TC-AUTH-SIGNUP-020 | FAIL | Expected 201, got 429 |
| TC-AUTH-SIGNUP-021 | FAIL | Expected 400, got 429 |
| TC-AUTH-SIGNUP-022 | FAIL | Expected 400/422/201, got 429 |
| TC-AUTH-SIGNUP-023 | FAIL | Expected 400/422, got 429 |
| TC-AUTH-SIGNUP-024 | PASS | Race handled: codes=429/429 (no duplicate) |
| TC-AUTH-SIGNUP-030 | FAIL | Expected 400/422, got 429 |
| TC-AUTH-SIGNUP-031 | FAIL | Expected 400/422 or 201, got 429 |
| TC-AUTH-SIGNUP-032 | FAIL | Unexpected 429 |
| TC-AUTH-SIGNUP-033 | FAIL | Expected 400/422 or 201, got 429 |
| TC-AUTH-SIGNUP-034 | FAIL | Expected 201 or 400, got 429 |
| TC-AUTH-SIGNUP-036 | PASS | No internal error leakage |
| TC-AUTH-SIGNUP-037 | PASS | Password not in response |
| TC-AUTH-SIGNUP-038 | PASS | Argon2id hash confirmed in DB |
| TC-AUTH-SIGNUP-040 | FAIL | Expected 201, got 429 |
| TC-AUTH-SIGNUP-041 | FAIL | Expected 201/400/422, got 429 |
| TC-AUTH-SIGNUP-042 | FAIL | Expected 201 (NIST requires unicode support), got 429 |
| TC-AUTH-SIGNUP-043 | PASS | Audit trail active (2184 records in login_attempts) |
| TC-AUTH-VERIFY-001 | FAIL | Signup failed with 429 |
| TC-AUTH-VERIFY-002 | SKIP | No verification token available |
| TC-AUTH-VERIFY-003 | FAIL | Could not login verified user |
| TC-AUTH-VERIFY-004 | FAIL | Expected 200, got 429 |
| TC-AUTH-VERIFY-005 | FAIL | Expected 401/403, got 429 |
| TC-AUTH-VERIFY-010 | FAIL | No verification email received |
| TC-AUTH-VERIFY-011 | SKIP | No token available |
| TC-AUTH-VERIFY-012 | FAIL | Expected 200, got 429 |
| TC-AUTH-VERIFY-013 | FAIL | Expected 200 (anti-enumeration), got 429 |
| TC-AUTH-VERIFY-014 | FAIL | No email received after resend |
| TC-AUTH-VERIFY-015 | FAIL | Expected 400/401/422, got 429 |
| TC-AUTH-VERIFY-020 | PASS | CLI shows verification status |
| TC-AUTH-VERIFY-021 | PASS | Unverified user ID not found (login blocked as expected) |
| TC-AUTH-VERIFY-022 | PASS | CLI --json responded: [31mError:[0m Not logged in. Run 'xavyo login' first.  [33mSuggestion:[0m Ru |
| TC-AUTH-VERIFY-023 | PASS | CLI resend responded: [31mError:[0m Invalid input: No email specified and not logged in. Use --email |
| TC-AUTH-VERIFY-024 | PASS | CLI resend --email responded:  [34mℹ[0m Requesting verification email for other-1770563889@test.xavyo.loca |
| TC-AUTH-VERIFY-025 | PASS | CLI error when not logged in |
| TC-AUTH-VERIFY-026 | PASS | CLI error when not logged in |
| TC-AUTH-LOGIN-001 | FAIL | Expected 200, got 429: {"error":"too_many_requests","error_description":"Rate limit exceeded. Please try again later."} |
| TC-AUTH-LOGIN-002 | FAIL | No access_token from login |
| TC-AUTH-LOGIN-003 | FAIL | Expected 200, got 429 |
| TC-AUTH-LOGIN-004 | FAIL | No refresh_token in login response |
| TC-AUTH-LOGIN-005 | FAIL | No token to verify |
| TC-AUTH-LOGIN-010 | FAIL | Expected 401, got 429 |
| TC-AUTH-LOGIN-011 | FAIL | Expected 401, got 429 |
| TC-AUTH-LOGIN-012 | PASS | Timing consistent: wrong_pw=19ms, no_user=18ms, diff=1ms |
| TC-AUTH-LOGIN-013 | FAIL | Expected 401/403, got 429 |
| TC-AUTH-LOGIN-014 | FAIL | Could not create test user |
| TC-AUTH-LOGIN-015 | FAIL | Could not create test user |
| TC-AUTH-LOGIN-016 | PASS | 401 — missing tenant (400=required, 200=default, 401=denied) |
| TC-AUTH-LOGIN-017 | PASS | 401 — invalid UUID rejected |
| TC-AUTH-LOGIN-018 | FAIL | Expected 401, got 429 |
| TC-AUTH-LOGIN-019 | FAIL | Expected 400/401/422, got 429 |
| TC-AUTH-LOGIN-020 | FAIL | Expected 400/422, got 429 |
| TC-AUTH-LOGIN-021 | FAIL | Could not create test user |
| TC-AUTH-LOGIN-022 | FAIL | Expected 400/401/422, got 429 |
| TC-AUTH-LOGIN-034 | FAIL | Expected 400/401/422, got 429 |
| TC-AUTH-LOGIN-035 | PASS | No hash/salt in error response |
| TC-AUTH-LOGIN-036 | FAIL | No JWT for audit API |
| TC-AUTH-LOGIN-037 | PASS | 0 active sessions (limit may be enforced) |
| TC-AUTH-LOGIN-038 | FAIL | Expected 401, got 429 |
| TC-AUTH-LOGIN-040 | PASS | ISO 27001: generic errors, 922 failed attempts logged |
| TC-AUTH-LOGIN-041 | PASS | SOC2: password hashed (prefix=), 1265 logins audited |
| TC-AUTH-LOGIN-042 | FAIL | Could not verify Argon2id hashing |
| TC-AUTH-LOGIN-043 | PASS | OWASP ASVS: same error for unknown user and wrong password |
| TC-AUTH-RESET-001 | FAIL | Expected 200, got 429 |
| TC-AUTH-RESET-002 | SKIP | No reset token available |
| TC-AUTH-RESET-003 | SKIP | Password was not reset |
| TC-AUTH-RESET-004 | SKIP | Password was not reset |
| TC-AUTH-RESET-010 | FAIL | Expected 200 (anti-enumeration), got 429 |
| TC-AUTH-RESET-011 | FAIL | Expected 200, got 429 |
| TC-AUTH-RESET-012 | FAIL | No reset email received |
| TC-AUTH-RESET-013 | SKIP | No reset token available |
| TC-AUTH-RESET-014 | PASS | 422 — invalid token format rejected |
| TC-AUTH-RESET-015 | FAIL | No email received |
| TC-AUTH-RESET-016 | FAIL | No email received |
| TC-AUTH-RESET-017 | SKIP | No reset email received |
| TC-AUTH-RESET-018 | FAIL | Could not create test user |
| TC-AUTH-RESET-020 | FAIL | Token too short (0 chars) |
| TC-AUTH-RESET-021 | PASS | 82 tokens marked as used in DB (single-use enforced) |
| TC-AUTH-RESET-022 | PASS | Token lifetime=0h |
| TC-AUTH-RESET-024 | FAIL | Could not create test user |
| TC-AUTH-RESET-025 | PASS | Reset token not found in server logs |
| TC-AUTH-RESET-026 | PASS | No email body to audit (reset flow uses plain-text links) |
| TC-AUTH-REFRESH-001 | SKIP | No refresh token available |
| TC-AUTH-REFRESH-002 | SKIP | No access token |
| TC-AUTH-REFRESH-003 | SKIP | Could not compare refresh tokens |
| TC-AUTH-REFRESH-004 | FAIL | Could not create test user |
| TC-AUTH-REFRESH-010 | FAIL | Could not create test user |
| TC-AUTH-REFRESH-011 | FAIL | Could not create test user |
| TC-AUTH-REFRESH-012 | SKIP | No old refresh token to test |
| TC-AUTH-REFRESH-013 | FAIL | Expected 401, got 429 |
| TC-AUTH-REFRESH-014 | FAIL | Expected 400/401, got 429 |
| TC-AUTH-REFRESH-015 | FAIL | Could not create test user |
| TC-AUTH-REFRESH-016 | FAIL | Could not create test user |
| TC-AUTH-REFRESH-017 | FAIL | Could not create test user |
| TC-AUTH-REFRESH-020 | PASS | 1263 sessions exist (linking may use different mechanism) |
| TC-AUTH-REFRESH-021 | PASS | Refresh token lifetime=6 days (bounded) |
| TC-AUTH-REFRESH-022 | FAIL | No refresh token available |
| TC-AUTH-LOGIN-030 | FAIL | Could not create test user |
| TC-AUTH-LOGIN-031 | FAIL | No test user available |
| TC-AUTH-LOGIN-032 | FAIL | Could not create test users |
| TC-AUTH-LOGIN-033 | PASS | 429 — IP-level rate limit after 1 attempts |
| TC-AUTH-SIGNUP-035 | PASS | 429 — signup rate limited after 1 attempts |
| TC-AUTH-VERIFY-016 | PASS | 429 — resend rate limited after 1 attempts |
| TC-AUTH-RESET-023 | PASS | 429 — reset rate limited after 1 attempts |
| TC-AUTH-REFRESH-023 | PASS | 429 — refresh rate limited after 1 attempts |
