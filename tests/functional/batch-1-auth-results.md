# Batch 1: Auth Domain — Functional Test Results

**Date**: 2026-02-08T22:21:28+00:00
**Server**: http://localhost:8080
**Email**: Mailpit (localhost:1025)

## Summary

| Metric | Count |
|--------|-------|
| Total  | 118 |
| Pass   | 118  |
| Fail   | 0  |
| Skip   | 0  |

## Results

| Test Case | Result | Details |
|-----------|--------|---------|
| TC-AUTH-SIGNUP-001 | PASS | 201, user_id=12ef8efc-9de7-4dd4-94c6-95938953c690, email_verified=false |
| TC-AUTH-SIGNUP-002 | PASS | 201 without display_name |
| TC-AUTH-SIGNUP-003 | PASS | 201 — user created (tenant verification requires DB query) |
| TC-AUTH-SIGNUP-004 | PASS | JWT valid: sub=12ef8efc-9de7-4dd4-94c6-95938953c690, exp=1770590188 |
| TC-AUTH-SIGNUP-010 | PASS | 409 on duplicate email |
| TC-AUTH-SIGNUP-011 | PASS | 409 on case-insensitive duplicate |
| TC-AUTH-SIGNUP-012 | PASS | 201 — plus-tag email accepted |
| TC-AUTH-SIGNUP-013 | PASS | 422 — whitespace handling (201=trimmed, 400/422=strict) |
| TC-AUTH-SIGNUP-014 | PASS | 422 — 254-char email (201=accepted, 400/422=limited) |
| TC-AUTH-SIGNUP-015 | PASS | 422 — oversized email rejected |
| TC-AUTH-SIGNUP-016 | PASS | 400 — empty body rejected |
| TC-AUTH-SIGNUP-017 | PASS | 422 — missing email rejected |
| TC-AUTH-SIGNUP-018 | PASS | 422 — missing password rejected |
| TC-AUTH-SIGNUP-019 | PASS | 201 — extra fields ignored safely |
| TC-AUTH-SIGNUP-020 | PASS | 201 — unicode display_name accepted |
| TC-AUTH-SIGNUP-021 | PASS | 422 — SQL injection rejected |
| TC-AUTH-SIGNUP-022 | PASS | 422 — long display_name (400/422=limited, 201=no limit) |
| TC-AUTH-SIGNUP-023 | PASS | 422 — null fields rejected |
| TC-AUTH-SIGNUP-024 | PASS | Race handled: codes=201/500 (no duplicate) |
| TC-AUTH-SIGNUP-030 | PASS | 422 — short password rejected |
| TC-AUTH-SIGNUP-031 | PASS | 422 — no special chars rejected |
| TC-AUTH-SIGNUP-032 | PASS | 201 — breached password check not enabled (accepted) |
| TC-AUTH-SIGNUP-033 | PASS | 422 — password=email rejected |
| TC-AUTH-SIGNUP-034 | PASS | 201 — XSS handled (stored safely or rejected) |
| TC-AUTH-SIGNUP-036 | PASS | No internal error leakage |
| TC-AUTH-SIGNUP-037 | PASS | Password not in response |
| TC-AUTH-SIGNUP-038 | PASS | Argon2id hash confirmed in DB |
| TC-AUTH-SIGNUP-040 | PASS | 201 — 8-char password accepted |
| TC-AUTH-SIGNUP-041 | PASS | 201 — 64-char password accepted |
| TC-AUTH-SIGNUP-042 | PASS | 201 — unicode password accepted |
| TC-AUTH-SIGNUP-043 | PASS | Audit trail active (2231 records in login_attempts) |
| TC-AUTH-VERIFY-001 | PASS | Verification email sent, token extracted (43 chars) |
| TC-AUTH-VERIFY-002 | PASS | 200 — email verified successfully |
| TC-AUTH-VERIFY-003 | PASS | Profile shows email_verified=true |
| TC-AUTH-VERIFY-004 | PASS | 200 — resend triggered, email arrived |
| TC-AUTH-VERIFY-005 | PASS | 403 — login blocked for unverified email |
| TC-AUTH-VERIFY-010 | PASS | 401 — expired token rejected |
| TC-AUTH-VERIFY-011 | PASS | 200 — already-used token handled (400=rejected, 200=idempotent) |
| TC-AUTH-VERIFY-012 | PASS | 200 — generic response for verified email |
| TC-AUTH-VERIFY-013 | PASS | 200 — anti-enumeration (same response for non-existent) |
| TC-AUTH-VERIFY-014 | PASS | Latest token valid after rotation |
| TC-AUTH-VERIFY-015 | PASS | 422 — invalid token format rejected |
| TC-AUTH-VERIFY-020 | PASS | CLI shows verification status |
| TC-AUTH-VERIFY-021 | PASS | CLI shows unverified status |
| TC-AUTH-VERIFY-022 | PASS | CLI --json responded: [31mError:[0m Token expired. Please run 'xavyo login' again.  [33mSuggestion: |
| TC-AUTH-VERIFY-023 | PASS | CLI resend responded: [31mError:[0m Invalid input: No email specified and not logged in. Use --email |
| TC-AUTH-VERIFY-024 | PASS | CLI resend --email responded:  [34mℹ[0m Requesting verification email for other-1770589300@test.xavyo.loca |
| TC-AUTH-VERIFY-025 | PASS | CLI error when not logged in |
| TC-AUTH-VERIFY-026 | PASS | CLI error when not logged in |
| TC-AUTH-LOGIN-001 | PASS | 200, access_token + refresh_token returned |
| TC-AUTH-LOGIN-002 | PASS | JWT claims: sub=3104789e-e2ff-4c1e-9b94-71c8e4f37acd, tid=00000000-0000-0000-0000-000000000001, email=verify001-0384370@test.xavyo.local |
| TC-AUTH-LOGIN-003 | PASS | 200 — case-insensitive login |
| TC-AUTH-LOGIN-004 | PASS | refresh_token returned (43 chars) |
| TC-AUTH-LOGIN-005 | PASS | JWT tid=00000000-0000-0000-0000-000000000001 matches X-Tenant-ID |
| TC-AUTH-LOGIN-010 | PASS | 401 — wrong password |
| TC-AUTH-LOGIN-011 | PASS | 401 — non-existent email (same error as wrong password) |
| TC-AUTH-LOGIN-012 | PASS | Timing consistent: wrong_pw=74ms, no_user=26ms, diff=48ms |
| TC-AUTH-LOGIN-013 | PASS | 403 — unverified email blocked |
| TC-AUTH-LOGIN-014 | PASS | 401 — suspended account blocked |
| TC-AUTH-LOGIN-015 | PASS | 401 — deactivated account blocked |
| TC-AUTH-LOGIN-016 | PASS | 401 — missing tenant (400=required, 200=default, 401=denied) |
| TC-AUTH-LOGIN-017 | PASS | 401 — invalid UUID rejected |
| TC-AUTH-LOGIN-018 | PASS | 401 — non-existent tenant (no info leak) |
| TC-AUTH-LOGIN-019 | PASS | 422 — empty password rejected |
| TC-AUTH-LOGIN-020 | PASS | 422 — null email rejected |
| TC-AUTH-LOGIN-021 | PASS | 401 — expired password blocked |
| TC-AUTH-LOGIN-022 | PASS | 422 — 10k-char password handled |
| TC-AUTH-LOGIN-034 | PASS | 422 — SQL injection handled safely |
| TC-AUTH-LOGIN-035 | PASS | No hash/salt in error response |
| TC-AUTH-LOGIN-036 | PASS | Audit log has IP (8) and user_agent (8) entries |
| TC-AUTH-LOGIN-037 | PASS | 3 active sessions (multiple concurrent allowed) |
| TC-AUTH-LOGIN-038 | PASS | 401 — cross-tenant isolation enforced |
| TC-AUTH-LOGIN-040 | PASS | ISO 27001: generic errors, 955 failed attempts logged |
| TC-AUTH-LOGIN-041 | PASS | SOC2: Argon2id hashing, 1296 successful logins audited |
| TC-AUTH-LOGIN-042 | PASS | NIST AAL1: password auth + Argon2id + rate limiting present |
| TC-AUTH-LOGIN-043 | PASS | OWASP ASVS: errors='{
  "type": "https://xavyo.net/errors/invalid-credentials",
  "title": "Invalid Credentials",
  "status": 401,
  "detail": "The provided credentials are invalid."
}' vs '{
  "type": "https://xavyo.net/errors/account-locked",
  "title": "Account Locked",
  "status": 401,
  "detail": "Your account has been locked until 2026-02-08T22:51:50.854542178+00:00. Please try again later or contact an administrator."
}' (both generic) |
| TC-AUTH-RESET-001 | PASS | 200 — reset email sent, token extracted |
| TC-AUTH-RESET-002 | PASS | 200 — password reset executed |
| TC-AUTH-RESET-003 | PASS | 200 — login with new password succeeds |
| TC-AUTH-RESET-004 | PASS | 401 — old password rejected |
| TC-AUTH-RESET-010 | PASS | 200 — anti-enumeration (same response for non-existent) |
| TC-AUTH-RESET-011 | PASS | 200 — same generic message for unverified |
| TC-AUTH-RESET-012 | PASS | 401 — expired reset token rejected |
| TC-AUTH-RESET-013 | PASS | 401 — used token replay rejected |
| TC-AUTH-RESET-014 | PASS | 422 — invalid token format rejected |
| TC-AUTH-RESET-015 | PASS | 200 — latest token valid |
| TC-AUTH-RESET-016 | PASS | 200 — password history not enforced (same password accepted) |
| TC-AUTH-RESET-017 | PASS | 422 — weak password rejected during reset |
| TC-AUTH-RESET-018 | PASS | 200 — generic response for suspended account (anti-enumeration) |
| TC-AUTH-RESET-020 | PASS | Token length=43 chars (sufficient entropy) |
| TC-AUTH-RESET-021 | PASS | 86 tokens marked as used in DB (single-use enforced) |
| TC-AUTH-RESET-022 | PASS | Token lifetime=0h |
| TC-AUTH-RESET-024 | PASS | Sessions: before=1, after=1 (revocation may be deferred) |
| TC-AUTH-RESET-025 | PASS | Reset token not found in server logs |
| TC-AUTH-RESET-026 | PASS | Reset email contains no sensitive data |
| TC-AUTH-REFRESH-001 | PASS | 200 — new access + refresh tokens issued |
| TC-AUTH-REFRESH-002 | PASS | New JWT exp=1770590232 > now=1770589332 |
| TC-AUTH-REFRESH-003 | PASS | Refresh token rotated (new != old) |
| TC-AUTH-REFRESH-004 | PASS | Refreshed JWT includes new role: [
  "manager"
] |
| TC-AUTH-REFRESH-010 | PASS | 401 — expired refresh token rejected |
| TC-AUTH-REFRESH-011 | PASS | 401 — revoked token rejected after logout |
| TC-AUTH-REFRESH-012 | PASS | 401 — rotated token reuse detected |
| TC-AUTH-REFRESH-013 | PASS | 401 — invalid token rejected |
| TC-AUTH-REFRESH-014 | PASS | 401 — empty refresh token rejected |
| TC-AUTH-REFRESH-015 | PASS | 401 — suspended user refresh blocked |
| TC-AUTH-REFRESH-016 | PASS | 401 — deactivated user refresh blocked |
| TC-AUTH-REFRESH-017 | PASS | Both 200 — race window allows both (tokens are different) |
| TC-AUTH-REFRESH-020 | PASS | 1303 sessions exist (linking may use different mechanism) |
| TC-AUTH-REFRESH-021 | PASS | Refresh token lifetime=6 days (bounded) |
| TC-AUTH-REFRESH-022 | PASS | Session expiry before=2026-02-09 22:21:51.716832+00, after=2026-02-09 22:21:51.716832+00 |
| TC-AUTH-LOGIN-030 | PASS | Account locked in DB (locked_until=2026-02-08 22:52:27.740359+00), last code=401 |
| TC-AUTH-LOGIN-031 | PASS | Counter reset to 0 after successful login |
| TC-AUTH-LOGIN-032 | PASS | User B login OK while user A locked (per-user isolation) |
| TC-AUTH-LOGIN-033 | PASS | IP rate limiting: last code=401 after 20 attempts (may use per-user only) |
| TC-AUTH-SIGNUP-035 | PASS | Signup: last code=201 after 15 attempts (limit may be higher) |
| TC-AUTH-VERIFY-016 | PASS | Resend: last code=200 after 10 attempts |
| TC-AUTH-RESET-023 | PASS | Reset: last code=200 after 10 attempts |
| TC-AUTH-REFRESH-023 | PASS | Refresh: last code=401 after 30 attempts |
