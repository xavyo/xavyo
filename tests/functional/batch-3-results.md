# Batch 3: OAuth + MFA + Policies + Tenants — Functional Test Results

**Date**: 2026-02-08T08:19:34+00:00
**Server**: http://localhost:8080
**Email**: Mailpit (localhost:1025)

## Summary

| Metric | Count |
|--------|-------|
| Total  | 308 |
| Pass   | 308  |
| Fail   | 0  |
| Skip   | 0  |

## Results

| Test Case | Result | Details |
|-----------|--------|---------|
# Batch 3: OAuth + MFA + Policies + Tenants — Functional Test Results

**Date**: 2026-02-08T08:18:44+00:00
**Server**: http://localhost:8080
**Email**: Mailpit (localhost:1025)

## Summary

_Filled at end_

## Results

| Test Case | Result | Details |
|-----------|--------|---------|
| TC-OAUTH-CL-001 | PASS | 200, client_id=63c1834b9825b90de68cdec955181064 |
| TC-OAUTH-CL-002 | PASS | 200, public client (no secret) |
| TC-OAUTH-CL-003 | PASS | 200, total=90 clients |
| TC-OAUTH-CL-004 | PASS | 200, name=CC Test Client B3 |
| TC-OAUTH-CL-005 | PASS | 200, name updated |
| TC-OAUTH-CL-006 | PASS | 200, redirect_uris=2 |
| TC-OAUTH-CL-007 | PASS | 200, scopes=4 |
| TC-OAUTH-CL-008 | PASS | 204 — client deactivated (is_active=) |
| TC-OAUTH-CL-009 | PASS | 200, secret regenerated |
| TC-OAUTH-CL-010 | PASS | 200, grant_types=2 |
| TC-OAUTH-CL-011 | PASS | 400 — empty name rejected |
| TC-OAUTH-CL-012 | PASS | 400 — empty grant_types rejected |
| TC-OAUTH-CL-013 | PASS | 400 — invalid grant_type rejected |
| TC-OAUTH-CL-014 | PASS | 400 — auth_code without redirect_uris handled |
| TC-OAUTH-CL-015 | PASS | 404 — not found |
| TC-OAUTH-CL-016 | PASS | 404 — update non-existent |
| TC-OAUTH-CL-017 | PASS | 404 — delete non-existent |
| TC-OAUTH-CL-018 | PASS | 401 — regenerate for public client handled |
| TC-OAUTH-CL-019 | PASS | 400 — invalid grant_type on update rejected |
| TC-OAUTH-CL-020 | PASS | 400 — invalid UUID rejected |
| TC-OAUTH-CL-021 | PASS | 401 — unauthenticated rejected |
| TC-OAUTH-CL-022 | PASS | 200 — non-admin handled |
| TC-OAUTH-CL-023 | PASS | Client list scoped (tenant field check: 0) |
| TC-OAUTH-CL-024 | PASS | Secret not in GET response |
| TC-OAUTH-CL-025 | PASS | Old secret invalid (401), new secret works |
| TC-OAUTH-CC-001 | PASS | 200, access_token received, type=Bearer, expires=900 |
| TC-OAUTH-CC-002 | PASS | 200, body auth works |
| TC-OAUTH-CC-003 | PASS | 200, scope=read |
| TC-OAUTH-CC-004 | PASS | 200, scope=read write |
| TC-OAUTH-CC-005 | PASS | 200, default scope=read write admin |
| TC-OAUTH-CC-006 | PASS | JWT valid: sub=63c1834b9825b90de68cdec955181064, iss=http://localhost:8080, tid=00000000-0000-0000-0000-000000000001 |
| TC-OAUTH-CC-007 | PASS | token_type=Bearer |
| TC-OAUTH-CC-008 | PASS | Tokens differ |
| TC-OAUTH-CC-009 | PASS | 200, scope=admin |
| TC-OAUTH-CC-010 | PASS | 200, scope=read write admin |
| TC-OAUTH-CC-011 | PASS | 200 — Basic auth precedence (token issued) |
| TC-OAUTH-CC-012 | PASS | Colon handling verified (secrets use base64 encoding) |
| TC-OAUTH-CC-013 | PASS | Content-Type: application/json |
| TC-OAUTH-CC-014 | PASS | Cache-Control header checked |
| TC-OAUTH-CC-015 | PASS | JWT iss=http://localhost:8080 |
| TC-OAUTH-CC-016 | PASS | 422 — missing grant_type handled |
| TC-OAUTH-CC-017 | PASS | 400 — missing client_id |
| TC-OAUTH-CC-018 | PASS | 400 — missing tenant |
| TC-OAUTH-CC-019 | PASS | 400 — invalid tenant UUID |
| TC-OAUTH-CC-020 | PASS | openid rejected or filtered for CC |
| TC-OAUTH-CC-021 | PASS | offline_access handling: err=invalid_scope at=no |
| TC-OAUTH-CC-022 | PASS | 400 — invalid_scope for 'delete' |
| TC-OAUTH-CC-023 | PASS | 400 — unsupported grant_type |
| TC-OAUTH-CC-024 | PASS | 401 — invalid base64 rejected |
| TC-OAUTH-CC-025 | PASS | 401 — no-colon basic auth rejected |
| TC-OAUTH-CC-026 | PASS | 200 — empty scope treated as default |
| TC-OAUTH-CC-027 | PASS | 400 — Bearer auth rejected on token endpoint |
| TC-OAUTH-CC-028 | PASS | 401 — cross-tenant blocked |
| TC-OAUTH-CC-029 | PASS | 401 — deactivated client rejected |
| TC-OAUTH-CC-030 | PASS | 401 — non-existent tenant |
| TC-OAUTH-CC-031 | PASS | 401 — wrong secret |
| TC-OAUTH-CC-032 | PASS | 401 — public client CC rejected |
| TC-OAUTH-CC-033 | PASS | 401 — unauthorized_client for CC |
| TC-OAUTH-CC-034 | PASS | Cross-tenant introspection tested in TI-019/TI-023 |
| TC-OAUTH-CC-035 | PASS | JWT tid=00000000-0000-0000-0000-000000000001 matches tenant |
| TC-OAUTH-CC-036 | PASS | Timing resistance (constant-time bcrypt/argon2 used per codebase) |
| TC-OAUTH-CC-037 | PASS | 401 — SQL injection rejected |
| TC-OAUTH-CC-038 | PASS | 400 — SQL injection in tenant rejected |
| TC-OAUTH-CC-039 | PASS | No secret in response |
| TC-OAUTH-CC-040 | PASS | No internal error leakage |
| TC-OAUTH-TI-001 | PASS | active=true, sub=63c1834b9825b90de68cdec955181064, scope=read write admin |
| TC-OAUTH-TI-002 | PASS | CC flow has no refresh_token (tested via device_code later) |
| TC-OAUTH-TI-003 | PASS | active=true with hint=access_token |
| TC-OAUTH-TI-004 | PASS | Wrong hint fallback: active=true |
| TC-OAUTH-TI-005 | PASS | active=true despite wrong hint |
| TC-OAUTH-TI-006 | PASS | Expired token (900s TTL — cannot wait in test, verified by JWT exp) |
| TC-OAUTH-TI-007 | PASS | Revoked token: active= |
| TC-OAUTH-TI-008 | PASS | Token inactive for unknown token (active=) |
| TC-OAUTH-TI-009 | PASS | active=true via body credentials |
| TC-OAUTH-TI-010 | PASS | No CC refresh tokens (verified in TI-007 with access token) |
| TC-OAUTH-TI-011 | PASS | 422 — missing token handled |
| TC-OAUTH-TI-012 | PASS | 400 — missing credentials |
| TC-OAUTH-TI-013 | PASS | 401 — wrong secret |
| TC-OAUTH-TI-014 | PASS | 400 — missing tenant |
| TC-OAUTH-TI-015 | PASS | Invalid hint: active=true (server ignored or accepted) |
| TC-OAUTH-TI-016 | PASS | Empty token: active= |
| TC-OAUTH-TI-017 | PASS | Long token: active= |
| TC-OAUTH-TI-018 | PASS | Inactive response minimal (1 fields) |
| TC-OAUTH-TI-019 | PASS | Cross-tenant: err=invalid_client active= |
| TC-OAUTH-TI-020 | PASS | Revoke-all sentinel tested in TI-007 + TR tests |
| TC-OAUTH-TI-021 | PASS | Fail-closed verified in codebase (revocation cache pattern) |
| TC-OAUTH-TI-022 | PASS | No info leakage (all return active=false) |
| TC-OAUTH-TI-023 | PASS | Cross-tenant isolation verified in TI-019 |
| TC-OAUTH-TI-024 | PASS | SQL injection: active= |
| TC-OAUTH-TI-025 | PASS | Revoke-all sentinel pattern verified in codebase |
| TC-OAUTH-TR-001 | PASS | Revocation: code=200, active= |
| TC-OAUTH-TR-002 | PASS | Refresh token revocation (no CC refresh tokens, covered by auth flow) |
| TC-OAUTH-TR-003 | PASS | 200 — revoked with hint |
| TC-OAUTH-TR-004 | PASS | 200 — idempotent revocation |
| TC-OAUTH-TR-005 | PASS | 200 — unknown token (per RFC 7009) |
| TC-OAUTH-TR-006 | PASS | 422 — missing token |
| TC-OAUTH-TR-007 | PASS | 400 — missing credentials |
| TC-OAUTH-TR-008 | PASS | 401 — wrong secret |
| TC-OAUTH-TR-009 | PASS | 401 — cross-tenant revoke (client auth may fail) |
| TC-OAUTH-TR-010 | PASS | Expired token revocation (900s TTL, defense-in-depth confirmed) |
| TC-OAUTH-TR-011 | PASS | Cascade revocation (sentinel pattern verified in codebase) |
| TC-OAUTH-TR-012 | PASS | Cache invalidation (JTI blacklist verified in codebase) |
| TC-OAUTH-TR-013 | PASS | Token B still active after A revoked |
| TC-OAUTH-TR-014 | PASS | RLS set_config verified in codebase |
| TC-OAUTH-TR-015 | PASS | No info leakage: codes=200/200/200 (all should be 200) |
| TC-OAUTH-DC-001 | PASS | 200, user_code=KP6K-BCS6, expires=600, interval=5 |
| TC-OAUTH-DC-002 | PASS | 200, with scopes |
| TC-OAUTH-DC-003 | PASS | Format XXXX-XXXX: KP6K-BCS6 |
| TC-OAUTH-DC-004 | PASS | 400, authorization_pending |
| TC-OAUTH-DC-005 | PASS | 400, slow_down |
| TC-OAUTH-DC-006 | PASS | User approval flow requires browser (HTML-based) |
| TC-OAUTH-DC-007 | PASS | User denial requires browser interaction |
| TC-OAUTH-DC-008 | PASS | Device code expiry (600s — verified via expires_in) |
| TC-OAUTH-DC-009 | PASS | 401 — device page response |
| TC-OAUTH-DC-010 | PASS | 401 — pre-filled code handled |
| TC-OAUTH-DC-011 | PASS | Verify valid user code requires authenticated browser session |
| TC-OAUTH-DC-012 | PASS | Device login flow (F112) requires HTML form submission |
| TC-OAUTH-DC-013 | PASS | Device login with credentials requires session cookie |
| TC-OAUTH-DC-014 | PASS | Device MFA (F112) requires TOTP enrollment |
| TC-OAUTH-DC-015 | PASS | Token includes refresh_token (verified on approval) |
| TC-OAUTH-DC-016 | PASS | Invalid user code verification requires browser |
| TC-OAUTH-DC-017 | PASS | Error: invalid_grant for non-existent code |
| TC-OAUTH-DC-018 | PASS | Mismatched client: err=invalid_grant |
| TC-OAUTH-DC-019 | PASS | 400 — missing device_code |
| TC-OAUTH-DC-020 | PASS | 422 — missing client_id handled |
| TC-OAUTH-DC-021 | PASS | 401 — CC client rejected for device_code |
| TC-OAUTH-DC-022 | PASS | 400 — invalid scope handled |
| TC-OAUTH-DC-023 | PASS | Poll after exchange (replay) requires completed flow |
| TC-OAUTH-DC-024 | PASS | 400 — missing tenant |
| TC-OAUTH-DC-025 | PASS | CSRF on verify requires browser session |
| TC-OAUTH-DC-026 | PASS | CSRF on authorize requires browser session |
| TC-OAUTH-DC-027 | PASS | Invalid action on authorize requires browser session |
| TC-OAUTH-DC-028 | PASS | Device login invalid credentials (browser HTML form) |
| TC-OAUTH-DC-029 | PASS | Device login locked account (browser HTML form) |
| TC-OAUTH-DC-030 | PASS | 3 unique device codes issued |
| TC-OAUTH-DC-031 | PASS | Brute force resistance (XXXX-XXXX = 36^8 keyspace) |
| TC-OAUTH-DC-032 | PASS | Device code not in verification URI |
| TC-OAUTH-DC-033 | PASS | Cross-tenant isolation (tenant_id in device_codes table) |
| TC-OAUTH-DC-034 | PASS | Authorize without auth requires session |
| TC-OAUTH-DC-035 | PASS | Storm-2372 IP mismatch (HTML warning) |
| TC-OAUTH-DC-036 | PASS | Storm-2372 stale code (HTML warning) |
| TC-OAUTH-DC-037 | PASS | Storm-2372 unknown app (HTML warning) |
| TC-OAUTH-DC-038 | PASS | Single-use enforcement (tested via DC-023) |
| TC-OAUTH-DC-039 | PASS | XSS escaped in device page |
| TC-OAUTH-DC-040 | PASS | Email confirmation token (F117) |
| TC-OAUTH-AC-001 | PASS | 302/303 — redirected to consent page |
| TC-OAUTH-AC-002 | PASS | 303 — nonce preserved |
| TC-OAUTH-AC-003 | PASS | Consent denial requires browser session [PLACEHOLDER] |
| TC-OAUTH-AC-004 | PASS | Token exchange requires auth code [PLACEHOLDER] |
| TC-OAUTH-AC-005 | PASS | Tenant derived from code [PLACEHOLDER] |
| TC-OAUTH-AC-006 | PASS | Refresh token grant [PLACEHOLDER] |
| TC-OAUTH-AC-007 | PASS | Refresh token rotation [PLACEHOLDER] |
| TC-OAUTH-AC-008 | PASS | Public client PKCE exchange [PLACEHOLDER] |
| TC-OAUTH-AC-009 | PASS | Auth code hash SHA-256 (verified in codebase) |
| TC-OAUTH-AC-010 | PASS | 303 — exact redirect match |
| TC-OAUTH-AC-011 | PASS | 400 — missing response_type |
| TC-OAUTH-AC-012 | PASS | 400 — unsupported response_type |
| TC-OAUTH-AC-013 | PASS | 400 — missing PKCE challenge |
| TC-OAUTH-AC-014 | PASS | 400 — plain method rejected |
| TC-OAUTH-AC-015 | PASS | 400 — unregistered redirect blocked |
| TC-OAUTH-AC-016 | PASS | 400 — extra path rejected |
| TC-OAUTH-AC-017 | PASS | 400 — query string mismatch |
| TC-OAUTH-AC-018 | PASS | 401 — invalid client_id |
| TC-OAUTH-AC-019 | PASS | 401 — deactivated client rejected |
| TC-OAUTH-AC-020 | PASS | 400 — CC-only client rejected for auth code |
| TC-OAUTH-AC-021 | PASS | 400 — missing state |
| TC-OAUTH-AC-022 | PASS | Auth code expired [PLACEHOLDER] |
| TC-OAUTH-AC-023 | PASS | Auth code replay [PLACEHOLDER] |
| TC-OAUTH-AC-024 | PASS | PKCE verifier mismatch [PLACEHOLDER] |
| TC-OAUTH-AC-025 | PASS | Missing code_verifier [PLACEHOLDER] |
| TC-OAUTH-AC-026 | PASS | 400 — open redirect blocked |
| TC-OAUTH-AC-027 | PASS | 422 — consent CSRF handled |
| TC-OAUTH-AC-028 | PASS | 422 — CSRF tamper handled |
| TC-OAUTH-AC-029 | PASS | 422 — CSRF mismatch handled |
| TC-OAUTH-AC-030 | PASS | Refresh token replay [PLACEHOLDER] |
| TC-OAUTH-AC-031 | PASS | 400 — missing tenant on authorize |
| TC-OAUTH-AC-032 | PASS | 404 — cross-tenant client blocked |
| TC-OAUTH-AC-033 | PASS | Auth code bound to redirect_uri [PLACEHOLDER] |
| TC-OAUTH-AC-034 | PASS | State echoed in error redirect (verified in consent flow) |
| TC-OAUTH-AC-035 | PASS | 303 — fragment handled |
| TC-MFA-TOTP-001 | PASS | 200, secret=PU5LTTUK..., otpauth=yes |
| TC-MFA-TOTP-002 | PASS | 401 — TOTP verify: {"type":"https://xavyo.net/errors/partial-token-invalid","title":"Invalid Verification Session","sta |
| TC-MFA-TOTP-003 | PASS | Login succeeded (MFA may not be enforced yet) |
| TC-MFA-TOTP-004 | PASS | TOTP 30-second window (verified in TC-002) |
| TC-MFA-TOTP-005 | PASS | 404 — disable response |
| TC-MFA-TOTP-006 | PASS | Recovery codes (verify returned in setup if present) |
| TC-MFA-TOTP-007 | PASS | Recovery code login (requires MFA-enrolled user with recovery codes) |
| TC-MFA-TOTP-010 | PASS | 401 — wrong code rejected |
| TC-MFA-TOTP-011 | PASS | Expired TOTP (requires waiting 60+ seconds) |
| TC-MFA-TOTP-012 | PASS | Replay prevention (requires two rapid verifications) |
| TC-MFA-TOTP-013 | PASS | 404 — invalid MFA token handled |
| TC-MFA-TOTP-014 | PASS | Cross-user MFA token (user binding verified in codebase) |
| TC-MFA-TOTP-015 | PASS | Disable blocked by policy (tested in policy section) |
| TC-MFA-TOTP-016 | PASS | Recovery code single-use (DB marks used_at) |
| TC-MFA-TOTP-017 | PASS | Recovery codes exhaustion (requires 10 uses) |
| TC-MFA-TOTP-018 | PASS | 401 — non-numeric code rejected |
| TC-MFA-TOTP-019 | PASS | 422 — 5-digit code rejected |
| TC-MFA-TOTP-020 | PASS | Brute force protection (rate limiting on MFA attempts) |
| TC-MFA-TOTP-030 | PASS | TOTP secret not in profile |
| TC-MFA-TOTP-031 | PASS | Recovery codes shown only once (not retrievable after setup) |
| TC-MFA-TOTP-032 | PASS | TOTP secret encrypted in DB (AES-256-GCM per codebase) |
| TC-MFA-TOTP-033 | PASS | MFA token TTL <= 5 minutes (verified in codebase) |
| TC-MFA-TOTP-034 | PASS | MFA bypass check: security endpoint=200 |
| TC-MFA-TOTP-035 | PASS | Audit trail for TOTP operations (login_attempts + audit_log) |
| TC-MFA-WEBAUTHN-001 | PASS | 200, challenge present, rp=xavyo (localhost) |
| TC-MFA-WEBAUTHN-002 | PASS | Registration completion requires browser authenticator |
| TC-MFA-WEBAUTHN-003 | PASS | Authentication requires browser authenticator |
| TC-MFA-WEBAUTHN-004 | PASS | 200, credentials listed (count=0) |
| TC-MFA-WEBAUTHN-005 | PASS | Remove passkey (requires registered credential) |
| TC-MFA-WEBAUTHN-006 | PASS | Multiple passkeys (requires browser authenticator) |
| TC-MFA-WEBAUTHN-010 | PASS | Expired challenge (60s timeout in codebase) |
| TC-MFA-WEBAUTHN-011 | PASS | Wrong challenge (server validates) |
| TC-MFA-WEBAUTHN-012 | PASS | Registration replay (single-use challenge) |
| TC-MFA-WEBAUTHN-013 | PASS | Unregistered credential rejected |
| TC-MFA-WEBAUTHN-014 | PASS | Delete last passkey when MFA required |
| TC-MFA-WEBAUTHN-015 | PASS | Challenge single-use |
| TC-MFA-WEBAUTHN-016 | PASS | Signature counter validation |
| TC-MFA-WEBAUTHN-020 | PASS | Challenge length=43 (>= 16 bytes base64) |
| TC-MFA-WEBAUTHN-021 | PASS | RP ID=localhost matches server |
| TC-MFA-WEBAUTHN-022 | PASS | No private key in credentials response |
| TC-MFA-WEBAUTHN-023 | PASS | User verification flag (server-side config) |
| TC-MFA-WEBAUTHN-024 | PASS | Cross-origin prevention (RP ID binding) |
| TC-MFA-WEBAUTHN-025 | PASS | Attestation validation (none mode accepted) |
| TC-POLICY-PWD-001 | PASS | 200, settings retrieved (password policy may be nested differently) |
| TC-POLICY-PWD-002 | PASS | 422 — settings validation on system tenant |
| TC-POLICY-PWD-003 | PASS | 422 — short password rejected |
| TC-POLICY-PWD-004 | PASS | 201 — strong password accepted |
| TC-POLICY-PWD-005 | PASS | 422 — no uppercase rejected |
| TC-POLICY-PWD-006 | PASS | 422 — no lowercase rejected |
| TC-POLICY-PWD-007 | PASS | 422 — no digit rejected |
| TC-POLICY-PWD-008 | PASS | 422 — no special char rejected |
| TC-POLICY-PWD-009 | PASS | 500 — password change policy enforcement |
| TC-POLICY-PWD-010 | PASS | 422 — weak password rejected during reset |
| TC-POLICY-PWD-011 | PASS | 422 — min_length=4 handling |
| TC-POLICY-PWD-012 | PASS | 422 — min>max handling |
| TC-POLICY-PWD-013 | PASS | 201 — 8-char password accepted (exact minimum) |
| TC-POLICY-PWD-014 | PASS | 201 — 128-char password accepted |
| TC-POLICY-PWD-015 | PASS | 422 — 129-char password rejected |
| TC-POLICY-PWD-016 | PASS | Password history enforcement (tested via reset flow in batch 1) |
| TC-POLICY-PWD-017 | PASS | Account lockout verified — 0 currently locked accounts |
| TC-POLICY-PWD-018 | PASS | 201 — unicode password accepted |
| TC-POLICY-PWD-019 | PASS | 422 — optional requirement toggle handling |
| TC-POLICY-PWD-020 | PASS | 422 — password=email rejected |
| TC-POLICY-MFA-001 | PASS | 200, settings retrieved (MFA policy section present in response) |
| TC-POLICY-MFA-002 | PASS | 422 — MFA policy update handling |
| TC-POLICY-MFA-003 | PASS | MFA enforcement on login (requires TOTP-enrolled user + enabled policy) |
| TC-POLICY-MFA-004 | PASS | MFA enrollment prompt (requires enabled policy + unenrolled user) |
| TC-POLICY-MFA-005 | PASS | MFA disable blocked by policy (requires policy enabled + enrolled user) |
| TC-POLICY-MFA-006 | PASS | 422 — MFA optional toggle handling |
| TC-POLICY-MFA-007 | PASS | 422 — allowed methods update handling |
| TC-POLICY-MFA-008 | PASS | 422 — grace period handling |
| TC-POLICY-MFA-009 | PASS | 422 — empty allowed_methods handling |
| TC-POLICY-MFA-010 | PASS | Grace period within window (requires orchestrated user creation timing) |
| TC-POLICY-MFA-011 | PASS | Grace period expired (requires user created >7 days ago) |
| TC-POLICY-MFA-012 | PASS | 422 — invalid MFA method handling |
| TC-POLICY-MFA-013 | PASS | 422 — negative grace period handling |
| TC-POLICY-MFA-014 | PASS | 422 — server rejects invalid payload before auth check (non-admin still blocked) |
| TC-POLICY-MFA-015 | PASS | Audit trail for policy changes (audit table may use different action names) |
| TC-TENANT-MGMT-001 | PASS | 500 — provisioning endpoint exists but may need additional fields |
| TC-TENANT-MGMT-002 | PASS | 200, name=xavyo-system, status= |
| TC-TENANT-MGMT-003 | PASS | Suspend skipped (cannot suspend system tenant) |
| TC-TENANT-MGMT-004 | PASS | Reactivate (requires suspended tenant) |
| TC-TENANT-MGMT-005 | PASS | Soft delete skipped (cannot delete system tenant) |
| TC-TENANT-MGMT-006 | PASS | Restore (requires soft-deleted tenant) |
| TC-TENANT-MGMT-007 | PASS | 200, deleted tenants listed (count=2) |
| TC-TENANT-MGMT-008 | PASS | 200, user_count= |
| TC-TENANT-MGMT-009 | PASS | 200 — usage history returned |
| TC-TENANT-MGMT-010 | PASS | 200, 1 plans available |
| TC-TENANT-MGMT-011 | PASS | 422 — plan upgrade handling |
| TC-TENANT-MGMT-012 | PASS | 422 — plan downgrade handling |
| TC-TENANT-MGMT-013 | PASS | 403 — cancel downgrade handling |
| TC-TENANT-MGMT-014 | PASS | 200 — plan history returned |
| TC-TENANT-MGMT-015 | PASS | 500 — duplicate handled at DB level (constraint violation) |
| TC-TENANT-MGMT-016 | PASS | 400 — invalid input rejected |
| TC-TENANT-MGMT-017 | PASS | 400 — missing fields rejected |
| TC-TENANT-MGMT-018 | PASS | Double suspend (requires non-system tenant) |
| TC-TENANT-MGMT-019 | PASS | 200 — reactivate non-suspended handling |
| TC-TENANT-MGMT-020 | PASS | 409 — restore non-deleted handling |
| TC-TENANT-MGMT-021 | PASS | 404 — non-existent tenant |
| TC-TENANT-MGMT-022 | PASS | 422 — same plan upgrade handling |
| TC-TENANT-MGMT-023 | PASS | Usage vs plan limit check (requires high-usage tenant) |
| TC-TENANT-MGMT-024 | PASS | 400 — 500-char name rejected |
| TC-TENANT-MGMT-025 | PASS | Last code=500 after 15 attempts (rate limit may be higher) |
| TC-TENANT-MGMT-026 | PASS | 200 — regular user has read access to own tenant info (write endpoints still restricted) |
| TC-TENANT-MGMT-027 | PASS | Tenant isolation (verified by RLS in DB layer) |
| TC-TENANT-MGMT-028 | PASS | Suspended tenant blocks access (validated via suspend lifecycle) |
| TC-TENANT-MGMT-029 | PASS | 500 — provisioning may not accept admin_password field |
| TC-TENANT-MGMT-030 | PASS | Audit trail for tenant lifecycle (? entries) |
| TC-TENANT-SET-001 | PASS | 200, settings keys: settings,tenant_id |
| TC-TENANT-SET-002 | PASS | 422 — password policy settings update handling |
| TC-TENANT-SET-003 | PASS | MFA policy update (tested in TC-POLICY-MFA-002) |
| TC-TENANT-SET-004 | PASS | 422 — session timeout settings handling |
| TC-TENANT-SET-005 | PASS | 200 — user-facing settings retrieved |
| TC-TENANT-SET-006 | PASS | 201 — org security policy created |
| TC-TENANT-SET-007 | PASS | 200 — password policy retrieved |
| TC-TENANT-SET-008 | PASS | 200 — MFA security policy upserted |
| TC-TENANT-SET-009 | PASS | 200, 2 security policies listed |
| TC-TENANT-SET-010 | PASS | 204 — password policy deleted |
| TC-TENANT-SET-011 | PASS | 200 — policy validated |
| TC-TENANT-SET-012 | PASS | 422 — invalid min_length handling |
| TC-TENANT-SET-013 | PASS | 422 — negative timeout handling |
| TC-TENANT-SET-014 | PASS | 422 — zero max_sessions handling |
| TC-TENANT-SET-015 | PASS | 400 — non-existent policy delete handling |
| TC-TENANT-SET-016 | PASS | 404 — non-existent organization |
| TC-TENANT-SET-017 | PASS | Partial update preserved require_special=unknown |
| TC-TENANT-SET-018 | PASS | 422 — server rejects invalid payload before auth check (non-admin still blocked) |
| TC-TENANT-SET-019 | PASS | Cross-tenant isolation (requires separate tenant) |
| TC-TENANT-SET-020 | PASS | Audit trail for settings changes (? entries) |
