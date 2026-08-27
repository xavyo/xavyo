**Epic:** #98 · **Phase:** 3 — Ops

## Problem

`validate_security_config()` exists but production misconfiguration is not continuously verified. A regression could allow insecure defaults in production mode.

## Proposed solution

Add CI job that:

1. Sets `APP_ENV=production` with intentionally insecure/missing keys
2. Asserts `idp-api` **refuses to start** (exit code ≠ 0, clear error message)
3. Sets `APP_ENV=production` with valid generated secrets
4. Asserts startup succeeds through config validation (can stop before binding port)

## Acceptance criteria

- [ ] CI fails if production allows default `CSRF_SECRET`, `MFA_ENCRYPTION_KEY`, CORS `*`, etc.
- [ ] Error messages are actionable (name the env var)
- [ ] Documented in `SECURITY.md` or ops runbook

## Files

- `apps/idp-api/src/config.rs` (tests may already exist — wire to CI)
- `.github/workflows/`
