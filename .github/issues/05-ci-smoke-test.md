**Epic:** #98 · **Phase:** 2 — CI

## Problem

There is no automated proof that the **golden path** works on every PR. Regressions in bootstrap, migrations, or auth can slip through despite 1,700+ functional tests that may not run on every change.

## Proposed solution

Add a **smoke test job** to GitHub Actions that:

1. Starts `postgres` + `mailpit` (service containers or docker compose)
2. Builds and runs `idp-api` (or uses pre-built image)
3. Asserts:
   - `GET /readyz` → 200
   - `GET /health` → database connected
   - `POST /auth/login` with bootstrap admin credentials → 200 + access_token
4. Fails the PR if any step fails

Keep runtime under ~10 minutes (reuse `SQLX_OFFLINE` build, cache cargo).

## Acceptance criteria

- [ ] Smoke job runs on every PR to `master`
- [ ] Covers fresh DB (migrations + system tenant bootstrap)
- [ ] Uses credentials from `INSTALL.md` / docker-compose defaults
- [ ] Documented in `CONTRIBUTING.md` ("CI will verify golden path")

## Files

- `.github/workflows/` (new `smoke.yml` or extend existing CI)
- optionally `tests/smoke/` script
