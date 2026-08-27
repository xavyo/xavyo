**Epic:** #98 · **Phase:** 1 — Golden path

## Problem

If `XAVYO_SIEM_ENCRYPTION_KEY` (and possibly `XAVYO_TICKETING_ENCRYPTION_KEY`) are unset, the API **panics at router construction** instead of failing fast during config load:

```
thread 'main' panicked at crates/xavyo-api-governance/src/router.rs:706:10:
Failed to initialize GovernanceState (check XAVYO_SIEM_ENCRYPTION_KEY)
```

## Fix

1. Load governance encryption keys in `apps/idp-api/src/config.rs` (with dev defaults documented in `INSTALL.md`).
2. Pass resolved values into `GovernanceState` — router must not read env vars or panic.
3. In `APP_ENV=production`, reject missing/insecure values via `validate_security_config()`.

## Acceptance criteria

- [ ] Missing keys in development: warn + use documented dev default (or clear error at config load)
- [ ] Missing keys in production: process exits with actionable message before migrations
- [ ] No `panic!` on missing governance encryption keys in router
- [ ] `docker/docker-compose.yml` env vars documented in `.env.example`

## Files

- `apps/idp-api/src/config.rs`
- `crates/xavyo-api-governance/src/router.rs`
- `.env.example`
