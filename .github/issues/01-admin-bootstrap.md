**Epic:** #98 · **Phase:** 1 — Golden path

## Problem

Documented first-boot admin (`ADMIN_EMAIL=admin@xavyo.local`) is not created. Bootstrap logs:

```
Failed to create admin user: there is no unique or exclusion constraint matching the ON CONFLICT specification
```

## Root cause

`apps/idp-api/src/bootstrap.rs` uses:

```sql
ON CONFLICT (tenant_id, email) DO NOTHING
```

But the `users` table has a **case-insensitive** unique index:

```sql
users_tenant_email_ci_unique UNIQUE (tenant_id, lower(email))
```

PostgreSQL requires the `ON CONFLICT` target to match an exact unique index/exclusion constraint.

## Fix

Update `bootstrap_admin_user()` to use one of:

1. `ON CONFLICT ON CONSTRAINT users_tenant_email_ci_unique DO NOTHING`, or
2. Remove `ON CONFLICT` and use a pre-insert `SELECT` + idempotent role assignment (already partially implemented).

Also add an integration test: fresh DB → start idp-api with `ADMIN_EMAIL`/`ADMIN_PASSWORD` → user exists with `super_admin` role.

## Acceptance criteria

- [ ] Fresh install with `ADMIN_EMAIL` + `ADMIN_PASSWORD` creates `admin@xavyo.local` with `super_admin`
- [ ] Restart is idempotent (no duplicate users, no errors)
- [ ] `INSTALL.md` quick-start login works without manual signup workaround
- [ ] Test added under `apps/idp-api/tests/` or functional suite

## Files

- `apps/idp-api/src/bootstrap.rs`
- `INSTALL.md` (verify credentials section)
