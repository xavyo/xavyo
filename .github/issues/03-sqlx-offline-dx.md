**Epic:** #98 · **Phase:** 1 — DX

## Problem

`cargo build` fails when `DATABASE_URL` is in `.env` but the DB schema is not migrated:

```
error: error returned from database: relation "gov_license_entitlement_links" does not exist
```

Developers must discover `SQLX_OFFLINE=true` independently.

## Proposed solution

Pick one or combine:

- **Document** in `CONTRIBUTING.md` / `INSTALL.md`: `SQLX_OFFLINE=true cargo build -p idp-api`
- **Wrapper script** `scripts/cargo-dev.sh` that sets `SQLX_OFFLINE=true`
- **`.cargo/config.toml`** dev env alias (if CI sqlx prepare is unaffected)

## Acceptance criteria

- [ ] Clone → build works without a running migrated DB
- [ ] CI still validates sqlx cache freshness
- [ ] No regression for online sqlx workflows

## Files

- `CONTRIBUTING.md`, `INSTALL.md`, optionally `.cargo/config.toml`
