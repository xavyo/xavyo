**Epic:** #98 · **Phase:** 3 — Ops

## Problem

Operators deploying xavyo for the first time lack a single document covering secrets, rotation, backup, and upgrade — beyond `INSTALL.md` dev setup.

## Proposed solution

Create `docs/operations/first-deployment.md` covering:

1. **Secrets inventory** — all required env vars for production (JWT, encryption keys, DB, SMTP)
2. **Key generation** — `openssl rand` commands (match `INSTALL.md` encryption key section)
3. **Postgres** — backup/restore, connection pooling, `APP_DATABASE_URL` for RLS
4. **JWT rotation** — multi-key setup via `JWT_SIGNING_KEYS`
5. **Upgrade procedure** — migration expectations, rollback strategy
6. **Health monitoring** — `/readyz`, `/livez`, `/metrics`, recommended alerts
7. **Incident basics** — tenant suspension, admin lockout recovery

## Acceptance criteria

- [ ] Doc linked from `INSTALL.md` and `README.md`
- [ ] Reviewed against actual `config.rs` required vars (no stale references)
- [ ] Includes production checklist (copy-pasteable)

## Files

- `docs/operations/first-deployment.md` (new)
- `INSTALL.md`, `README.md` (links)
