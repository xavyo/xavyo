**Epic:** #98 · **Phase:** 1 — DX

## Problem

Local dev requires piecing together `INSTALL.md`, `docker-compose.yml`, and `scripts/dev-env.sh`. No single entry point for the documented quick start.

## Proposed solution

Add **`make dev`** (or extend `scripts/dev-env.sh`) that:

1. Generates JWT keys (`docker/generate-keys.sh`)
2. Creates `.env` with dev-safe defaults (incl. governance encryption keys)
3. Starts `postgres` + `mailpit` via docker compose
4. Waits for Postgres (`scripts/wait-for-services.sh`)
5. Builds: `SQLX_OFFLINE=true cargo build -p idp-api`
6. Prints admin credentials from `INSTALL.md`

Optional `make dev-run` for `cargo run -p idp-api`.

## Acceptance criteria

- [ ] One command from clean clone (with Docker) → `curl localhost:8080/readyz` returns 200
- [ ] Admin login works per `INSTALL.md` without manual signup
- [ ] Documented in `CONTRIBUTING.md` as recommended path

## Files

- `Makefile`, `scripts/dev-env.sh`, `CONTRIBUTING.md`
