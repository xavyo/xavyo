**Epic:** #98 · **Phase:** 3 — Ops

## Problem

`docker/docker-compose.dist.yml` is the documented path for end users (`INSTALL.md` standalone distribution), but it is not validated in CI. Regressions in the published GHCR image or compose file go unnoticed.

## Proposed solution

Add CI job (nightly or on release tags):

1. `docker compose -f docker-compose.dist.yml up -d`
2. Wait for healthcheck
3. `curl http://localhost:8080/readyz` → 200
4. Login with default admin credentials
5. Tear down

May use `docker-compose.dist.yml` with locally built image on PRs and GHCR image on release.

## Acceptance criteria

- [ ] Dist compose path verified automatically
- [ ] Failure blocks release (or nightly alert)
- [ ] Documented in release checklist

## Files

- `docker/docker-compose.dist.yml`
- `.github/workflows/`
