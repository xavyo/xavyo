**Epic:** #98 · **Phase:** 4 — Crate maturity

## Context

`xavyo-api-scim` is 🟡 beta with **45 tests but no integration tests**. SCIM provisioning is core IGA functionality.

## Goal

Promote to 🟢 stable:

- [ ] End-to-end SCIM 2.0 resource tests (Users, Groups) with bearer token auth
- [ ] Pagination, filtering, PATCH semantics
- [ ] Multi-tenant isolation in SCIM handlers
- [ ] Update maturity matrix + `llms.txt`

## Suggested work

1. Add `tests/` integration suite hitting `/scim/v2/*` routes
2. Reuse patterns from `xavyo-api-users` integration tests
3. Document SCIM token provisioning in ops runbook (#TBD linked after creation)

## Files

- `crates/xavyo-api-scim/`
- `tests/functional/` (possible new SCIM batch)
