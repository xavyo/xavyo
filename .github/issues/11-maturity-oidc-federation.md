**Epic:** #98 · **Phase:** 4 — Crate maturity

## Context

`xavyo-api-oidc-federation` is 🟡 beta with **13 tests** — insufficient for enterprise IdP federation (Azure AD, Okta, Google Workspace).

## Goal

Promote to 🟢 stable per `docs/crates/maturity-matrix.md`:

- [ ] 50+ tests
- [ ] Integration tests: discover, authorize, callback, logout flows
- [ ] Error paths (invalid state, expired session, domain mismatch)
- [ ] Update maturity matrix + `llms.txt`

## Suggested work

1. Mock OIDC provider for integration tests (or use wiremock)
2. Cover tenant-scoped vs callback routes (see `main.rs` federation route split)
3. Document required env vars and encryption key setup

## Files

- `crates/xavyo-api-oidc-federation/`
- `apps/idp-api/src/main.rs` (federation routes)
