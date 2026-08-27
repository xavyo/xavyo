**Epic:** #98 · **Phase:** 4 — Crate maturity

## Context

Per `docs/crates/maturity-matrix.md`, `xavyo-api-saml` is 🟡 beta with only **13 tests** and 3 TODOs. SAML is required for most enterprise deployments.

## Goal

Promote `xavyo-api-saml` to 🟢 stable per matrix criteria:

- [ ] 50+ tests including edge cases
- [ ] Integration tests (IdP-initiated + SP-initiated flows)
- [ ] Critical TODOs resolved
- [ ] `CRATE.md` updated
- [ ] Update `docs/crates/maturity-matrix.md` and `llms.txt`

## Suggested work

1. Audit `crates/xavyo-api-saml/` for TODO/FIXME
2. Add integration tests with test SP (may use docker or embedded XML fixtures)
3. Document supported bindings and limitations
4. Run security review on XML signature validation paths

## Files

- `crates/xavyo-api-saml/`
- `docs/crates/maturity-matrix.md`
