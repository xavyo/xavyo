# Product maturity backlog

Tracking epic: **[#98 — Product maturity](https://github.com/xavyo/xavyo/issues/98)** — delivered in [PR #114](https://github.com/xavyo/xavyo/pull/114) (+ follow-ups [#115](https://github.com/xavyo/xavyo/pull/115), [xavyo-web#16](https://github.com/xavyo/xavyo-web/pull/16), [xavyo-web#17](https://github.com/xavyo/xavyo-web/pull/17)).

Issue bodies are also stored under [`.github/issues/`](issues/) for editing before `gh issue create`.

## Status (2026-08-27)

| Phase | Status |
|-------|--------|
| Phase 1 — Golden path & DX | ✅ Done |
| Phase 2 — CI gates | ✅ Done |
| Phase 3 — Operations | ✅ Done |
| Phase 4 — Crate promotion (SAML/OIDC/SCIM) | ✅ Done (see `docs/crates/maturity-matrix.md`) |

## Phase 1 — Golden path & DX (start here)

| # | Issue | Repo |
|---|-------|------|
| 1 | [#110 Fix admin bootstrap ON CONFLICT](https://github.com/xavyo/xavyo/issues/110) | xavyo |
| 2 | [#111 Fail fast on governance encryption keys](https://github.com/xavyo/xavyo/issues/111) | xavyo |
| 3 | [#99 SQLX_OFFLINE local build DX](https://github.com/xavyo/xavyo/issues/99) | xavyo |
| 4 | [#100 `make dev` single-command setup](https://github.com/xavyo/xavyo/issues/100) | xavyo |
| 5 | [xavyo-web#15 Default system tenant on `/login`](https://github.com/xavyo/xavyo-web/issues/15) | xavyo-web |

## Phase 2 — CI gates

| # | Issue |
|---|-------|
| 6 | [#101 E2E smoke test (readyz + admin login)](https://github.com/xavyo/xavyo/issues/101) |
| 7 | [#102 Critical auth + RLS tests on every PR](https://github.com/xavyo/xavyo/issues/102) |

## Phase 3 — Operations

| # | Issue |
|---|-------|
| 8 | [#103 Production config validation in CI](https://github.com/xavyo/xavyo/issues/103) |
| 9 | [#104 First deployment runbook](https://github.com/xavyo/xavyo/issues/104) |
| 10 | [#105 Validate docker-compose.dist.yml in CI](https://github.com/xavyo/xavyo/issues/105) |
| 11 | [#109 Optional Kafka must not fail `/readyz`](https://github.com/xavyo/xavyo/issues/109) |

## Phase 4 — Crate promotion (enterprise paths)

| # | Issue | Crate |
|---|-------|-------|
| 12 | [#106 Promote SAML to stable](https://github.com/xavyo/xavyo/issues/106) | `xavyo-api-saml` |
| 13 | [#107 Promote OIDC federation to stable](https://github.com/xavyo/xavyo/issues/107) | `xavyo-api-oidc-federation` |
| 14 | [#108 Promote SCIM to stable](https://github.com/xavyo/xavyo/issues/108) | `xavyo-api-scim` |

## Suggested sprint order

```
Week 1:  #110 → #111 → #100 → xavyo-web#15 → #101
Week 2:  #102 → #103 → #99
Week 3:  #104 → #105 → #109
Week 4+: #106 → #107 → #108 (parallel if team capacity allows)
```

## Product Definition of Done

See epic [#98](https://github.com/xavyo/xavyo/issues/98) checklist.
