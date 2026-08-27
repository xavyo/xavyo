# Crate Maturity Matrix

This document defines maturity levels for all xavyo crates and provides a detailed assessment of each crate's production-readiness.

## Maturity Levels

### 🟢 Stable

**Production-ready** with comprehensive functionality and test coverage.

Criteria:
- Complete public API matching design specifications
- Extensive test suite (typically 50+ tests)
- No critical TODOs or known gaps
- Used in production paths
- Well-documented with CRATE.md

### 🟡 Beta

**Functional** but may have gaps in edge cases or test coverage.

Criteria:
- Core functionality complete and working
- Adequate test coverage (20-50 tests)
- May have non-critical TODOs
- Lacks integration tests or edge case coverage
- API stable but minor changes possible

### 🔴 Alpha

**Experimental** or minimal implementation.

Criteria:
- Skeleton or partial implementation
- Limited test coverage (<20 tests)
- Few public items (<20)
- API may change significantly
- Not recommended for production use

---

## Complete Matrix

### Foundation Layer

| Crate | Status | Tests | Public Items | Notes |
|-------|--------|-------|--------------|-------|
| xavyo-core | 🟢 stable | 54 | 76 | Foundational types, well-tested |
| xavyo-auth | 🟢 stable | 51 | 46 | JWT/Argon2id + DPoP, acr/amr/auth_time, RFC 9470 step-up |
| xavyo-db | 🟢 stable | 958+ | 400+ | 111K LOC, excellent coverage |
| xavyo-tenant | 🟢 stable | 30 | 13 | Middleware complete |
| xavyo-events | 🟢 stable | 123+ | 45 | Kafka bus with idempotence |
| xavyo-nhi | 🟢 stable | 58+ | 30+ | Complete with 37 unit + 21 doc tests |

### Domain Layer

| Crate | Status | Tests | Public Items | Notes |
|-------|--------|-------|--------------|-------|
| xavyo-connector | 🟢 stable | 137 | 79 | Mature framework |
| xavyo-provisioning | 🟢 stable | 335 | 89 | Remediation executor + transform engine; `tests/remediation_tests.rs` |
| xavyo-governance | 🟢 stable | 173+ | 50+ | Complete IGA with integration tests |
| xavyo-authorization | 🟢 stable | 76 | 16 | Foundation only |
| xavyo-webhooks | 🟢 stable | 160+ | 31 | 198 tests with `integration` feature; delivery, retry, DLQ |
| xavyo-siem | 🟢 stable | 118+ | 47 | 269 tests with `integration` feature; syslog, Splunk HEC |
| xavyo-ssf | 🔴 alpha | 16 | 24 | CAEP/SSF SET signing + emitter (incl. SSF verification event), no integration tests |
| xavyo-secrets | 🟢 stable | 51 | 28 | Multi-provider (Vault, AWS) |
| xavyo-scim-client | 🟢 stable | 150+ | 24 | Full integration test coverage |
| xavyo-scim-types | 🟢 stable | 9 | 17 | Pure SCIM 2.0 DTOs (RFC 7643/7644); RFC-pinned shape |
| xavyo-ext-authz | 🟡 beta | 62 | 12 | Envoy ext_authz v3 gRPC; integration stub only |

### Connector Layer

| Crate | Status | Tests | Public Items | Notes |
|-------|--------|-------|--------------|-------|
| xavyo-connector-ldap | 🟢 stable | 239 | 31 | Most mature connector |
| xavyo-connector-entra | 🟢 stable | 64 | 42 | Crate/API with rate limiting; no UI form |
| xavyo-connector-rest | 🟢 stable | 114 | 7 | Matches CRATE.md: CRUD, rate limit, retry, SSRF. Crate/API; not a production UI path |
| xavyo-connector-database | 🟡 beta | 51 | 4 | PostgreSQL CRUD + transactions; needs DB integration tests |

### API Layer

| Crate | Status | Tests | Public Items | Notes |
|-------|--------|-------|--------------|-------|
| xavyo-api-auth | 🟢 stable | 254 | 89 | MFA, passwordless complete |
| xavyo-api-oauth | 🟢 stable | 201 | 63 | OAuth2/OIDC complete |
| xavyo-api-users | 🟢 stable | 95+ | 34 | Full integration test coverage |
| xavyo-api-scim | 🟢 stable | 370+ | 27 | SCIM 2.0 compliance + IdP interop integration tests |
| xavyo-api-saml | 🟢 stable | 160+ | 18 | SP/IdP flows, security + vendor interop tests |
| xavyo-api-social | 🟢 stable | 120 | 19 | Provider OAuth flows (Google, Microsoft, Apple, GitHub) |
| xavyo-api-governance | 🟢 stable | 1058 | 180+ | 135K LOC, massive coverage |
| xavyo-api-connectors | 🟡 beta | 239 | 42 | 2 TODOs; some endpoints return 501 |
| xavyo-api-tenants | 🟢 stable | 121 | 38 | Multi-tenant bootstrap complete |
| xavyo-api-authorization | 🟡 beta | 112+ | 37 | 112 tests with `integration` feature (requires PostgreSQL) |
| xavyo-api-import | 🟢 stable | 92+ | 45+ | Full integration test coverage |
| xavyo-api-oidc-federation | 🟢 stable | 79+ | 16 | IdP interop tests (Auth0, Azure AD, Okta, Google) |
| xavyo-api-nhi | 🟢 stable | 77 | 33 | Complete with risk scoring, F-047 & F-048 |
| xavyo-api-ssf | 🔴 alpha | 20 | 50 | SSF push + poll (RFC 8936) delivery + SSRF guard, no integration tests |

---

## Summary by Status

| Status | Count | Crates |
|--------|-------|--------|
| 🟢 Stable | 27 | xavyo-core, xavyo-auth, xavyo-db, xavyo-tenant, xavyo-events, xavyo-nhi, xavyo-secrets, xavyo-connector, xavyo-connector-ldap, xavyo-connector-entra, xavyo-connector-rest, xavyo-governance, xavyo-provisioning, xavyo-webhooks, xavyo-siem, xavyo-scim-client, xavyo-scim-types, xavyo-api-auth, xavyo-api-oauth, xavyo-api-governance, xavyo-api-tenants, xavyo-api-import, xavyo-api-users, xavyo-api-scim, xavyo-api-saml, xavyo-api-oidc-federation, xavyo-api-social, xavyo-api-nhi |
| 🟡 Beta | 6 | xavyo-authorization, xavyo-ext-authz, xavyo-connector-database, xavyo-api-connectors, xavyo-api-authorization |
| 🔴 Alpha | 2 | xavyo-ssf, xavyo-api-ssf |

---

## Promotion Criteria

### Alpha → Beta

- [ ] Core functionality implemented and working
- [ ] At least 20 unit tests
- [ ] No compilation errors or critical bugs
- [ ] Basic documentation in CRATE.md

### Beta → Stable

- [ ] Complete API matching specifications
- [ ] 50+ tests including edge cases
- [ ] Integration tests or E2E coverage
- [ ] All critical TODOs resolved
- [ ] Production usage validated
- [ ] Comprehensive error handling

---

## Evaluation Methodology

Maturity was assessed based on:

1. **Test count**: `cargo test -p <crate> -- --list 2>/dev/null | grep -c "test$"`
2. **Public API surface**: Approximate count of public items
3. **Lines of code**: Indicator of implementation completeness
4. **TODO comments**: `grep -r "TODO\|FIXME" crates/<crate>/`
5. **Integration tests**: Presence of `tests/` directory with integration tests
6. **Documentation**: Quality and completeness of CRATE.md

---

*Last updated: 2026-08-27*
