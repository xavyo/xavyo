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
| xavyo-auth | 🟢 stable | 44 | 39 | JWT/Argon2id complete |
| xavyo-db | 🟢 stable | 958+ | 400+ | 111K LOC, excellent coverage |
| xavyo-tenant | 🟢 stable | 30 | 13 | Middleware complete |
| xavyo-events | 🟢 stable | 123+ | 45 | Kafka bus with idempotence |
| xavyo-nhi | 🔴 alpha | 26 | 11 | Minimal stub implementation |

### Domain Layer

| Crate | Status | Tests | Public Items | Notes |
|-------|--------|-------|--------------|-------|
| xavyo-connector | 🟢 stable | 137 | 79 | Mature framework |
| xavyo-provisioning | 🟡 beta | 215 | 89 | 11 TODOs in reconciliation |
| xavyo-governance | 🟡 beta | 3 | 9 | Minimal domain layer |
| xavyo-authorization | 🔴 alpha | 47 | 16 | Foundation only |
| xavyo-webhooks | 🟡 beta | 59 | 31 | Needs integration tests |
| xavyo-siem | 🟡 beta | 115 | 47 | Good coverage, no integration tests |
| xavyo-secrets | 🟢 stable | 51 | 28 | Multi-provider (Vault, AWS) |
| xavyo-scim-client | 🟡 beta | 37+ | 24 | Core OK, limited coverage |

### Connector Layer

| Crate | Status | Tests | Public Items | Notes |
|-------|--------|-------|--------------|-------|
| xavyo-connector-ldap | 🟢 stable | 239 | 31 | Most mature connector |
| xavyo-connector-entra | 🟡 beta | 22 | 12 | Functional, limited tests |
| xavyo-connector-rest | 🔴 alpha | 36 | 7 | Stub implementation |
| xavyo-connector-database | 🔴 alpha | 33 | 4 | Skeleton only |

### API Layer

| Crate | Status | Tests | Public Items | Notes |
|-------|--------|-------|--------------|-------|
| xavyo-api-auth | 🟢 stable | 254 | 89 | MFA, passwordless complete |
| xavyo-api-oauth | 🟢 stable | 201 | 63 | OAuth2/OIDC complete |
| xavyo-api-users | 🟡 beta | 56 | 34 | No integration tests |
| xavyo-api-scim | 🟡 beta | 45 | 27 | No integration tests |
| xavyo-api-saml | 🟡 beta | 13 | 18 | 3 TODOs, limited coverage |
| xavyo-api-social | 🟡 beta | 27 | 19 | Needs validation tests |
| xavyo-api-agents | 🟢 stable | 335 | 112 | AI agent platform mature |
| xavyo-api-governance | 🟢 stable | 1058 | 180+ | 135K LOC, massive coverage |
| xavyo-api-connectors | 🟡 beta | 69 | 42 | 6 TODOs |
| xavyo-api-tenants | 🟢 stable | 121 | 38 | Multi-tenant bootstrap complete |
| xavyo-api-authorization | 🔴 alpha | 8 | 37 | Early-stage |
| xavyo-api-import | 🔴 alpha | 22 | 21 | Not validated |
| xavyo-api-oidc-federation | 🟡 beta | 13 | 16 | Insufficient coverage |
| xavyo-api-nhi | 🟡 beta | 55 | 33 | No integration tests |

---

## Summary by Status

| Status | Count | Crates |
|--------|-------|--------|
| 🟢 Stable | 13 | xavyo-core, xavyo-auth, xavyo-db, xavyo-tenant, xavyo-events, xavyo-secrets, xavyo-connector, xavyo-connector-ldap, xavyo-api-auth, xavyo-api-oauth, xavyo-api-agents, xavyo-api-governance, xavyo-api-tenants |
| 🟡 Beta | 13 | xavyo-provisioning, xavyo-governance, xavyo-webhooks, xavyo-siem, xavyo-scim-client, xavyo-connector-entra, xavyo-api-users, xavyo-api-scim, xavyo-api-saml, xavyo-api-social, xavyo-api-connectors, xavyo-api-oidc-federation, xavyo-api-nhi |
| 🔴 Alpha | 6 | xavyo-nhi, xavyo-authorization, xavyo-connector-rest, xavyo-connector-database, xavyo-api-authorization, xavyo-api-import |

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

*Last updated: 2026-02-02*
