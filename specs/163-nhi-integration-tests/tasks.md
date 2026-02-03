# Tasks: NHI Integration Tests

**Branch**: `163-nhi-integration-tests` | **Date**: 2026-02-03

## Task List

### T-001: Create test infrastructure
**Description**: Set up the integration test module structure and common utilities.

**Files**:
- `crates/xavyo-api-nhi/tests/integration_tests.rs` (new)
- `crates/xavyo-api-nhi/tests/integration/mod.rs` (new)
- `crates/xavyo-api-nhi/tests/integration/common.rs` (new)
- `crates/xavyo-api-nhi/tests/integration/fixtures.rs` (new)

**Acceptance**:
- [ ] Test harness compiles
- [ ] Common utilities exported
- [ ] Fixtures module ready

---

### T-002: Implement service account lifecycle tests
**Description**: Add tests for service account CRUD and lifecycle operations.

**Files**:
- `crates/xavyo-api-nhi/tests/integration/service_account_tests.rs` (new)

**Tests**:
- `test_create_service_account` - POST /nhi/service-accounts creates account
- `test_get_service_account` - GET /nhi/service-accounts/:id returns account
- `test_update_service_account` - PUT /nhi/service-accounts/:id updates attributes
- `test_suspend_service_account` - POST /nhi/service-accounts/:id/suspend changes status
- `test_reactivate_service_account` - POST /nhi/service-accounts/:id/reactivate restores status
- `test_delete_service_account` - DELETE removes account

**Depends on**: T-001

---

### T-003: Implement credential rotation tests
**Description**: Add tests for credential rotation and validation.

**Files**:
- `crates/xavyo-api-nhi/tests/integration/credential_tests.rs` (new)

**Tests**:
- `test_list_credentials` - GET /nhi/service-accounts/:id/credentials lists creds
- `test_rotate_credentials` - POST /nhi/service-accounts/:id/credentials/rotate generates new
- `test_revoke_credential` - POST revokes specific credential
- `test_old_credential_invalid` - Rotated-out credentials no longer work

**Depends on**: T-001

---

### T-004: Implement unified NHI list tests
**Description**: Add tests for the unified NHI listing endpoint.

**Files**:
- `crates/xavyo-api-nhi/tests/integration/unified_list_tests.rs` (new)

**Tests**:
- `test_list_all_nhis` - GET /nhi returns service accounts and agents
- `test_filter_by_type` - Type filter returns only matching NHIs
- `test_pagination` - Limit/offset pagination works correctly
- `test_get_nhi_by_id` - GET /nhi/:id returns specific NHI

**Depends on**: T-001

---

### T-005: Implement governance tests (risk/certification)
**Description**: Add tests for risk scoring and certification features.

**Files**:
- `crates/xavyo-api-nhi/tests/integration/governance_tests.rs` (new)

**Tests**:
- `test_get_risk_summary` - GET /nhi/risk-summary returns statistics
- `test_certify_service_account` - POST /nhi/service-accounts/:id/certify marks certified
- `test_certification_status_persisted` - Certification visible in GET
- `test_risk_score_endpoint` - GET /nhi/service-accounts/:id/risk returns score

**Depends on**: T-001

---

### T-006: Implement tenant isolation tests
**Description**: Add tests verifying multi-tenant data isolation.

**Files**:
- `crates/xavyo-api-nhi/tests/integration/tenant_isolation_tests.rs` (new)

**Tests**:
- `test_tenant_cannot_list_others_nhis` - Tenant A cannot see Tenant B's NHIs
- `test_tenant_cannot_access_others_by_id` - Cross-tenant ID access denied
- `test_tenant_cannot_update_others` - Cross-tenant mutations rejected
- `test_tenant_cannot_delete_others` - Cross-tenant deletes rejected

**Depends on**: T-001

---

### T-007: Update CRATE.md and verify tests
**Description**: Update documentation and run full test suite.

**Files**:
- `crates/xavyo-api-nhi/CRATE.md` (update)

**Acceptance**:
- [ ] All tests pass
- [ ] Clippy clean
- [ ] CRATE.md updated with test count
- [ ] Maturity status updated if needed

**Depends on**: T-002, T-003, T-004, T-005, T-006

---

## Summary

| Task | Description | Est. Tests |
|------|-------------|------------|
| T-001 | Test infrastructure | 0 |
| T-002 | Service account lifecycle | 6 |
| T-003 | Credential rotation | 4 |
| T-004 | Unified NHI list | 4 |
| T-005 | Governance (risk/cert) | 4 |
| T-006 | Tenant isolation | 4 |
| T-007 | Documentation | 0 |
| **Total** | | **22** |
