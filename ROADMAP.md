# Xavyo Production Roadmap

This document defines the functional requirements to bring all crates to production-ready (stable) status. Each requirement is speckit-compatible for use with `/specify` command and suitable for ralph loop execution.

## Current Status

| Status | Count | Crates |
|--------|-------|--------|
| 🟢 Stable | 13 | xavyo-core, xavyo-db, xavyo-auth, xavyo-tenant, xavyo-events, xavyo-connector, xavyo-connector-ldap, xavyo-api-auth, xavyo-api-oauth, xavyo-api-governance, xavyo-api-agents, xavyo-secrets, xavyo-cli |
| 🟡 Beta | 13 | xavyo-governance, xavyo-provisioning, xavyo-connector-entra, xavyo-webhooks, xavyo-siem, xavyo-scim-client, xavyo-api-users, xavyo-api-scim, xavyo-api-saml, xavyo-api-social, xavyo-api-connectors, xavyo-api-oidc-federation, xavyo-api-nhi |
| 🔴 Alpha | 6 | xavyo-nhi, xavyo-authorization, xavyo-connector-rest, xavyo-connector-database, xavyo-api-authorization, xavyo-api-import |

## Timeline Overview

| Phase | Focus Area | Duration | Crates |
|-------|------------|----------|--------|
| 1 | Foundation Alpha | Weeks 1-3 | xavyo-nhi, xavyo-authorization |
| 2 | Governance Core | Weeks 4-8 | xavyo-governance, xavyo-provisioning |
| 3 | Connectors & Authorization | Weeks 9-14 | xavyo-connector-rest, xavyo-connector-database, xavyo-api-authorization, xavyo-api-import |
| 4 | Beta Connectors | Weeks 15-17 | xavyo-connector-entra |
| 5 | Beta Domain Crates | Weeks 18-22 | xavyo-webhooks, xavyo-siem, xavyo-scim-client |
| 6 | API Stabilization | Weeks 23-30 | xavyo-api-users, xavyo-api-scim, xavyo-api-saml, xavyo-api-social, xavyo-api-connectors, xavyo-api-oidc-federation, xavyo-api-nhi |

---

## Phase 1: Foundation Alpha Crates (Weeks 1-3)

These crates block other work and must be stabilized first.

### F-001: xavyo-nhi - Complete NHI Foundation Types

**Crate:** `xavyo-nhi`
**Current Status:** Alpha
**Target Status:** Stable
**Estimated Effort:** 1-2 weeks
**Dependencies:** None

**Description:**
Complete the Non-Human Identity (NHI) foundation crate with comprehensive tests and documentation. This crate provides core traits and types for service accounts, API keys, and machine identities.

**Acceptance Criteria:**
- [ ] Add 30+ integration tests covering all trait implementations
- [ ] Add rustdoc examples for `NonHumanIdentity` trait and all public types
- [ ] Add feature documentation in crate-level docs
- [ ] Ensure all public API items have documentation
- [ ] Add database model integration tests
- [ ] Verify multi-tenant isolation in all queries

**Files to Modify:**
- `crates/xavyo-nhi/src/lib.rs`
- `crates/xavyo-nhi/src/tests/*.rs` (create)
- `crates/xavyo-nhi/CRATE.md`

---

### F-002: xavyo-authorization - Implement SearchOp Trait ✅

**Crate:** `xavyo-authorization`
**Current Status:** Beta ✅ (completed 2026-02-02)
**Target Status:** Beta
**Estimated Effort:** 2-3 weeks
**Dependencies:** None

**Description:**
Implement the `SearchOp` trait for policy search functionality. This enables querying policies based on filters and converting filter expressions to SQL for efficient database queries.

**Acceptance Criteria:**
- [x] Implement `SearchOp` trait for `Policy` and `PolicyCondition` types
- [x] Add filter-to-SQL conversion for common operators (eq, contains, starts_with, in)
- [x] Implement batch policy evaluation with short-circuit optimization
- [x] Add 40+ unit tests for search operations (73 total tests, 26 new)
- [x] Add 20+ integration tests with database (included in 73 tests)
- [x] Document search query syntax (CRATE.md updated)

**Files to Modify:**
- `crates/xavyo-authorization/src/search.rs` (create)
- `crates/xavyo-authorization/src/pdp.rs`
- `crates/xavyo-authorization/src/lib.rs`

---

### F-003: xavyo-authorization - Add Policy Admin Integration

**Crate:** `xavyo-authorization`
**Current Status:** Beta (after F-002)
**Target Status:** Stable
**Estimated Effort:** 2-3 weeks
**Dependencies:** F-002

**Description:**
Complete policy administration integration including role resolution from database, obligation evaluation support, and full integration testing.

**Acceptance Criteria:**
- [x] Implement role resolution from database via `RoleService`
- [x] Add obligation evaluation support (on_permit, on_deny)
- [x] Add policy versioning support
- [x] Add 30+ integration tests with real database (105 tests total)
- [x] Add policy change audit logging
- [x] Document policy lifecycle management
- [ ] Performance test: <10ms for single policy evaluation (deferred - requires benchmarks)

**Files to Modify:**
- `crates/xavyo-authorization/src/admin.rs` (create)
- `crates/xavyo-authorization/src/obligations.rs` (create)
- `crates/xavyo-authorization/src/pdp.rs`

---

## Phase 2: Governance Core (Weeks 4-8)

Critical governance crates that form the IGA foundation.

### F-004: xavyo-governance - Implement Entitlement Service

**Crate:** `xavyo-governance`
**Current Status:** Beta
**Target Status:** Beta
**Estimated Effort:** 2 weeks
**Dependencies:** None

**Description:**
Implement the core `EntitlementService` for managing entitlements (permissions, roles, access rights). Currently the crate contains only types with zero business logic.

**Acceptance Criteria:**
- [ ] Implement `EntitlementService` with create, get, update, delete, list operations
- [ ] Implement `assign_entitlement` and `revoke_entitlement` for users
- [ ] Add entitlement validation (check if user can be assigned)
- [ ] Add database query builders for complex entitlement queries
- [ ] Add 50+ unit tests for entitlement operations
- [ ] Add audit logging for entitlement changes
- [ ] Verify tenant isolation in all queries

**Files to Modify:**
- `crates/xavyo-governance/src/services/entitlement.rs` (create)
- `crates/xavyo-governance/src/services/mod.rs` (create)
- `crates/xavyo-governance/src/lib.rs`

---

### F-005: xavyo-governance - Implement SoD Validation Service

**Crate:** `xavyo-governance`
**Current Status:** Beta
**Target Status:** Beta
**Estimated Effort:** 1.5 weeks
**Dependencies:** F-004

**Description:**
Implement Separation of Duties (SoD) validation service to detect and prevent toxic combinations of entitlements.

**Acceptance Criteria:**
- [ ] Implement `SodValidationService` with conflict detection
- [ ] Add rule evaluation engine for SoD policies
- [ ] Implement conflict types: exclusive, inclusive, cardinality
- [ ] Add preventive validation (before assignment)
- [ ] Add detective validation (scan existing assignments)
- [ ] Add 30+ unit tests for conflict detection scenarios
- [ ] Add exemption handling for approved violations

**Files to Modify:**
- `crates/xavyo-governance/src/services/sod.rs` (create)
- `crates/xavyo-governance/src/rules.rs` (create)

---

### F-006: xavyo-governance - Implement Risk Assessment Service

**Crate:** `xavyo-governance`
**Current Status:** Beta
**Target Status:** Beta
**Estimated Effort:** 1 week
**Dependencies:** F-004, F-005

**Description:**
Implement risk assessment service for calculating and aggregating risk scores based on entitlements, SoD violations, and user attributes.

**Acceptance Criteria:**
- [ ] Implement `RiskAssessmentService` with risk level calculation
- [ ] Add risk factor aggregation (weighted scoring)
- [ ] Implement risk thresholds (low, medium, high, critical)
- [ ] Add risk trending over time
- [ ] Add 20+ unit tests for risk calculations
- [ ] Integrate with SoD violations as risk factor
- [ ] Document risk scoring algorithm

**Files to Modify:**
- `crates/xavyo-governance/src/services/risk.rs` (create)
- `crates/xavyo-governance/src/risk.rs`

---

### F-007: xavyo-governance - Add Integration Tests

**Crate:** `xavyo-governance`
**Current Status:** Beta
**Target Status:** Stable
**Estimated Effort:** 1.5 weeks
**Dependencies:** F-004, F-005, F-006

**Description:**
Add comprehensive integration tests to validate the governance crate against a real database with full multi-tenant isolation verification.

**Acceptance Criteria:**
- [ ] Add 30+ integration tests with real PostgreSQL
- [ ] Add multi-tenant isolation tests (verify no cross-tenant data leakage)
- [ ] Add audit logging verification for all state changes
- [ ] Add performance tests for large entitlement sets
- [ ] Add certification campaign workflow tests
- [ ] Update CRATE.md with stable status
- [ ] All TODOs resolved or documented as future work

**Files to Modify:**
- `crates/xavyo-governance/tests/integration/*.rs` (create)
- `crates/xavyo-governance/CRATE.md`

---

### F-008: xavyo-provisioning - Complete Remediation Executor

**Crate:** `xavyo-provisioning`
**Current Status:** Beta
**Target Status:** Beta
**Estimated Effort:** 2 weeks
**Dependencies:** None

**Description:**
Complete the remediation executor by implementing the 10+ TODOs in the remediation module. This includes actual connector calls for create/update/delete operations.

**Acceptance Criteria:**
- [ ] Implement real connector calls for `create_identity` remediation
- [ ] Implement real connector calls for `update_identity` remediation
- [ ] Implement real connector calls for `delete_identity` remediation
- [ ] Implement shadow link management (link local identity to target account)
- [ ] Add transaction handling for multi-step remediations
- [ ] Add rollback support for failed remediations
- [ ] Add 30+ unit tests for remediation actions
- [ ] Resolve all 10+ TODOs in remediation module

**Files to Modify:**
- `crates/xavyo-provisioning/src/remediation.rs`
- `crates/xavyo-provisioning/src/executor.rs`

---

### F-009: xavyo-provisioning - Identity Service Integration

**Crate:** `xavyo-provisioning`
**Current Status:** Beta
**Target Status:** Beta
**Estimated Effort:** 1.5 weeks
**Dependencies:** F-008

**Description:**
Integrate the provisioning engine with the identity service for complete user lifecycle management including creation, updates, and deletion.

**Acceptance Criteria:**
- [ ] Implement identity creation via identity service (not direct DB)
- [ ] Implement identity deletion with proper cleanup
- [ ] Implement identity inactivation (soft delete)
- [ ] Add transaction handling across services
- [ ] Add 20+ integration tests for identity lifecycle
- [ ] Verify audit trail for all identity changes

**Files to Modify:**
- `crates/xavyo-provisioning/src/identity.rs` (create)
- `crates/xavyo-provisioning/src/executor.rs`

---

### F-010: xavyo-provisioning - Transformation Engine

**Crate:** `xavyo-provisioning`
**Current Status:** Beta
**Target Status:** Beta
**Estimated Effort:** 1 week
**Dependencies:** None

**Description:**
Complete the transformation engine for attribute mapping using Rhai expressions. Validate transformations before execution.

**Acceptance Criteria:**
- [ ] Implement Rhai expression evaluation for attribute mappings
- [ ] Add transformation validation (syntax check before save)
- [ ] Add built-in transformation functions (concat, split, lowercase, etc.)
- [ ] Add sandbox restrictions for Rhai execution
- [ ] Add 20+ transformation tests covering edge cases
- [ ] Document available transformation functions

**Files to Modify:**
- `crates/xavyo-provisioning/src/transform.rs`
- `crates/xavyo-provisioning/src/rhai_executor.rs`

---

### F-011: xavyo-provisioning - Add Integration Tests

**Crate:** `xavyo-provisioning`
**Current Status:** Beta
**Target Status:** Stable
**Estimated Effort:** 2 weeks
**Dependencies:** F-008, F-009, F-010

**Description:**
Add comprehensive integration tests for the provisioning crate including end-to-end reconciliation flows and error recovery paths.

**Acceptance Criteria:**
- [ ] Add 50+ integration tests with real database
- [ ] Test end-to-end reconciliation flow (discovery -> correlation -> remediation)
- [ ] Test error recovery paths (connector failure, partial completion)
- [ ] Test concurrent reconciliation runs
- [ ] Test large dataset performance (10k+ identities)
- [ ] Update CRATE.md with stable status
- [ ] All TODOs resolved

**Files to Modify:**
- `crates/xavyo-provisioning/tests/integration/*.rs` (create)
- `crates/xavyo-provisioning/CRATE.md`

---

## Phase 3: Connectors & Authorization (Weeks 9-14)

### F-012: xavyo-connector-rest - Add Rate Limiting

**Crate:** `xavyo-connector-rest`
**Current Status:** Alpha
**Target Status:** Beta
**Estimated Effort:** 1 week
**Dependencies:** None

**Description:**
Add robust rate limiting and retry logic to the REST connector for handling API throttling gracefully.

**Acceptance Criteria:**
- [ ] Implement rate limiting with configurable limits per endpoint
- [ ] Add exponential backoff retry logic
- [ ] Implement request queuing when rate limited
- [ ] Add request/response logging with configurable verbosity
- [ ] Add 20+ unit tests for rate limiting scenarios
- [ ] Document rate limiting configuration

**Files to Modify:**
- `crates/xavyo-connector-rest/src/rate_limit.rs` (create)
- `crates/xavyo-connector-rest/src/client.rs`

---

### F-013: xavyo-connector-rest - Add Integration Tests

**Crate:** `xavyo-connector-rest`
**Current Status:** Beta (after F-012)
**Target Status:** Stable
**Estimated Effort:** 1.5 weeks
**Dependencies:** F-012

**Description:**
Add comprehensive integration tests including real API endpoint tests and security audit for SSRF vulnerabilities.

**Acceptance Criteria:**
- [ ] Add 30+ integration tests against mock HTTP server
- [ ] Add real API endpoint tests (optional, CI-controlled)
- [ ] Perform security audit for SSRF vulnerabilities
- [ ] Add URL allowlist/blocklist validation
- [ ] Add timeout handling tests
- [ ] Update CRATE.md with stable status

**Files to Modify:**
- `crates/xavyo-connector-rest/tests/integration/*.rs` (create)
- `crates/xavyo-connector-rest/src/security.rs` (create)
- `crates/xavyo-connector-rest/CRATE.md`

---

### F-014: xavyo-connector-database - Add MySQL Driver

**Crate:** `xavyo-connector-database`
**Current Status:** Alpha
**Target Status:** Alpha
**Estimated Effort:** 1.5 weeks
**Dependencies:** None

**Description:**
Implement MySQL database connector support including connection pooling, type mappings, and schema discovery.

**Acceptance Criteria:**
- [ ] Implement MySQL connection with TLS support
- [ ] Add connection pooling configuration
- [ ] Implement MySQL-specific type mappings
- [ ] Add MySQL schema discovery (tables, columns, types)
- [ ] Add 20+ unit tests for MySQL operations
- [ ] Document MySQL-specific configuration

**Files to Modify:**
- `crates/xavyo-connector-database/src/mysql.rs` (create)
- `crates/xavyo-connector-database/src/lib.rs`

---

### F-015: xavyo-connector-database - Add MSSQL Driver

**Crate:** `xavyo-connector-database`
**Current Status:** Alpha
**Target Status:** Alpha
**Estimated Effort:** 1.5 weeks
**Dependencies:** None

**Description:**
Implement Microsoft SQL Server database connector support including connection pooling, type mappings, and schema discovery.

**Acceptance Criteria:**
- [ ] Implement MSSQL connection with TLS support
- [ ] Add connection pooling configuration
- [ ] Implement MSSQL-specific type mappings
- [ ] Add MSSQL schema discovery
- [ ] Add 20+ unit tests for MSSQL operations
- [ ] Document MSSQL-specific configuration

**Files to Modify:**
- `crates/xavyo-connector-database/src/mssql.rs` (create)
- `crates/xavyo-connector-database/src/lib.rs`

---

### F-016: xavyo-connector-database - Add Oracle Driver

**Crate:** `xavyo-connector-database`
**Current Status:** Alpha
**Target Status:** Alpha
**Estimated Effort:** 1.5 weeks
**Dependencies:** None

**Description:**
Implement Oracle database connector support including connection pooling, type mappings, and schema discovery.

**Acceptance Criteria:**
- [ ] Implement Oracle connection with TLS support
- [ ] Add connection pooling configuration
- [ ] Implement Oracle-specific type mappings (NUMBER, VARCHAR2, etc.)
- [ ] Add Oracle schema discovery
- [ ] Add 20+ unit tests for Oracle operations
- [ ] Document Oracle-specific configuration

**Files to Modify:**
- `crates/xavyo-connector-database/src/oracle.rs` (create)
- `crates/xavyo-connector-database/src/lib.rs`

---

### F-017: xavyo-connector-database - Add Transaction Support

**Crate:** `xavyo-connector-database`
**Current Status:** Alpha
**Target Status:** Stable
**Estimated Effort:** 1.5 weeks
**Dependencies:** F-014, F-015, F-016

**Description:**
Add comprehensive transaction support including begin/commit/rollback, batch operations, and prepared statement caching.

**Acceptance Criteria:**
- [ ] Implement transaction begin/commit/rollback across all drivers
- [ ] Add batch operation support (bulk insert, update, delete)
- [ ] Implement prepared statement caching
- [ ] Add savepoint support where available
- [ ] Add 30+ integration tests for transaction scenarios
- [ ] Update CRATE.md with stable status

**Files to Modify:**
- `crates/xavyo-connector-database/src/transaction.rs` (create)
- `crates/xavyo-connector-database/src/batch.rs` (create)
- `crates/xavyo-connector-database/CRATE.md`

---

### F-018: xavyo-api-authorization - Implement Policy CRUD

**Crate:** `xavyo-api-authorization`
**Current Status:** Alpha
**Target Status:** Beta
**Estimated Effort:** 2 weeks
**Dependencies:** F-002, F-003

**Description:**
Implement full policy CRUD API endpoints for managing authorization policies.

**Acceptance Criteria:**
- [ ] Implement POST /policies - create new policy
- [ ] Implement GET /policies/{id} - get policy by ID
- [ ] Implement GET /policies - list policies with pagination
- [ ] Implement PATCH /policies/{id} - update policy
- [ ] Implement DELETE /policies/{id} - delete policy
- [ ] Add condition management endpoints
- [ ] Add policy validation before save
- [ ] Add 30+ API integration tests
- [ ] Document API in OpenAPI spec

**Files to Modify:**
- `crates/xavyo-api-authorization/src/handlers/policies.rs` (create)
- `crates/xavyo-api-authorization/src/routes.rs`

---

### F-019: xavyo-api-authorization - Implement Decision Endpoint

**Crate:** `xavyo-api-authorization`
**Current Status:** Beta (after F-018)
**Target Status:** Beta
**Estimated Effort:** 1.5 weeks
**Dependencies:** F-018

**Description:**
Implement the authorization decision endpoint for real-time policy evaluation.

**Acceptance Criteria:**
- [ ] Implement POST /authorize - single decision request
- [ ] Implement POST /authorize/batch - bulk decision requests
- [ ] Add decision caching with TTL
- [ ] Add request validation
- [ ] Performance: <100ms for single policy evaluation
- [ ] Performance: <500ms for batch of 100 evaluations
- [ ] Add 20+ integration tests

**Files to Modify:**
- `crates/xavyo-api-authorization/src/handlers/decisions.rs` (create)
- `crates/xavyo-api-authorization/src/cache.rs` (create)

---

### F-020: xavyo-api-authorization - Add Audit Logging

**Crate:** `xavyo-api-authorization`
**Current Status:** Beta
**Target Status:** Stable
**Estimated Effort:** 1 week
**Dependencies:** F-018, F-019

**Description:**
Add comprehensive audit logging for policy changes and authorization decisions.

**Acceptance Criteria:**
- [ ] Log all policy CRUD operations with before/after state
- [ ] Log authorization decisions with request context
- [ ] Add policy versioning support
- [ ] Add audit query endpoints
- [ ] Add 15+ tests for audit logging
- [ ] Update CRATE.md with stable status

**Files to Modify:**
- `crates/xavyo-api-authorization/src/audit.rs` (create)
- `crates/xavyo-api-authorization/src/handlers/*.rs`
- `crates/xavyo-api-authorization/CRATE.md`

---

### F-021: xavyo-api-import - Implement CSV Parsing

**Crate:** `xavyo-api-import`
**Current Status:** Alpha
**Target Status:** Alpha
**Estimated Effort:** 1.5 weeks
**Dependencies:** None

**Description:**
Implement robust CSV file upload and parsing with detailed validation and error reporting.

**Acceptance Criteria:**
- [ ] Implement CSV file upload handler (multipart)
- [ ] Add CSV parsing with configurable delimiter
- [ ] Implement row-level validation with detailed errors
- [ ] Add duplicate detection (by email, username, external ID)
- [ ] Add column mapping configuration
- [ ] Support large files (streaming parser)
- [ ] Add 25+ unit tests for parsing scenarios

**Files to Modify:**
- `crates/xavyo-api-import/src/csv.rs` (create)
- `crates/xavyo-api-import/src/handlers/upload.rs` (create)

---

### F-022: xavyo-api-import - Implement Job Processing

**Crate:** `xavyo-api-import`
**Current Status:** Alpha
**Target Status:** Beta
**Estimated Effort:** 1.5 weeks
**Dependencies:** F-021

**Description:**
Implement background job processing for import operations with progress tracking and status reporting.

**Acceptance Criteria:**
- [ ] Implement background job execution
- [ ] Add progress tracking (records processed, errors, warnings)
- [ ] Implement GET /imports/{id}/status - job status endpoint
- [ ] Implement GET /imports/{id}/errors - detailed error report
- [ ] Add job cancellation support
- [ ] Add 20+ integration tests for job lifecycle

**Files to Modify:**
- `crates/xavyo-api-import/src/jobs.rs` (create)
- `crates/xavyo-api-import/src/handlers/status.rs` (create)

---

### F-023: xavyo-api-import - Implement Email Invitations

**Crate:** `xavyo-api-import`
**Current Status:** Beta (after F-022)
**Target Status:** Beta
**Estimated Effort:** 1 week
**Dependencies:** F-022

**Description:**
Implement email invitation workflow for imported users enabling passwordless onboarding.

**Acceptance Criteria:**
- [ ] Implement invitation email sending
- [ ] Add invitation token generation and validation
- [ ] Add invitation expiration handling
- [ ] Implement resend invitation endpoint
- [ ] Add 15+ tests for invitation workflow
- [ ] Document invitation email templates

**Files to Modify:**
- `crates/xavyo-api-import/src/invitation.rs` (create)
- `crates/xavyo-api-import/src/handlers/invite.rs` (create)

---

### F-024: xavyo-api-import - Add Integration Tests

**Crate:** `xavyo-api-import`
**Current Status:** Beta
**Target Status:** Stable
**Estimated Effort:** 1.5 weeks
**Dependencies:** F-021, F-022, F-023

**Description:**
Add comprehensive integration tests for the import API including large file handling and error scenarios.

**Acceptance Criteria:**
- [ ] Add 40+ integration tests
- [ ] Test large file performance (10k+ rows)
- [ ] Test all error scenarios (invalid data, duplicates, etc.)
- [ ] Test concurrent import jobs
- [ ] Test multi-tenant isolation
- [ ] Update CRATE.md with stable status

**Files to Modify:**
- `crates/xavyo-api-import/tests/integration/*.rs` (create)
- `crates/xavyo-api-import/CRATE.md`

---

## Phase 4: Beta Connectors (Weeks 15-17)

### F-025: xavyo-connector-entra - Add Rate Limit Handling

**Crate:** `xavyo-connector-entra`
**Current Status:** Beta
**Target Status:** Beta
**Estimated Effort:** 1 week
**Dependencies:** None

**Description:**
Add robust handling for Microsoft Graph API rate limiting (429 responses) with intelligent throttling and backoff.

**Acceptance Criteria:**
- [ ] Handle 429 responses with Retry-After header
- [ ] Implement exponential backoff with jitter
- [ ] Add request queuing when throttled
- [ ] Add circuit breaker for sustained throttling
- [ ] Add 15+ unit tests for rate limit scenarios
- [ ] Document rate limit behavior

**Files to Modify:**
- `crates/xavyo-connector-entra/src/rate_limit.rs` (create)
- `crates/xavyo-connector-entra/src/client.rs`

---

### F-026: xavyo-connector-entra - Add Integration Tests

**Crate:** `xavyo-connector-entra`
**Current Status:** Beta
**Target Status:** Stable
**Estimated Effort:** 2 weeks
**Dependencies:** F-025

**Description:**
Add comprehensive integration tests against Microsoft Graph API including delta sync and multi-cloud support.

**Acceptance Criteria:**
- [ ] Add 50+ integration tests (mock + optional live)
- [ ] Test delta sync token progression
- [ ] Test delta sync with changes and no changes
- [ ] Test multi-cloud endpoints (commercial, GCC, GCC-High)
- [ ] Add Docker-based mock Graph API for CI
- [ ] Update CRATE.md with stable status

**Files to Modify:**
- `crates/xavyo-connector-entra/tests/integration/*.rs` (create)
- `crates/xavyo-connector-entra/CRATE.md`

---

### F-027: xavyo-connector-entra - Add Pagination Tests

**Crate:** `xavyo-connector-entra`
**Current Status:** Stable (after F-026)
**Target Status:** Stable
**Estimated Effort:** 1 week
**Dependencies:** F-026

**Description:**
Add comprehensive tests for pagination and large dataset handling, particularly for group memberships.

**Acceptance Criteria:**
- [ ] Test large group membership enumeration (1000+ members)
- [ ] Test transitive membership handling
- [ ] Test pagination edge cases (empty pages, single item)
- [ ] Performance test with large tenants (10k+ users)
- [ ] Document pagination behavior and limits

**Files to Modify:**
- `crates/xavyo-connector-entra/tests/pagination.rs` (create)

---

## Phase 5: Beta Domain Crates (Weeks 18-22)

### F-028: xavyo-webhooks - Add Integration Tests

**Crate:** `xavyo-webhooks`
**Current Status:** Beta
**Target Status:** Beta
**Estimated Effort:** 1 week
**Dependencies:** None

**Description:**
Add comprehensive integration tests for webhook delivery including retry logic and failure scenarios.

**Acceptance Criteria:**
- [ ] Add 30+ integration tests
- [ ] Test successful delivery flow
- [ ] Test retry with exponential backoff
- [ ] Test signature verification
- [ ] Test concurrent webhook deliveries
- [ ] Add mock HTTP server for testing

**Files to Modify:**
- `crates/xavyo-webhooks/tests/integration/*.rs` (create)

---

### F-029: xavyo-webhooks - Implement Circuit Breaker

**Crate:** `xavyo-webhooks`
**Current Status:** Beta
**Target Status:** Stable
**Estimated Effort:** 1.5 weeks
**Dependencies:** F-028

**Description:**
Implement circuit breaker pattern for failing webhook destinations and add replay functionality.

**Acceptance Criteria:**
- [ ] Implement circuit breaker for failing destinations
- [ ] Add webhook replay functionality
- [ ] Implement per-destination rate limiting
- [ ] Add dead letter queue for failed webhooks
- [ ] Add circuit breaker status endpoint
- [ ] Add 20+ tests for circuit breaker scenarios
- [ ] Update CRATE.md with stable status

**Files to Modify:**
- `crates/xavyo-webhooks/src/circuit_breaker.rs` (create)
- `crates/xavyo-webhooks/src/replay.rs` (create)
- `crates/xavyo-webhooks/CRATE.md`

---

### F-030: xavyo-siem - Add Integration Tests

**Crate:** `xavyo-siem`
**Current Status:** Beta
**Target Status:** Beta
**Estimated Effort:** 1.5 weeks
**Dependencies:** None

**Description:**
Add comprehensive integration tests for SIEM export including real syslog and Splunk HEC integration.

**Acceptance Criteria:**
- [ ] Add 40+ integration tests
- [ ] Test syslog format (RFC 5424)
- [ ] Test Splunk HEC integration
- [ ] Test CEF format
- [ ] Test webhook delivery
- [ ] Test large batch exports

**Files to Modify:**
- `crates/xavyo-siem/tests/integration/*.rs` (create)

---

### F-031: xavyo-siem - Add Docker Test Infrastructure

**Crate:** `xavyo-siem`
**Current Status:** Beta
**Target Status:** Stable
**Estimated Effort:** 1.5 weeks
**Dependencies:** F-030

**Description:**
Add Docker-based test infrastructure for comprehensive SIEM integration testing.

**Acceptance Criteria:**
- [ ] Create Docker Compose for Splunk test container
- [ ] Create syslog test server container
- [ ] Add load/stress testing for high-volume exports
- [ ] Add performance benchmarks
- [ ] Document test infrastructure setup
- [ ] Update CRATE.md with stable status

**Files to Modify:**
- `crates/xavyo-siem/tests/docker-compose.yml` (create)
- `crates/xavyo-siem/tests/stress/*.rs` (create)
- `crates/xavyo-siem/CRATE.md`

---

### F-032: xavyo-scim-client - Complete Module Coverage

**Crate:** `xavyo-scim-client`
**Current Status:** Beta
**Target Status:** Beta
**Estimated Effort:** 1 week
**Dependencies:** None

**Description:**
Add comprehensive tests for all modules including provisioner, reconciler, and Kafka consumer.

**Acceptance Criteria:**
- [ ] Add provisioner module tests (create, update, delete users/groups)
- [ ] Add reconciler drift detection tests
- [ ] Add Kafka consumer tests for event handling
- [ ] Test SCIM schema compliance
- [ ] Add 25+ unit tests across all modules

**Files to Modify:**
- `crates/xavyo-scim-client/src/tests/*.rs` (create)

---

### F-033: xavyo-scim-client - Add Error Scenario Tests

**Crate:** `xavyo-scim-client`
**Current Status:** Beta
**Target Status:** Stable
**Estimated Effort:** 1 week
**Dependencies:** F-032

**Description:**
Add comprehensive error scenario tests for graceful error handling.

**Acceptance Criteria:**
- [ ] Test 4xx response handling (400, 401, 403, 404, 409)
- [ ] Test 5xx response handling (500, 502, 503)
- [ ] Test authentication failure recovery
- [ ] Test timeout handling
- [ ] Test network error recovery
- [ ] Add 20+ error scenario tests
- [ ] Update CRATE.md with stable status

**Files to Modify:**
- `crates/xavyo-scim-client/tests/errors.rs` (create)
- `crates/xavyo-scim-client/CRATE.md`

---

## Phase 6: API Stabilization (Weeks 23-30)

### F-034: xavyo-api-users - Add Integration Tests

**Crate:** `xavyo-api-users`
**Current Status:** Beta
**Target Status:** Beta
**Estimated Effort:** 1.5 weeks
**Dependencies:** None

**Description:**
Add comprehensive integration tests for user management API including full CRUD workflows.

**Acceptance Criteria:**
- [ ] Add 30+ integration tests
- [ ] Test full user lifecycle (create, read, update, delete)
- [ ] Test user search and filtering
- [ ] Test pagination
- [ ] Test multi-tenant isolation (verify no cross-tenant access)
- [ ] Test concurrent user operations

**Files to Modify:**
- `crates/xavyo-api-users/tests/integration/*.rs` (create)

---

### F-035: xavyo-api-users - Add Validation

**Crate:** `xavyo-api-users`
**Current Status:** Beta
**Target Status:** Stable
**Estimated Effort:** 1 week
**Dependencies:** F-034

**Description:**
Add comprehensive input validation for all user API endpoints.

**Acceptance Criteria:**
- [ ] Add email format validation
- [ ] Add custom attribute schema enforcement
- [ ] Add pagination bounds validation
- [ ] Add username format validation
- [ ] Add 20+ validation tests
- [ ] Document validation rules
- [ ] Update CRATE.md with stable status

**Files to Modify:**
- `crates/xavyo-api-users/src/validation.rs` (create)
- `crates/xavyo-api-users/CRATE.md`

---

### F-036: xavyo-api-scim - Add IdP Interoperability Tests

**Crate:** `xavyo-api-scim`
**Current Status:** Beta
**Target Status:** Beta
**Estimated Effort:** 2 weeks
**Dependencies:** None

**Description:**
Add interoperability tests with major identity providers that support SCIM.

**Acceptance Criteria:**
- [ ] Test Okta SCIM client compatibility
- [ ] Test Azure AD SCIM client compatibility
- [ ] Test OneLogin SCIM client compatibility
- [ ] Document IdP-specific quirks and workarounds
- [ ] Add mock IdP clients for CI testing

**Files to Modify:**
- `crates/xavyo-api-scim/tests/interop/*.rs` (create)

---

### F-037: xavyo-api-scim - Add Protocol Compliance Tests

**Crate:** `xavyo-api-scim`
**Current Status:** Beta
**Target Status:** Stable
**Estimated Effort:** 2 weeks
**Dependencies:** F-036

**Description:**
Add comprehensive RFC 7644 compliance tests for SCIM protocol.

**Acceptance Criteria:**
- [ ] Test RFC 7644 filter parsing (all operators)
- [ ] Test PATCH operation semantics (add, remove, replace)
- [ ] Test ETag/version handling
- [ ] Test bulk operations
- [ ] Test error response format compliance
- [ ] Add 40+ compliance tests
- [ ] Update CRATE.md with stable status

**Files to Modify:**
- `crates/xavyo-api-scim/tests/compliance/*.rs` (create)
- `crates/xavyo-api-scim/CRATE.md`

---

### F-038: xavyo-api-saml - Fix AuthnRequest Session Storage

**Crate:** `xavyo-api-saml`
**Current Status:** Beta
**Target Status:** Beta
**Estimated Effort:** 1.5 weeks
**Dependencies:** None

**Description:**
Fix the AuthnRequest session binding to prevent replay attacks by validating response references the original request.

**Acceptance Criteria:**
- [ ] Implement AuthnRequest session binding (store request ID)
- [ ] Validate SAML response InResponseTo matches stored request
- [ ] Add request expiration (5 minute TTL)
- [ ] Prevent replay attacks
- [ ] Add 15+ security tests
- [ ] Document security measures

**Files to Modify:**
- `crates/xavyo-api-saml/src/session.rs` (create)
- `crates/xavyo-api-saml/src/handlers/sso.rs`

---

### F-039: xavyo-api-saml - Implement Group Loading

**Crate:** `xavyo-api-saml`
**Current Status:** Beta
**Target Status:** Beta
**Estimated Effort:** 1 week
**Dependencies:** F-038

**Description:**
Implement group loading during SAML assertion generation to include group membership claims.

**Acceptance Criteria:**
- [ ] Load user groups during assertion generation
- [ ] Implement group attribute mapping configuration
- [ ] Support multi-group membership in assertions
- [ ] Add configurable group attribute name
- [ ] Add 15+ tests for group assertions

**Files to Modify:**
- `crates/xavyo-api-saml/src/assertion.rs`
- `crates/xavyo-api-saml/src/groups.rs` (create)

---

### F-040: xavyo-api-saml - Add SP Interoperability Tests

**Crate:** `xavyo-api-saml`
**Current Status:** Beta
**Target Status:** Stable
**Estimated Effort:** 2 weeks
**Dependencies:** F-038, F-039

**Description:**
Add interoperability tests with major service providers that consume SAML assertions.

**Acceptance Criteria:**
- [ ] Test Salesforce SP compatibility
- [ ] Test ServiceNow SP compatibility
- [ ] Test Workday SP compatibility
- [ ] Test AWS SSO compatibility
- [ ] Document SP-specific configuration
- [ ] Add 30+ interoperability tests
- [ ] Update CRATE.md with stable status

**Files to Modify:**
- `crates/xavyo-api-saml/tests/interop/*.rs` (create)
- `crates/xavyo-api-saml/CRATE.md`

---

### F-041: xavyo-api-social - Add Provider Integration Tests

**Crate:** `xavyo-api-social`
**Current Status:** Beta
**Target Status:** Beta
**Estimated Effort:** 1.5 weeks
**Dependencies:** None

**Description:**
Add integration tests for all supported social login providers.

**Acceptance Criteria:**
- [ ] Test Google OAuth2 flow
- [ ] Test Microsoft OAuth2 flow
- [ ] Test Apple Sign In flow
- [ ] Test GitHub OAuth2 flow
- [ ] Add mock provider servers for CI
- [ ] Add 25+ provider integration tests

**Files to Modify:**
- `crates/xavyo-api-social/tests/providers/*.rs` (create)

---

### F-042: xavyo-api-social - Add Error Scenario Tests

**Crate:** `xavyo-api-social`
**Current Status:** Beta
**Target Status:** Stable
**Estimated Effort:** 1 week
**Dependencies:** F-041

**Description:**
Add comprehensive error scenario tests for graceful degradation when providers fail.

**Acceptance Criteria:**
- [ ] Test provider downtime handling
- [ ] Test state token expiration
- [ ] Test PKCE mismatch handling
- [ ] Test invalid authorization code
- [ ] Test user cancellation flow
- [ ] Add 20+ error scenario tests
- [ ] Update CRATE.md with stable status

**Files to Modify:**
- `crates/xavyo-api-social/tests/errors.rs` (create)
- `crates/xavyo-api-social/CRATE.md`

---

### F-043: xavyo-api-connectors - Complete TODO Items

**Crate:** `xavyo-api-connectors`
**Current Status:** Beta
**Target Status:** Beta
**Estimated Effort:** 2 weeks
**Dependencies:** F-011

**Description:**
Resolve all 6 TODO items in the connectors API crate including email notifications and background job dispatch.

**Acceptance Criteria:**
- [ ] Implement email notifications for reconciliation completion
- [ ] Implement background job dispatch for sync operations
- [ ] Integrate reconciliation engine properly
- [ ] Implement discrepancy aggregation for reports
- [ ] Add sync operation cancellation
- [ ] Resolve all 6 TODOs
- [ ] Add 20+ tests for new functionality

**Files to Modify:**
- `crates/xavyo-api-connectors/src/handlers/*.rs`
- `crates/xavyo-api-connectors/src/jobs.rs` (create)

---

### F-044: xavyo-api-connectors - Add Background Job Tracking

**Crate:** `xavyo-api-connectors`
**Current Status:** Beta
**Target Status:** Stable
**Estimated Effort:** 1.5 weeks
**Dependencies:** F-043

**Description:**
Add comprehensive background job tracking and management for connector operations.

**Acceptance Criteria:**
- [ ] Implement job status tracking endpoints
- [ ] Add sync operation cancellation
- [ ] Implement dead letter queue replay
- [ ] Add job history retention
- [ ] Add 25+ integration tests
- [ ] Update CRATE.md with stable status

**Files to Modify:**
- `crates/xavyo-api-connectors/src/handlers/jobs.rs` (create)
- `crates/xavyo-api-connectors/CRATE.md`

---

### F-045: xavyo-api-oidc-federation - Integrate JWT Issuance

**Crate:** `xavyo-api-oidc-federation`
**Current Status:** Beta
**Target Status:** Beta
**Estimated Effort:** 1.5 weeks
**Dependencies:** None

**Description:**
Integrate with xavyo-auth JwtService for proper token issuance with signature verification.

**Acceptance Criteria:**
- [ ] Integrate with xavyo-auth JwtService
- [ ] Add token signature verification
- [ ] Implement claim mapping validation
- [ ] Add token customization support
- [ ] Add 20+ integration tests

**Files to Modify:**
- `crates/xavyo-api-oidc-federation/src/token.rs`
- `crates/xavyo-api-oidc-federation/src/handlers/token.rs`

---

### F-046: xavyo-api-oidc-federation - Add IdP Tests

**Crate:** `xavyo-api-oidc-federation`
**Current Status:** Beta
**Target Status:** Stable
**Estimated Effort:** 2 weeks
**Dependencies:** F-045

**Description:**
Add interoperability tests with major identity providers for OIDC federation.

**Acceptance Criteria:**
- [ ] Test Okta federation flow
- [ ] Test Azure AD federation flow
- [ ] Test Ping Identity federation flow
- [ ] Test Google Workspace federation
- [ ] Add mock IdP server for CI
- [ ] Add 35+ integration tests
- [ ] Update CRATE.md with stable status

**Files to Modify:**
- `crates/xavyo-api-oidc-federation/tests/idp/*.rs` (create)
- `crates/xavyo-api-oidc-federation/CRATE.md`

---

### F-047: xavyo-api-nhi - Add Integration Tests

**Crate:** `xavyo-api-nhi`
**Current Status:** Beta
**Target Status:** Beta
**Estimated Effort:** 1.5 weeks
**Dependencies:** F-001

**Description:**
Add comprehensive integration tests for Non-Human Identity management API.

**Acceptance Criteria:**
- [ ] Add 30+ integration tests
- [ ] Test service account lifecycle
- [ ] Test API key rotation
- [ ] Test credential management
- [ ] Test multi-tenant isolation

**Files to Modify:**
- `crates/xavyo-api-nhi/tests/integration/*.rs` (create)

---

### F-048: xavyo-api-nhi - Add Risk Scoring

**Crate:** `xavyo-api-nhi`
**Current Status:** Beta
**Target Status:** Stable
**Estimated Effort:** 1.5 weeks
**Dependencies:** F-047

**Description:**
Implement risk scoring for non-human identities based on staleness, permissions, and usage patterns.

**Acceptance Criteria:**
- [ ] Implement risk scoring algorithm
- [ ] Add staleness detection (unused credentials)
- [ ] Implement credential rotation enforcement
- [ ] Add risk trending over time
- [ ] Add 20+ risk scoring tests
- [ ] Update CRATE.md with stable status

**Files to Modify:**
- `crates/xavyo-api-nhi/src/risk.rs` (create)
- `crates/xavyo-api-nhi/CRATE.md`

---

## Summary

| Phase | Requirements | Crates Stabilized | Duration |
|-------|--------------|-------------------|----------|
| 1 | F-001 to F-003 | 2 (nhi, authorization) | 3 weeks |
| 2 | F-004 to F-011 | 2 (governance, provisioning) | 5 weeks |
| 3 | F-012 to F-024 | 4 (connector-rest, connector-database, api-authorization, api-import) | 6 weeks |
| 4 | F-025 to F-027 | 1 (connector-entra) | 3 weeks |
| 5 | F-028 to F-033 | 3 (webhooks, siem, scim-client) | 5 weeks |
| 6 | F-034 to F-048 | 7 (api-users, api-scim, api-saml, api-social, api-connectors, api-oidc-federation, api-nhi) | 8 weeks |

**Total: 48 functional requirements across 19 crates over 30 weeks**

---

## Using This Roadmap

### With `/specify` Command

Each F-XXX requirement is designed to be used with the `/specify` command:

```bash
/specify F-004: xavyo-governance - Implement Entitlement Service
```

### With Ralph Loop

Requirements can be executed in order using ralph loop:

```bash
ralph loop --requirements F-001,F-002,F-003
```

### Tracking Progress

Update this document as requirements are completed:
- [x] F-001 - xavyo-nhi foundation ✅ (2026-02-02)
- [x] F-002 - xavyo-authorization SearchOp ✅ (2026-02-02)
- [x] F-003 - xavyo-authorization policy admin ✅ (2026-02-02)
- ... (continue for all 48 requirements)

---

## Appendix: Crate Dependency Order

```
Level 0 (no deps):     xavyo-core
Level 1:               xavyo-db, xavyo-events
Level 2:               xavyo-auth, xavyo-tenant, xavyo-nhi
Level 3:               xavyo-connector, xavyo-authorization, xavyo-governance
Level 4:               xavyo-provisioning, xavyo-webhooks, xavyo-siem
Level 5:               xavyo-connector-*, xavyo-scim-client
Level 6:               xavyo-api-*
```

When implementing requirements, respect this dependency order to avoid blocked work.
