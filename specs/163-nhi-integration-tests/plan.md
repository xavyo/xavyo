# Implementation Plan: NHI Integration Tests

**Branch**: `163-nhi-integration-tests` | **Date**: 2026-02-03 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/163-nhi-integration-tests/spec.md`

## Summary

Add comprehensive integration tests for the NHI (Non-Human Identity) API including service account lifecycle, credential rotation, unified NHI listing, risk scoring, certification, and multi-tenant isolation.

## Technical Context

**Language/Version**: Rust 1.75+ (per constitution)
**Primary Dependencies**: xavyo-api-nhi (existing), axum-test (HTTP testing), tokio (async runtime), sqlx (test database)
**Storage**: PostgreSQL (via xavyo-db test infrastructure)
**Testing**: cargo test, axum-test for HTTP testing
**Target Platform**: Linux server (CI/CD)
**Project Type**: Single crate (test module)
**Performance Goals**: Test suite completes in under 60 seconds
**Constraints**: Tests must use isolated test database, no side effects
**Scale/Scope**: 20+ integration tests across 5 user stories

## Constitution Check

- [x] Rust 1.75+ required - PASS
- [x] Multi-tenancy patterns - Tests verify isolation
- [x] Clippy warnings as errors - Will verify
- [x] No UI components - PASS (tests only)

## Project Structure

### Documentation (this feature)

```text
specs/163-nhi-integration-tests/
├── spec.md              # Feature specification
├── plan.md              # This file
├── research.md          # Test infrastructure research
├── data-model.md        # Test fixture structures
└── tasks.md             # Implementation tasks
```

### Source Code (repository root)

```text
crates/xavyo-api-nhi/
├── src/                     # Existing source (no changes)
└── tests/
    ├── integration_tests.rs # Test harness
    └── integration/
        ├── mod.rs           # Module root
        ├── common.rs        # Shared test utilities
        ├── fixtures.rs      # Test data fixtures
        ├── service_account_tests.rs  # Lifecycle tests
        ├── credential_tests.rs       # Rotation tests
        ├── unified_list_tests.rs     # Unified NHI tests
        ├── governance_tests.rs       # Risk/cert tests
        └── tenant_isolation_tests.rs # Multi-tenant tests
```

**Structure Decision**: Tests organized in a dedicated `integration` module with per-user-story test files.

## Complexity Tracking

No constitution violations - standard test module structure.
