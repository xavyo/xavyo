# Feature Specification: NHI Integration Tests

**Feature Branch**: `163-nhi-integration-tests`
**Created**: 2026-02-03
**Status**: Draft
**Input**: User description: "F-047: xavyo-api-nhi - Add Integration Tests. Add integration tests for the NHI (Non-Human Identity) management API including service account lifecycle and credential rotation tests."

## User Scenarios & Testing _(mandatory)_

### User Story 1 - Service Account Lifecycle Tests (Priority: P1)

As a developer maintaining the NHI API, I need integration tests that verify the complete service account lifecycle (create, read, update, suspend, delete) works correctly end-to-end so that service account management is reliable in production.

**Why this priority**: Service accounts are the core functionality of the NHI API. Testing the complete lifecycle ensures the most critical operations work correctly.

**Independent Test**: Can be fully tested by executing the full CRUD workflow against a test database and verifying state changes.

**Acceptance Scenarios**:

1. **Given** no service account exists, **When** creating a new service account via POST /service-accounts, **Then** the service account is created with correct attributes and returned with an ID
2. **Given** a service account exists, **When** updating it via PATCH /service-accounts/:id, **Then** the attributes are updated correctly
3. **Given** an active service account, **When** suspending it via POST /service-accounts/:id/suspend, **Then** the status changes to suspended
4. **Given** a service account exists, **When** deleting it via DELETE /service-accounts/:id, **Then** the account is removed (or soft-deleted)

---

### User Story 2 - Credential Rotation Tests (Priority: P1)

As a developer maintaining the NHI API, I need integration tests that verify credential rotation works correctly so that security-critical operations are reliable.

**Why this priority**: Credential rotation is a critical security operation. Testing ensures credentials are properly regenerated and old credentials are invalidated.

**Independent Test**: Can be fully tested by rotating credentials and verifying the new credentials work while old ones are invalidated.

**Acceptance Scenarios**:

1. **Given** a service account with credentials, **When** rotating via POST /service-accounts/:id/rotate, **Then** new credentials are generated
2. **Given** credentials have been rotated, **When** using the old credentials, **Then** authentication fails
3. **Given** credentials have been rotated, **When** using the new credentials, **Then** authentication succeeds

---

### User Story 3 - Unified NHI List Tests (Priority: P2)

As a developer maintaining the NHI API, I need integration tests for the unified NHI listing endpoint that aggregates service accounts and AI agents so that the unified view works correctly.

**Why this priority**: The unified list is a key feature for administrators to view all NHIs in one place.

**Independent Test**: Can be fully tested by creating both service accounts and agents, then verifying they appear in the unified list.

**Acceptance Scenarios**:

1. **Given** multiple NHIs exist (service accounts and agents), **When** listing via GET /nhi, **Then** all NHIs are returned in a unified format
2. **Given** NHIs exist across multiple types, **When** filtering by type, **Then** only matching NHIs are returned
3. **Given** many NHIs exist, **When** paginating, **Then** results are correctly paginated

---

### User Story 4 - Risk Score and Certification Tests (Priority: P2)

As a developer maintaining the NHI API, I need integration tests for risk scoring and certification endpoints so that governance features work correctly.

**Why this priority**: Risk scoring and certification are important governance features that help organizations manage NHI security.

**Independent Test**: Can be fully tested by getting risk scores and performing certifications against test NHIs.

**Acceptance Scenarios**:

1. **Given** an NHI exists, **When** getting risk score via GET /nhi/:id/risk, **Then** a risk score is returned with factors
2. **Given** an uncertified NHI, **When** certifying via POST /nhi/:id/certify, **Then** the NHI is marked as certified with timestamp
3. **Given** a certified NHI, **When** getting its details, **Then** certification status is correctly reflected

---

### User Story 5 - Multi-Tenant Isolation Tests (Priority: P2)

As a developer maintaining the NHI API, I need integration tests that verify tenant isolation so that NHIs from one tenant cannot be accessed by another.

**Why this priority**: Multi-tenant isolation is critical for security in a SaaS environment.

**Independent Test**: Can be fully tested by creating NHIs for multiple tenants and verifying cross-tenant access is blocked.

**Acceptance Scenarios**:

1. **Given** NHIs exist for tenant A, **When** tenant B tries to list NHIs, **Then** tenant A's NHIs are not visible
2. **Given** an NHI belongs to tenant A, **When** tenant B tries to access it by ID, **Then** access is denied
3. **Given** an NHI belongs to tenant A, **When** tenant B tries to update/delete it, **Then** the operation is rejected

---

### Edge Cases

- What happens when creating a service account with duplicate name? (Should fail with conflict error)
- What happens when rotating credentials for a suspended account? (Should fail or have defined behavior)
- What happens when deleting an NHI that has active sessions? (Should handle gracefully)
- What happens when certifying an already-certified NHI? (Should update certification timestamp)

## Requirements _(mandatory)_

### Functional Requirements

- **FR-001**: System MUST support full CRUD operations on service accounts with proper state management
- **FR-002**: System MUST properly rotate credentials and invalidate old credentials
- **FR-003**: System MUST provide unified listing of all NHI types (service accounts, agents)
- **FR-004**: System MUST calculate and return risk scores for NHIs
- **FR-005**: System MUST support NHI certification with timestamp tracking
- **FR-006**: System MUST enforce tenant isolation for all NHI operations
- **FR-007**: System MUST handle error cases gracefully with appropriate HTTP status codes

### Key Entities

- **ServiceAccount**: A non-human identity representing a service or application
- **Agent**: An AI agent identity managed alongside service accounts
- **NHI**: Unified representation of any non-human identity
- **Credentials**: Authentication credentials associated with a service account
- **Certification**: Record of NHI governance certification

## Success Criteria _(mandatory)_

### Measurable Outcomes

- **SC-001**: All 5 user stories have passing integration tests
- **SC-002**: Each user story has at least 3 test cases covering primary flows
- **SC-003**: Test suite executes in under 60 seconds (using test database)
- **SC-004**: Tests achieve code coverage of NHI API handlers exceeding 80%
- **SC-005**: Multi-tenant isolation is verified with cross-tenant access tests

## Assumptions

- Tests will use axum-test or similar HTTP testing framework
- Tests will use an in-memory or test PostgreSQL database
- Test fixtures will create realistic NHI data
- The existing 55 unit tests provide foundation; integration tests add end-to-end coverage
