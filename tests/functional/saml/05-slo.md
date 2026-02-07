# Single Logout (SLO) Functional Tests

**API Endpoints**:
- SLO is referenced but not fully implemented in the current codebase. These tests document the expected behavior for SAML 2.0 Single Logout as specified by the OASIS standard.
- Session management is handled via `AuthnRequestSession` store (PostgreSQL-backed in production, in-memory for testing)

**Related Components**:
- `SessionStore` trait (`store.rs`): `store()`, `get()`, `validate_and_consume()`, `cleanup_expired()`
- `AuthnRequestSession` type (`types.rs`): session tracking with TTL and replay prevention
- `PostgresSessionStore`: Production implementation with atomic validate-and-consume
- `InMemorySessionStore`: Test implementation

**Applicable Standards**: SAML 2.0 Profiles (section 4.4 - Single Logout Profile), SAML 2.0 Bindings, SAML 2.0 Core, NIST SP 800-63C (Session Management), OWASP ASVS 3.3, 3.7

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`
- **Special Setup**: Session store must be initialized (InMemory for unit tests, PostgreSQL for integration tests); SP must be registered for SSO session tracking tests

---

## Nominal Cases

### TC-SAML-SLO-001: Store AuthnRequest session for SSO flow tracking
- **Category**: Nominal
- **Standard**: SAML 2.0 Profiles 4.1.2 (SSO session tracking prerequisite for SLO)
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`. Session store initialized (InMemory or PostgreSQL)
- **Input**: Store a new AuthnRequest session:
  ```
  AuthnRequestSession {
    tenant_id: <T1_uuid>,
    request_id: "_req_abc123",
    sp_entity_id: "https://sp.example.com/saml/metadata",
    relay_state: Some("https://sp.example.com/dashboard")
  }
  ```
- **Expected Output**: Session stored successfully (no error)
- **Verification**:
  - Session retrievable via `get(tenant_id, "_req_abc123")`
  - Retrieved session has `consumed_at = None`
  - `expires_at` = `created_at + 300 seconds` (default TTL)

### TC-SAML-SLO-002: Validate and consume AuthnRequest session (single use)
- **Category**: Nominal
- **Standard**: SAML 2.0 Profiles 4.1 (Request-Response correlation)
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`. Session `_req_abc123` stored for tenant T1
- **Input**: `validate_and_consume(T1_uuid, "_req_abc123")`
- **Expected Output**: Returns consumed session with `consumed_at` set to current timestamp
- **Verification**: Session is marked as used; relay_state preserved in returned session

### TC-SAML-SLO-003: Session with custom TTL
- **Category**: Nominal
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`.
- **Input**: Create session with 60-second TTL:
  ```
  AuthnRequestSession::with_ttl(
    tenant_id, "req-short", "https://sp.example.com", None, 60
  )
  ```
- **Expected Output**: `expires_at` = `created_at + 60 seconds`
- **Verification**: Short-lived sessions expire sooner

### TC-SAML-SLO-004: Session with relay_state preserved
- **Category**: Nominal
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`.
- **Input**: Store session with `relay_state = Some("https://sp.example.com/deep-link")`
- **Expected Output**: After `validate_and_consume()`, returned session has `relay_state = Some("https://sp.example.com/deep-link")`

### TC-SAML-SLO-005: Cleanup expired sessions
- **Category**: Nominal
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`. Store 3 sessions: 2 expired (expires_at in past), 1 valid
- **Input**: `cleanup_expired()`
- **Expected Output**: Returns `2` (number deleted)
- **Verification**:
  - Expired sessions no longer retrievable
  - Valid session still exists

### TC-SAML-SLO-006: PostgreSQL session store - atomic validate and consume
- **Category**: Nominal
- **Standard**: SAML 2.0 Profiles 4.1 (Replay Prevention)
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`. PostgreSQL-backed session store, session stored
- **Input**: `validate_and_consume(tenant_id, request_id)` via PostgreSQL store
- **Expected Output**: Atomic UPDATE sets `consumed_at` WHERE `consumed_at IS NULL AND expires_at > threshold`
- **Verification**: SQL uses single-statement UPDATE...RETURNING for atomicity

### TC-SAML-SLO-007: Session default TTL is 5 minutes (300 seconds)
- **Category**: Nominal
- **Standard**: SAML 2.0 operational best practice
- **Preconditions**: Fixtures: `TEST_TENANT`.
- **Input**: `AuthnRequestSession::new(...)` with default TTL
- **Expected Output**: `DEFAULT_SESSION_TTL_SECONDS = 300`
- **Verification**: Session expires 5 minutes after creation (plus grace period)

### TC-SAML-SLO-008: Session validates not-expired and not-consumed
- **Category**: Nominal
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`.
- **Input**: Call `session.validate()` on a fresh (not expired, not consumed) session
- **Expected Output**: Returns `Ok(())`

### TC-SAML-SLO-009: SP-initiated SSO generates SAML Response with SessionIndex
- **Category**: Nominal
- **Standard**: SAML 2.0 Core 2.7.2 (AuthnStatement)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`. SSO flow completes successfully
- **Expected Output**: SAML Response contains:
  ```xml
  <saml:AuthnStatement AuthnInstant="<timestamp>" SessionIndex="_session_<uuid>">
  ```
- **Verification**: SessionIndex is present and unique; SPs use this for SLO correlation

### TC-SAML-SLO-010: IdP-initiated SSO includes SessionIndex for SLO correlation
- **Category**: Nominal
- **Standard**: SAML 2.0 Profiles 4.4 (SLO requires SessionIndex)
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`.
- **Input**: IdP-initiated SSO via `POST /saml/initiate/<sp_id>`
- **Expected Output**: SAML Response Assertion includes `<saml:AuthnStatement SessionIndex="_session_<uuid>">`
- **Verification**: SessionIndex is generated even for unsolicited responses

---

## Edge Cases

### TC-SAML-SLO-011: Replay attack - consume same session twice
- **Category**: Edge Case
- **Standard**: SAML 2.0 Profiles 4.1.2 (One-time use)
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`. Session stored and consumed once
- **Input**: Second call to `validate_and_consume(tenant_id, request_id)`
- **Expected Output**: Error:
  ```
  SessionError::AlreadyConsumed {
    request_id: "_req_abc123",
    consumed_at: <first_consumption_timestamp>
  }
  ```
- **HTTP Error** (if exposed via API):
  ```
  Status: 400 Bad Request
  Body: {
    "error": "replay_attack_detected",
    "message": "Replay attack detected: AuthnRequest _req_abc123 was already used at <timestamp>",
    "saml_status": "urn:oasis:names:tc:SAML:2.0:status:Requester"
  }
  ```

### TC-SAML-SLO-012: Consume expired session
- **Category**: Edge Case
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`. Session with `expires_at` in the past (beyond grace period)
- **Input**: `validate_and_consume(tenant_id, request_id)`
- **Expected Output**: Error:
  ```
  SessionError::Expired {
    request_id: "_req_expired",
    expired_at: <expiry_timestamp>
  }
  ```
- **HTTP Error**:
  ```
  Status: 400 Bad Request
  Body: {
    "error": "request_expired",
    "message": "AuthnRequest expired: _req_expired (expired at <timestamp>)",
    "saml_status": "urn:oasis:names:tc:SAML:2.0:status:Requester"
  }
  ```

### TC-SAML-SLO-013: Consume nonexistent session
- **Category**: Edge Case
- **Preconditions**: Fixtures: `TEST_TENANT`.
- **Input**: `validate_and_consume(tenant_id, "nonexistent-request-id")`
- **Expected Output**: Error:
  ```
  SessionError::NotFound("nonexistent-request-id")
  ```
- **HTTP Error**:
  ```
  Status: 400 Bad Request
  Body: {
    "error": "unknown_request",
    "message": "AuthnRequest not found: nonexistent-request-id",
    "saml_status": "urn:oasis:names:tc:SAML:2.0:status:Requester"
  }
  ```

### TC-SAML-SLO-014: Store duplicate AuthnRequest ID
- **Category**: Edge Case
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`. Session with request_id `_req_dup` already stored
- **Input**: Store another session with same tenant_id and request_id `_req_dup`
- **Expected Output**: Error:
  ```
  SessionError::DuplicateRequestId("_req_dup")
  ```
- **HTTP Error**:
  ```
  Status: 409 Conflict
  Body: {
    "error": "duplicate_request",
    "message": "Duplicate AuthnRequest ID: _req_dup",
    "saml_status": "urn:oasis:names:tc:SAML:2.0:status:Requester"
  }
  ```

### TC-SAML-SLO-015: Session within grace period (not yet expired)
- **Category**: Edge Case
- **Standard**: SAML 2.0 clock skew tolerance
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`. Session with `expires_at` = 15 seconds ago (grace period is 30 seconds)
- **Input**: `session.is_expired()` or `validate_and_consume()`
- **Expected Output**: Session is NOT expired (15 < 30 second grace period)
- **Verification**: `CLOCK_SKEW_GRACE_SECONDS = 30` provides tolerance

### TC-SAML-SLO-016: Session past grace period (fully expired)
- **Category**: Edge Case
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`. Session with `expires_at` = 60 seconds ago (beyond 30-second grace)
- **Input**: `session.is_expired()`
- **Expected Output**: Returns `true` (expired beyond grace)

### TC-SAML-SLO-017: Cleanup with no expired sessions
- **Category**: Edge Case
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`. All sessions are still valid
- **Input**: `cleanup_expired()`
- **Expected Output**: Returns `0` (nothing deleted)

### TC-SAML-SLO-018: Cleanup with all sessions expired
- **Category**: Edge Case
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`. All stored sessions have `expires_at` in the distant past
- **Input**: `cleanup_expired()`
- **Expected Output**: Returns count equal to total sessions stored
- **Verification**: Session store is empty after cleanup

### TC-SAML-SLO-019: PostgreSQL store - ON CONFLICT behavior for duplicate request
- **Category**: Edge Case
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`. PostgreSQL session store
- **Input**: Store a session, then store another with same `(tenant_id, request_id)`
- **Expected Output**: Second insert is a no-op (`ON CONFLICT DO NOTHING`); original session preserved
- **Note**: InMemorySessionStore returns `DuplicateRequestId` error; PostgreSQL silently ignores

### TC-SAML-SLO-020: Concurrent validate_and_consume on same session (PostgreSQL)
- **Category**: Edge Case
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`. PostgreSQL session store with valid session
- **Input**: Two concurrent `validate_and_consume()` calls for the same session
- **Expected Output**: Exactly one succeeds, the other returns `AlreadyConsumed`
- **Verification**: Atomic UPDATE ensures only one caller can set `consumed_at`; no race condition

---

## Security Cases

### TC-SAML-SLO-021: Tenant isolation in session store
- **Category**: Security
- **Standard**: Multi-tenancy isolation
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`. Tenant A stores session with request_id `_req_shared`; Tenant B has no sessions
- **Input**: `validate_and_consume(tenant_b_id, "_req_shared")`
- **Expected Output**: Error `SessionError::NotFound("_req_shared")`
- **Verification**: Session store is keyed by `(tenant_id, request_id)` tuple; cross-tenant access impossible

### TC-SAML-SLO-022: Session replay attack detection and logging
- **Category**: Security
- **Standard**: OWASP ASVS 3.7.1
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`. Session consumed once
- **Input**: Second `validate_and_consume()` attempt
- **Expected Output**: Error with `AlreadyConsumed` variant
- **Verification**: PostgreSQL implementation logs a warning:
  ```
  "Replay attack detected: AuthnRequest already consumed"
  ```
  with tenant_id, request_id, and consumed_at

### TC-SAML-SLO-023: Expired session replay attempt logged
- **Category**: Security
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`. Expired session exists in store
- **Input**: `validate_and_consume()` on expired session
- **Expected Output**: Error with `Expired` variant
- **Verification**: PostgreSQL implementation logs:
  ```
  "Expired AuthnRequest replay attempt"
  ```
  with tenant_id, request_id, and expires_at

### TC-SAML-SLO-024: Session store does not leak session data across tenants
- **Category**: Security
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`. T1 has session `_req_001`, T2 has session `_req_002`
- **Input**:
  - `get(T1_id, "_req_002")` should return `None`
  - `get(T2_id, "_req_001")` should return `None`
- **Expected Output**: Both return `None`; each tenant sees only its own sessions

### TC-SAML-SLO-025: PostgreSQL cleanup uses expiry-based deletion
- **Category**: Security
- **Standard**: Data Minimization
- **Preconditions**: Fixtures: `TEST_TENANT`.
- **Verification**: Cleanup query is:
  ```sql
  DELETE FROM saml_authn_request_sessions
  WHERE expires_at < NOW() - INTERVAL '30 seconds'
  ```
- **Note**: Grace period (30 seconds) is included in cleanup threshold to match validation logic

### TC-SAML-SLO-026: SAML Response StatusCode for error conditions
- **Category**: Security
- **Standard**: SAML 2.0 Core 3.2.2.2
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`.
- **Verification**: Error responses include appropriate SAML status URIs:
  - Replay attack: `urn:oasis:names:tc:SAML:2.0:status:Requester`
  - Expired request: `urn:oasis:names:tc:SAML:2.0:status:Requester`
  - Unknown request: `urn:oasis:names:tc:SAML:2.0:status:Requester`
  - Storage error: `urn:oasis:names:tc:SAML:2.0:status:Responder`

### TC-SAML-SLO-027: Session consumed_at timestamp is server-side (not client-provided)
- **Category**: Security
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`.
- **Verification**: `consumed_at` is set to `Utc::now()` by the server, not from any client input
- **Note**: Prevents timestamp manipulation attacks

---

## Compliance Cases

### TC-SAML-SLO-028: Session TTL aligns with SAML clock skew recommendations
- **Category**: Compliance
- **Standard**: SAML 2.0 Core 1.3.3 (time synchronization)
- **Preconditions**: Fixtures: `TEST_TENANT`.
- **Verification**:
  - Default TTL: 300 seconds (5 minutes) - reasonable for SSO redirect flow
  - Grace period: 30 seconds - accommodates clock skew between IdP and SP
  - Combined window: 330 seconds maximum from creation to rejection

### TC-SAML-SLO-029: Session store supports PostgreSQL for production persistence
- **Category**: Compliance
- **Standard**: SAML 2.0 (stateful session requirement)
- **Preconditions**: Fixtures: `TEST_TENANT`.
- **Verification**:
  - `PostgresSessionStore` persists sessions to `saml_authn_request_sessions` table
  - Schema includes: `id`, `tenant_id`, `request_id`, `sp_entity_id`, `created_at`, `expires_at`, `consumed_at`, `relay_state`
  - `(tenant_id, request_id)` has UNIQUE constraint for deduplication

### TC-SAML-SLO-030: AuthnStatement SessionIndex format
- **Category**: Compliance
- **Standard**: SAML 2.0 Core 2.7.2
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`, `SAML_SP`.
- **Input**: Any SSO flow
- **Expected Output**: `SessionIndex="_session_<uuid>"` where UUID is version 4
- **Verification**: SessionIndex uniquely identifies the session for future SLO correlation

### TC-SAML-SLO-031: Session cleanup removes only expired sessions
- **Category**: Compliance
- **Standard**: Data lifecycle management
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`.
  - Session A: expires_at = 10 minutes ago (expired)
  - Session B: consumed_at = 3 minutes ago, expires_at = 2 minutes from now (consumed but not expired)
  - Session C: expires_at = 5 minutes from now (active)
- **Input**: `cleanup_expired()`
- **Expected Output**: Only Session A deleted; Sessions B and C remain
- **Verification**: Consumed sessions are retained until they expire (for audit/replay detection)

### TC-SAML-SLO-032: NIST SP 800-63C session binding
- **Category**: Compliance
- **Standard**: NIST SP 800-63C Section 5.3 (Session Binding)
- **Preconditions**: Fixtures: `TEST_TENANT`, `SAML_SP`.
- **Verification**:
  - SSO sessions are bound to specific tenant and SP (via `tenant_id` and `sp_entity_id`)
  - Sessions have bounded lifetime (TTL + grace period)
  - Consumed sessions cannot be reused (one-time use enforcement)
  - Session state persists across IdP restarts (PostgreSQL store)

### TC-SAML-SLO-033: Session ID uniqueness
- **Category**: Compliance
- **Standard**: SAML 2.0 Core 1.3.4
- **Preconditions**: Fixtures: `TEST_TENANT`.
- **Verification**: Each `AuthnRequestSession.id` is a UUID v4, providing sufficient randomness (122 bits of entropy) to prevent collision and guessing
