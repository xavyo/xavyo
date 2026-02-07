# NHI Credential Management Functional Tests

**API Endpoints**:
- `GET /nhi/agents/:id/credentials` - List agent credentials
- `POST /nhi/agents/:id/credentials/rotate` - Rotate agent credentials
- `GET /nhi/agents/:agent_id/credentials/:credential_id` - Get credential
- `POST /nhi/agents/:agent_id/credentials/:credential_id/revoke` - Revoke credential
- `POST /nhi/agents/:id/credentials/validate` - Validate a credential
- `POST /nhi/agents/:id/credentials/request` - Request ephemeral credentials (F120)

**Authentication**: Bearer JWT (admin role for mutations)
**Required Headers**: `Content-Type: application/json`, `Authorization: Bearer <jwt>`
**Applicable Standards**: NIST SP 800-63B (Credential Management), NIST SP 800-57 (Key Management), SOC 2 CC6.1

---

## Nominal Cases

### TC-NHI-CRED-001: Rotate credentials for an active agent
- **Category**: Nominal
- **Standard**: NIST SP 800-63B Section 5.1.2 (Credential Rotation)
- **Preconditions**: Active agent exists with at least one credential
- **Input**:
  ```json
  POST /nhi/agents/<agent-id>/credentials/rotate
  {
    "rotation_reason": "scheduled_rotation",
    "validity_days": 90
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "credential": {
      "id": "<uuid>",
      "nhi_id": "<agent-id>",
      "credential_hash": "<hash>",
      "valid_from": "<ISO8601>",
      "valid_until": "<ISO8601>",
      "status": "active",
      "created_at": "<ISO8601>"
    },
    "secret": "xnhi_<base64-encoded-secret>",
    "warning": "This is the only time the secret will be shown. Store it securely."
  }
  ```
- **Side Effects**:
  - New credential created with `status=active`
  - Previous credential remains active during grace period (or revoked if immediate)

### TC-NHI-CRED-002: List credentials for an agent
- **Category**: Nominal
- **Preconditions**: Agent with 3 credentials (2 active, 1 revoked)
- **Input**: `GET /nhi/agents/<agent-id>/credentials`
- **Expected Output**:
  ```json
  Status: 200 OK
  {
    "credentials": [
      { "id": "<uuid>", "status": "active", ... },
      { "id": "<uuid>", "status": "active", ... },
      { "id": "<uuid>", "status": "revoked", ... }
    ],
    "total": 3
  }
  ```

### TC-NHI-CRED-003: List only active credentials
- **Category**: Nominal
- **Input**: `GET /nhi/agents/<agent-id>/credentials?active_only=true`
- **Expected Output**: Status 200, only credentials with `status=active` returned

### TC-NHI-CRED-004: Get a specific credential by ID
- **Category**: Nominal
- **Input**: `GET /nhi/agents/<agent-id>/credentials/<credential-id>`
- **Expected Output**:
  ```json
  Status: 200 OK
  {
    "id": "<credential-id>",
    "nhi_id": "<agent-id>",
    "status": "active",
    "valid_from": "<ISO8601>",
    "valid_until": "<ISO8601>",
    "created_at": "<ISO8601>"
  }
  ```
- **Verification**: Response does NOT contain the plaintext secret or full credential hash

### TC-NHI-CRED-005: Revoke a credential with reason
- **Category**: Nominal
- **Standard**: NIST SP 800-63B Section 6.1 (Credential Revocation)
- **Preconditions**: Active credential exists
- **Input**:
  ```json
  POST /nhi/agents/<agent-id>/credentials/<credential-id>/revoke
  {
    "reason": "Suspected compromise",
    "immediate": true
  }
  ```
- **Expected Output**:
  ```json
  Status: 200 OK
  {
    "id": "<credential-id>",
    "status": "revoked",
    "revoked_at": "<ISO8601>",
    "revoked_by": "<actor-uuid>",
    "revocation_reason": "Suspected compromise"
  }
  ```

### TC-NHI-CRED-006: Revoke credential with deferred invalidation
- **Category**: Nominal
- **Input**:
  ```json
  POST /nhi/agents/<agent-id>/credentials/<credential-id>/revoke
  {
    "reason": "Scheduled decommission",
    "immediate": false
  }
  ```
- **Expected Output**: Status 200, credential marked for revocation (grace period)

### TC-NHI-CRED-007: Validate a valid credential
- **Category**: Nominal
- **Preconditions**: Agent has an active, non-expired credential
- **Input**:
  ```json
  POST /nhi/agents/<agent-id>/credentials/validate
  {
    "credential": "xnhi_<valid-secret>"
  }
  ```
- **Expected Output**:
  ```json
  Status: 200 OK
  {
    "valid": true,
    "agent_id": "<agent-id>",
    "tenant_id": "<tenant-uuid>",
    "nhi_type": "ai_agent",
    "message": "Credential is valid"
  }
  ```

### TC-NHI-CRED-008: Request ephemeral credentials (F120 dynamic secrets)
- **Category**: Nominal
- **Standard**: NIST SP 800-57 (Just-in-Time Provisioning)
- **Preconditions**: Agent has secret-permission for "postgres-readonly" secret type
- **Input**:
  ```json
  POST /agents/<agent-id>/credentials/request
  {
    "secret_type": "postgres-readonly",
    "ttl_seconds": 300,
    "context": {
      "conversation_id": "<uuid>",
      "user_instruction": "Query customer data"
    }
  }
  ```
- **Expected Output**:
  ```
  Status: 200 OK
  Headers: X-RateLimit-Remaining: 9, X-RateLimit-Reset: <ISO8601>
  Body: {
    "credential_id": "<uuid>",
    "credentials": { "username": "dynamic_user_<id>", "password": "...", "host": "...", "port": 5432 },
    "issued_at": "<ISO8601>",
    "expires_at": "<ISO8601>",
    "ttl_seconds": 300,
    "provider": "openbao"
  }
  ```

### TC-NHI-CRED-009: Request ephemeral credentials with default TTL
- **Category**: Nominal
- **Input**:
  ```json
  POST /agents/<agent-id>/credentials/request
  { "secret_type": "aws-readonly" }
  ```
- **Expected Output**: Status 200, `ttl_seconds` matches default TTL for the secret type config

### TC-NHI-CRED-010: Rotate credentials records actor in audit trail
- **Category**: Nominal
- **Standard**: SOC 2 CC6.1
- **Input**: Rotate credentials as admin user
- **Verification**: Audit log entry created with actor_id, action, timestamp, agent_id

---

## Edge Cases

### TC-NHI-CRED-020: Rotate credentials for suspended agent
- **Category**: Edge Case
- **Preconditions**: Agent is suspended
- **Input**: `POST /nhi/agents/<agent-id>/credentials/rotate { ... }`
- **Expected Output**: Status 400 ("Agent is suspended, cannot rotate credentials")

### TC-NHI-CRED-021: Revoke already-revoked credential
- **Category**: Edge Case
- **Input**: Revoke credential, then revoke again
- **Expected Output**: Status 400 ("Credential already revoked")

### TC-NHI-CRED-022: Get credential from wrong agent
- **Category**: Edge Case
- **Preconditions**: Credential belongs to Agent A
- **Input**: `GET /nhi/agents/<agent-b-id>/credentials/<agent-a-credential-id>`
- **Expected Output**: Status 404 (credential not found for this agent)

### TC-NHI-CRED-023: Validate expired credential
- **Category**: Edge Case
- **Preconditions**: Credential exists but `valid_until` is in the past
- **Input**: `POST /nhi/agents/<id>/credentials/validate { "credential": "xnhi_<expired>" }`
- **Expected Output**: Status 401 ("Invalid or expired credential")

### TC-NHI-CRED-024: Validate revoked credential
- **Category**: Edge Case
- **Input**: Validate a credential that has been revoked
- **Expected Output**: Status 401

### TC-NHI-CRED-025: Validate credential for wrong agent ID in path
- **Category**: Edge Case
- **Preconditions**: Credential belongs to Agent A
- **Input**: `POST /nhi/agents/<agent-b-id>/credentials/validate { "credential": "xnhi_<agent-a-secret>" }`
- **Expected Output**: Status 400 ("Credential does not belong to this agent")

### TC-NHI-CRED-026: Request ephemeral credentials with TTL exceeding max_ttl
- **Category**: Edge Case
- **Preconditions**: Secret type "postgres-readonly" has `max_ttl=3600`
- **Input**: `{ "secret_type": "postgres-readonly", "ttl_seconds": 86400 }`
- **Expected Output**: Status 400 (invalid TTL) OR Status 200 with TTL clamped to `max_ttl`

### TC-NHI-CRED-027: Request ephemeral credentials for unknown secret type
- **Category**: Edge Case
- **Input**: `{ "secret_type": "nonexistent-secret-type" }`
- **Expected Output**: Status 404 (secret type not found)

### TC-NHI-CRED-028: Request ephemeral credentials exceeds rate limit
- **Category**: Edge Case
- **Preconditions**: Agent has 10/hr rate limit, already made 10 requests
- **Input**: 11th request in the same window
- **Expected Output**:
  ```
  Status: 429 Too Many Requests
  Headers: Retry-After: <seconds>
  ```

### TC-NHI-CRED-029: List credentials for non-existent agent
- **Category**: Edge Case
- **Input**: `GET /nhi/agents/<nonexistent-uuid>/credentials`
- **Expected Output**: Status 404

### TC-NHI-CRED-030: Rotate credentials with zero validity_days
- **Category**: Edge Case
- **Input**: `{ "rotation_reason": "test", "validity_days": 0 }`
- **Expected Output**: Status 400 (validity must be positive)

---

## Security Cases

### TC-NHI-CRED-040: Secret is only shown once at creation/rotation
- **Category**: Security
- **Standard**: NIST SP 800-63B Section 5.1.1
- **Input**: Rotate credentials, note the secret
- **Verification**:
  - The `secret` field appears only in the rotation response (201)
  - Subsequent `GET /nhi/agents/<id>/credentials/<cred-id>` does NOT include the secret
  - Database stores only the hash (`credential_hash`), never plaintext

### TC-NHI-CRED-041: Credential hash uses CSPRNG
- **Category**: Security
- **Standard**: NIST SP 800-63B Section 5.1.1
- **Verification**: Credential secret is generated using `OsRng` (CSPRNG), not a predictable PRNG

### TC-NHI-CRED-042: Credential revocation is immediate when flagged
- **Category**: Security
- **Input**: Revoke with `"immediate": true`
- **Verification**: Credential is immediately unusable (validate returns 401)

### TC-NHI-CRED-043: Cross-tenant credential isolation
- **Category**: Security
- **Standard**: SOC 2 CC6.1
- **Preconditions**: Credential created in Tenant A
- **Input**: Tenant B attempts `GET /nhi/agents/<tenant-a-agent>/credentials/<tenant-a-cred>`
- **Expected Output**: Status 404

### TC-NHI-CRED-044: Rotate credentials without admin role
- **Category**: Security
- **Input**: Non-admin attempts rotation
- **Expected Output**: Status 403 Forbidden

### TC-NHI-CRED-045: Revoke credential without authentication
- **Category**: Security
- **Input**: `POST /nhi/agents/<id>/credentials/<cred-id>/revoke` without Authorization header
- **Expected Output**: Status 401 Unauthorized

### TC-NHI-CRED-046: Ephemeral credentials denied for agent without permission
- **Category**: Security
- **Standard**: Zero Trust - explicit verification
- **Preconditions**: Agent has no secret-permission for "aws-admin"
- **Input**: `POST /agents/<agent-id>/credentials/request { "secret_type": "aws-admin" }`
- **Expected Output**: Status 403 ("Permission denied for secret type")

### TC-NHI-CRED-047: Ephemeral credentials denied for disabled secret type
- **Category**: Security
- **Preconditions**: Secret type "postgres-readonly" is disabled
- **Input**: `POST /agents/<agent-id>/credentials/request { "secret_type": "postgres-readonly" }`
- **Expected Output**: Status 403 or 400 ("Secret type is disabled")

### TC-NHI-CRED-048: Ephemeral credentials denied for suspended agent
- **Category**: Security
- **Input**: Suspended agent requests credentials
- **Expected Output**: Status 403 ("Agent suspended")

### TC-NHI-CRED-049: Denied credential requests are audited
- **Category**: Security
- **Standard**: SOC 2 CC7.2
- **Input**: Any denied credential request (permissions, rate limit, suspended)
- **Verification**: Audit log entry created with outcome=`denied` or `rate_limited`, error_code, source_ip

### TC-NHI-CRED-050: Ephemeral credentials denied for expired agent
- **Category**: Security
- **Input**: Agent past its `expires_at` date requests credentials
- **Expected Output**: Status 403 ("Agent expired")
