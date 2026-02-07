# Connector Configuration Functional Tests

**API Endpoints**:
- `POST /connectors` (create connector)
- `GET /connectors` (list connectors)
- `GET /connectors/:id` (get connector details)
- `PUT /connectors/:id` (update connector)
- `DELETE /connectors/:id` (delete connector)
- `POST /connectors/:id/test` (test connectivity)
- `POST /connectors/:id/activate` (activate connector)
- `POST /connectors/:id/deactivate` (deactivate connector)
- `GET /connectors/:id/health` (get connector health)
- `GET /connectors/:id/schema` (get discovered schema)
- `POST /connectors/:id/schema/discover` (discover remote schema)
- `GET /connectors/:id/mappings` (list attribute mappings)
- `POST /connectors/:id/mappings` (create attribute mapping)
- `PUT /connectors/:id/mappings/:mapping_id` (update mapping)
- `DELETE /connectors/:id/mappings/:mapping_id` (delete mapping)
**Authentication**: JWT (Bearer token) with admin role
**Applicable Standards**: Identity provisioning, SCIM 2.0, LDAP RFC 4510

---

## Prerequisites

> All fixtures referenced below are defined in [PREREQUISITES.md](../PREREQUISITES.md).

- **Fixtures Required**: `ADMIN_JWT`, `TEST_TENANT`
- **Special Setup**: Target connector systems (LDAP, Entra ID, REST, Database) must be simulated or available for connectivity tests

---

## Nominal Cases

### TC-CONN-CFG-001: Create LDAP connector
- **Category**: Nominal
- **Standard**: LDAP RFC 4510
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated admin
- **Input**:
  ```json
  POST /connectors
  {
    "name": "Corporate LDAP",
    "connector_type": "ldap",
    "config": {
      "host": "ldap.example.com",
      "port": 636,
      "use_ssl": true,
      "bind_dn": "cn=admin,dc=example,dc=com",
      "base_dn": "dc=example,dc=com"
    },
    "credentials": {
      "bind_password": "secret123"
    }
  }
  ```
- **Expected Output**:
  ```
  Status: 201 Created
  Body: {
    "id": "<uuid>",
    "name": "Corporate LDAP",
    "connector_type": "ldap",
    "status": "inactive",
    "created_at": "2026-02-07T..."
  }
  ```
- **Side Effects**: Credentials encrypted at rest, audit log: `connector.created`

### TC-CONN-CFG-002: Create Entra ID (Azure AD) connector
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated admin
- **Input**:
  ```json
  POST /connectors
  {
    "name": "Entra ID",
    "connector_type": "entra",
    "config": {
      "tenant_id": "<azure_tenant_id>",
      "client_id": "<app_client_id>",
      "directory_id": "<directory_id>"
    },
    "credentials": {
      "client_secret": "<secret>"
    }
  }
  ```
- **Expected Output**: Status 201, connector created with `status: "inactive"`

### TC-CONN-CFG-003: Create REST API connector
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated admin
- **Input**:
  ```json
  POST /connectors
  {
    "name": "HR System REST",
    "connector_type": "rest",
    "config": {
      "base_url": "https://hr.example.com/api/v1",
      "auth_type": "bearer"
    },
    "credentials": {
      "api_key": "hr_api_key_123"
    }
  }
  ```
- **Expected Output**: Status 201

### TC-CONN-CFG-004: Create database connector
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Authenticated admin
- **Input**:
  ```json
  POST /connectors
  {
    "name": "Legacy DB",
    "connector_type": "database",
    "config": {
      "db_type": "postgresql",
      "host": "db.example.com",
      "port": 5432,
      "database": "legacy_users"
    },
    "credentials": {
      "username": "readonly",
      "password": "dbpass"
    }
  }
  ```
- **Expected Output**: Status 201

### TC-CONN-CFG-005: List all connectors
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. 3 connectors exist (LDAP, Entra, REST)
- **Input**: `GET /connectors`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: {
    "connectors": [
      { "id": "...", "name": "Corporate LDAP", "connector_type": "ldap", "status": "active", ... },
      { "id": "...", "name": "Entra ID", "connector_type": "entra", "status": "inactive", ... },
      { "id": "...", "name": "HR System REST", "connector_type": "rest", "status": "active", ... }
    ]
  }
  ```
- **Verification**: Credentials are NOT included in list response

### TC-CONN-CFG-006: Get connector details
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Existing connector
- **Input**: `GET /connectors/:id`
- **Expected Output**: Status 200, full connector config (without credentials)

### TC-CONN-CFG-007: Update connector configuration
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Existing connector
- **Input**:
  ```json
  PUT /connectors/:id
  {
    "name": "Updated LDAP",
    "config": { "host": "ldap2.example.com", "port": 636, "use_ssl": true, "bind_dn": "cn=admin,dc=example,dc=com", "base_dn": "dc=example,dc=com" }
  }
  ```
- **Expected Output**: Status 200, connector updated
- **Side Effects**: Audit log: `connector.updated`

### TC-CONN-CFG-008: Delete connector
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Connector is deactivated
- **Input**: `DELETE /connectors/:id`
- **Expected Output**: Status 200, connector deleted
- **Side Effects**: Audit log: `connector.deleted`

### TC-CONN-CFG-009: Test connector connectivity
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. LDAP connector configured with valid credentials
- **Input**: `POST /connectors/:id/test`
- **Expected Output**:
  ```
  Status: 200 OK
  Body: { "success": true, "message": "Connection successful", "latency_ms": 45 }
  ```

### TC-CONN-CFG-010: Activate connector
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Connector exists with status "inactive"
- **Input**: `POST /connectors/:id/activate`
- **Expected Output**: Status 200, connector status changes to "active"

### TC-CONN-CFG-011: Deactivate connector
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Connector is active
- **Input**: `POST /connectors/:id/deactivate`
- **Expected Output**: Status 200, connector status changes to "inactive"

### TC-CONN-CFG-012: Discover schema from connector
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Active LDAP connector with reachable server
- **Input**: `POST /connectors/:id/schema/discover`
- **Expected Output**: Status 200, discovered object classes and attributes

### TC-CONN-CFG-013: Create attribute mapping
- **Category**: Nominal
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Active connector with discovered schema
- **Input**:
  ```json
  POST /connectors/:id/mappings
  {
    "source_attribute": "sAMAccountName",
    "target_attribute": "username",
    "direction": "inbound",
    "transformation": null
  }
  ```
- **Expected Output**: Status 201, mapping created

---

## Edge Cases

### TC-CONN-CFG-014: Create connector with missing required fields
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: `{ "name": "Incomplete" }` (no connector_type or config)
- **Expected Output**: Status 400 with validation errors

### TC-CONN-CFG-015: Create connector with invalid host
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: LDAP connector with `"host": "not a valid hostname!!!"`
- **Expected Output**: Status 400 "Invalid host"

### TC-CONN-CFG-016: Test connector with unreachable server
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Connector configured with unreachable host
- **Input**: `POST /connectors/:id/test` (server is down)
- **Expected Output**: Status 200 with `{ "success": false, "message": "Connection timed out" }`

### TC-CONN-CFG-017: Delete active connector
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Connector is active with pending sync operations
- **Input**: `DELETE /connectors/:id`
- **Expected Output**: Status 400 "Deactivate connector before deletion" OR Status 200 (cascade)

### TC-CONN-CFG-018: Update non-existent connector
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`
- **Input**: `PUT /connectors/00000000-0000-0000-0000-000000000099`
- **Expected Output**: Status 404 "Connector not found"

### TC-CONN-CFG-019: Create connector with duplicate name
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Connector with same name exists
- **Input**: Two connectors with name "LDAP Primary"
- **Expected Output**: Status 409 "Connector name already exists" OR allowed

### TC-CONN-CFG-020: Activate already active connector
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Connector is already active
- **Input**: `POST /connectors/:id/activate` on active connector
- **Expected Output**: Status 200 (idempotent) OR Status 400

### TC-CONN-CFG-021: Get connector health
- **Category**: Edge Case
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Existing connector
- **Input**: `GET /connectors/:id/health`
- **Expected Output**: Status 200 with health metrics (last check, status, error count)

---

## Security Cases

### TC-CONN-CFG-022: Credentials not returned in GET responses
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Connector with credentials exists
- **Input**: `GET /connectors/:id`
- **Expected Output**: Response does NOT contain `bind_password`, `client_secret`, `api_key`, or any credential values

### TC-CONN-CFG-023: Credentials encrypted at rest
- **Category**: Security
- **Standard**: OWASP ASVS 6.4.1
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Connector with credentials exists
- **Verification**: `credentials_encrypted` column in database is AES-256-GCM encrypted, not plaintext

### TC-CONN-CFG-024: Cross-tenant connector isolation
- **Category**: Security
- **Preconditions**: Fixtures: `ADMIN_JWT`, `TEST_TENANT`. Tenant A has connector C1
- **Input**: Admin of tenant B calls `GET /connectors/:c1_id`
- **Expected Output**: Status 404 (not visible to other tenants)

### TC-CONN-CFG-025: Non-admin cannot manage connectors
- **Category**: Security
- **Preconditions**: Fixtures: `TEST_TENANT`. Authenticated as regular (non-admin) user
- **Input**: Regular user calls `POST /connectors`
- **Expected Output**: Status 403 Forbidden
