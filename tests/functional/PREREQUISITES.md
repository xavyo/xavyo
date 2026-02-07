# Global Test Prerequisites & Shared Fixtures

This document defines everything needed before running any functional test in the suite.
Every test file references fixtures defined here by their **Fixture ID** (e.g., `ADMIN_JWT`).

> **See also**: Individual test files may define additional domain-specific prerequisites in their `## Prerequisites` section.

---

## Environment Setup

Before running any test, ensure the following environment is ready:

### Running Services

| Service | URL / Connection | Notes |
|---------|-----------------|-------|
| **xavyo API** | `http://localhost:8080` | Main IDP API server |
| **PostgreSQL 15+** | `DATABASE_URL` env var | All migrations applied (`sqlx migrate run`) |

### Required Environment Variables

| Variable | Example | Purpose |
|----------|---------|---------|
| `DATABASE_URL` | `postgres://xavyo:password@localhost/xavyo_test` | Database connection |
| `JWT_PRIVATE_KEY_1` | *(RSA PEM)* | JWT token signing |
| `JWT_PUBLIC_KEY_1` | *(RSA PEM)* | JWT token verification |
| `ISSUER_URL` | `http://localhost:8080` | JWT `iss` claim |
| `FRONTEND_BASE_URL` | `http://localhost:3000` | Email verification links |
| `ENCRYPTION_KEY` | *(32-byte hex)* | Credential encryption at rest |

### Optional Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `EMAIL_SMTP_HOST` | *(unset)* | If unset, `MockEmailSender` is active (emails logged, not sent) |
| `EMAIL_SMTP_PORT` | `587` | SMTP port |
| `EMAIL_FROM` | `noreply@xavyo.io` | Sender address |

---

## Shared Fixtures

These fixtures are referenced by **Fixture ID** in individual test cases.
Create them in the order listed — later fixtures depend on earlier ones.

### Tenant & User Fixtures

| Fixture ID | Description | How to Create | Key Fields |
|------------|-------------|---------------|------------|
| `SYS_TENANT` | System tenant (pre-exists after DB bootstrap) | Automatic — exists after migrations | `id: 00000000-0000-0000-0000-000000000001` |
| `TEST_TENANT` | Isolated test tenant | `POST /tenants/provision` | `id: <uuid>`, `name: "Test Tenant"` |
| `ADMIN_USER` | Admin user with `admin` role in `TEST_TENANT` | `POST /admin/users` + `POST /admin/roles/assign` | `email: admin@test-tenant.example.com` |
| `ADMIN_JWT` | JWT bearer token for `ADMIN_USER` | `POST /auth/login` (after email verification) | Claims: `sub=<user_id>`, `tid=<tenant_id>`, `roles=["admin"]` |
| `REGULAR_USER` | Non-admin user in `TEST_TENANT` | `POST /auth/signup` + email verification | `email: user@test-tenant.example.com` |
| `USER_JWT` | JWT bearer token for `REGULAR_USER` | `POST /auth/login` | Claims: `sub=<user_id>`, `tid=<tenant_id>`, `roles=["user"]` |

### Protocol Fixtures

| Fixture ID | Description | How to Create | Key Fields |
|------------|-------------|---------------|------------|
| `OAUTH_CC_CLIENT` | Confidential OAuth client with `client_credentials` grant | `POST /admin/oauth/clients` with `ADMIN_JWT` | `client_id`, `client_secret`, `grant_types: ["client_credentials"]` |
| `SCIM_TOKEN` | SCIM bearer token for `TEST_TENANT` | `POST /admin/scim/tokens` with `ADMIN_JWT` | `token: <scim-bearer-token>` |
| `SAML_SP` | SAML Service Provider configuration | `POST /admin/saml/service-providers` with `ADMIN_JWT` | `entity_id`, `acs_url`, `metadata_url` |
| `SOCIAL_GOOGLE` | Google social provider configured | `PUT /admin/social-providers/google` with `ADMIN_JWT` | `client_id`, `client_secret`, `enabled: true` |

### Infrastructure Fixtures

| Fixture ID | Description | How to Create | Key Fields |
|------------|-------------|---------------|------------|
| `WEBHOOK_SUB` | Webhook subscription | `POST /webhooks/subscriptions` with `ADMIN_JWT` | `id`, `url`, `events`, `secret` |
| `TEST_CONNECTOR` | Provisioning connector | `POST /connectors` with `ADMIN_JWT` | `id`, `name`, `connector_type`, `status` |
| `TEST_AGENT` | NHI agent entity | `POST /nhi/agents` with `ADMIN_JWT` | `id`, `name`, `agent_type`, `status: "active"` |
| `TEST_SA` | NHI service account | `POST /nhi/service-accounts` with `ADMIN_JWT` | `id`, `name`, `status: "active"` |

---

## Fixture Creation Payloads

### `TEST_TENANT`

```json
POST /tenants/provision
{
  "name": "Test Tenant",
  "slug": "test-tenant",
  "admin_email": "admin@test-tenant.example.com",
  "admin_password": "MyP@ssw0rd_2026"
}
```

### `ADMIN_USER` (if not created by tenant provisioning)

```json
POST /admin/users
Authorization: Bearer <ADMIN_JWT>
X-Tenant-ID: <TEST_TENANT.id>
{
  "email": "admin@test-tenant.example.com",
  "password": "MyP@ssw0rd_2026",
  "display_name": "Test Admin",
  "email_verified": true
}
```

Role assignment:
```json
POST /admin/roles/assign
Authorization: Bearer <ADMIN_JWT>
{
  "user_id": "<ADMIN_USER.id>",
  "role_name": "admin"
}
```

### `ADMIN_JWT`

```json
POST /auth/login
{
  "email": "admin@test-tenant.example.com",
  "password": "MyP@ssw0rd_2026"
}
→ Response: { "access_token": "<ADMIN_JWT>", ... }
```

### `REGULAR_USER`

```json
POST /auth/signup
{
  "email": "user@test-tenant.example.com",
  "password": "MyP@ssw0rd_2026",
  "display_name": "Regular User"
}
```
Then verify email (via MockEmailSender log or verification endpoint).

### `USER_JWT`

```json
POST /auth/login
{
  "email": "user@test-tenant.example.com",
  "password": "MyP@ssw0rd_2026"
}
→ Response: { "access_token": "<USER_JWT>", ... }
```

### `OAUTH_CC_CLIENT`

```json
POST /admin/oauth/clients
Authorization: Bearer <ADMIN_JWT>
X-Tenant-ID: <TEST_TENANT.id>
{
  "name": "Test CC Client",
  "grant_types": ["client_credentials"],
  "scopes": ["read", "write"],
  "token_endpoint_auth_method": "client_secret_basic"
}
→ Response: { "client_id": "...", "client_secret": "...", ... }
```

### `SCIM_TOKEN`

```json
POST /admin/scim/tokens
Authorization: Bearer <ADMIN_JWT>
X-Tenant-ID: <TEST_TENANT.id>
{
  "description": "Test SCIM token"
}
→ Response: { "token": "<SCIM_TOKEN>", ... }
```

### `SAML_SP`

```json
POST /admin/saml/service-providers
Authorization: Bearer <ADMIN_JWT>
X-Tenant-ID: <TEST_TENANT.id>
{
  "name": "Test SP",
  "entity_id": "https://sp.example.com/saml/metadata",
  "acs_url": "https://sp.example.com/saml/acs",
  "slo_url": "https://sp.example.com/saml/slo"
}
→ Response: { "id": "...", "entity_id": "...", ... }
```

### `WEBHOOK_SUB`

```json
POST /webhooks/subscriptions
Authorization: Bearer <ADMIN_JWT>
X-Tenant-ID: <TEST_TENANT.id>
{
  "url": "https://webhook.example.com/events",
  "events": ["user.created", "user.updated", "user.deleted"],
  "secret": "whsec_test_secret_key_32chars_min"
}
→ Response: { "id": "...", "url": "...", ... }
```

### `TEST_CONNECTOR`

```json
POST /connectors
Authorization: Bearer <ADMIN_JWT>
X-Tenant-ID: <TEST_TENANT.id>
{
  "name": "Test LDAP Connector",
  "connector_type": "ldap",
  "config": {
    "host": "ldap.example.com",
    "port": 636,
    "use_ssl": true,
    "bind_dn": "cn=admin,dc=example,dc=com",
    "base_dn": "dc=example,dc=com"
  },
  "credentials": {
    "bind_password": "test_password"
  }
}
→ Response: { "id": "...", "status": "inactive", ... }
```

### `TEST_AGENT`

```json
POST /nhi/agents
Authorization: Bearer <ADMIN_JWT>
X-Tenant-ID: <TEST_TENANT.id>
{
  "name": "test-agent",
  "agent_type": "copilot",
  "description": "Test agent for functional tests",
  "risk_level": "medium"
}
→ Response: { "id": "...", "status": "active", ... }
```

### `TEST_SA`

```json
POST /nhi/service-accounts
Authorization: Bearer <ADMIN_JWT>
X-Tenant-ID: <TEST_TENANT.id>
{
  "name": "test-service-account",
  "description": "Test service account for functional tests"
}
→ Response: { "id": "...", "status": "active", ... }
```

---

## Authentication Reference

### Password Requirements

- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character (`@`, `!`, `#`, `$`, `%`, etc.)
- Standard test password: `MyP@ssw0rd_2026`

### JWT Claims Structure

```json
{
  "sub": "<user_id (UUID)>",
  "tid": "<tenant_id (UUID)>",
  "email": "<user email>",
  "roles": ["admin"],
  "iat": 1707300000,
  "exp": 1707303600,
  "iss": "http://localhost:8080"
}
```

### Common Headers

| Header | Value | When Required |
|--------|-------|---------------|
| `Authorization` | `Bearer <jwt>` | All authenticated endpoints |
| `X-Tenant-ID` | `<tenant_id UUID>` | Most endpoints (tenant context) |
| `Content-Type` | `application/json` | All POST/PUT/PATCH requests |

### Rate Limiting

- Login: 5 attempts per 60 seconds per email
- Signup: Standard rate limiting applies
- API: Per-tenant rate limits

---

## Fixture Dependency Graph

```
SYS_TENANT (pre-exists)
│
└── TEST_TENANT
    ├── ADMIN_USER → ADMIN_JWT
    │   ├── OAUTH_CC_CLIENT
    │   ├── SCIM_TOKEN
    │   ├── SAML_SP
    │   ├── SOCIAL_GOOGLE
    │   ├── WEBHOOK_SUB
    │   ├── TEST_CONNECTOR
    │   ├── TEST_AGENT
    │   └── TEST_SA
    │
    └── REGULAR_USER → USER_JWT
```
