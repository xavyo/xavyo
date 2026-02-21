---
title: Tenant Setup & Management
description: Complete guide to creating, configuring, and managing tenants in xavyo-idp, including settings, OAuth clients, API keys, and lifecycle operations.
sidebar_position: 1
---

# Tenant Setup & Management

## Overview

xavyo-idp is a multi-tenant identity platform where each tenant operates as an isolated organizational unit with its own users, groups, policies, and configurations. Every API request is scoped to a tenant via the `X-Tenant-ID` header, ensuring strict data isolation enforced at both the application and database level through PostgreSQL Row-Level Security (RLS).

This guide covers the full tenant lifecycle: provisioning, configuration, API key management, OAuth client setup, and operational tasks.

## Provisioning a Tenant

To create a new tenant, send a POST request to the provisioning endpoint. This is typically performed by a platform operator or super administrator.

```bash
curl -X POST https://your-domain.com/tenants/provision \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{
    "name": "Acme Corporation",
    "slug": "acme-corp",
    "plan": "enterprise",
    "settings": {
      "session_timeout_minutes": 60,
      "max_sessions_per_user": 5
    }
  }'
```

**Response (201 Created):**
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "name": "Acme Corporation",
  "slug": "acme-corp",
  "plan": "enterprise",
  "is_active": true,
  "created_at": "2026-02-07T12:00:00Z"
}
```

The returned `id` is a UUID that must be included as the `X-Tenant-ID` header in all subsequent API calls scoped to this tenant.

## Tenant Settings

Tenant settings control security policies, session behavior, and platform features. Retrieve and update settings through the admin API.

### Retrieving Settings

```bash
curl https://your-domain.com/admin/tenants/{tenant_id}/settings \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Updating Settings

```bash
curl -X PUT https://your-domain.com/admin/tenants/{tenant_id}/settings \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "session_timeout_minutes": 30,
    "max_sessions_per_user": 3,
    "require_mfa": true,
    "password_policy": {
      "min_length": 12,
      "require_uppercase": true,
      "require_lowercase": true,
      "require_numbers": true,
      "require_special_chars": true,
      "password_history_count": 5,
      "max_age_days": 90
    },
    "lockout_policy": {
      "max_attempts": 5,
      "lockout_duration_minutes": 15,
      "reset_after_minutes": 60
    }
  }'
```

### Key Settings Reference

| Setting | Type | Description |
|---------|------|-------------|
| `session_timeout_minutes` | integer | Idle session timeout |
| `max_sessions_per_user` | integer | Maximum concurrent sessions |
| `require_mfa` | boolean | Enforce MFA for all users |
| `password_policy` | object | Password complexity requirements |
| `lockout_policy` | object | Account lockout rules |
| `allowed_domains` | string[] | Restrict signup to specific email domains |

## OAuth Client Management

Each tenant can have multiple OAuth 2.0 clients for machine-to-machine communication, single-page applications, and server-side integrations.

### Creating a Confidential Client

Confidential clients (server-side applications) receive a `client_secret` that must be stored securely.

```bash
curl -X POST https://your-domain.com/admin/oauth/clients \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Backend API Service",
    "client_type": "confidential",
    "redirect_uris": [],
    "grant_types": ["client_credentials"],
    "scopes": ["read", "write", "admin"]
  }'
```

**Response (200):**
```json
{
  "id": "uuid-of-client-record",
  "client_id": "generated-client-id",
  "client_secret": "generated-secret-shown-only-once",
  "name": "Backend API Service",
  "client_type": "confidential",
  "grant_types": ["client_credentials"],
  "scopes": ["read", "write", "admin"],
  "is_active": true
}
```

:::warning
The `client_secret` is returned only once at creation time. Store it immediately in a secure vault. Subsequent GET requests will not include the secret.
:::

### Creating a Public Client

Public clients (SPAs, mobile apps) do not receive a secret and must use PKCE for authorization code flows.

```bash
curl -X POST https://your-domain.com/admin/oauth/clients \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Frontend SPA",
    "client_type": "public",
    "redirect_uris": ["https://app.example.com/callback"],
    "grant_types": ["authorization_code"],
    "scopes": ["openid", "profile", "email"]
  }'
```

### Managing Clients

| Operation | Method | Endpoint |
|-----------|--------|----------|
| List all clients | GET | `/admin/oauth/clients` |
| Get client by ID | GET | `/admin/oauth/clients/{id}` |
| Update client | PUT | `/admin/oauth/clients/{id}` |
| Delete (deactivate) | DELETE | `/admin/oauth/clients/{id}` |
| Regenerate secret | POST | `/admin/oauth/clients/{id}/regenerate-secret` |

### Obtaining Tokens via Client Credentials

Once a confidential client is created, obtain access tokens using the client credentials grant:

```bash
curl -X POST https://your-domain.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=client_credentials&scope=read write"
```

**Response:**
```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "read write"
}
```

### Token Introspection

Validate a token and retrieve its metadata:

```bash
curl -X POST https://your-domain.com/oauth/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "token=$ACCESS_TOKEN"
```

**Response:**
```json
{
  "active": true,
  "sub": "client-uuid",
  "scope": "read write",
  "iss": "https://your-domain.com",
  "tid": "tenant-uuid",
  "exp": 1707350400
}
```

### Token Revocation

Revoke a token per RFC 7009:

```bash
curl -X POST https://your-domain.com/oauth/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "token=$ACCESS_TOKEN"
```

Revocation is always idempotent and returns `200 OK` even for unknown or already-revoked tokens, as required by RFC 7009.

### Regenerating a Client Secret

When a secret is compromised, regenerate it immediately. The old secret becomes invalid as soon as the new one is issued.

```bash
curl -X POST https://your-domain.com/admin/oauth/clients/{id}/regenerate-secret \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

## API Key Management

API keys provide a simpler authentication mechanism for integrations that do not require the full OAuth 2.0 flow.

### Creating an API Key

```bash
curl -X POST https://your-domain.com/admin/api-keys \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "CI/CD Pipeline Key",
    "scopes": ["read", "write"],
    "expires_at": "2027-01-01T00:00:00Z"
  }'
```

**Response:**
```json
{
  "id": "key-uuid",
  "name": "CI/CD Pipeline Key",
  "key": "xavyo_ak_...",
  "scopes": ["read", "write"],
  "expires_at": "2027-01-01T00:00:00Z",
  "created_at": "2026-02-07T12:00:00Z"
}
```

:::warning
The raw API key value is returned only once. Store it securely.
:::

### API Key Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create key | POST | `/admin/api-keys` |
| List keys | GET | `/admin/api-keys` |
| Get key details | GET | `/admin/api-keys/{id}` |
| Delete key | DELETE | `/admin/api-keys/{id}` |
| Introspect key | POST | `/admin/api-keys/introspect` |
| Usage statistics | GET | `/admin/api-keys/{id}/usage` |

## Tenant Lifecycle Operations

### Suspending a Tenant

Suspending a tenant prevents all authentication and API access for that tenant's users while preserving data.

```bash
curl -X POST https://your-domain.com/system/tenants/{tenant_id}/suspend \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $SYSTEM_TENANT_ID"
```

### Reactivating a Tenant

```bash
curl -X POST https://your-domain.com/system/tenants/{tenant_id}/reactivate \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $SYSTEM_TENANT_ID"
```

### WebAuthn Policy

Configure WebAuthn/FIDO2 settings per tenant:

```bash
curl -X PUT https://your-domain.com/admin/tenants/{tenant_id}/webauthn-policy \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "enabled": true,
    "attestation_preference": "direct",
    "user_verification": "required",
    "resident_key": "preferred"
  }'
```

## Invitations

Invite users to join a tenant with pre-assigned roles:

```bash
curl -X POST https://your-domain.com/admin/invitations \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "email": "new.user@example.com",
    "roles": ["user", "editor"],
    "message": "Welcome to Acme Corp!"
  }'
```

Invitees receive an email with a link to complete registration. Manage invitations with these endpoints:

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create invitation | POST | `/admin/invitations` |
| List invitations | GET | `/admin/invitations` |
| Get invitation | GET | `/admin/invitations/{id}` |
| Resend invitation | POST | `/admin/invitations/{id}/resend` |
| Bulk resend | POST | `/admin/invitations/bulk-resend` |
| Accept (public) | POST | `/invite/{token}` |

## Security Considerations

- **Tenant isolation** is enforced at the database level through PostgreSQL RLS. Every query includes a `tenant_id` filter, preventing cross-tenant data access even in the event of application-level bugs.
- **System tenant** (`00000000-0000-0000-0000-000000000001`) is reserved for platform operations. Never use it for regular user workloads.
- **OAuth client secrets** are hashed before storage. The plaintext secret is available only at creation and regeneration time.
- **API keys** include SQL-level expiry filtering as defense-in-depth, so expired keys are rejected even if the application cache is stale.
- **Rate limiting** applies to authentication endpoints (5 attempts per 60 seconds for login) to prevent brute-force attacks.
- **Cross-tenant client usage** is prevented: clients can only be used within the tenant in which they were created.

## Related

- [Authentication Configuration](./authentication.md) -- Password policies, MFA, and federation setup
- [User Management](./user-management.md) -- Creating and managing users within a tenant
- [Security Hardening](./security-hardening.md) -- IP restrictions, key rotation, and audit logging
