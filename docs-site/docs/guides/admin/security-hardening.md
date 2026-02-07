---
title: Security Hardening
description: Guide to IP restrictions, branding and email templates, key management, audit logging, session security, webhook security, and defense-in-depth practices in xavyo-idp.
sidebar_position: 7
---

# Security Hardening

## Overview

xavyo-idp is built with security as a foundational principle. This guide covers the administrative features available for hardening your deployment: IP access restrictions, branding and email template customization, cryptographic key management, audit logging, session security controls, and webhook delivery security.

All security management endpoints require the `admin` role, and several sensitive operations require the `super_admin` role.

## IP Restrictions

Control which IP addresses can access your tenant's APIs. IP restrictions support both whitelist (allow only specified IPs) and blacklist (deny specified IPs) modes.

### Configuring IP Settings

```bash
# Get current IP restriction settings
curl https://your-domain.com/admin/ip-restrictions/settings \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Enable whitelist mode
curl -X PUT https://your-domain.com/admin/ip-restrictions/settings \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "enforcement_mode": "whitelist",
    "bypass_for_super_admin": true
  }'
```

### Enforcement Modes

| Mode | Behavior |
|------|----------|
| `disabled` | No IP restrictions applied |
| `whitelist` | Only IPs matching whitelist rules are allowed |
| `blacklist` | IPs matching blacklist rules are denied |

### Managing IP Rules

```bash
# Create a whitelist rule
curl -X POST https://your-domain.com/admin/ip-restrictions/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "rule_type": "whitelist",
    "scope": "all",
    "ip_cidr": "10.0.0.0/8",
    "name": "Internal Network",
    "description": "Allow all internal IPs",
    "is_active": true
  }'

# Create a blacklist rule
curl -X POST https://your-domain.com/admin/ip-restrictions/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "rule_type": "blacklist",
    "scope": "all",
    "ip_cidr": "203.0.113.0/24",
    "name": "Blocked Network",
    "is_active": true
  }'

# Validate an IP against current rules
curl -X POST https://your-domain.com/admin/ip-restrictions/validate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "ip_address": "10.0.0.1",
    "role": "admin"
  }'
```

:::warning
When enabling whitelist mode, ensure your own IP is included in an active whitelist rule. Otherwise, you may lock yourself out. The `bypass_for_super_admin` flag provides a safety net.
:::

### IP Restriction Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Get settings | GET | `/admin/ip-restrictions/settings` |
| Update settings | PUT | `/admin/ip-restrictions/settings` |
| List rules | GET | `/admin/ip-restrictions/rules` |
| Create rule | POST | `/admin/ip-restrictions/rules` |
| Get rule | GET | `/admin/ip-restrictions/rules/{id}` |
| Update rule | PUT | `/admin/ip-restrictions/rules/{id}` |
| Delete rule | DELETE | `/admin/ip-restrictions/rules/{id}` |
| Validate IP | POST | `/admin/ip-restrictions/validate` |

## Branding & Email Templates

Customize the look and feel of authentication pages and transactional emails sent by xavyo-idp.

:::warning
Branding and email template endpoints require the `super_admin` role, not just `admin`.
:::

### Branding Configuration

```bash
# Get current branding
curl https://your-domain.com/admin/branding \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Update branding
curl -X PUT https://your-domain.com/admin/branding \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "primary_color": "#3366FF",
    "secondary_color": "#FF6633",
    "login_page_title": "Acme Corp Sign In",
    "privacy_policy_url": "https://acme.com/privacy",
    "terms_of_service_url": "https://acme.com/tos",
    "support_url": "https://acme.com/support"
  }'
```

### Branding Assets

Upload logos and other visual assets:

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Get branding | GET | `/admin/branding` |
| Update branding | PUT | `/admin/branding` |
| List assets | GET | `/admin/branding/assets` |
| Get asset | GET | `/admin/branding/assets/{id}` |
| Upload asset | POST | `/admin/branding/assets` |
| Delete asset | DELETE | `/admin/branding/assets/{id}` |

### Email Templates

Customize transactional email content using Handlebars templates. xavyo-idp supports the following template types:

| Template Type | Trigger |
|--------------|---------|
| `welcome` | New user registration |
| `password_reset` | Password reset request |
| `email_verification` | Email address verification |
| `mfa_setup` | MFA enrollment notification |
| `security_alert` | Security-related notifications |
| `account_locked` | Account lockout notification |

```bash
# List all email templates
curl https://your-domain.com/admin/branding/email-templates \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Get a specific template
curl https://your-domain.com/admin/branding/email-templates/welcome \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Update a template
curl -X PUT https://your-domain.com/admin/branding/email-templates/welcome \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "subject": "Welcome to {{tenant_name}}!",
    "body_html": "<h1>Welcome, {{user_name}}!</h1><p>Your account is ready.</p>",
    "body_text": "Welcome, {{user_name}}! Your account is ready.",
    "is_active": true
  }'

# Preview a template with sample data
curl -X POST https://your-domain.com/admin/branding/email-templates/welcome/preview \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "sample_data": {
      "user_name": "Jane Doe",
      "tenant_name": "Acme Corp"
    }
  }'

# Reset a template to the system default
curl -X POST https://your-domain.com/admin/branding/email-templates/welcome/reset \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Email Template Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| List templates | GET | `/admin/branding/email-templates` |
| Get template | GET | `/admin/branding/email-templates/{type}` |
| Update template | PUT | `/admin/branding/email-templates/{type}` |
| Preview template | POST | `/admin/branding/email-templates/{type}/preview` |
| Reset template | POST | `/admin/branding/email-templates/{type}/reset` |

## Key Management

Manage the cryptographic keys used for JWT signing and token verification. Key rotation is essential for maintaining security over time.

### Listing Keys

```bash
curl https://your-domain.com/admin/keys \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Rotating Keys

Key rotation generates a new signing key and marks the previous key as inactive. Existing tokens signed with the old key remain valid until they expire.

```bash
curl -X POST https://your-domain.com/admin/keys/rotate \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

**Response:**
```json
{
  "kid": "new-key-id",
  "algorithm": "RS256",
  "created_at": "2026-02-07T12:00:00Z",
  "status": "active"
}
```

### Revoking Keys

```bash
curl -X DELETE https://your-domain.com/admin/keys/{kid} \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

:::warning
Revoking a key immediately invalidates all tokens signed with that key. Users will need to re-authenticate.
:::

### Key Management Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| List keys | GET | `/admin/keys` |
| Rotate key | POST | `/admin/keys/rotate` |
| Revoke key | DELETE | `/admin/keys/{kid}` |

### JWKS Endpoint

The public keys are published at the standard JWKS endpoint for token verification by relying parties:

```
GET /.well-known/jwks.json
```

## Audit Logging

xavyo-idp maintains a comprehensive audit trail of all administrative and security-relevant actions.

### Viewing Audit Logs

```bash
# List recent audit events
curl "https://your-domain.com/admin/audit-logs?limit=50&offset=0" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Filter by resource type
curl "https://your-domain.com/admin/audit-logs?resource_type=user&action=create&limit=20" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Audit Event Types

All mutation operations are recorded, including:

- User create, update, delete, and role changes
- OAuth client management
- SCIM token operations
- SAML and OIDC provider configuration
- Key rotation and revocation
- IP restriction changes
- Branding and email template updates
- Delegation assignment and revocation
- Governance decisions (certify, revoke, approve, reject)
- NHI agent and credential management

### Security Alerts

Configure alerts for suspicious activity patterns:

```bash
# List security alerts
curl https://your-domain.com/admin/security-alerts \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

## Organization Security Policies

Define organization-wide security policies that govern authentication behavior:

```bash
# Get current security policies
curl https://your-domain.com/organizations/{org_id}/security-policies \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Update security policies
curl -X PUT https://your-domain.com/organizations/{org_id}/security-policies \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "require_mfa": true,
    "allowed_auth_methods": ["password", "webauthn", "magic_link"],
    "session_timeout_minutes": 30,
    "max_sessions_per_user": 3
  }'
```

## Session Security

### Session Management

xavyo-idp implements several session security measures:

- **Session isolation**: All session queries include `tenant_id` to prevent cross-tenant session hijacking
- **Concurrent session limits**: Configurable maximum sessions per user (oldest session revoked when limit exceeded)
- **Activity tracking**: Sessions record last activity timestamps for idle timeout enforcement
- **Cache-Control headers**: All responses include `no-store, no-cache, must-revalidate, private` headers

### Device Management

Users can view and manage their registered devices:

```bash
# List my devices
curl https://your-domain.com/me/devices \
  -H "Authorization: Bearer $USER_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Revoke a device
curl -X DELETE https://your-domain.com/me/devices/{device_id} \
  -H "Authorization: Bearer $USER_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

## Defense-in-Depth Practices

xavyo-idp employs multiple layers of security controls:

### Input Validation
- All request types use the `Validate` trait for input validation
- Pagination limits are clamped to a maximum of 100 items per page
- Pagination offsets are clamped to non-negative values
- Integer arithmetic uses `saturating_add()` to prevent overflow

### Cryptographic Security
- **Token generation**: All security tokens (password reset, email verification, MFA codes) use CSPRNG via `OsRng`
- **Password hashing**: Argon2id with configurable parameters
- **Encryption**: AES-256-GCM for sensitive data at rest
- **Key derivation**: Constant-time comparison for all secret validation

### Database Security
- **Row-Level Security**: All tenant data is isolated through PostgreSQL RLS policies
- **Parameterized queries**: All SQL uses parameterized queries via SQLx (compile-time verified)
- **Connection pool limits**: `idle_timeout(600s)` and `max_lifetime(1800s)` on database connections

### HTTP Security
- **CORS**: Configurable origin restrictions
- **Security headers**: `Cache-Control`, `X-Content-Type-Options`, `X-Frame-Options`, `Strict-Transport-Security`
- **Rate limiting**: 5 login attempts per 60 seconds per IP/email combination
- **HTTP client timeouts**: 10-second timeout on all outbound HTTP requests
- **SSRF protection**: URL validation against private IP ranges for webhook and connector endpoints

### Error Handling
- **No sensitive data in errors**: All error responses are sanitized to prevent information leakage
- **Login enumeration prevention**: Invalid credentials and inactive accounts return the same generic error
- **Lock poisoning safety**: All mutex `.unwrap()` calls use `.unwrap_or_else(|e| e.into_inner())` pattern

### Serialization Security
- **Secret field protection**: All hash, key, and secret fields use `#[serde(skip_serializing)]` to prevent accidental exposure in API responses
- **CSV injection protection**: Import files sanitize cells starting with `=`, `+`, `-`, `@`

## License Management

Manage tenant license entitlements:

```bash
# Get license status
curl https://your-domain.com/governance/licenses/status \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# List license allocations
curl https://your-domain.com/governance/licenses/allocations \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

## Security Considerations

- **Super admin separation**: Branding, delegation, and certain sensitive operations require `super_admin` rather than `admin` to enforce separation of duties between operational and security administration.
- **Key rotation cadence**: Rotate signing keys regularly (recommended: every 90 days). The JWKS endpoint automatically publishes both old and new keys during transition.
- **IP restriction testing**: Always validate your IP rules before switching to whitelist mode. Use the `/admin/ip-restrictions/validate` endpoint to verify.
- **Email template validation**: Template preview uses sample data to verify Handlebars syntax. Always preview templates before activating them.
- **Audit log retention**: Audit logs are tenant-isolated and should be exported to a SIEM system for long-term retention and correlation.

## Related

- [Authentication](./authentication.md) -- Password policies, MFA, and session management
- [Authorization](./authorization.md) -- Role-based access control and delegation
- [Tenant Setup](./tenant-setup.md) -- Tenant-level security configuration
- [Governance](./governance.md) -- Compliance monitoring and certification campaigns
