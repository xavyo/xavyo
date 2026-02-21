---
title: Authentication Configuration
description: Guide to configuring authentication in xavyo-idp including password policies, MFA, social login, SAML, OIDC federation, passwordless authentication, and device management.
sidebar_position: 3
---

# Authentication Configuration

## Overview

xavyo-idp supports a comprehensive range of authentication methods: traditional email/password with configurable policies, multi-factor authentication (TOTP and WebAuthn/FIDO2), social login providers (Google, Microsoft, GitHub, Apple), SAML 2.0 identity provider integration, OpenID Connect federation, and passwordless authentication via magic links and email OTPs.

All authentication behavior is configurable per tenant, allowing each organization to enforce its own security posture.

## Password-Based Authentication

### User Registration

Users register through the public signup endpoint:

```bash
curl -X POST https://your-domain.com/auth/signup \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "email": "user@example.com",
    "password": "SecureP@ssw0rd!",
    "display_name": "New User"
  }'
```

**Response (201 Created):**
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "email_verified": false,
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

After signup, a verification email is sent automatically. Users must verify their email before they can log in.

### Email Verification

```bash
curl -X POST https://your-domain.com/auth/verify-email \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"token": "verification-token-from-email"}'
```

To resend the verification email:

```bash
curl -X POST https://your-domain.com/auth/resend-verification \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"email": "user@example.com"}'
```

### Login

```bash
curl -X POST https://your-domain.com/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "email": "user@example.com",
    "password": "SecureP@ssw0rd!"
  }'
```

**Response (200):**
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

The JWT `access_token` contains claims: `sub` (user ID), `tid` (tenant ID), `roles` (role names), `email`, and standard JWT fields (`iss`, `exp`, `iat`, `jti`).

### Token Refresh

```bash
curl -X POST https://your-domain.com/auth/refresh \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"refresh_token": "eyJ..."}'
```

### Password Reset Flow

1. **Request reset**: User submits their email address
2. **Email sent**: A password reset link is sent via email
3. **Reset password**: User submits the token with a new password

```bash
# Step 1: Request reset
curl -X POST https://your-domain.com/auth/forgot-password \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"email": "user@example.com"}'

# Step 3: Reset with token from email
curl -X POST https://your-domain.com/auth/reset-password \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "token": "reset-token-from-email",
    "new_password": "NewSecureP@ssw0rd!"
  }'
```

### Password Change (Authenticated)

```bash
curl -X POST https://your-domain.com/auth/password \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "current_password": "OldP@ssw0rd!",
    "new_password": "NewP@ssw0rd!"
  }'
```

### Password Policy Configuration

Configure password requirements through tenant settings:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `min_length` | Minimum password length | 8 |
| `require_uppercase` | At least one uppercase letter | true |
| `require_lowercase` | At least one lowercase letter | true |
| `require_numbers` | At least one digit | true |
| `require_special_chars` | At least one special character | true |
| `password_history_count` | Number of previous passwords to check | 5 |
| `max_age_days` | Force password change after N days | 90 |

### Account Lockout Policy

| Parameter | Description | Default |
|-----------|-------------|---------|
| `max_attempts` | Failed attempts before lockout | 5 |
| `lockout_duration_minutes` | Duration of lockout | 15 |
| `reset_after_minutes` | Reset attempt counter after inactivity | 60 |

:::info
Rate limiting enforces a maximum of 5 login attempts per 60 seconds per IP/email combination at the API level, independent of the account lockout policy.
:::

## Multi-Factor Authentication (MFA)

### TOTP Setup

Users enroll in TOTP-based MFA through a two-step process:

```bash
# Step 1: Enable MFA and get provisioning URI
curl -X POST https://your-domain.com/auth/mfa/setup \
  -H "Authorization: Bearer $USER_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

**Response:**
```json
{
  "secret": "BASE32-ENCODED-SECRET",
  "provisioning_uri": "otpauth://totp/xavyo:user@example.com?secret=...",
  "qr_code_url": "data:image/png;base64,..."
}
```

```bash
# Step 2: Verify with code from authenticator app
curl -X POST https://your-domain.com/auth/mfa/verify \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"code": "123456"}'
```

### WebAuthn / FIDO2

Register hardware security keys or platform authenticators:

```bash
# Step 1: Start registration
curl -X POST https://your-domain.com/auth/mfa/webauthn/register/start \
  -H "Authorization: Bearer $USER_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Step 2: Complete registration (send attestation from browser)
curl -X POST https://your-domain.com/auth/mfa/webauthn/register/finish \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{ ... attestation response ... }'
```

### WebAuthn Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Start registration | POST | `/auth/mfa/webauthn/register/start` |
| Finish registration | POST | `/auth/mfa/webauthn/register/finish` |
| Start authentication | POST | `/auth/mfa/webauthn/authenticate/start` |
| Finish authentication | POST | `/auth/mfa/webauthn/authenticate/finish` |
| List credentials | GET | `/auth/mfa/webauthn/credentials` |
| Delete credential | DELETE | `/auth/mfa/webauthn/credentials/{id}` |

### Tenant MFA Policy

When a tenant requires MFA (`require_mfa: true` in settings), users cannot disable their MFA enrollment. Attempting to do so returns `403 Forbidden`.

## Social Login

Configure social identity providers to enable "Sign in with Google/Microsoft/GitHub/Apple".

### Configuring a Social Provider

```bash
curl -X POST https://your-domain.com/admin/social-providers \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "provider": "google",
    "client_id": "your-google-client-id",
    "client_secret": "your-google-client-secret",
    "enabled": true,
    "scopes": ["openid", "email", "profile"]
  }'
```

### Supported Providers

| Provider | Config Endpoint | Login Initiation |
|----------|-----------------|------------------|
| Google | `/admin/social-providers/google` | `/auth/social/google` |
| Microsoft | `/admin/social-providers/microsoft` | `/auth/social/microsoft` |
| GitHub | `/admin/social-providers/github` | `/auth/social/github` |
| Apple | `/admin/social-providers/apple` | `/auth/social/apple` |

### Social Provider Management

| Operation | Method | Endpoint |
|-----------|--------|----------|
| List providers | GET | `/admin/social-providers` |
| Get provider | GET | `/admin/social-providers/{provider}` |
| Configure provider | POST | `/admin/social-providers` |
| Update provider | PUT | `/admin/social-providers/{provider}` |
| Delete provider | DELETE | `/admin/social-providers/{provider}` |

## SAML 2.0 Federation

### Configuring a SAML Service Provider

Register external SAML service providers to enable SSO:

```bash
curl -X POST https://your-domain.com/admin/saml/service-providers \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Corporate SSO",
    "entity_id": "https://sp.example.com/saml/metadata",
    "acs_url": "https://sp.example.com/saml/acs",
    "sign_assertions": true,
    "name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  }'
```

### SAML Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| List SPs | GET | `/admin/saml/service-providers` |
| Get SP | GET | `/admin/saml/service-providers/{sp_id}` |
| Create SP | POST | `/admin/saml/service-providers` |
| Update SP | PUT | `/admin/saml/service-providers/{sp_id}` |
| Delete SP | DELETE | `/admin/saml/service-providers/{sp_id}` |
| Manage certificates | GET/POST | `/admin/saml/certificates` |
| Activate certificate | POST | `/admin/saml/certificates/{cert_id}/activate` |
| IdP metadata | GET | `/saml/metadata` |
| SSO endpoint | POST | `/saml/sso` |
| Initiate SSO | GET | `/saml/initiate/{sp_id}` |
| SP-initiated SLO | POST | `/saml/slo` |
| IdP-initiated SLO | POST | `/saml/slo/initiate` |

### Certificate Management

SAML signing certificates have validity periods. Monitor expiry and rotate proactively:

```bash
curl https://your-domain.com/admin/saml/certificates \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

## OpenID Connect Federation

### Configuring an OIDC Identity Provider

```bash
curl -X POST https://your-domain.com/admin/federation/identity-providers \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Corporate OIDC",
    "issuer_url": "https://idp.example.com",
    "client_id": "your-client-id",
    "client_secret": "your-client-secret",
    "scopes": ["openid", "email", "profile"],
    "enabled": true
  }'
```

### Federation Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| List IdPs | GET | `/admin/federation/identity-providers` |
| Get IdP | GET | `/admin/federation/identity-providers/{idp_id}` |
| Create IdP | POST | `/admin/federation/identity-providers` |
| Update IdP | PUT | `/admin/federation/identity-providers/{idp_id}` |
| Delete IdP | DELETE | `/admin/federation/identity-providers/{idp_id}` |
| Toggle enabled | POST | `/admin/federation/identity-providers/{idp_id}/toggle` |
| Validate config | POST | `/admin/federation/identity-providers/{idp_id}/validate` |
| Manage domains | GET/POST | `/admin/federation/identity-providers/{idp_id}/domains` |

### Domain-Based Routing

Associate email domains with identity providers for automatic federation:

```bash
curl -X POST https://your-domain.com/admin/federation/identity-providers/{idp_id}/domains \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"domain": "example.com"}'
```

When a user logs in with `user@example.com`, they are automatically redirected to the configured OIDC identity provider for authentication.

## Passwordless Authentication

### Magic Links

```bash
# Request magic link
curl -X POST https://your-domain.com/auth/passwordless/magic-link \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"email": "user@example.com"}'

# Verify (user clicks link with token)
curl -X POST https://your-domain.com/auth/passwordless/magic-link/verify \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"token": "magic-link-token"}'
```

### Email OTP

```bash
# Request OTP
curl -X POST https://your-domain.com/auth/passwordless/email-otp \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"email": "user@example.com"}'

# Verify OTP
curl -X POST https://your-domain.com/auth/passwordless/email-otp/verify \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"email": "user@example.com", "code": "123456"}'
```

### Passwordless Policy and Methods

```bash
# Get tenant passwordless policy
curl https://your-domain.com/auth/passwordless/policy \
  -H "X-Tenant-ID: $TENANT_ID"

# List available passwordless methods
curl https://your-domain.com/auth/passwordless/methods \
  -H "X-Tenant-ID: $TENANT_ID"
```

## Session and Token Management

### Token Revocation

```bash
# Revoke a specific token
curl -X POST https://your-domain.com/auth/tokens/revoke \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"token": "token-to-revoke"}'

# Revoke all tokens for a user (admin)
curl -X POST https://your-domain.com/auth/tokens/revoke-user \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"user_id": "user-uuid"}'
```

### Logout

```bash
curl -X POST https://your-domain.com/auth/logout \
  -H "Authorization: Bearer $USER_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

## SAML Single Logout (SLO)

xavyo-idp supports SAML 2.0 Single Logout for both SP-initiated and IdP-initiated flows. Per-SP session tracking enables the IdP to send LogoutRequests to all Service Providers that have active sessions for a user.

### SP-Initiated SLO

When a Service Provider initiates logout, it sends a signed `LogoutRequest` to the IdP. The IdP validates the request, revokes the user's sessions (honoring `SessionIndex` if provided), and returns a signed `LogoutResponse`.

```bash
# SP sends a LogoutRequest (base64-encoded SAML XML) to the IdP
curl -X POST https://your-domain.com/saml/slo \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d "SAMLRequest=$(base64-encoded-logout-request)&RelayState=optional-state"
```

The response is a form-encoded `SAMLResponse` containing the signed `LogoutResponse` XML.

### IdP-Initiated SLO

An authenticated user (or admin) can trigger logout across all SPs with active sessions. The IdP sends back-channel LogoutRequests to each SP's configured SLO URL and revokes all SP sessions regardless of SP responses.

```bash
curl -X POST https://your-domain.com/saml/slo/initiate \
  -H "Authorization: Bearer $USER_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

**Response (200):**
```json
{
  "total": 3,
  "succeeded": 2,
  "failed": 0,
  "no_slo_url": 1
}
```

### Per-SP Session Tracking

When the IdP issues a SAML assertion, it records a session entry (`saml_sp_sessions`) containing the SP ID, user ID, session index, NameID, and expiry. This enables:

- **Targeted logout**: SP-initiated SLO can revoke only the specific session identified by `SessionIndex`
- **Broadcast logout**: IdP-initiated SLO can enumerate all active SP sessions and notify each SP
- **Session cleanup**: Expired and revoked sessions are automatically cleaned up

### Configuring SLO for a Service Provider

Set the `slo_url` and `slo_binding` when creating or updating a Service Provider:

```bash
curl -X POST https://your-domain.com/admin/saml/service-providers \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Corporate SSO",
    "entity_id": "https://sp.example.com/saml/metadata",
    "acs_url": "https://sp.example.com/saml/acs",
    "sign_assertions": true,
    "slo_url": "https://sp.example.com/saml/slo",
    "slo_binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  }'
```

SPs without an `slo_url` configured are skipped during IdP-initiated SLO (reported in the `no_slo_url` count).

### SLO Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| SP-initiated SLO | POST | `/saml/slo` |
| IdP-initiated SLO | POST | `/saml/slo/initiate` |

## OIDC RP-Initiated Logout

xavyo-idp implements [OIDC RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) via the `end_session_endpoint` published in the OIDC discovery document.

### Initiating Logout

The endpoint accepts both GET (query params) and POST (form body):

```bash
# GET with query parameters
curl -G "https://your-domain.com/oauth/logout" \
  -H "X-Tenant-ID: $TENANT_ID" \
  --data-urlencode "id_token_hint=$ID_TOKEN" \
  --data-urlencode "post_logout_redirect_uri=https://app.example.com/logged-out" \
  --data-urlencode "state=abc123" \
  --data-urlencode "client_id=my-client"
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `id_token_hint` | Recommended | Previously issued ID token (may be expired). Used to identify the user and client. |
| `post_logout_redirect_uri` | Optional | URI to redirect the user after logout. Must be registered on the OAuth client. |
| `client_id` | Optional | OAuth2 client identifier. Must match the `id_token_hint` audience if both are provided. |
| `state` | Optional | Opaque value passed through to the redirect URI as a query parameter. |

### Behavior

1. **Validates `id_token_hint`**: Verifies the JWT signature (expired tokens accepted per spec), validates the issuer, and extracts the user identity.
2. **Validates `post_logout_redirect_uri`**: Checks that the URI is registered in the client's `post_logout_redirect_uris` list.
3. **Revokes sessions**: Deletes all user sessions and revokes all OAuth2 refresh tokens.
4. **Redirects or returns JSON**: If a valid `post_logout_redirect_uri` is provided, responds with `303 See Other`. Otherwise returns `200` with a JSON success message.

### Registering Post-Logout Redirect URIs

When creating or updating an OAuth client, include the `post_logout_redirect_uris` field:

```bash
curl -X POST https://your-domain.com/oauth/clients \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "client_id": "my-app",
    "name": "My Application",
    "client_type": "confidential",
    "redirect_uris": ["https://app.example.com/callback"],
    "post_logout_redirect_uris": [
      "https://app.example.com/logged-out",
      "https://app.example.com/goodbye"
    ],
    "grant_types": ["authorization_code"],
    "scopes": ["openid", "profile", "email"]
  }'
```

:::warning
If `post_logout_redirect_uri` is provided but not registered on the client, the redirect is silently ignored per the OIDC specification. The user is still logged out, but no redirect occurs.
:::

### OIDC Logout Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| End session | GET/POST | `/oauth/logout` |

## OIDC Discovery

xavyo-idp publishes standard OpenID Connect discovery documents:

| Endpoint | Description |
|----------|-------------|
| `/.well-known/openid-configuration` | OIDC discovery metadata |
| `/.well-known/jwks.json` | JSON Web Key Set for token verification |

## Security Considerations

- **Login enumeration prevention**: Invalid credentials and inactive accounts return the same generic error to prevent email enumeration.
- **Rate limiting**: Authentication endpoints enforce 5 attempts per 60 seconds per IP/email to prevent brute-force attacks.
- **OIDC ID token verification**: ID tokens are verified using JWKS (RS256) with nonce validation to prevent replay attacks.
- **OIDC logout `id_token_hint` validation**: The `id_token_hint` JWT signature is verified using JWKS key matching by `kid`. Expired tokens are accepted per spec, but unknown key IDs are rejected (no fallback to active key).
- **OIDC `post_logout_redirect_uri` validation**: Redirect URIs are validated against the client's registered `post_logout_redirect_uris` using URL-parsed comparison (case-insensitive host, port normalization). Invalid URIs are silently ignored.
- **SAML SLO signature validation**: SP-initiated LogoutRequests are validated against the SP's certificate when `validate_signatures` is enabled.
- **SAML SLO URL validation**: IdP-initiated SLO only sends LogoutRequests to HTTPS URLs (HTTP allowed for localhost in development). Private IP ranges are blocked to prevent SSRF.
- **SAML decompression protection**: A 1 MB limit is enforced on SAML response decompression to prevent decompression bombs. LogoutRequest size is limited to 512 KB.
- **Social login redirect protection**: Callback redirect URIs are validated to allow only relative paths, preventing open redirect attacks.
- **Token security**: All security tokens (reset, verification, MFA) use cryptographically secure random generation (CSPRNG via `OsRng`).
- **Session isolation**: Sessions include `tenant_id` in all database queries to prevent cross-tenant session hijacking.
- **Social link tenant check**: Linking a social account validates that the JWT tenant matches the request tenant.

## Related

- [Tenant Setup](./tenant-setup.md) -- Configuring tenant-level password and lockout policies
- [Security Hardening](./security-hardening.md) -- IP restrictions, key management, and audit logging
- [User Management](./user-management.md) -- Creating users and managing credentials
