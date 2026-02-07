---
title: Self-Service Portal
description: Manage your profile, security settings, sessions, and devices through the self-service API.
sidebar_position: 1
---

# Self-Service Portal

xavyo provides a set of self-service endpoints under the `/me` namespace that let authenticated users manage their own profile, security settings, active sessions, and devices. All self-service endpoints are scoped to the currently authenticated user -- you can only view and modify your own data.

## Profile Management

### View Your Profile

Retrieve your current profile information:

```bash
curl https://idp.example.com/me/profile \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200 OK):**

```json
{
  "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "email": "alice@example.com",
  "display_name": "Alice Smith",
  "first_name": "Alice",
  "last_name": "Smith",
  "avatar_url": "https://gravatar.com/avatar/abc123",
  "email_verified": true,
  "created_at": "2026-01-15T10:30:00Z"
}
```

### Update Your Profile

Update your display name, first name, last name, or avatar URL:

```bash
curl -X PUT https://idp.example.com/me/profile \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "display_name": "Alice J. Smith",
    "first_name": "Alice",
    "last_name": "Smith",
    "avatar_url": "https://gravatar.com/avatar/def456"
  }'
```

:::info
You cannot change your email through the profile update endpoint. Email changes require a separate verification flow described below.
:::

## Email Change

Changing your email address requires a two-step verification process to protect against account takeover.

### Step 1: Initiate Email Change

```bash
curl -X POST https://idp.example.com/me/email/change \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "new_email": "alice.smith@newdomain.com",
    "password": "current-password"
  }'
```

**Response (200 OK):**

```json
{
  "message": "Verification email sent to alice.smith@newdomain.com"
}
```

A verification link is sent to the new email address. The link expires after 24 hours.

### Step 2: Verify Email Change

Click the verification link in the email, or call the verification endpoint directly:

```bash
curl -X POST https://idp.example.com/me/email/verify \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "token": "email-change-verification-token"
  }'
```

:::warning
You can only have one pending email change at a time. Starting a new change request cancels any previous pending request.
:::

## Password Change

Change your password while authenticated:

```bash
curl -X PUT https://idp.example.com/auth/password \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "MyOldP@ssw0rd",
    "new_password": "MyNewP@ssw0rd_2026",
    "revoke_other_sessions": true
  }'
```

**Response (200 OK):**

```json
{
  "message": "Password changed successfully",
  "sessions_revoked": 3
}
```

### Password Requirements

Your new password must meet the tenant's password policy. The default requirements are:

- At least 8 characters
- At least one uppercase letter (A-Z)
- At least one lowercase letter (a-z)
- At least one digit (0-9)
- At least one special character

Additional tenant-specific policies may include:

| Policy | Description |
|--------|-------------|
| **Password history** | Cannot reuse recently used passwords |
| **Minimum age** | Must wait a minimum period before changing again |
| **Expiration** | Passwords expire after a set period |

:::tip
Set `revoke_other_sessions` to `true` when changing your password to log out all other devices. This is recommended if you suspect your password has been compromised.
:::

## Security Overview

Get a consolidated view of your account security status:

```bash
curl https://idp.example.com/me/security \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200 OK):**

```json
{
  "mfa_enabled": true,
  "mfa_methods": ["totp"],
  "trusted_devices_count": 2,
  "active_sessions_count": 3,
  "last_password_change": "2026-01-20T14:00:00Z",
  "recent_security_alerts_count": 1,
  "password_expires_at": null
}
```

## Session Management

### List Active Sessions

View all your active sessions across devices:

```bash
curl https://idp.example.com/users/me/sessions \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200 OK):**

```json
{
  "sessions": [
    {
      "id": "a1b2c3d4-5678-90ab-cdef-1234567890ab",
      "ip_address": "203.0.113.42",
      "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...",
      "created_at": "2026-02-07T09:00:00Z",
      "last_active_at": "2026-02-07T15:30:00Z",
      "is_current": true
    },
    {
      "id": "b2c3d4e5-6789-0abc-def1-234567890abc",
      "ip_address": "198.51.100.10",
      "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)...",
      "created_at": "2026-02-05T18:00:00Z",
      "last_active_at": "2026-02-06T12:00:00Z",
      "is_current": false
    }
  ],
  "total": 2
}
```

The `is_current` flag indicates the session making the current request.

### Revoke a Session

Log out a specific device by revoking its session:

```bash
curl -X DELETE https://idp.example.com/users/me/sessions/{session_id} \
  -H "Authorization: Bearer $TOKEN"
```

**Response:** `204 No Content`

:::warning
You cannot revoke your current session. To log out from the current device, use the logout endpoint (`POST /auth/logout`).
:::

### Revoke All Other Sessions

Log out all devices except the current one:

```bash
curl -X DELETE https://idp.example.com/users/me/sessions \
  -H "Authorization: Bearer $TOKEN"
```

## MFA Status

Check your current MFA configuration:

```bash
curl https://idp.example.com/me/mfa \
  -H "Authorization: Bearer $TOKEN"
```

**Response (200 OK):**

```json
{
  "totp_enabled": true,
  "webauthn_enabled": false,
  "recovery_codes_remaining": 8,
  "available_methods": ["totp", "recovery"],
  "setup_at": "2026-01-15T11:00:00Z",
  "last_used_at": "2026-02-07T09:05:00Z"
}
```

For details on setting up MFA, see the [MFA Setup Guide](./mfa-setup.md).

## Device Management

### List Trusted Devices

```bash
curl https://idp.example.com/me/devices \
  -H "Authorization: Bearer $TOKEN"
```

### Revoke Device Trust

Remove a device from your trusted devices list. Future logins from that device will require full authentication:

```bash
curl -X DELETE https://idp.example.com/me/devices/{device_id} \
  -H "Authorization: Bearer $TOKEN"
```

## Security Alerts

### View Recent Alerts

```bash
curl "https://idp.example.com/users/me/alerts?limit=20&offset=0" \
  -H "Authorization: Bearer $TOKEN"
```

Alerts notify you of security-relevant events on your account:

| Alert Type | Description |
|------------|-------------|
| Login from new device | First login from an unrecognized device |
| Login from new location | Login from an unusual geographic location |
| Password changed | Your password was changed |
| MFA disabled | Multi-factor authentication was disabled |
| Multiple failed logins | Several failed login attempts detected |

### Acknowledge an Alert

Mark an alert as reviewed:

```bash
curl -X POST https://idp.example.com/users/me/alerts/{id}/acknowledge \
  -H "Authorization: Bearer $TOKEN"
```

## Logging Out

### Current Session

```bash
curl -X POST https://idp.example.com/auth/logout \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "your-refresh-token"
  }'
```

This revokes the refresh token and ends the current session.

## Best Practices

1. **Review sessions regularly** -- Check your active sessions periodically and revoke any you do not recognize
2. **Enable MFA** -- Protect your account with TOTP or WebAuthn (see [MFA Setup](./mfa-setup.md))
3. **Use strong passwords** -- Choose unique passwords that meet the tenant's password policy
4. **Act on security alerts** -- Investigate unfamiliar login alerts promptly. If suspicious, change your password and revoke all sessions
5. **Limit trusted devices** -- Only trust devices you physically control
