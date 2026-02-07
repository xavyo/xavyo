---
title: Error Codes
description: Complete catalog of xavyo API error types, HTTP status codes, and troubleshooting guidance.
sidebar_position: 1
---

# Error Codes Reference

xavyo uses [RFC 7807 Problem Details](https://tools.ietf.org/html/rfc7807) for all error responses. Every error includes a machine-readable `type` URI, a human-readable `title`, the HTTP `status` code, and an optional `detail` message.

## Error Response Format

```json
{
  "type": "https://xavyo.net/errors/invalid-credentials",
  "title": "Invalid Credentials",
  "status": 401,
  "detail": "The provided credentials are invalid."
}
```

The `Content-Type` for error responses is `application/problem+json`.

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | URI identifying the error type (stable, machine-readable) |
| `title` | string | Short human-readable summary |
| `status` | integer | HTTP status code |
| `detail` | string | Human-readable explanation (optional, may vary) |
| `instance` | string | URI identifying the specific occurrence (optional) |

## Authentication Errors

Errors related to login, signup, and credential management.

| Error Type | Status | Title | Description |
|------------|--------|-------|-------------|
| `invalid-credentials` | 401 | Invalid Credentials | Email or password is incorrect. Intentionally generic to prevent email enumeration. |
| `email-in-use` | 409 | Email Already in Use | The email address is already registered in this tenant. |
| `weak-password` | 400 | Weak Password | Password does not meet the tenant's password policy. The `detail` field lists specific failures. |
| `invalid-email` | 400 | Invalid Email Format | The email address format is invalid. |
| `email-not-verified` | 403 | Email Not Verified | Login denied because the account's email has not been verified. |
| `account-inactive` | 401 | Invalid Credentials | Account is disabled or suspended. Returns generic error to prevent enumeration. |
| `account-locked` | 423 | Account Locked | Account is temporarily locked due to too many failed login attempts. |
| `account-locked-until` | 423 | Account Locked | Account is locked with a specific unlock time provided in `detail`. |
| `password-expired` | 403 | Password Expired | Password has expired per the tenant's password policy. Must be changed before login. |
| `unauthorized` | 401 | Unauthorized | Missing, malformed, or expired authentication credentials. |

## Token Errors

Errors related to JWT access tokens, refresh tokens, and other security tokens.

| Error Type | Status | Title | Description |
|------------|--------|-------|-------------|
| `token-expired` | 401 | Token Expired | The refresh token has expired. Re-authenticate to obtain new tokens. |
| `token-revoked` | 401 | Token Revoked | The refresh token has been revoked (e.g., by logout or admin action). |
| `invalid-token` | 401 | Invalid Token | The token is malformed or not recognized. |
| `token-used` | 400 | Token Already Used | The password reset or verification token has already been consumed. |

## MFA Errors

Errors related to multi-factor authentication setup and verification.

| Error Type | Status | Title | Description |
|------------|--------|-------|-------------|
| `mfa-already-enabled` | 409 | MFA Already Enabled | TOTP setup was attempted but MFA is already active. Disable first to reconfigure. |
| `mfa-setup-not-initiated` | 400 | MFA Setup Not Initiated | Verification was attempted without first calling the setup endpoint. |
| `mfa-setup-expired` | 400 | MFA Setup Expired | The setup session expired (10 minute window). Restart the setup process. |
| `mfa-disabled-by-policy` | 403 | MFA Disabled by Policy | The tenant's MFA policy is set to "disabled", preventing setup. |
| `mfa-not-enabled` | 400 | MFA Not Enabled | An MFA operation was attempted but MFA is not enabled for this user. |
| `invalid-totp-code` | 401 | Invalid TOTP Code | The 6-digit TOTP code is incorrect or expired. |
| `totp-verification-locked` | 429 | TOTP Verification Locked | Too many failed TOTP attempts. Locked for 5 minutes. Includes `Retry-After: 300` header. |
| `partial-token-expired` | 401 | MFA Verification Token Expired | The partial token issued after password login has expired (5 minute window). |
| `partial-token-invalid` | 401 | Invalid MFA Token | The partial token is malformed or not recognized. |
| `invalid-recovery-code` | 401 | Invalid Recovery Code | The recovery code is incorrect or has already been used. |
| `no-recovery-codes` | 400 | No Recovery Codes | All recovery codes have been consumed. Contact admin for MFA reset. |
| `mfa-required-by-policy` | 403 | MFA Required by Policy | The tenant requires MFA but the user has not set it up. |
| `cannot-disable-mfa` | 403 | Cannot Disable MFA | Cannot disable MFA when the tenant policy requires it. |

## Session Errors

| Error Type | Status | Title | Description |
|------------|--------|-------|-------------|
| `session-not-found` | 404 | Session Not Found | The specified session ID does not exist or belongs to another user. |
| `cannot-revoke-current` | 400 | Cannot Revoke Current Session | Cannot revoke the session making the current request. Use `/auth/logout` instead. |
| `session-expired` | 401 | Session Expired | The session has expired due to inactivity or time limit. |
| `session-revoked` | 401 | Session Revoked | The session has been revoked by the user or an administrator. |

## Rate Limiting Errors

| Error Type | Status | Title | Description |
|------------|--------|-------|-------------|
| `rate-limited` | 429 | Rate Limit Exceeded | Too many requests. Includes `Retry-After` header with seconds to wait. See [Rate Limits](/docs/reference/rate-limits). |

## Email Change Errors

| Error Type | Status | Title | Description |
|------------|--------|-------|-------------|
| `email-already-exists` | 409 | Email Already Exists | The new email address is already in use by another account. |
| `email-change-pending` | 409 | Email Change Pending | A pending email change already exists. Complete or cancel it first. |
| `email-change-token-expired` | 400 | Token Expired | The email change verification token has expired (24 hour window). |
| `email-change-token-invalid` | 400 | Token Invalid | The email change verification token is invalid. |
| `same-email` | 400 | Same Email | Cannot change to the same email address. |

## WebAuthn Errors

| Error Type | Status | Title | Description |
|------------|--------|-------|-------------|
| `webauthn-disabled` | 403 | WebAuthn Disabled | WebAuthn is disabled for this tenant. |
| `max-webauthn-credentials` | 400 | Max Credentials Reached | Maximum number of WebAuthn credentials registered. Remove one before adding another. |
| `webauthn-challenge-not-found` | 400 | Challenge Not Found | The WebAuthn challenge was not found or has been consumed. |
| `webauthn-challenge-expired` | 400 | Challenge Expired | The WebAuthn challenge has expired. Start a new registration or authentication. |
| `webauthn-verification-failed` | 400 | Verification Failed | The WebAuthn credential response failed validation. |
| `webauthn-credential-exists` | 409 | Credential Exists | This security key is already registered. |
| `webauthn-credential-not-found` | 404 | Credential Not Found | The specified WebAuthn credential was not found. |
| `webauthn-no-credentials` | 400 | No Credentials | No WebAuthn credentials are registered for this user. |
| `webauthn-rate-limited` | 429 | Rate Limited | Too many WebAuthn attempts. Wait before retrying. |
| `webauthn-counter-anomaly` | 403 | Counter Anomaly | Credential counter regression detected, indicating a possible cloned key. |

## Device Errors

| Error Type | Status | Title | Description |
|------------|--------|-------|-------------|
| `device-not-found` | 404 | Device Not Found | The specified device ID does not exist or belongs to another user. |
| `device-revoked` | 400 | Device Revoked | The device trust has already been revoked. |
| `trust-not-allowed` | 403 | Trust Not Allowed | Device trust is not allowed by the tenant's policy. |

## Alert Errors

| Error Type | Status | Title | Description |
|------------|--------|-------|-------------|
| `alert-not-found` | 404 | Alert Not Found | The specified alert ID does not exist. |
| `alert-already-acknowledged` | 400 | Already Acknowledged | The alert has already been acknowledged. |

## IP Restriction Errors

| Error Type | Status | Title | Description |
|------------|--------|-------|-------------|
| `ip-blocked` | 403 | IP Blocked | The request IP address is blocked by the tenant's IP restriction rules. |
| `invalid-cidr` | 400 | Invalid CIDR | The CIDR notation is malformed. Use format like `192.168.1.0/24`. |
| `rule-name-exists` | 409 | Rule Name Exists | An IP restriction rule with this name already exists. |
| `rule-not-found` | 404 | Rule Not Found | The specified IP restriction rule was not found. |

## Delegated Administration Errors

| Error Type | Status | Title | Description |
|------------|--------|-------|-------------|
| `permission-denied` | 403 | Permission Denied | The user lacks the required delegated administration permission. |
| `template-name-exists` | 409 | Template Name Exists | A role template with this name already exists. |
| `template-not-found` | 404 | Template Not Found | The specified role template was not found. |
| `assignment-not-found` | 404 | Assignment Not Found | The specified delegation assignment was not found. |
| `cannot-delete-system-template` | 400 | Cannot Delete System Template | Built-in system templates cannot be deleted. |
| `scope-violation` | 403 | Scope Violation | The resource is outside the user's assigned administrative scope. |

## Branding Errors

| Error Type | Status | Title | Description |
|------------|--------|-------|-------------|
| `file-too-large` | 400 | File Too Large | The uploaded file exceeds the maximum size limit. |
| `invalid-image-format` | 400 | Invalid Image Format | The file is not a supported image format (PNG, JPEG, SVG). |
| `dimensions-too-large` | 400 | Dimensions Too Large | The image dimensions exceed the maximum allowed. |
| `asset-in-use` | 409 | Asset In Use | The asset is referenced in branding configuration and cannot be deleted. |
| `invalid-css` | 400 | Invalid CSS | The custom CSS contains disallowed content. |

## Validation Errors

| Error Type | Status | Title | Description |
|------------|--------|-------|-------------|
| `validation-error` | 400 | Validation Error | Request body failed validation. The `detail` field lists specific field errors. |
| `user-not-found` | 404 | User Not Found | The specified user does not exist in this tenant. |

## General Errors

| Error Type | Status | Title | Description |
|------------|--------|-------|-------------|
| `internal-error` | 500 | Internal Server Error | An unexpected server error occurred. Retry the request. If persistent, contact support. |
| `email-send-failed` | 500 | Email Send Failed | The server failed to send an email. The operation may have partially succeeded. |

## SCIM Errors

SCIM endpoints use a different error format per RFC 7644:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "409",
  "scimType": "uniqueness",
  "detail": "User with this userName already exists"
}
```

| Status | SCIM Type | Description |
|--------|-----------|-------------|
| `400` | `invalidFilter` | The SCIM filter expression is malformed. |
| `400` | `invalidValue` | An attribute value is invalid. |
| `401` | -- | SCIM token is missing or invalid. |
| `404` | -- | The SCIM resource was not found. |
| `409` | `uniqueness` | A resource with the same unique attribute already exists. |

## Handling Errors in Your Application

### General Strategy

```javascript
async function callXavyoApi(url, options) {
  const response = await fetch(url, options);

  if (!response.ok) {
    const contentType = response.headers.get('content-type');

    if (contentType?.includes('application/problem+json')) {
      const error = await response.json();
      // Use error.type for programmatic handling
      switch (error.type) {
        case 'https://xavyo.net/errors/rate-limited':
          const retryAfter = response.headers.get('Retry-After');
          await sleep(parseInt(retryAfter, 10) * 1000);
          return callXavyoApi(url, options); // Retry
        case 'https://xavyo.net/errors/token-expired':
          await refreshTokens();
          return callXavyoApi(url, options); // Retry with new token
        default:
          throw new ApiError(error.title, error.status, error.detail);
      }
    }

    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }

  return response.json();
}
```

### Key Recommendations

1. **Match on `type`, not `title`** -- The `type` URI is stable and machine-readable. The `title` and `detail` fields are human-readable and may change between versions.
2. **Handle `429` with `Retry-After`** -- Always respect the `Retry-After` header to avoid compounding rate limit issues.
3. **Refresh tokens on `401`** -- If the access token has expired, use your refresh token to obtain a new one before retrying.
4. **Log the full error response** -- Include the `type`, `status`, and `detail` fields in your application logs for debugging.
5. **Do not expose `detail` to end users** -- The `detail` field may contain internal information. Show the `title` to users and log the `detail` for debugging.
