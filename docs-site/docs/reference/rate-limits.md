---
title: Rate Limits
description: Per-endpoint rate limiting details, response headers, and strategies for handling rate limits.
sidebar_position: 2
---

# Rate Limits Reference

xavyo applies rate limiting to protect the platform from abuse and ensure fair usage. This page documents the rate limits for each endpoint category, the response headers used to communicate limits, and strategies for handling `429 Too Many Requests` responses.

## Response Headers

Rate limit information is communicated through HTTP response headers on every request:

| Header | Description | Example |
|--------|-------------|---------|
| `X-RateLimit-Limit` | Maximum requests allowed in the current window | `100` |
| `X-RateLimit-Remaining` | Requests remaining in the current window | `87` |
| `Retry-After` | Seconds to wait before retrying (only on `429` responses) | `60` |

## Rate Limit Response

When you exceed a rate limit, xavyo returns a `429 Too Many Requests` response:

```json
{
  "type": "https://xavyo.net/errors/rate-limited",
  "title": "Rate Limit Exceeded",
  "status": 429,
  "detail": "Too many requests. Please try again later."
}
```

The `Retry-After` header tells you how many seconds to wait before sending the next request.

## Per-Endpoint Rate Limits

### Authentication Endpoints

These endpoints have the strictest rate limits to prevent credential stuffing and brute force attacks.

| Endpoint | Limit | Window | Key |
|----------|-------|--------|-----|
| `POST /auth/login` | 5 requests | 60 seconds | Per email address |
| `POST /auth/signup` | 10 requests | 60 seconds | Per IP address |
| `POST /auth/register` | 10 requests | 60 seconds | Per IP address |
| `POST /auth/forgot-password` | 3 requests | 60 seconds | Per email address |
| `POST /auth/reset-password` | 5 requests | 60 seconds | Per token |
| `POST /auth/verify-email` | 5 requests | 60 seconds | Per token |
| `POST /auth/resend-verification` | 3 requests | 60 seconds | Per email address |

:::warning
Login rate limits are enforced per email address. After 5 failed attempts within 60 seconds, all login attempts for that email are blocked until the window resets. Additionally, after a configurable number of consecutive failures (default: 10), the account is locked.
:::

### MFA Endpoints

| Endpoint | Limit | Window | Key |
|----------|-------|--------|-----|
| `POST /auth/mfa/totp/setup` | 5 requests | 60 seconds | Per user |
| `POST /auth/mfa/totp/verify-setup` | 5 requests | 60 seconds | Per user |
| `POST /auth/mfa/totp/verify` | 5 requests | 60 seconds | Per user |
| `POST /auth/mfa/recovery/verify` | 5 requests | 60 seconds | Per user |
| `POST /auth/mfa/webauthn/*/start` | 5 requests | 60 seconds | Per user |
| `POST /auth/mfa/webauthn/*/finish` | 5 requests | 60 seconds | Per user |

After 5 failed TOTP verification attempts, the TOTP verification endpoint is locked for 5 minutes (300 seconds). The response includes `Retry-After: 300`.

### Token Endpoints

| Endpoint | Limit | Window | Key |
|----------|-------|--------|-----|
| `POST /oauth/token` | 30 requests | 60 seconds | Per client ID |
| `POST /oauth/introspect` | 60 requests | 60 seconds | Per client ID |
| `POST /oauth/revoke` | 30 requests | 60 seconds | Per client ID |
| `POST /oauth/device/code` | 10 requests | 60 seconds | Per client ID |
| `POST /auth/refresh` | 30 requests | 60 seconds | Per user |

### Admin API Endpoints

Admin endpoints have higher limits since they are typically called by automation and internal tools.

| Endpoint Category | Limit | Window | Key |
|-------------------|-------|--------|-----|
| `GET /admin/*` (read operations) | 100 requests | 60 seconds | Per tenant |
| `POST/PUT/PATCH /admin/*` (writes) | 50 requests | 60 seconds | Per tenant |
| `DELETE /admin/*` | 30 requests | 60 seconds | Per tenant |

### User Self-Service Endpoints

| Endpoint Category | Limit | Window | Key |
|-------------------|-------|--------|-----|
| `GET /me/*` | 60 requests | 60 seconds | Per user |
| `PUT /me/*` | 10 requests | 60 seconds | Per user |
| `PUT /auth/password` | 3 requests | 60 seconds | Per user |
| `POST /me/email/change` | 3 requests | 60 seconds | Per user |

### SCIM Endpoints

| Endpoint Category | Limit | Window | Key |
|-------------------|-------|--------|-----|
| `GET /scim/v2/*` | 100 requests | 60 seconds | Per SCIM token |
| `POST /scim/v2/*` | 50 requests | 60 seconds | Per SCIM token |
| `PUT/PATCH /scim/v2/*` | 50 requests | 60 seconds | Per SCIM token |
| `DELETE /scim/v2/*` | 30 requests | 60 seconds | Per SCIM token |

### Governance Endpoints

| Endpoint Category | Limit | Window | Key |
|-------------------|-------|--------|-----|
| `GET /governance/*` (read) | 100 requests | 60 seconds | Per tenant |
| `POST /governance/*` (write) | 50 requests | 60 seconds | Per tenant |
| `POST /governance/access-requests` | 10 requests | 60 seconds | Per user |

### Webhook Endpoints

| Endpoint Category | Limit | Window | Key |
|-------------------|-------|--------|-----|
| `GET /webhooks/*` | 60 requests | 60 seconds | Per tenant |
| `POST /webhooks/*` | 30 requests | 60 seconds | Per tenant |
| `POST /webhooks/dlq/*/replay` | 10 requests | 60 seconds | Per tenant |

### NHI Endpoints

| Endpoint Category | Limit | Window | Key |
|-------------------|-------|--------|-----|
| `GET /nhi/*` (read) | 100 requests | 60 seconds | Per tenant |
| `POST/PUT/PATCH /nhi/*` (write) | 50 requests | 60 seconds | Per tenant |
| `POST /nhi/agents/*/authorize` | 60 requests | 60 seconds | Per agent |

### Public Endpoints

Unauthenticated endpoints have conservative limits.

| Endpoint | Limit | Window | Key |
|----------|-------|--------|-----|
| `GET /.well-known/openid-configuration` | 100 requests | 60 seconds | Per IP address |
| `GET /.well-known/jwks.json` | 100 requests | 60 seconds | Per IP address |
| `GET /saml/metadata` | 30 requests | 60 seconds | Per IP address |

## Rate Limit Keys

Rate limits are keyed differently depending on the endpoint:

| Key Type | Description |
|----------|-------------|
| **Per email** | Limits apply per unique email address. Used for login and password reset to prevent credential stuffing. |
| **Per IP address** | Limits apply per source IP. Used for unauthenticated endpoints. |
| **Per user** | Limits apply per authenticated user (from JWT `sub` claim). |
| **Per tenant** | Limits apply per tenant (from JWT `tid` claim). Shared across all users in the tenant. |
| **Per client ID** | Limits apply per OAuth client. |
| **Per SCIM token** | Limits apply per SCIM bearer token. |
| **Per agent** | Limits apply per AI agent identity. |

## Handling Rate Limits

### Basic Strategy

```python
import time
import requests

def call_api_with_retry(url, headers, max_retries=3):
    for attempt in range(max_retries):
        response = requests.get(url, headers=headers)

        if response.status_code == 429:
            retry_after = int(response.headers.get('Retry-After', 60))
            time.sleep(retry_after)
            continue

        return response

    raise Exception("Max retries exceeded")
```

### Exponential Backoff

For bulk operations, use exponential backoff to avoid hammering the API:

```python
import time
import random

def call_with_backoff(url, headers, max_retries=5):
    for attempt in range(max_retries):
        response = requests.get(url, headers=headers)

        if response.status_code == 429:
            retry_after = int(response.headers.get('Retry-After', 1))
            # Exponential backoff with jitter
            wait = max(retry_after, (2 ** attempt) + random.uniform(0, 1))
            time.sleep(wait)
            continue

        return response

    raise Exception("Max retries exceeded")
```

### Proactive Rate Limit Management

Monitor the rate limit headers on every response to avoid hitting limits:

```javascript
function checkRateLimits(response) {
  const remaining = parseInt(response.headers.get('X-RateLimit-Remaining'), 10);
  const limit = parseInt(response.headers.get('X-RateLimit-Limit'), 10);

  if (remaining < limit * 0.1) {
    console.warn(`Rate limit nearly exhausted: ${remaining}/${limit} remaining`);
    // Slow down request rate
  }
}
```

## Best Practices

1. **Respect `Retry-After`** -- Always wait the full duration specified by the `Retry-After` header before retrying. Retrying sooner extends the lockout.
2. **Implement exponential backoff** -- For automated systems, use exponential backoff with jitter to avoid thundering herd problems.
3. **Cache responses** -- Cache OIDC discovery documents, JWKS keys, and other slowly-changing data to reduce unnecessary API calls.
4. **Use bulk endpoints** -- When available, use bulk operations instead of individual requests (e.g., SCIM bulk operations, bulk certification decisions).
5. **Monitor rate limit headers** -- Track `X-RateLimit-Remaining` proactively and throttle your request rate before hitting limits.
6. **Distribute load** -- Spread requests evenly over time rather than sending bursts. Use queue-based processing for batch operations.
7. **Use API keys for automation** -- API keys have separate rate limit pools from user tokens, which helps when running automation alongside user activity.
