---
title: API Overview
description: Fundamentals of the xavyo REST API — authentication, headers, pagination, errors, and rate limiting.
sidebar_position: 1
---

# API Overview

xavyo exposes a REST API for identity management, governance, and security operations. All interactions are JSON over HTTPS. This guide covers the fundamentals you need to know before calling any endpoint.

## Base URL

All API requests are relative to your xavyo instance base URL:

```
https://idp.example.com
```

The API does not use versioned URL prefixes (e.g., `/v1/`). Breaking changes are communicated through deprecation headers and changelogs.

## Authentication

xavyo supports two authentication methods:

### JWT Bearer Tokens

Most API calls require a JWT access token obtained through the [authentication flows](./authentication-flows.md). Include it in the `Authorization` header:

```
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

The JWT contains these standard claims:

| Claim | Description |
|-------|-------------|
| `sub` | User ID (UUID) |
| `tid` | Tenant ID (UUID) |
| `roles` | Array of role names (e.g., `["admin", "user"]`) |
| `email` | User email address |
| `exp` | Expiration timestamp (Unix epoch) |
| `iat` | Issued-at timestamp (Unix epoch) |
| `iss` | Issuer URL |
| `aud` | Audience (client ID) |
| `jti` | Unique token identifier |

### API Keys

For machine-to-machine integrations, use an API key via the `X-API-Key` header:

```
X-API-Key: xavyo_ak_abc123def456...
```

API keys are scoped to a tenant and can have restricted permissions.

## Multi-Tenancy

xavyo is multi-tenant. Every request must include a tenant context. For authenticated requests, the tenant is extracted from the JWT `tid` claim. For unauthenticated requests (e.g., login, signup, OAuth token exchange), include the `X-Tenant-ID` header:

```
X-Tenant-ID: 550e8400-e29b-41d4-a716-446655440000
```

:::warning
Omitting the tenant context results in a `400 Bad Request`. All data access is tenant-isolated at the database level using Row-Level Security (RLS).
:::

## Request Format

- **Content-Type**: `application/json` for all request bodies
- **Character encoding**: UTF-8
- **UUID format**: Standard RFC 4122 format (`550e8400-e29b-41d4-a716-446655440000`)
- **Timestamps**: ISO 8601 / RFC 3339 format (`2026-02-07T15:30:00Z`)

```bash
curl -X POST https://idp.example.com/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: 550e8400-e29b-41d4-a716-446655440000" \
  -d '{
    "email": "user@example.com",
    "password": "SecureP@ss123"
  }'
```

## Response Format

Successful responses return JSON with the appropriate HTTP status code:

| Status | Meaning |
|--------|---------|
| `200 OK` | Successful read or update |
| `201 Created` | Resource created |
| `204 No Content` | Successful delete |
| `400 Bad Request` | Malformed request |
| `401 Unauthorized` | Missing or invalid credentials |
| `403 Forbidden` | Insufficient permissions |
| `404 Not Found` | Resource not found |
| `409 Conflict` | Duplicate resource |
| `422 Unprocessable Entity` | Validation error |
| `429 Too Many Requests` | Rate limit exceeded |
| `500 Internal Server Error` | Server error |
| `503 Service Unavailable` | Temporarily unavailable |

## Pagination

List endpoints support offset-based pagination using `limit` and `offset` query parameters:

```bash
curl "https://idp.example.com/admin/users?limit=25&offset=50" \
  -H "Authorization: Bearer $TOKEN"
```

**Parameters:**

| Parameter | Type | Default | Max | Description |
|-----------|------|---------|-----|-------------|
| `limit` | integer | 20 | 100 | Number of items to return |
| `offset` | integer | 0 | -- | Number of items to skip |

**Response shape:**

```json
{
  "items": [ ... ],
  "total": 150,
  "limit": 25,
  "offset": 50
}
```

The `total` field reflects the total count of matching records.

:::tip
Always use both `limit` and `offset` for deterministic pagination. Results are ordered by creation time (newest first) unless a `sort_by` parameter is available.
:::

## Error Responses

xavyo uses [RFC 7807 Problem Details](https://tools.ietf.org/html/rfc7807) for error responses. The `Content-Type` is `application/problem+json`.

```json
{
  "type": "https://xavyo.net/errors/invalid-credentials",
  "title": "Invalid Credentials",
  "status": 401,
  "detail": "The provided credentials are invalid."
}
```

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | URI identifying the error type |
| `title` | string | Short human-readable summary |
| `status` | integer | HTTP status code |
| `detail` | string | Human-readable explanation (optional) |
| `instance` | string | URI of the specific occurrence (optional) |

See the [Error Codes Reference](/docs/reference/error-codes) for a complete catalog of error types.

## Rate Limiting

xavyo applies rate limiting to protect against abuse. Rate limit information is communicated via response headers:

| Header | Description |
|--------|-------------|
| `X-RateLimit-Limit` | Maximum requests allowed in the window |
| `X-RateLimit-Remaining` | Requests remaining in the current window |
| `Retry-After` | Seconds to wait before retrying (on `429` responses) |

When you exceed the rate limit, you receive a `429 Too Many Requests` response:

```json
{
  "type": "https://xavyo.net/errors/rate-limited",
  "title": "Rate Limit Exceeded",
  "status": 429,
  "detail": "Too many login attempts. Please try again later."
}
```

:::info
Login endpoints are limited to 5 attempts per 60 seconds per email address. See the [Rate Limits Reference](/docs/reference/rate-limits) for per-endpoint details.
:::

**Best practices for handling rate limits:**

1. Check the `Retry-After` header and wait the specified duration
2. Implement exponential backoff for retries
3. Cache responses where appropriate to reduce API calls

## CORS

xavyo includes CORS headers for browser-based applications:

- `Access-Control-Allow-Methods`: `GET, POST, PUT, PATCH, DELETE, OPTIONS`
- `Access-Control-Allow-Headers`: `Content-Type, Authorization, X-Tenant-ID, X-API-Key, X-Device-Fingerprint`
- `Access-Control-Max-Age`: `86400` (24 hours)

## Security Headers

All responses include security headers:

```
Cache-Control: no-store, no-cache, must-revalidate, private
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

## SCIM Endpoints

SCIM endpoints use `application/scim+json` as the content type per RFC 7644. See the [SCIM Integration Guide](./scim-integration.md) for details.

## OIDC Discovery

xavyo publishes OpenID Connect discovery documents at:

- **Discovery**: `GET /.well-known/openid-configuration`
- **JWKS**: `GET /.well-known/jwks.json`

These endpoints do not require authentication. See [Authentication Flows](./authentication-flows.md) for usage details.

## SDK Recommendations

While xavyo does not ship client SDKs, any standard HTTP client works:

| Language | Library |
|----------|---------|
| JavaScript/TypeScript | `fetch` (built-in), `axios` |
| Python | `httpx`, `requests` |
| Go | `net/http` (standard library) |
| Rust | `reqwest` |
| Java | `java.net.http.HttpClient` |
| CLI | `curl`, xavyo CLI (`xavyo`) |

For OAuth 2.0 flows, use a certified OIDC client library (e.g., `openid-client` for Node.js, `authlib` for Python) to handle token management, PKCE, and discovery automatically.
