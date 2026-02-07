---
title: SCIM Integration
description: Integrate with xavyo's SCIM 2.0 server for automated user and group provisioning.
sidebar_position: 3
---

# SCIM 2.0 Integration

xavyo implements a SCIM 2.0 server (RFC 7643 / RFC 7644) for automated user and group provisioning. This enables identity providers like Azure AD (Entra ID), Okta, and OneLogin to synchronize users and groups with xavyo automatically.

## Overview

SCIM (System for Cross-domain Identity Management) provides a standardized REST API for managing identity data. xavyo's SCIM server supports:

- **User resources**: Create, read, update, patch, and delete users
- **Group resources**: Create, read, update, patch, and delete groups
- **Filtering**: `eq`, `co`, `sw`, `and`, `or` operators
- **Pagination**: 1-based indexing with `startIndex` and `count`
- **Bulk operations**: Multiple operations in a single request

## Authentication

SCIM endpoints require a SCIM bearer token, created through the admin API. Include it in the `Authorization` header:

```bash
curl https://idp.example.com/scim/v2/Users \
  -H "Authorization: Bearer scim_token_abc123..." \
  -H "Content-Type: application/scim+json"
```

:::warning
SCIM tokens are tenant-scoped. Each token can only access resources within its tenant.
:::

## Content Type

All SCIM requests and responses use the `application/scim+json` content type per RFC 7644.

## User Operations

### List Users

```bash
curl "https://idp.example.com/scim/v2/Users?startIndex=1&count=25" \
  -H "Authorization: Bearer $SCIM_TOKEN"
```

**Response:**

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
  "totalResults": 42,
  "startIndex": 1,
  "itemsPerPage": 25,
  "Resources": [
    {
      "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
      "id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
      "userName": "alice@example.com",
      "name": {
        "givenName": "Alice",
        "familyName": "Smith"
      },
      "emails": [
        {
          "value": "alice@example.com",
          "type": "work",
          "primary": true
        }
      ],
      "active": true,
      "meta": {
        "resourceType": "User",
        "created": "2026-01-15T10:30:00Z",
        "lastModified": "2026-02-01T14:22:00Z",
        "location": "https://idp.example.com/scim/v2/Users/f47ac10b-58cc-4372-a567-0e02b2c3d479"
      }
    }
  ]
}
```

### Get a User

```bash
curl https://idp.example.com/scim/v2/Users/f47ac10b-58cc-4372-a567-0e02b2c3d479 \
  -H "Authorization: Bearer $SCIM_TOKEN"
```

### Create a User

```bash
curl -X POST https://idp.example.com/scim/v2/Users \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "bob@example.com",
    "name": {
      "givenName": "Bob",
      "familyName": "Jones"
    },
    "emails": [
      {
        "value": "bob@example.com",
        "type": "work",
        "primary": true
      }
    ],
    "active": true
  }'
```

**Response (201 Created):**

The created user resource is returned with `id` and `meta` populated.

### Replace a User (PUT)

Full replacement of a user resource:

```bash
curl -X PUT https://idp.example.com/scim/v2/Users/f47ac10b-58cc-4372-a567-0e02b2c3d479 \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
    "userName": "alice@example.com",
    "name": {
      "givenName": "Alice",
      "familyName": "Johnson"
    },
    "emails": [
      {
        "value": "alice@example.com",
        "type": "work",
        "primary": true
      }
    ],
    "active": true
  }'
```

### Patch a User (PATCH)

Partial updates using SCIM PATCH operations:

```bash
curl -X PATCH https://idp.example.com/scim/v2/Users/f47ac10b-58cc-4372-a567-0e02b2c3d479 \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {
        "op": "replace",
        "path": "name.familyName",
        "value": "Johnson"
      },
      {
        "op": "replace",
        "path": "active",
        "value": false
      }
    ]
  }'
```

### Delete a User

```bash
curl -X DELETE https://idp.example.com/scim/v2/Users/f47ac10b-58cc-4372-a567-0e02b2c3d479 \
  -H "Authorization: Bearer $SCIM_TOKEN"
```

**Response:** `204 No Content`

## Group Operations

### List Groups

```bash
curl "https://idp.example.com/scim/v2/Groups?startIndex=1&count=25" \
  -H "Authorization: Bearer $SCIM_TOKEN"
```

### Create a Group

```bash
curl -X POST https://idp.example.com/scim/v2/Groups \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    "displayName": "Engineering",
    "members": [
      {"value": "f47ac10b-58cc-4372-a567-0e02b2c3d479"}
    ]
  }'
```

### Patch Group Membership

Add or remove members from a group:

```bash
curl -X PATCH https://idp.example.com/scim/v2/Groups/a1b2c3d4-5678-90ab-cdef-1234567890ab \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -H "Content-Type: application/scim+json" \
  -d '{
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {
        "op": "add",
        "path": "members",
        "value": [
          {"value": "new-user-uuid-here"}
        ]
      }
    ]
  }'
```

## Filtering

SCIM filtering follows RFC 7644 section 3.4.2.2. Supported operators:

| Operator | Description | Example |
|----------|-------------|---------|
| `eq` | Equal | `userName eq "alice@example.com"` |
| `co` | Contains | `userName co "alice"` |
| `sw` | Starts with | `userName sw "alice"` |
| `and` | Logical AND | `active eq true and userName co "alice"` |
| `or` | Logical OR | `userName eq "alice" or userName eq "bob"` |

```bash
# Find user by exact email
curl "https://idp.example.com/scim/v2/Users?filter=userName%20eq%20%22alice@example.com%22" \
  -H "Authorization: Bearer $SCIM_TOKEN"

# Find active users
curl "https://idp.example.com/scim/v2/Users?filter=active%20eq%20true" \
  -H "Authorization: Bearer $SCIM_TOKEN"
```

## Pagination

SCIM uses 1-based indexing (unlike xavyo's 0-based offset on other endpoints):

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `startIndex` | integer | 1 | 1-based index of first result |
| `count` | integer | 25 | Number of results per page |

```bash
# Page 1 (items 1-25)
curl "https://idp.example.com/scim/v2/Users?startIndex=1&count=25"

# Page 2 (items 26-50)
curl "https://idp.example.com/scim/v2/Users?startIndex=26&count=25"
```

## Error Handling

SCIM errors follow the RFC 7644 error response format:

```json
{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
  "status": "409",
  "scimType": "uniqueness",
  "detail": "User with this userName already exists"
}
```

| HTTP Status | SCIM Type | Description |
|-------------|-----------|-------------|
| `400` | `invalidFilter` | Invalid filter expression |
| `400` | `invalidValue` | Invalid attribute value |
| `401` | -- | Authentication required |
| `404` | -- | Resource not found |
| `409` | `uniqueness` | Duplicate resource |
| `500` | -- | Internal server error |

## Integration with Azure AD / Entra ID

To configure Azure AD SCIM provisioning:

1. **Create a SCIM token** in xavyo admin panel
2. In Azure AD, go to **Enterprise Applications** > your app > **Provisioning**
3. Set provisioning mode to **Automatic**
4. Enter:
   - **Tenant URL**: `https://idp.example.com/scim/v2`
   - **Secret Token**: your SCIM bearer token
5. Click **Test Connection** to verify
6. Configure **Attribute Mappings** (Azure AD maps `userPrincipalName` to `userName` by default)
7. Set provisioning scope and enable

:::tip
Azure AD sends PATCH requests to update users. Ensure your SCIM token has full CRUD permissions. Azure also uses the `externalId` attribute to correlate users -- xavyo maps this to the user's `external_id` field.
:::

## Integration with Okta

To configure Okta SCIM provisioning:

1. In Okta Admin Console, go to **Applications** > your app > **Provisioning**
2. Click **Configure API Integration**
3. Enter:
   - **SCIM 2.0 Base URL**: `https://idp.example.com/scim/v2`
   - **API Token**: your SCIM bearer token
4. Click **Test API Credentials**
5. Enable desired provisioning features:
   - Create Users
   - Update User Attributes
   - Deactivate Users
6. Configure attribute mappings under **To App** tab

:::tip
Okta uses `userName` as the primary identifier. Ensure email addresses are consistent between Okta and xavyo.
:::

## Attribute Mapping

### User Schema

| SCIM Attribute | xavyo Field | Type | Required |
|----------------|-------------|------|----------|
| `userName` | `email` | string | Yes |
| `name.givenName` | `first_name` | string | No |
| `name.familyName` | `last_name` | string | No |
| `displayName` | `display_name` | string | No |
| `active` | `is_active` | boolean | No |
| `emails[primary].value` | `email` | string | Yes |
| `externalId` | `external_id` | string | No |

### Group Schema

| SCIM Attribute | xavyo Field | Type | Required |
|----------------|-------------|------|----------|
| `displayName` | `display_name` | string | Yes |
| `members[].value` | `user_id` | UUID | No |
