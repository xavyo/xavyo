---
title: User & Group Management
description: Guide to user CRUD operations, group administration, bulk operations, import/export, and invitation management in xavyo-idp.
sidebar_position: 2
---

# User & Group Management

## Overview

xavyo-idp provides comprehensive user and group management through both a REST Admin API and a SCIM 2.0 interface. Administrators can create, update, search, and delete users; organize them into groups; perform bulk operations; and import or export user data in CSV format.

All user operations are scoped to the authenticated administrator's tenant, enforced by the `X-Tenant-ID` header and database-level Row-Level Security.

## User CRUD Operations

### Creating a User

```bash
curl -X POST https://your-domain.com/admin/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "email": "jane.doe@example.com",
    "password": "SecureP@ssw0rd!",
    "roles": ["user", "editor"],
    "display_name": "Jane Doe"
  }'
```

**Response (201 Created):**
```json
{
  "id": "user-uuid",
  "email": "jane.doe@example.com",
  "display_name": "Jane Doe",
  "roles": ["user", "editor"],
  "is_active": true,
  "email_verified": false,
  "created_at": "2026-02-07T12:00:00Z"
}
```

:::info
Users created via the admin API may have `email_verified` set to `false`. They will receive a verification email if the email service is configured.
:::

### Retrieving a User

```bash
curl https://your-domain.com/admin/users/{user_id} \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Listing Users

```bash
curl "https://your-domain.com/admin/users?limit=20&offset=0" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

**Response:**
```json
{
  "users": [
    {
      "id": "user-uuid",
      "email": "jane.doe@example.com",
      "display_name": "Jane Doe",
      "roles": ["user", "editor"],
      "is_active": true
    }
  ],
  "pagination": {
    "total_count": 42,
    "limit": 20,
    "offset": 0
  }
}
```

:::tip
The maximum page size is 100. Requests for larger limits are automatically clamped.
:::

### Updating a User

Updates are partial -- only the fields you include will be changed. Existing roles and attributes are preserved unless explicitly overwritten.

```bash
curl -X PUT https://your-domain.com/admin/users/{user_id} \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "display_name": "Jane M. Doe",
    "roles": ["user", "editor", "manager"],
    "is_active": true
  }'
```

### Disabling a User

Set `is_active` to `false` to disable a user without deleting their data:

```bash
curl -X PUT https://your-domain.com/admin/users/{user_id} \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"is_active": false}'
```

### Deleting a User

Deletion is a soft delete that deactivates the user account:

```bash
curl -X DELETE https://your-domain.com/admin/users/{user_id} \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### User Endpoints Summary

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create user | POST | `/admin/users` |
| List users | GET | `/admin/users` |
| Get user | GET | `/admin/users/{id}` |
| Update user | PUT | `/admin/users/{id}` |
| Delete user | DELETE | `/admin/users/{id}` |
| Custom attributes | GET/PUT | `/admin/users/{id}/custom-attributes` |
| WebAuthn credentials | GET | `/admin/users/{id}/webauthn/credentials` |
| Delete WebAuthn credential | DELETE | `/admin/users/{id}/webauthn/credentials/{cred_id}` |

## Custom Attributes

Define and manage custom attribute schemas for your tenant, then assign values to individual users.

### Defining Attribute Schemas

```bash
curl -X POST https://your-domain.com/admin/attribute-definitions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "department",
    "display_name": "Department",
    "data_type": "string",
    "required": false,
    "searchable": true
  }'
```

### Attribute Definition Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create definition | POST | `/admin/attribute-definitions` |
| List definitions | GET | `/admin/attribute-definitions` |
| Get definition | GET | `/admin/attribute-definitions/{id}` |
| Update definition | PUT | `/admin/attribute-definitions/{id}` |
| Delete definition | DELETE | `/admin/attribute-definitions/{id}` |
| Seed well-known | POST | `/admin/attribute-definitions/seed-wellknown` |
| Audit missing required | GET | `/admin/attribute-definitions/audit/missing-required` |

### Bulk Updating Custom Attributes

```bash
curl -X POST https://your-domain.com/admin/custom-attributes/bulk-update \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "updates": [
      {"user_id": "uuid-1", "attributes": {"department": "Engineering"}},
      {"user_id": "uuid-2", "attributes": {"department": "Marketing"}}
    ]
  }'
```

## Group Management

Groups organize users for access control, SCIM provisioning, and governance policies. Groups use `display_name` as their primary label and support hierarchical nesting.

### Creating a Group (via SCIM)

Groups are created through the SCIM 2.0 interface:

```bash
curl -X POST https://your-domain.com/scim/v2/Groups \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    "displayName": "Engineering Team",
    "members": [
      {"value": "user-uuid-1"},
      {"value": "user-uuid-2"}
    ]
  }'
```

### Group Hierarchy

Groups support parent-child relationships for organizational modeling:

| Operation | Method | Endpoint |
|-----------|--------|----------|
| List root groups | GET | `/groups/roots` |
| Get group children | GET | `/groups/{group_id}/children` |
| Get group ancestors | GET | `/groups/{group_id}/ancestors` |
| Get subtree | GET | `/groups/{group_id}/subtree` |
| Get subtree members | GET | `/groups/{group_id}/subtree-members` |
| Set parent | PUT | `/groups/{group_id}/parent` |

### Managing Members

Add or remove members using SCIM PATCH operations:

```bash
curl -X PATCH https://your-domain.com/scim/v2/Groups/{group_id} \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    "Operations": [
      {
        "op": "add",
        "path": "members",
        "value": [{"value": "new-user-uuid"}]
      }
    ]
  }'
```

## SCIM 2.0 Provisioning

xavyo-idp implements a full SCIM 2.0 server for automated user and group provisioning from identity providers such as Microsoft Entra ID, Okta, and OneLogin.

### SCIM Token Management

Before using SCIM, create a bearer token:

```bash
curl -X POST https://your-domain.com/admin/scim/tokens \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"name": "Entra ID SCIM Integration"}'
```

### SCIM User Operations

| Operation | Method | Endpoint | Content-Type |
|-----------|--------|----------|--------------|
| Create user | POST | `/scim/v2/Users` | `application/scim+json` |
| List/filter users | GET | `/scim/v2/Users` | -- |
| Get user | GET | `/scim/v2/Users/{id}` | -- |
| Replace user | PUT | `/scim/v2/Users/{id}` | `application/scim+json` |
| Patch user | PATCH | `/scim/v2/Users/{id}` | `application/scim+json` |
| Delete user | DELETE | `/scim/v2/Users/{id}` | -- |

### SCIM User with Enterprise Extension

```bash
curl -X POST https://your-domain.com/scim/v2/Users \
  -H "Content-Type: application/scim+json" \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "schemas": [
      "urn:ietf:params:scim:schemas:core:2.0:User",
      "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
    ],
    "userName": "jane.doe@example.com",
    "displayName": "Jane Doe",
    "name": {"givenName": "Jane", "familyName": "Doe"},
    "emails": [{"value": "jane.doe@example.com", "type": "work", "primary": true}],
    "active": true,
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
      "department": "Engineering",
      "costCenter": "CC-1234",
      "employeeNumber": "EMP-5678"
    }
  }'
```

### SCIM Filtering and Sorting

```
GET /scim/v2/Users?filter=userName eq "jane@example.com"
GET /scim/v2/Users?filter=displayName co "Jane"
GET /scim/v2/Users?startIndex=1&count=50&sortBy=userName&sortOrder=ascending
```

:::info
Pagination count is clamped to a maximum of 100 items per page.
:::

## User Import & Export

### Importing Users from CSV

Create an import job to bulk-create users from a CSV file:

```bash
curl -X POST https://your-domain.com/admin/import/jobs \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "type": "users",
    "format": "csv",
    "data": "email,display_name,roles\njane@example.com,Jane Doe,user\njohn@example.com,John Smith,\"user,editor\""
  }'
```

### Tracking Import Jobs

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create import job | POST | `/admin/import/jobs` |
| List import jobs | GET | `/admin/import/jobs` |
| Get job status | GET | `/admin/import/jobs/{id}` |
| List job errors | GET | `/admin/import/jobs/{id}/errors` |
| Download error report | GET | `/admin/import/jobs/{id}/errors/download` |

### Exporting Users

```bash
curl https://your-domain.com/admin/export/users \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -H "Accept: text/csv"
```

## Invitation System

Send email invitations for users to self-register into your tenant.

### Creating an Invitation

```bash
curl -X POST https://your-domain.com/admin/invitations \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "email": "new.hire@example.com",
    "roles": ["user"],
    "message": "Welcome to the team!"
  }'
```

### Bulk Resend Invitations

```bash
curl -X POST https://your-domain.com/admin/invitations/bulk-resend \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "invitation_ids": ["invite-uuid-1", "invite-uuid-2"]
  }'
```

## Security Considerations

- **Email uniqueness** is enforced per tenant with case-insensitive comparison. The same email can exist in different tenants.
- **Password requirements** include minimum length, uppercase, lowercase, numbers, and special characters. The exact policy is configurable per tenant.
- **Admin role required** for all user management endpoints under `/admin/users`. Non-admin users receive `403 Forbidden`.
- **Cross-tenant access** is blocked at the database level. Administrators can only see and modify users within their own tenant.
- **Import files** are validated for CSV injection protection (cells starting with `=`, `+`, `-`, `@` are sanitized).
- **Error CSV downloads** are capped at 50,000 rows to prevent unbounded memory usage.
- **super_admin role** restriction: Only super_admin users can assign or modify the `super_admin` role in create/update operations.

## Related

- [Tenant Setup](./tenant-setup.md) -- Configuring tenant-level policies that affect all users
- [Authentication](./authentication.md) -- Password policies, MFA enrollment, and login configuration
- [Authorization](./authorization.md) -- Role-based access control and entitlements
- [Connectors](./connectors.md) -- SCIM outbound provisioning to external systems
