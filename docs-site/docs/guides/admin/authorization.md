---
title: Authorization & Access Control
description: Guide to role-based access control, entitlements, separation of duties, delegation, meta-roles, identity archetypes, and the authorization decision engine in xavyo-idp.
sidebar_position: 4
---

# Authorization & Access Control

## Overview

xavyo-idp provides a comprehensive authorization framework that goes beyond simple RBAC. It includes hierarchical roles with inheritance, fine-grained entitlements, Separation of Duties (SoD) enforcement, delegated administration, meta-roles with automatic membership, parametric roles, identity archetypes for user classification, and a real-time authorization decision engine.

All authorization data is tenant-isolated and managed through the governance API.

## Role-Based Access Control

### Creating Roles

Roles are the primary unit of access control. They can be organized in hierarchies where child roles inherit permissions from parents.

```bash
curl -X POST https://your-domain.com/governance/roles \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Software Engineer",
    "description": "Standard engineering access"
  }'
```

**Response (201):**
```json
{
  "id": "role-uuid",
  "name": "Software Engineer",
  "description": "Standard engineering access",
  "version": 1,
  "hierarchy_depth": 0,
  "created_at": "2026-02-07T12:00:00Z"
}
```

### Role Hierarchies

Create child roles to model organizational access hierarchies:

```bash
curl -X POST https://your-domain.com/governance/roles \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Senior Software Engineer",
    "description": "Extended engineering access",
    "parent_role_id": "parent-role-uuid"
  }'
```

### Role Hierarchy Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create role | POST | `/governance/roles` |
| List roles | GET | `/governance/roles` |
| Get role | GET | `/governance/roles/{role_id}` |
| Update role | PUT | `/governance/roles/{role_id}` |
| Get role tree | GET | `/governance/roles/tree` |
| Get children | GET | `/governance/roles/{role_id}/children` |
| Get ancestors | GET | `/governance/roles/{role_id}/ancestors` |
| Get descendants | GET | `/governance/roles/{role_id}/descendants` |
| Move role | POST | `/governance/roles/{role_id}/move` |
| Impact analysis | GET | `/governance/roles/{role_id}/impact` |

### Role Assignments

Assign roles to users with optional justification:

```bash
curl -X POST https://your-domain.com/governance/assignments \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "user_id": "user-uuid",
    "role_id": "role-uuid",
    "justification": "Approved by manager"
  }'
```

Bulk assignment is also supported:

```bash
curl -X POST https://your-domain.com/governance/assignments/bulk \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "assignments": [
      {"user_id": "uuid-1", "role_id": "role-uuid"},
      {"user_id": "uuid-2", "role_id": "role-uuid"}
    ]
  }'
```

## Entitlement Management

Entitlements represent fine-grained permissions that can be associated with roles.

```bash
# Create an entitlement
curl -X POST https://your-domain.com/governance/entitlements \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "read:customer-data",
    "description": "Read access to customer records",
    "application_id": "app-uuid"
  }'

# Link entitlement to role
curl -X POST https://your-domain.com/governance/roles/{role_id}/entitlements \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"entitlement_id": "entitlement-uuid"}'
```

### Effective Entitlements

View the complete set of entitlements a role provides, including inherited entitlements from parent roles:

```bash
curl https://your-domain.com/governance/roles/{role_id}/effective-entitlements \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

## Separation of Duties (SoD)

SoD rules prevent users from holding conflicting roles or entitlements simultaneously.

### Creating SoD Rules

```bash
curl -X POST https://your-domain.com/governance/sod-rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Finance Segregation",
    "description": "Users cannot hold both Accounts Payable and Accounts Receivable",
    "rule_type": "mutual_exclusion",
    "left_role_id": "ap-role-uuid",
    "right_role_id": "ar-role-uuid",
    "enforcement": "hard"
  }'
```

### SoD Operations

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create rule | POST | `/governance/sod-rules` |
| List rules | GET | `/governance/sod-rules` |
| Get rule | GET | `/governance/sod-rules/{id}` |
| Update rule | PUT | `/governance/sod-rules/{id}` |
| Enable rule | POST | `/governance/sod-rules/{id}/enable` |
| Disable rule | POST | `/governance/sod-rules/{id}/disable` |
| Scan for violations | POST | `/governance/sod-rules/{id}/scan` |
| Check SoD | POST | `/governance/sod-check` |
| List violations | GET | `/governance/sod-violations` |
| Remediate violation | POST | `/governance/sod-violations/{id}/remediate` |
| Create exemption | POST | `/governance/sod-exemptions` |
| Revoke exemption | POST | `/governance/sod-exemptions/{id}/revoke` |

### SoD Check Before Assignment

Check whether a proposed role assignment would create violations:

```bash
curl -X POST https://your-domain.com/governance/sod-check \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "user_id": "user-uuid",
    "proposed_role_id": "role-uuid"
  }'
```

## Delegation & Power of Attorney

Delegation allows administrators to temporarily grant their permissions to other users.

### Creating a Delegation

```bash
curl -X POST https://your-domain.com/governance/delegations \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "delegate_user_id": "delegate-uuid",
    "permissions": ["users:read", "users:write"],
    "valid_from": "2026-02-07T00:00:00Z",
    "valid_until": "2026-03-07T00:00:00Z",
    "justification": "Covering for vacation"
  }'
```

:::info
Delegation permissions use a colon separator (e.g., `users:read`), not a dot separator.
:::

### Admin Delegation Management

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create assignment | POST | `/admin/delegation/assignments` |
| List assignments | GET | `/admin/delegation/assignments` |
| Get assignment | GET | `/admin/delegation/assignments/{id}` |
| Revoke assignment | DELETE | `/admin/delegation/assignments/{id}` |
| Check permission | POST | `/admin/delegation/check-permission` |
| List permissions | GET | `/admin/delegation/permissions` |
| Permissions by category | GET | `/admin/delegation/permissions/{category}` |
| Audit log | GET | `/admin/delegation/audit-log` |
| Role templates | GET/POST | `/admin/delegation/role-templates` |
| User permissions | GET | `/admin/delegation/users/{user_id}/permissions` |

:::warning
Delegation and branding endpoints require the `super_admin` role, not just `admin`.
:::

## Meta-Roles

Meta-roles automatically assign roles to users based on criteria expressions, such as department, location, or custom attributes.

```bash
curl -X POST https://your-domain.com/governance/meta-roles \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "All Engineers Meta-Role",
    "description": "Automatically assigns base engineering access",
    "target_role_id": "engineer-role-uuid",
    "enabled": true
  }'
```

### Meta-Role Criteria

```bash
curl -X POST https://your-domain.com/governance/meta-roles/{id}/criteria \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "attribute": "department",
    "operator": "equals",
    "value": "Engineering"
  }'
```

### Meta-Role Operations

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create | POST | `/governance/meta-roles` |
| List | GET | `/governance/meta-roles` |
| Get | GET | `/governance/meta-roles/{id}` |
| Update | PUT | `/governance/meta-roles/{id}` |
| Enable | POST | `/governance/meta-roles/{id}/enable` |
| Disable | POST | `/governance/meta-roles/{id}/disable` |
| Criteria | GET/POST | `/governance/meta-roles/{id}/criteria` |
| Entitlements | GET/POST | `/governance/meta-roles/{id}/entitlements` |
| Simulate | POST | `/governance/meta-roles/{id}/simulate` |
| Re-evaluate | POST | `/governance/meta-roles/{id}/reevaluate` |
| Cascade | POST | `/governance/meta-roles/{id}/cascade` |
| Conflicts | GET | `/governance/meta-roles/conflicts` |
| Constraints | GET/POST | `/governance/meta-roles/{id}/constraints` |
| Inheritances | GET | `/governance/meta-roles/{id}/inheritances` |

## Parametric Roles

Parametric roles extend standard roles with configurable parameters, allowing fine-grained access control per assignment.

```bash
# Define parameters for a role
curl -X POST https://your-domain.com/governance/roles/{role_id}/parameters \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "region",
    "data_type": "string",
    "allowed_values": ["us-east", "us-west", "eu-west"],
    "required": true
  }'

# Validate parameter values
curl -X POST https://your-domain.com/governance/roles/{role_id}/parameters/validate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"region": "us-east"}'
```

## Role Constructions & Inducements

Role constructions define how roles compose (conditional inclusion), while inducements specify additional entitlements granted when a role is assigned.

| Operation | Method | Endpoint |
|-----------|--------|----------|
| List constructions | GET | `/governance/roles/{role_id}/constructions` |
| List inducements | GET | `/governance/roles/{role_id}/inducements` |
| Inheritance blocks | GET/POST | `/governance/roles/{role_id}/inheritance-blocks` |

## Identity Archetypes

Archetypes classify users into categories (Employee, Contractor, Vendor) with associated lifecycle policies, naming patterns, and attribute mappings.

```bash
curl -X POST https://your-domain.com/governance/archetypes \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Contractor",
    "naming_pattern": "c.{last_name}",
    "lifecycle_policy": {
      "default_validity_days": 90,
      "max_validity_days": 365,
      "auto_extension_allowed": false,
      "extension_requires_approval": true,
      "on_physical_user_deactivation": "cascade_deactivate"
    },
    "attribute_mappings": {
      "propagate": [{"source": "company", "target": "organization", "mode": "always"}],
      "computed": [{"target": "display_name", "template": "{first_name} {last_name}"}]
    }
  }'
```

## Authorization Decision Engine

### Checking Authorization

```bash
# Admin: check authorization for any user
curl -X POST https://your-domain.com/admin/authorization/check \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"user_id": "uuid", "resource": "customers", "action": "read"}'

# Admin: bulk check
curl -X POST https://your-domain.com/admin/authorization/bulk-check \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "checks": [
      {"user_id": "uuid", "resource": "customers", "action": "read"},
      {"user_id": "uuid", "resource": "customers", "action": "delete"}
    ]
  }'

# Self-check: "can I?"
curl -X POST https://your-domain.com/authorization/can-i \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"resource": "reports", "action": "view"}'
```

### Authorization Policy Management

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create policy | POST | `/admin/authorization/policies` |
| List policies | GET | `/admin/authorization/policies` |
| Get policy | GET | `/admin/authorization/policies/{id}` |
| Update policy | PUT | `/admin/authorization/policies/{id}` |
| Delete policy | DELETE | `/admin/authorization/policies/{id}` |
| Create mapping | POST | `/admin/authorization/mappings` |
| List mappings | GET | `/admin/authorization/mappings` |

## Security Considerations

- **SoD enforcement** can be `hard` (blocks the assignment) or `soft` (logs a violation but allows the assignment). Use hard enforcement for regulatory compliance.
- **Delegation time bounds** are enforced at the database level. Expired delegations are automatically inactive.
- **Self-approval prevention**: Users cannot approve their own delegation or access requests. A database unique constraint enforces this.
- **Role version control**: Role updates increment the version number, enabling optimistic concurrency control.
- **Expression parser safety**: Meta-role criteria expressions have a recursion depth limit of 64 to prevent stack overflow attacks.
- **Admin role enforcement**: All mutation endpoints (create, update, delete) require the `admin` role. Non-admin users receive `403 Forbidden`.

## Related

- [Governance](./governance.md) -- Lifecycle management, certification campaigns, and compliance
- [User Management](./user-management.md) -- User CRUD and role assignment
- [Tenant Setup](./tenant-setup.md) -- Tenant-level security policies
