---
title: Governance & Compliance
description: Guide to identity governance including lifecycle management, certification campaigns, role mining, access requests, approval workflows, risk scoring, and GDPR compliance in xavyo-idp.
sidebar_position: 6
---

# Governance & Compliance

## Overview

xavyo-idp provides a comprehensive Identity Governance and Administration (IGA) framework that covers the full lifecycle of identity and access management. This includes lifecycle state machines, certification campaigns for periodic access reviews, role mining for discovering optimal role structures, a self-service access request catalog, multi-level approval workflows with escalation, risk scoring for access decisions, and GDPR data protection reporting.

All governance features are tenant-isolated. Most endpoints are under the `/governance` prefix, with bulk actions under `/admin/bulk-actions`.

## Lifecycle Management

### Lifecycle Configurations

Define lifecycle state machines that govern how users transition through states (e.g., active, suspended, terminated):

```bash
# Create a lifecycle configuration
curl -X POST https://your-domain.com/governance/lifecycle/configs \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Employee Lifecycle",
    "object_type": "user",
    "states": ["onboarding", "active", "suspended", "offboarding", "terminated"],
    "initial_state": "onboarding",
    "transitions": [
      {"from": "onboarding", "to": "active", "requires_approval": false},
      {"from": "active", "to": "suspended", "requires_approval": true},
      {"from": "suspended", "to": "active", "requires_approval": true},
      {"from": "active", "to": "offboarding", "requires_approval": true},
      {"from": "offboarding", "to": "terminated", "requires_approval": false}
    ]
  }'
```

### Lifecycle Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create config | POST | `/governance/lifecycle/configs` |
| List configs | GET | `/governance/lifecycle/configs` |
| Get config | GET | `/governance/lifecycle/configs/{id}` |
| Update config | PUT | `/governance/lifecycle/configs/{id}` |
| Delete config | DELETE | `/governance/lifecycle/configs/{id}` |
| Request transition | POST | `/governance/lifecycle/transition-requests` |
| List transitions | GET | `/governance/lifecycle/transition-requests` |
| Get transition | GET | `/governance/lifecycle/transition-requests/{id}` |
| Approve transition | POST | `/governance/lifecycle/transition-requests/{id}/approve` |
| Reject transition | POST | `/governance/lifecycle/transition-requests/{id}/reject` |
| Execute transition | POST | `/governance/lifecycle/transition-requests/{id}/execute` |
| Scheduled transitions | GET | `/governance/lifecycle/scheduled` |

:::info
The `object_type` field accepts `user`, `entitlement`, or `role`, allowing lifecycle policies for different identity objects.
:::

## Certification Campaigns

Certification campaigns enable periodic access reviews where reviewers verify that users still need their assigned roles and entitlements.

### Creating a Campaign

```bash
curl -X POST https://your-domain.com/governance/certifications/campaigns \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Q1 2026 Access Review",
    "description": "Quarterly review of all role assignments",
    "campaign_type": "user_access",
    "reviewer_strategy": "manager",
    "due_date": "2026-03-31T00:00:00Z",
    "auto_revoke_on_reject": true
  }'
```

### Campaign Lifecycle

1. **Create** -- Define the campaign scope, reviewers, and due date
2. **Launch** -- Generate review items for all in-scope assignments
3. **Review** -- Reviewers certify or revoke each assignment
4. **Complete** -- Campaign closes; revoked assignments are automatically removed

```bash
# Launch campaign
curl -X POST https://your-domain.com/governance/certifications/campaigns/{id}/launch \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# List review items
curl https://your-domain.com/governance/certifications/campaigns/{id}/items \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Decide on a review item (certify or revoke)
curl -X POST https://your-domain.com/governance/certifications/items/{item_id}/decide \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "decision": "certify",
    "comment": "Access still required for current project"
  }'

# Get campaign summary/progress
curl https://your-domain.com/governance/certifications/campaigns/{id}/summary \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Certification Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create campaign | POST | `/governance/certifications/campaigns` |
| List campaigns | GET | `/governance/certifications/campaigns` |
| Get campaign | GET | `/governance/certifications/campaigns/{id}` |
| Launch campaign | POST | `/governance/certifications/campaigns/{id}/launch` |
| Get summary | GET | `/governance/certifications/campaigns/{id}/summary` |
| List items | GET | `/governance/certifications/campaigns/{id}/items` |
| Decide on item | POST | `/governance/certifications/items/{id}/decide` |
| Cancel campaign | POST | `/governance/certifications/campaigns/{id}/cancel` |
| My pending reviews | GET | `/governance/certifications/my-pending` |

### Micro-Certifications

For targeted reviews of specific roles or entitlements:

```bash
curl -X POST https://your-domain.com/governance/certifications/micro \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "target_type": "role",
    "target_id": "role-uuid",
    "reviewer_id": "reviewer-uuid",
    "reason": "Role permissions changed"
  }'
```

## Role Mining

Role mining analyzes existing user-entitlement assignments to discover optimal role structures, identify excessive privileges, and suggest consolidation opportunities.

### Creating a Mining Job

```bash
curl -X POST https://your-domain.com/governance/role-mining/jobs \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Q1 Role Discovery",
    "parameters": {
      "min_support": 0.1,
      "min_confidence": 0.5
    }
  }'
```

### Mining Job Lifecycle

```bash
# Run the job
curl -X POST https://your-domain.com/governance/role-mining/jobs/{job_id}/run \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# View discovered role candidates
curl https://your-domain.com/governance/role-mining/jobs/{job_id}/candidates \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Promote a candidate to an actual role
curl -X POST https://your-domain.com/governance/role-mining/candidates/{candidate_id}/promote \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"role_name": "Discovered Engineering Role"}'

# Dismiss a candidate
curl -X POST https://your-domain.com/governance/role-mining/candidates/{candidate_id}/dismiss \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"reason": "Too broad, not actionable"}'
```

### Mining Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create job | POST | `/governance/role-mining/jobs` |
| List jobs | GET | `/governance/role-mining/jobs` |
| Get job | GET | `/governance/role-mining/jobs/{id}` |
| Run job | POST | `/governance/role-mining/jobs/{id}/run` |
| Cancel job | DELETE | `/governance/role-mining/jobs/{id}` |
| List candidates | GET | `/governance/role-mining/jobs/{id}/candidates` |
| Get candidate | GET | `/governance/role-mining/candidates/{id}` |
| Promote candidate | POST | `/governance/role-mining/candidates/{id}/promote` |
| Dismiss candidate | POST | `/governance/role-mining/candidates/{id}/dismiss` |
| List patterns | GET | `/governance/role-mining/jobs/{id}/patterns` |
| Get pattern | GET | `/governance/role-mining/patterns/{id}` |
| Excessive privileges | GET | `/governance/role-mining/jobs/{id}/excessive-privileges` |
| Review privilege | POST | `/governance/role-mining/excessive-privileges/{id}/review` |
| Consolidation suggestions | GET | `/governance/role-mining/jobs/{id}/consolidation-suggestions` |
| Dismiss suggestion | POST | `/governance/role-mining/consolidation-suggestions/{id}/dismiss` |

### Policy Simulations

Simulate the impact of role changes before applying them:

```bash
# Create a simulation
curl -X POST https://your-domain.com/governance/role-mining/simulations \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Add Engineering Role",
    "scenario_type": "add_role",
    "changes": {
      "role_name": "Platform Engineer",
      "role_description": "Platform engineering access",
      "entitlement_ids": ["ent-uuid-1", "ent-uuid-2"]
    }
  }'

# Run the simulation
curl -X POST https://your-domain.com/governance/role-mining/simulations/{id}/run \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Get simulation results
curl https://your-domain.com/governance/role-mining/simulations/{id}/results \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

## Identity Merge Operations

When duplicate identities are detected, merge operations allow combining them into a single canonical identity:

```bash
# Create a merge operation
curl -X POST https://your-domain.com/governance/identity-merge/operations \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "primary_user_id": "canonical-user-uuid",
    "secondary_user_ids": ["duplicate-uuid-1", "duplicate-uuid-2"],
    "merge_strategy": "keep_primary"
  }'
```

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create merge | POST | `/governance/identity-merge/operations` |
| List merges | GET | `/governance/identity-merge/operations` |
| Get merge | GET | `/governance/identity-merge/operations/{id}` |
| Execute merge | POST | `/governance/identity-merge/operations/{id}/execute` |
| Rollback merge | POST | `/governance/identity-merge/operations/{id}/rollback` |

## Personas

Personas allow a single user to maintain multiple identity contexts with different attributes and access levels:

```bash
# Create a persona
curl -X POST https://your-domain.com/governance/personas \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "user_id": "user-uuid",
    "name": "Admin Persona",
    "attributes": {"department": "IT", "role_context": "administration"}
  }'
```

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create persona | POST | `/governance/personas` |
| List personas | GET | `/governance/personas` |
| Get persona | GET | `/governance/personas/{id}` |
| Update persona | PUT | `/governance/personas/{id}` |
| Delete persona | DELETE | `/governance/personas/{id}` |
| Activate persona | POST | `/governance/personas/{id}/activate` |
| Deactivate persona | POST | `/governance/personas/{id}/deactivate` |

## Access Request Catalog

### Catalog Management

The access request catalog allows administrators to publish items (roles, entitlements, resources) that users can request through a self-service workflow.

```bash
# Create a catalog category
curl -X POST https://your-domain.com/governance/admin/catalog/categories \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Engineering Tools",
    "description": "Access to engineering platforms and tools"
  }'

# Create a catalog item
curl -X POST https://your-domain.com/governance/admin/catalog/items \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "GitHub Enterprise Access",
    "description": "Read/write access to organization repositories",
    "item_type": "entitlement",
    "target_id": "entitlement-uuid",
    "category_id": "category-uuid",
    "requires_approval": true,
    "approval_levels": 1,
    "risk_level": "medium"
  }'
```

### Self-Service Access Requests

Users can browse the catalog and submit access requests:

```bash
# Browse catalog
curl https://your-domain.com/governance/catalog \
  -H "Authorization: Bearer $USER_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Submit an access request
curl -X POST https://your-domain.com/governance/access-requests \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "catalog_item_id": "item-uuid",
    "justification": "Need access for Q1 project deliverables"
  }'
```

### Approval Workflows

Administrators review and approve or reject access requests:

```bash
# List pending approvals
curl https://your-domain.com/governance/access-requests?status=pending \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Approve a request
curl -X POST https://your-domain.com/governance/access-requests/{id}/approve \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"comment": "Approved for current sprint"}'

# Reject a request
curl -X POST https://your-domain.com/governance/access-requests/{id}/reject \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"comment": "Contact your manager for alternative access"}'
```

### Escalation

When access requests are not reviewed within the configured timeout, they are automatically escalated to approval groups:

```bash
# Create an approval group
curl -X POST https://your-domain.com/governance/escalation/approval-groups \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Engineering Managers",
    "member_ids": ["manager-uuid-1", "manager-uuid-2"]
  }'

# Create an escalation policy
curl -X POST https://your-domain.com/governance/escalation/policies \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Standard Escalation",
    "default_timeout_secs": 86400,
    "levels": [
      {"level": 1, "approval_group_id": "group-uuid", "timeout_secs": 43200}
    ]
  }'
```

:::warning
The `default_timeout_secs` must be greater than the `warning_threshold` (default 4 hours / 14400 seconds).
:::

## Risk Scoring

Risk scores are computed for access assignments based on factors like entitlement sensitivity, user history, and SoD violations:

```bash
# Get risk score for a user
curl https://your-domain.com/governance/risk/users/{user_id}/score \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Get risk distribution across the tenant
curl https://your-domain.com/governance/risk/distribution \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# List high-risk assignments
curl "https://your-domain.com/governance/risk/high-risk?threshold=80&limit=20" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

## Role Inducements

Role inducements define automatic role grants: when a parent role is assigned to a user, all induced child roles are automatically granted as well. Inducements support recursive traversal, enable/disable per inducement, and cycle detection.

### Creating a Role Inducement

```bash
curl -X POST https://your-domain.com/governance/roles/{role_id}/inducements \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "induced_role_id": "child-role-uuid",
    "description": "Automatically grants read access when engineering role is assigned"
  }'
```

### Managing Inducements

Individual inducements can be enabled or disabled without deleting them:

```bash
# Disable an inducement (stops automatic granting)
curl -X POST https://your-domain.com/governance/roles/{role_id}/inducements/{inducement_id}/disable \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Re-enable an inducement
curl -X POST https://your-domain.com/governance/roles/{role_id}/inducements/{inducement_id}/enable \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Viewing Induced Roles (Recursive)

Get the full tree of induced roles for a given role, including transitively induced roles:

```bash
curl https://your-domain.com/governance/roles/{role_id}/induced-roles \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Role Inducement Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| List inducements | GET | `/governance/roles/{role_id}/inducements` |
| Get inducement | GET | `/governance/roles/{role_id}/inducements/{id}` |
| Create inducement | POST | `/governance/roles/{role_id}/inducements` |
| Delete inducement | DELETE | `/governance/roles/{role_id}/inducements/{id}` |
| Enable inducement | POST | `/governance/roles/{role_id}/inducements/{id}/enable` |
| Disable inducement | POST | `/governance/roles/{role_id}/inducements/{id}/disable` |
| Get induced roles | GET | `/governance/roles/{role_id}/induced-roles` |

:::info
Cycle detection prevents creating inducements that would form circular dependencies (e.g., Role A induces Role B which induces Role A). The API returns `400 Bad Request` if a cycle is detected.
:::

## Power of Attorney

Power of Attorney (PoA) enables delegated administration where a user (donor) grants another user (attorney) the ability to act on their behalf for a defined scope and duration.

### Granting a Power of Attorney

```bash
curl -X POST https://your-domain.com/governance/power-of-attorney \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $USER_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "attorney_id": "attorney-user-uuid",
    "scope": ["users:read", "users:write"],
    "duration_hours": 24,
    "reason": "Covering during vacation"
  }'
```

### Assuming and Dropping Identity

The attorney can assume the donor's identity to perform actions within the granted scope:

```bash
# Assume the donor's identity
curl -X POST https://your-domain.com/governance/power-of-attorney/{id}/assume \
  -H "Authorization: Bearer $ATTORNEY_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Check current assumption
curl https://your-domain.com/governance/power-of-attorney/current-assumption \
  -H "Authorization: Bearer $ATTORNEY_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Drop the assumed identity
curl -X POST https://your-domain.com/governance/power-of-attorney/drop \
  -H "Authorization: Bearer $ATTORNEY_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Power of Attorney Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Grant PoA | POST | `/governance/power-of-attorney` |
| List my PoAs | GET | `/governance/power-of-attorney` |
| Get PoA | GET | `/governance/power-of-attorney/{id}` |
| Revoke PoA | POST | `/governance/power-of-attorney/{id}/revoke` |
| Extend PoA | POST | `/governance/power-of-attorney/{id}/extend` |
| Assume identity | POST | `/governance/power-of-attorney/{id}/assume` |
| Drop identity | POST | `/governance/power-of-attorney/drop` |
| Current assumption | GET | `/governance/power-of-attorney/current-assumption` |
| PoA audit trail | GET | `/governance/power-of-attorney/{id}/audit` |
| Admin list all PoAs | GET | `/governance/admin/power-of-attorney` |
| Admin revoke PoA | POST | `/governance/admin/power-of-attorney/{id}/revoke` |

:::warning
Users cannot grant a PoA to themselves. All PoA actions are recorded in the audit trail for compliance.
:::

## Bulk Actions

Execute governance operations in bulk with expression-based targeting, preview, and cancellation:

### Creating a Bulk Action

```bash
curl -X POST https://your-domain.com/admin/bulk-actions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "action_type": "revoke_role",
    "target_ids": ["assignment-uuid-1", "assignment-uuid-2"],
    "justification": "Quarterly cleanup"
  }'
```

### Bulk Action Workflow

1. **Create** the bulk action with target IDs and justification
2. **Preview** the impact before execution
3. **Execute** the action (processes targets in batch)
4. **Monitor** progress or cancel if needed

```bash
# Validate a targeting expression
curl -X POST https://your-domain.com/admin/bulk-actions/validate-expression \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"expression": "role == \"contractor\" AND department == \"engineering\""}'

# Preview the bulk action (see affected targets)
curl -X POST https://your-domain.com/admin/bulk-actions/{id}/preview \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Execute the bulk action
curl -X POST https://your-domain.com/admin/bulk-actions/{id}/execute \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Cancel an in-progress bulk action
curl -X POST https://your-domain.com/admin/bulk-actions/{id}/cancel \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Bulk Action Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create bulk action | POST | `/admin/bulk-actions` |
| List bulk actions | GET | `/admin/bulk-actions` |
| Get bulk action | GET | `/admin/bulk-actions/{id}` |
| Delete bulk action | DELETE | `/admin/bulk-actions/{id}` |
| Validate expression | POST | `/admin/bulk-actions/validate-expression` |
| Preview bulk action | POST | `/admin/bulk-actions/{id}/preview` |
| Execute bulk action | POST | `/admin/bulk-actions/{id}/execute` |
| Cancel bulk action | POST | `/admin/bulk-actions/{id}/cancel` |

## Object Templates

Object templates define reusable configuration templates for governance objects:

```bash
# Create a template
curl -X POST https://your-domain.com/governance/object-templates \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Standard Role Template",
    "template_type": "role",
    "template_data": {
      "description_pattern": "{name} - standard access",
      "default_entitlements": ["basic-read", "basic-write"]
    }
  }'
```

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create template | POST | `/governance/object-templates` |
| List templates | GET | `/governance/object-templates` |
| Get template | GET | `/governance/object-templates/{id}` |
| Update template | PUT | `/governance/object-templates/{id}` |
| Delete template | DELETE | `/governance/object-templates/{id}` |

## GDPR & Data Protection

### Data Protection Classification

Entitlements can be classified with data protection levels to support GDPR compliance tracking:

| Classification | Description |
|---------------|-------------|
| `none` | No personal data involved |
| `personal` | Contains basic personal data |
| `sensitive` | Contains sensitive personal data |
| `special_category` | Contains special category data (health, biometric, etc.) |

When creating or updating entitlements, you can set the GDPR metadata:

```bash
curl -X POST https://your-domain.com/governance/entitlements \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "customer-data:read",
    "description": "Read access to customer records",
    "application_id": "app-uuid",
    "risk_level": "high",
    "data_protection_classification": "sensitive",
    "legal_basis": "legitimate_interest",
    "retention_period_days": 365,
    "data_controller": "Acme Corp",
    "data_processor": "Cloud Analytics Inc",
    "purposes": ["analytics", "customer_support"]
  }'
```

### Legal Basis Types

| Legal Basis | Description |
|-------------|-------------|
| `consent` | Data subject has given consent |
| `contract` | Processing necessary for contract performance |
| `legal_obligation` | Processing necessary for legal compliance |
| `vital_interest` | Processing necessary to protect vital interests |
| `public_interest` | Processing necessary for public interest tasks |
| `legitimate_interest` | Processing necessary for legitimate interests |

### GDPR Compliance Report

Generate a tenant-wide GDPR compliance report summarizing classification coverage, legal basis distribution, and detailed entitlement breakdowns:

```bash
curl https://your-domain.com/governance/gdpr/report \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

The report includes:
- Total entitlement count and classification coverage percentage
- Breakdown by classification level and legal basis
- Detailed list of classified entitlements with retention periods, data controllers/processors, and active assignment counts

### Per-User Data Protection Summary

Get a per-user summary showing what classified data a specific user has access to:

```bash
curl https://your-domain.com/governance/gdpr/users/{user_id}/data-protection \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

This returns all entitlements assigned to the user that have a data protection classification, along with the legal basis and retention period for each.

### GDPR Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Compliance report | GET | `/governance/gdpr/report` |
| User data protection | GET | `/governance/gdpr/users/{user_id}/data-protection` |

## Applications & Entitlements

### Application Management

Applications represent systems that xavyo-idp governs access to:

```bash
curl -X POST https://your-domain.com/governance/applications \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Customer Portal",
    "app_type": "external",
    "description": "Customer-facing web application"
  }'
```

:::info
The `app_type` field accepts `internal` or `external` to classify the application.
:::

### Entitlement Management

Entitlements represent fine-grained permissions within applications:

```bash
curl -X POST https://your-domain.com/governance/entitlements \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "customer-data:read",
    "description": "Read access to customer records",
    "application_id": "app-uuid",
    "risk_level": "medium"
  }'
```

## Security Considerations

- **Admin role required**: All governance mutation endpoints require the `admin` role. Read endpoints for self-service (catalog, my-pending, can-i) are available to authenticated users.
- **Self-approval prevention**: Users cannot approve their own access requests or delegation assignments. A database unique constraint enforces this.
- **Optimistic concurrency**: Role updates use a `version` field for optimistic concurrency control. Stale updates are rejected with `409 Conflict`.
- **Expression parser safety**: Meta-role criteria expressions enforce a recursion depth limit of 64 to prevent stack overflow.
- **Audit trail**: All governance decisions (certify, revoke, approve, reject) are recorded in the audit log with the deciding user's identity and timestamp.
- **Scheduled transitions**: Lifecycle transition requests can be scheduled for future execution. The system automatically processes them at the scheduled time.

## Related

- [Authorization](./authorization.md) -- Role-based access control, SoD rules, and delegation
- [User Management](./user-management.md) -- User CRUD and group management
- [NHI Management](./nhi-management.md) -- Governance for non-human identities
- [Security Hardening](./security-hardening.md) -- Audit logging and compliance monitoring
