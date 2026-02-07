---
title: Non-Human Identity Management
description: Guide to managing non-human identities (NHI) including agents, service accounts, tools, credentials, certification campaigns, and approval workflows in xavyo-idp.
sidebar_position: 8
---

# Non-Human Identity Management

## Overview

xavyo-idp provides a comprehensive Non-Human Identity (NHI) management framework for governing machine identities -- automated agents, service accounts, and tools that interact with your systems. NHI management applies the same governance principles used for human identities: lifecycle management, credential rotation, access certification, and approval workflows.

The NHI subsystem covers:

- **Agents** -- Autonomous or semi-autonomous software entities
- **Service Accounts** -- Machine accounts for system-to-system communication
- **Tools** -- External capabilities that agents can be granted permission to use
- **Credentials** -- API keys and secrets issued to agents, with rotation and revocation
- **Certification Campaigns** -- Periodic reviews of NHI access and necessity
- **Approval Workflows** -- Request and approval flows for new service accounts

All NHI operations are tenant-isolated and require administrator authentication.

## Agent Management

### Creating an Agent

Agents represent autonomous software entities that perform actions on behalf of an organization:

```bash
curl -X POST https://your-domain.com/nhi/agents \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Data Pipeline Agent",
    "agent_type": "autonomous",
    "description": "Processes ETL pipelines for analytics",
    "risk_level": "medium",
    "owner_id": "owner-user-uuid"
  }'
```

**Response (201 Created):**
```json
{
  "id": "agent-uuid",
  "name": "Data Pipeline Agent",
  "agent_type": "autonomous",
  "risk_level": "medium",
  "owner_id": "owner-user-uuid",
  "status": "active",
  "created_at": "2026-02-07T12:00:00Z"
}
```

### Agent Types

| Type | Description |
|------|-------------|
| `autonomous` | Operates independently without human intervention |
| `semi_autonomous` | Requires human approval for certain actions |
| `supervised` | All actions require human oversight |

### Risk Levels

| Level | Description |
|-------|-------------|
| `low` | Limited access, read-only operations |
| `medium` | Standard operational access |
| `high` | Access to sensitive data or critical systems |
| `critical` | Full administrative or infrastructure access |

### Agent Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create agent | POST | `/nhi/agents` |
| List agents | GET | `/nhi/agents` |
| Get agent | GET | `/nhi/agents/{id}` |
| Update agent | PATCH | `/nhi/agents/{id}` |
| Delete agent | DELETE | `/nhi/agents/{id}` |
| Suspend agent | POST | `/nhi/agents/{id}/suspend` |
| Reactivate agent | POST | `/nhi/agents/{id}/reactivate` |

### Listing and Filtering Agents

```bash
# List all agents
curl https://your-domain.com/nhi/agents \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Filter by risk level
curl "https://your-domain.com/nhi/agents?risk_level=high&limit=20" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Filter by status
curl "https://your-domain.com/nhi/agents?status=active" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

## Credential Management

### Rotating Credentials

Credential rotation generates a new credential for an agent while optionally maintaining a grace period during which the old credential remains valid:

```bash
curl -X POST https://your-domain.com/nhi/agents/{agent_id}/credentials/rotate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "credential_type": "api_key",
    "name": "Pipeline API Key v2",
    "grace_period_hours": 24
  }'
```

**Response (201 Created):**
```json
{
  "credential": {
    "id": "cred-uuid",
    "name": "Pipeline API Key v2",
    "credential_type": "api_key",
    "status": "active",
    "valid_from": "2026-02-07T12:00:00Z"
  },
  "secret_value": "xavyo_nhi_sk_..."
}
```

:::warning
The `secret_value` is returned only once during credential rotation. Store it immediately in a secure vault. Subsequent GET requests will not include the secret.
:::

### Listing Credentials

```bash
# List all credentials for an agent
curl https://your-domain.com/nhi/agents/{agent_id}/credentials \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Filter active credentials only
curl "https://your-domain.com/nhi/agents/{agent_id}/credentials?status=active" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Revoking Credentials

```bash
curl -X POST https://your-domain.com/nhi/agents/{agent_id}/credentials/{credential_id}/revoke \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "reason": "Credential compromised"
  }'
```

### Validating Credentials

Check whether a credential is currently valid:

```bash
curl -X POST https://your-domain.com/nhi/agents/{agent_id}/credentials/validate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "credential": "xavyo_nhi_sk_..."
  }'
```

**Response:**
```json
{
  "valid": true,
  "credential_id": "cred-uuid",
  "expires_at": "2027-02-07T12:00:00Z"
}
```

### Credential Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Rotate credentials | POST | `/nhi/agents/{id}/credentials/rotate` |
| List credentials | GET | `/nhi/agents/{id}/credentials` |
| Get credential | GET | `/nhi/agents/{id}/credentials/{cred_id}` |
| Revoke credential | POST | `/nhi/agents/{id}/credentials/{cred_id}/revoke` |
| Validate credential | POST | `/nhi/agents/{id}/credentials/validate` |

## Tool Management

Tools represent external capabilities that agents can be authorized to use. Each tool has a defined risk level and can optionally require approval before an agent uses it.

### Registering a Tool

```bash
curl -X POST https://your-domain.com/nhi/tools \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Database Query Tool",
    "description": "Executes read-only SQL queries against analytics database",
    "category": "data_access",
    "risk_level": "medium",
    "requires_approval": true,
    "input_schema": {
      "type": "object",
      "properties": {
        "query": {"type": "string"},
        "database": {"type": "string"}
      },
      "required": ["query"]
    }
  }'
```

### Tool Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Register tool | POST | `/nhi/tools` |
| List tools | GET | `/nhi/tools` |
| Get tool | GET | `/nhi/tools/{id}` |
| Update tool | PATCH | `/nhi/tools/{id}` |
| Delete tool | DELETE | `/nhi/tools/{id}` |

### Filtering Tools

```bash
# Filter by category
curl "https://your-domain.com/nhi/tools?category=data_access" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Filter by risk level
curl "https://your-domain.com/nhi/tools?risk_level=high" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

## Agent Permissions

Grant or revoke tool access for specific agents:

```bash
# Grant tool permission to an agent
curl -X POST https://your-domain.com/nhi/agents/{agent_id}/permissions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "tool_id": "tool-uuid"
  }'

# List agent permissions
curl https://your-domain.com/nhi/agents/{agent_id}/permissions \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Revoke tool permission
curl -X DELETE https://your-domain.com/nhi/agents/{agent_id}/permissions/{tool_id} \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Permission Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Grant permission | POST | `/nhi/agents/{id}/permissions` |
| List permissions | GET | `/nhi/agents/{id}/permissions` |
| Revoke permission | DELETE | `/nhi/agents/{id}/permissions/{tool_id}` |

## Service Account Management

Service accounts are machine identities for system-to-system communication. Unlike agents, service accounts follow a request-and-approval workflow before creation.

### Requesting a Service Account

```bash
curl -X POST https://your-domain.com/nhi/service-accounts/requests \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "CI/CD Pipeline Account",
    "purpose": "Automated deployment pipeline for production services",
    "owner_id": "owner-user-uuid",
    "risk_level": "medium"
  }'
```

### Approval Workflow

```bash
# List pending requests
curl https://your-domain.com/nhi/service-accounts/requests?status=pending \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# View my pending approvals
curl https://your-domain.com/nhi/service-accounts/requests/my-pending \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Approve a request
curl -X POST https://your-domain.com/nhi/service-accounts/requests/{request_id}/approve \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "comment": "Approved for production deployment use case"
  }'

# Reject a request
curl -X POST https://your-domain.com/nhi/service-accounts/requests/{request_id}/reject \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "comment": "Use existing shared service account instead"
  }'

# Cancel a request (by the requester)
curl -X POST https://your-domain.com/nhi/service-accounts/requests/{request_id}/cancel \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Request Summary

```bash
curl https://your-domain.com/nhi/service-accounts/requests/summary \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Service Account Request Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Submit request | POST | `/nhi/service-accounts/requests` |
| List requests | GET | `/nhi/service-accounts/requests` |
| Get request | GET | `/nhi/service-accounts/requests/{id}` |
| Approve request | POST | `/nhi/service-accounts/requests/{id}/approve` |
| Reject request | POST | `/nhi/service-accounts/requests/{id}/reject` |
| Cancel request | POST | `/nhi/service-accounts/requests/{id}/cancel` |
| My pending | GET | `/nhi/service-accounts/requests/my-pending` |
| Summary | GET | `/nhi/service-accounts/requests/summary` |

## NHI Certification Campaigns

Just as human identities undergo periodic access reviews, non-human identities should be certified regularly to ensure they are still needed and properly scoped.

### Creating a Certification Campaign

```bash
curl -X POST https://your-domain.com/nhi/certifications/campaigns \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Q1 2026 NHI Review",
    "description": "Quarterly review of all service accounts and agents",
    "nhi_types": ["service_account", "agent"],
    "reviewer_id": "reviewer-user-uuid",
    "due_date": "2026-03-31T00:00:00Z"
  }'
```

### Campaign Lifecycle

```bash
# Launch the campaign (generates review items)
curl -X POST https://your-domain.com/nhi/certifications/campaigns/{id}/launch \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# View campaign summary
curl https://your-domain.com/nhi/certifications/campaigns/{id}/summary \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# List review items
curl https://your-domain.com/nhi/certifications/campaigns/{id}/items \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Decide on an item (certify or revoke)
curl -X POST https://your-domain.com/nhi/certifications/items/{item_id}/decide \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "decision": "certify",
    "comment": "Agent still needed for daily data processing"
  }'

# View my pending certification items
curl https://your-domain.com/nhi/certifications/my-pending \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Cancel a campaign
curl -X POST https://your-domain.com/nhi/certifications/campaigns/{id}/cancel \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Certification Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create campaign | POST | `/nhi/certifications/campaigns` |
| List campaigns | GET | `/nhi/certifications/campaigns` |
| Get campaign | GET | `/nhi/certifications/campaigns/{id}` |
| Launch campaign | POST | `/nhi/certifications/campaigns/{id}/launch` |
| Get summary | GET | `/nhi/certifications/campaigns/{id}/summary` |
| List items | GET | `/nhi/certifications/campaigns/{id}/items` |
| Decide on item | POST | `/nhi/certifications/items/{id}/decide` |
| Cancel campaign | POST | `/nhi/certifications/campaigns/{id}/cancel` |
| My pending items | GET | `/nhi/certifications/my-pending` |

## CA Integration

For agents that require X.509 certificates, xavyo-idp provides Certificate Authority integration:

| Operation | Method | Endpoint |
|-----------|--------|----------|
| List CA providers | GET | `/nhi/ca/providers` |
| Create CA provider | POST | `/nhi/ca/providers` |
| Get CA provider | GET | `/nhi/ca/providers/{id}` |
| Issue certificate | POST | `/nhi/ca/providers/{id}/issue` |
| Revoke certificate | POST | `/nhi/ca/certificates/{id}/revoke` |
| List certificates | GET | `/nhi/ca/certificates` |

## Identity Providers for NHI

Configure identity providers specifically for non-human identity authentication:

| Operation | Method | Endpoint |
|-----------|--------|----------|
| List NHI IdPs | GET | `/nhi/identity-providers` |
| Create NHI IdP | POST | `/nhi/identity-providers` |
| Get NHI IdP | GET | `/nhi/identity-providers/{id}` |
| Update NHI IdP | PUT | `/nhi/identity-providers/{id}` |
| Delete NHI IdP | DELETE | `/nhi/identity-providers/{id}` |

## Secret Types and Permissions

Define categories of secrets and control which agents can access them:

```bash
# Create a secret type
curl -X POST https://your-domain.com/nhi/secret-types \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Database Credentials",
    "description": "Production database connection credentials",
    "rotation_policy_days": 90
  }'

# Grant secret permission to an agent
curl -X POST https://your-domain.com/nhi/agents/{agent_id}/secret-permissions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "secret_type_id": "secret-type-uuid",
    "access_level": "read"
  }'
```

### Secret Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create secret type | POST | `/nhi/secret-types` |
| List secret types | GET | `/nhi/secret-types` |
| Get secret type | GET | `/nhi/secret-types/{id}` |
| Delete secret type | DELETE | `/nhi/secret-types/{id}` |
| Grant secret permission | POST | `/nhi/agents/{id}/secret-permissions` |
| List secret permissions | GET | `/nhi/agents/{id}/secret-permissions` |
| Revoke secret permission | DELETE | `/nhi/agents/{id}/secret-permissions/{perm_id}` |

## Role Mappings

Map NHI agents to governance roles for access control:

| Operation | Method | Endpoint |
|-----------|--------|----------|
| List role mappings | GET | `/nhi/agents/{id}/role-mappings` |
| Create role mapping | POST | `/nhi/agents/{id}/role-mappings` |
| Delete role mapping | DELETE | `/nhi/agents/{id}/role-mappings/{mapping_id}` |

## Anomaly Detection

Monitor NHI behavior for anomalous patterns:

```bash
# List detected anomalies
curl https://your-domain.com/nhi/anomalies \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Get anomaly details
curl https://your-domain.com/nhi/anomalies/{anomaly_id} \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

## Security Considerations

- **Admin authentication required**: All NHI management endpoints require the `admin` role. Non-admin users receive `403 Forbidden`.
- **Credential security**: Agent credentials are hashed before storage. The plaintext secret is only available at rotation time.
- **Self-approval prevention**: Service account request approvers cannot approve their own requests. A database constraint enforces this.
- **Input validation**: All NHI creation requests are validated using the `Validate` trait. Invalid requests return `400` or `422`.
- **Referential integrity**: Secret types cannot be deleted if they have active permissions or credentials referencing them.
- **Credential revocation tracking**: All credential revocations record the `revoked_by` user ID for audit purposes.
- **Tenant isolation**: All NHI data is scoped to the authenticated tenant through PostgreSQL Row-Level Security.
- **Duplicate prevention**: Tool names must be unique within a tenant. Attempting to register a duplicate name returns `409 Conflict`.

## Related

- [Authorization](./authorization.md) -- Role-based access control for managing NHI access
- [Governance](./governance.md) -- Certification campaigns and lifecycle policies
- [Connectors](./connectors.md) -- Provisioning NHI to external systems
- [Security Hardening](./security-hardening.md) -- Key management and audit logging
