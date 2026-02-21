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
    "owner_id": "owner-user-uuid",
    "model_provider": "anthropic",
    "model_name": "claude-opus-4-6",
    "requires_human_approval": false
  }'
```

**Response (201 Created):**
```json
{
  "id": "agent-uuid",
  "name": "Data Pipeline Agent",
  "agent_type": "autonomous",
  "owner_id": "owner-user-uuid",
  "lifecycle_state": "active",
  "created_at": "2026-02-07T12:00:00Z"
}
```

### Agent Types

The `agent_type` field is a free-form string. Common values include:

| Type | Description |
|------|-------------|
| `autonomous` | Operates independently without human intervention |
| `supervised` | Actions require human oversight |
| `copilot` | Works alongside human operators |

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

## Vault (Secret Management)

xavyo includes a built-in encrypted vault for managing NHI secrets. Secrets are encrypted at rest using AES-256-GCM.

### Storing a Secret

```bash
curl -X POST https://your-domain.com/nhi/{nhi_id}/vault/secrets \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Pipeline API Key",
    "secret_type": "api_key",
    "secret_value": "your-secret-value"
  }'
```

### Listing Secrets

```bash
curl https://your-domain.com/nhi/{nhi_id}/vault/secrets \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

:::warning
Secret values are not returned in list responses. The plaintext is only available at creation time.
:::

### Rotating a Secret

```bash
curl -X POST https://your-domain.com/nhi/{nhi_id}/vault/secrets/{secret_id}/rotate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"new_value": "rotated-secret-value"}'
```

### Deleting a Secret

```bash
curl -X DELETE https://your-domain.com/nhi/{nhi_id}/vault/secrets/{secret_id} \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Lease Management

Leases provide time-limited access to secrets:

```bash
# Create a lease
curl -X POST https://your-domain.com/nhi/{nhi_id}/vault/leases \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"secret_id": "secret-uuid", "ttl_seconds": 3600}'

# List active leases
curl https://your-domain.com/nhi/{nhi_id}/vault/leases \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Renew a lease
curl -X POST https://your-domain.com/nhi/{nhi_id}/vault/leases/{lease_id}/renew \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Revoke a lease
curl -X DELETE https://your-domain.com/nhi/{nhi_id}/vault/leases/{lease_id} \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Vault Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Store secret | POST | `/nhi/{id}/vault/secrets` |
| List secrets | GET | `/nhi/{id}/vault/secrets` |
| Delete secret | DELETE | `/nhi/{id}/vault/secrets/{secret_id}` |
| Rotate secret | POST | `/nhi/{id}/vault/secrets/{secret_id}/rotate` |
| Create lease | POST | `/nhi/{id}/vault/leases` |
| List leases | GET | `/nhi/{id}/vault/leases` |
| Renew lease | POST | `/nhi/{id}/vault/leases/{lease_id}/renew` |
| Revoke lease | DELETE | `/nhi/{id}/vault/leases/{lease_id}` |

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

## Agent Tool Permissions

Grant or revoke tool access for specific agents:

```bash
# Grant tool permission to an agent
curl -X POST https://your-domain.com/nhi/agents/{agent_id}/tools/{tool_id}/grant \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# List tools granted to an agent
curl https://your-domain.com/nhi/agents/{agent_id}/tools \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# List agents granted to a tool
curl https://your-domain.com/nhi/tools/{tool_id}/agents \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Revoke tool permission from an agent
curl -X POST https://your-domain.com/nhi/agents/{agent_id}/tools/{tool_id}/revoke \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Tool Permission Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Grant tool to agent | POST | `/nhi/agents/{id}/tools/{tool_id}/grant` |
| Revoke tool from agent | POST | `/nhi/agents/{id}/tools/{tool_id}/revoke` |
| List agent's tools | GET | `/nhi/agents/{id}/tools` |
| List tool's agents | GET | `/nhi/tools/{tool_id}/agents` |

## Service Account Management

Service accounts are machine identities for system-to-system communication.

### Creating a Service Account

```bash
curl -X POST https://your-domain.com/nhi/service-accounts \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "CI/CD Pipeline Account",
    "description": "Automated deployment pipeline for production services",
    "purpose": "Continuous deployment",
    "owner_id": "owner-user-uuid"
  }'
```

### Listing Service Accounts

```bash
curl https://your-domain.com/nhi/service-accounts \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Get, Update, Delete

```bash
# Get a service account
curl https://your-domain.com/nhi/service-accounts/{id} \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Update a service account
curl -X PATCH https://your-domain.com/nhi/service-accounts/{id} \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"description": "Updated description"}'

# Delete a service account
curl -X DELETE https://your-domain.com/nhi/service-accounts/{id} \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Service Account Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create | POST | `/nhi/service-accounts` |
| List | GET | `/nhi/service-accounts` |
| Get | GET | `/nhi/service-accounts/{id}` |
| Update | PATCH | `/nhi/service-accounts/{id}` |
| Delete | DELETE | `/nhi/service-accounts/{id}` |

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

### Campaign Operations

```bash
# Certify an NHI in a campaign
curl -X POST https://your-domain.com/nhi/certifications/{campaign_id}/certify/{nhi_id} \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "comment": "Agent still needed for daily data processing"
  }'

# Revoke an NHI in a campaign
curl -X POST https://your-domain.com/nhi/certifications/{campaign_id}/revoke/{nhi_id} \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "comment": "No longer needed"
  }'
```

### Certification Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create campaign | POST | `/nhi/certifications` |
| List campaigns | GET | `/nhi/certifications` |
| Certify NHI | POST | `/nhi/certifications/{campaign_id}/certify/{nhi_id}` |
| Revoke NHI | POST | `/nhi/certifications/{campaign_id}/revoke/{nhi_id}` |

## NHI Permission Model

Beyond tool-level permissions, xavyo-idp provides a fine-grained permission model for controlling who can interact with NHI identities and how NHIs can interact with each other.

### User-to-NHI Permissions

Control which users can access specific NHI identities. Permission types follow a hierarchy: `use` (invoke the NHI), `manage` (configure and modify), and `admin` (full control including permission grants).

```bash
# Grant a user permission to use an NHI
curl -X POST https://your-domain.com/nhi/{nhi_id}/users/{user_id}/grant \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "permission_type": "use",
    "expires_at": "2026-06-30T00:00:00Z"
  }'

# Revoke a user's permission
curl -X POST https://your-domain.com/nhi/{nhi_id}/users/{user_id}/revoke \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"permission_type": "use"}'

# List users with access to an NHI
curl https://your-domain.com/nhi/{nhi_id}/users \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# List NHIs accessible by a user
curl https://your-domain.com/nhi/users/{user_id}/accessible \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

Non-admin users can only view their own accessible NHIs via the `/nhi/users/{user_id}/accessible` endpoint.

### NHI-to-NHI Calling Permissions

Control which NHIs can invoke or delegate to other NHIs. Supports rate limiting (`max_calls_per_hour`), allowed action filtering, and expiry.

```bash
# Grant NHI calling permission (source can call target)
curl -X POST https://your-domain.com/nhi/{source_id}/call/{target_id}/grant \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "permission_type": "call",
    "allowed_actions": ["read", "query"],
    "max_calls_per_hour": 100,
    "expires_at": "2026-12-31T00:00:00Z"
  }'

# Revoke NHI calling permission
curl -X POST https://your-domain.com/nhi/{source_id}/call/{target_id}/revoke \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"permission_type": "call"}'

# List NHIs that can call this NHI (callers)
curl https://your-domain.com/nhi/{nhi_id}/callers \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# List NHIs this NHI can call (callees)
curl https://your-domain.com/nhi/{nhi_id}/callees \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### NHI Permission Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Grant user permission | POST | `/nhi/{id}/users/{user_id}/grant` |
| Revoke user permission | POST | `/nhi/{id}/users/{user_id}/revoke` |
| List NHI users | GET | `/nhi/{id}/users` |
| List user's NHIs | GET | `/nhi/users/{user_id}/accessible` |
| Grant NHI calling | POST | `/nhi/{id}/call/{target_id}/grant` |
| Revoke NHI calling | POST | `/nhi/{id}/call/{target_id}/revoke` |
| List callers | GET | `/nhi/{id}/callers` |
| List callees | GET | `/nhi/{id}/callees` |

:::info
Admin and super_admin users bypass NHI permission checks. Non-admin users can only access NHIs they have explicit permissions for. The `list_nhis` endpoint filters results based on the caller's permissions.
:::

## NHI Segregation of Duties (SoD)

Define segregation of duties rules for NHI identities to prevent conflicting permissions:

```bash
# Create an SoD rule
curl -X POST https://your-domain.com/nhi/sod/rules \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Production Write Separation",
    "nhi_ids": ["agent-uuid-1", "agent-uuid-2"],
    "description": "These agents must not both have write access to production"
  }'

# Check for SoD violations
curl -X POST https://your-domain.com/nhi/sod/check \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{"nhi_id": "agent-uuid"}'

# List all SoD rules
curl https://your-domain.com/nhi/sod/rules \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Delete an SoD rule
curl -X DELETE https://your-domain.com/nhi/sod/rules/{rule_id} \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### SoD Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create SoD rule | POST | `/nhi/sod/rules` |
| List SoD rules | GET | `/nhi/sod/rules` |
| Delete SoD rule | DELETE | `/nhi/sod/rules/{id}` |
| Check violations | POST | `/nhi/sod/check` |

## MCP Tool Discovery

xavyo-idp integrates with AgentGateway to discover and import MCP (Model Context Protocol) tools as NHI tool records. This enables centralized governance of AI agent capabilities.

### Discovering Tools

```bash
# List configured gateways
curl https://your-domain.com/nhi/mcp-discovery/gateways \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Discover available MCP tools from all gateways
curl https://your-domain.com/nhi/mcp-discovery/tools \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Filter by specific gateway
curl "https://your-domain.com/nhi/mcp-discovery/tools?gateway_name=production" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Importing Tools

Import discovered tools as NHI tool records for governance:

```bash
curl -X POST https://your-domain.com/nhi/mcp-discovery/import \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "tools": [
      {"name": "database-query", "description": "Execute SQL queries", "gateway_name": "production"},
      {"name": "file-reader", "description": "Read files from storage", "gateway_name": "production"}
    ]
  }'
```

### Sync Check

Compare live gateway tools against stored NHI records to detect drift:

```bash
curl "https://your-domain.com/nhi/mcp-discovery/sync-check?gateway_name=production" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### MCP Discovery Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| List gateways | GET | `/nhi/mcp-discovery/gateways` |
| Discover tools | GET | `/nhi/mcp-discovery/tools` |
| Import tools | POST | `/nhi/mcp-discovery/import` |
| Sync check | GET | `/nhi/mcp-discovery/sync-check` |

## A2A Agent Discovery

xavyo-idp implements the A2A (Agent-to-Agent) Protocol v0.3 for agent card discovery. This allows AI agents to discover each other's capabilities through a standardized format.

### Agent Card Endpoint

The agent card is publicly accessible (no authentication required) and returns the agent's capabilities, skills, and authentication requirements:

```bash
curl https://your-domain.com/.well-known/agents/{agent_id}
```

**Response (200):**
```json
{
  "name": "Data Pipeline Agent",
  "description": "Processes ETL pipelines for analytics",
  "url": "https://api.xavyo.net/agents/data-pipeline",
  "version": "1.0.0",
  "protocol_version": "0.3",
  "capabilities": {
    "streaming": false,
    "push_notifications": false
  },
  "authentication": {
    "schemes": ["bearer"]
  },
  "skills": [
    {
      "id": "database_query",
      "name": "DATABASE QUERY",
      "description": "Execute read-only SQL queries"
    }
  ]
}
```

Only active agents are returned. Inactive or suspended agents return `404`.

### A2A Discovery Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Get agent card | GET | `/.well-known/agents/{id}` |

## Security Considerations

- **Admin authentication required**: All NHI management endpoints require the `admin` role. Non-admin users receive `403 Forbidden`.
- **Permission model**: User-to-NHI permissions (use/manage/admin) control who can interact with each NHI. Admin and super_admin roles bypass permission checks.
- **Vault security**: Secrets stored in the vault are encrypted at rest. Vault leases enforce time-limited access.
- **Input validation**: All NHI creation requests are validated using the `Validate` trait. Invalid requests return `400` or `422`.
- **Tenant isolation**: All NHI data is scoped to the authenticated tenant through PostgreSQL Row-Level Security.
- **Duplicate prevention**: Tool names must be unique within a tenant. Attempting to register a duplicate name returns `409 Conflict`.

## Related

- [Authorization](./authorization.md) -- Role-based access control for managing NHI access
- [Governance](./governance.md) -- Certification campaigns and lifecycle policies
- [Connectors](./connectors.md) -- Provisioning NHI to external systems
- [Security Hardening](./security-hardening.md) -- Key management and audit logging
