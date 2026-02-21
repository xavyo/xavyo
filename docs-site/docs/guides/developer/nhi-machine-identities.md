---
title: Non-Human Identities (Machine Identities)
description: Manage AI agents, service accounts, and tools through the NHI API -- credential rotation, risk assessment, and HITL approvals.
sidebar_position: 5
---

# Non-Human Identities (NHI)

xavyo provides a unified API for managing Non-Human Identities (NHI) -- the machine accounts, AI agents, and automated tools that interact with your systems. The NHI API consolidates service account management, AI agent governance, tool registration, credential lifecycle, risk assessment, and human-in-the-loop (HITL) approval workflows into a single namespace.

## Overview

Non-Human Identities fall into three categories:

| Category | Description | Use Case |
|----------|-------------|----------|
| **Service Accounts** | Long-lived machine identities for automated processes | CI/CD pipelines, background jobs, integrations |
| **AI Agents** | Autonomous software agents with security boundaries | LLM-powered assistants, automation bots, copilots |
| **Tools** | Registered capabilities that agents can invoke | Database queries, API calls, file operations |

All NHI resources are tenant-scoped and require JWT authentication. Mutation operations (create, update, delete) require the `admin` role.

## Service Accounts

Service accounts are traditional machine identities for automated processes that need to authenticate with xavyo-protected resources.

### Create a Service Account

```bash
curl -X POST https://idp.example.com/nhi/service-accounts \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ci-pipeline-prod",
    "description": "Production CI/CD pipeline service account",
    "purpose": "Automated deployment pipeline",
    "owner_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"
  }'
```

**Response (201 Created):**

```json
{
  "id": "a1b2c3d4-5678-90ab-cdef-1234567890ab",
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "ci-pipeline-prod",
  "description": "Production CI/CD pipeline service account",
  "nhi_type": "service_account",
  "owner_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "lifecycle_state": "active",
  "created_at": "2026-02-07T10:00:00Z",
  "updated_at": "2026-02-07T10:00:00Z"
}
```

### List Service Accounts

```bash
curl "https://idp.example.com/nhi/service-accounts?limit=20&offset=0" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Filter by status or search by name:

```bash
curl "https://idp.example.com/nhi/service-accounts?status=active&search=ci-pipeline" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### Get Summary Statistics

```bash
curl https://idp.example.com/nhi/service-accounts/summary \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Returns aggregate counts of service accounts by status and risk level.

### Update a Service Account

```bash
curl -X PATCH https://idp.example.com/nhi/service-accounts/{id} \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Updated description",
    "risk_level": "high"
  }'
```

### Suspend and Reactivate

Suspend a service account to immediately revoke access without deleting it:

```bash
# Suspend
curl -X POST https://idp.example.com/nhi/service-accounts/{id}/suspend \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "Credential compromise suspected"
  }'

# Reactivate
curl -X POST https://idp.example.com/nhi/service-accounts/{id}/reactivate \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "Investigation complete, no compromise found"
  }'
```

### Transfer Ownership

Transfer a service account to a new owner:

```bash
curl -X POST https://idp.example.com/nhi/service-accounts/{id}/transfer \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "new_owner_id": "b2c3d4e5-6789-0abc-def1-234567890abc"
  }'
```

### Delete a Service Account

```bash
curl -X DELETE https://idp.example.com/nhi/service-accounts/{id} \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

**Response:** `204 No Content`

## AI Agents

AI agents are autonomous software entities that operate within defined security boundaries. xavyo provides governance controls including permission management, behavioral anomaly detection, and human-in-the-loop approval gates.

### Register an Agent

```bash
curl -X POST https://idp.example.com/nhi/agents \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "data-analyst-bot",
    "description": "Automated data analysis agent",
    "agent_type": "autonomous",
    "model_provider": "anthropic",
    "model_name": "claude-opus-4-6",
    "owner_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "requires_human_approval": false
  }'
```

### List Agents

```bash
curl "https://idp.example.com/nhi/agents?limit=20&offset=0" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### Get Agent Details

```bash
curl https://idp.example.com/nhi/agents/{id} \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### Update an Agent

```bash
curl -X PATCH https://idp.example.com/nhi/agents/{id} \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Updated agent description",
    "requires_human_approval": true
  }'
```

### Agent Tool Permissions

Grant and manage tool access for agents:

```bash
# Grant a tool to an agent
curl -X POST https://idp.example.com/nhi/agents/{id}/tools/{tool_id}/grant \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json"

# List tools granted to an agent
curl "https://idp.example.com/nhi/agents/{id}/tools" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# List agents with access to a tool
curl "https://idp.example.com/nhi/tools/{tool_id}/agents" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Revoke a tool from an agent
curl -X POST https://idp.example.com/nhi/agents/{id}/tools/{tool_id}/revoke \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

## Tools

Tools represent capabilities that agents can invoke. Registering tools gives administrators visibility into what actions are available and allows policy enforcement.

### Register a Tool

```bash
curl -X POST https://idp.example.com/nhi/tools \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "sql-query",
    "description": "Execute read-only SQL queries against the analytics database",
    "category": "database",
    "requires_approval": true,
    "input_schema": {
      "type": "object",
      "properties": {
        "query": {"type": "string"},
        "database": {"type": "string", "enum": ["analytics", "reporting"]}
      },
      "required": ["query", "database"]
    }
  }'
```

### List Tools

```bash
curl "https://idp.example.com/nhi/tools?limit=20&offset=0" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Filter by category, risk level, or approval requirement:

```bash
curl "https://idp.example.com/nhi/tools?category=database&requires_approval=true" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### Update a Tool

```bash
curl -X PATCH https://idp.example.com/nhi/tools/{id} \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "requires_approval": false,
    "risk_level": "low"
  }'
```

### Delete a Tool

```bash
curl -X DELETE https://idp.example.com/nhi/tools/{id} \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

## Human-in-the-Loop (HITL) Configuration

Agents can be configured to require human approval before performing actions by setting `requires_human_approval: true` during creation or update:

```bash
# Create an agent that requires human approval
curl -X POST https://idp.example.com/nhi/agents \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "production-deployer",
    "agent_type": "supervised",
    "description": "Production deployment agent",
    "owner_id": "f47ac10b-...",
    "requires_human_approval": true
  }'

# Update an existing agent to require approval
curl -X PATCH https://idp.example.com/nhi/agents/{id} \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"requires_human_approval": true}'
```

Tools can also be marked with `requires_approval: true` to indicate that invocations of that tool should go through a review process.

## Risk Assessment

xavyo provides risk visibility across all NHI types.

### Risk Summary

Get aggregated risk statistics across all service accounts and agents:

```bash
curl https://idp.example.com/nhi/risk-summary \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

**Response:**

```json
{
  "total_count": 47,
  "by_type": {
    "service_account": 35,
    "ai_agent": 12
  },
  "by_risk_level": {
    "critical": 2,
    "high": 8,
    "medium": 22,
    "low": 15
  },
  "pending_certification": 5,
  "inactive_30_days": 3,
  "expiring_7_days": 1
}
```

### Staleness Report

Identify inactive NHIs that may be candidates for decommissioning:

```bash
curl -X POST "https://idp.example.com/nhi/inactivity/detect" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

## Certification Campaigns

Certification campaigns enable periodic review of all NHI access to ensure compliance and least-privilege adherence.

### Create a Campaign

```bash
curl -X POST https://idp.example.com/nhi/certifications \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Q1 2026 NHI Review",
    "description": "Quarterly review of all service accounts and agents",
    "nhi_types": ["service_account", "ai_agent"],
    "reviewer_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "due_date": "2026-03-31T23:59:59Z",
    "filter": {
      "risk_min": 3,
      "inactive_days": 30
    }
  }'
```

### Campaign Lifecycle

1. **Draft** -- Campaign created, items not yet populated
2. **Active** -- Campaign launched, reviewer can certify or revoke items
3. **Completed** -- All items reviewed or campaign closed
4. **Cancelled** -- Campaign abandoned

### Certify or Revoke Items

For each NHI in the campaign, the reviewer decides to certify (keep) or revoke (decommission):

```bash
# Certify an NHI in a campaign
curl -X POST https://idp.example.com/nhi/certifications/{campaign_id}/certify/{nhi_id} \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "comment": "Still in active use for production deployments"
  }'

# Revoke an NHI in a campaign
curl -X POST https://idp.example.com/nhi/certifications/{campaign_id}/revoke/{nhi_id} \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "comment": "No longer needed, project decommissioned"
  }'
```

## NHI Permission Model

xavyo enforces fine-grained permissions for who can interact with NHI resources and how NHIs can call each other. There are two permission dimensions:

### User-to-NHI Permissions

Control which human users can interact with a specific NHI. Permission levels form a hierarchy:

| Level | Description | Includes |
|-------|-------------|----------|
| `use` | Invoke the NHI (e.g., call an agent's tools) | -- |
| `manage` | Configure and update the NHI | `use` |
| `admin` | Full control including lifecycle transitions and deletion | `use`, `manage` |

Admin and super_admin users bypass these checks entirely (backward compatible).

```bash
# Grant a user "manage" access to an NHI
curl -X POST http://localhost:8080/nhi/{nhi_id}/users/{user_id}/grant \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"permission_level": "manage"}'

# Revoke a user's access to an NHI
curl -X POST http://localhost:8080/nhi/{nhi_id}/users/{user_id}/revoke \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# List users with access to an NHI
curl http://localhost:8080/nhi/{nhi_id}/users \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# List NHIs accessible by a specific user
curl http://localhost:8080/nhi/users/{user_id}/accessible \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

:::info
Non-admin users can only see and interact with NHIs they have explicit permissions for. The `GET /nhi` list endpoint filters results automatically based on the calling user's permissions.
:::

### NHI-to-NHI Permissions

Control which NHIs can call or delegate to other NHIs. Permission types:

| Type | Description |
|------|-------------|
| `calling` | Source NHI can invoke the target NHI |
| `delegation` | Source NHI can act on behalf of the target NHI |

```bash
# Grant agent-A permission to call tool-B
curl -X POST http://localhost:8080/nhi/{source_id}/call/{target_id}/grant \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"permission_type": "calling"}'

# Revoke the permission
curl -X POST http://localhost:8080/nhi/{source_id}/call/{target_id}/revoke \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# List NHIs that can call a given NHI (callers)
curl http://localhost:8080/nhi/{nhi_id}/callers \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# List NHIs that a given NHI can call (callees)
curl http://localhost:8080/nhi/{nhi_id}/callees \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

## MCP Discovery

xavyo integrates with [AgentGateway](https://agentgateway.dev) to discover and import MCP (Model Context Protocol) tools. This provides a bridge between external tool servers and xavyo's NHI governance.

### List Gateways

```bash
curl http://localhost:8080/nhi/mcp-discovery/gateways \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### Discover Available Tools

```bash
curl http://localhost:8080/nhi/mcp-discovery/tools \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### Import Tools into NHI Registry

Import discovered tools so they are tracked and governed as NHI tool identities:

```bash
curl -X POST http://localhost:8080/nhi/mcp-discovery/import \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_names": ["sql-query", "file-reader"]
  }'
```

### Check Sync Status

Detect drift between discovered tools and the NHI registry:

```bash
curl http://localhost:8080/nhi/mcp-discovery/sync-check \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

## MCP Protocol Endpoints

xavyo exposes MCP-compatible endpoints at `/mcp` for agents to list and invoke tools directly:

```bash
# List tools available to the authenticated agent
curl http://localhost:8080/mcp/tools \
  -H "Authorization: Bearer $AGENT_TOKEN"

# Invoke a tool by name
curl -X POST http://localhost:8080/mcp/tools/sql-query/call \
  -H "Authorization: Bearer $AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "SELECT count(*) FROM orders",
    "database": "analytics"
  }'
```

## A2A Protocol (Agent-to-Agent)

xavyo supports the [A2A Protocol](https://google.github.io/A2A/) for asynchronous agent-to-agent communication. Agents can create tasks for other agents, check status, and cancel in-flight work.

### Agent Card Discovery

Each registered agent publishes an A2A AgentCard at a well-known URL:

```bash
curl http://localhost:8080/.well-known/agents/{agent_id}
```

This public endpoint (no authentication required) returns the agent's capabilities, supported protocols, and endpoint URLs.

### Task Management

```bash
# Create a task for another agent
curl -X POST http://localhost:8080/a2a/tasks \
  -H "Authorization: Bearer $AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target_agent_id": "b2c3d4e5-...",
    "description": "Analyze Q1 sales data",
    "parameters": {
      "quarter": "Q1-2026",
      "format": "summary"
    }
  }'

# List tasks created by or assigned to the authenticated agent
curl http://localhost:8080/a2a/tasks \
  -H "Authorization: Bearer $AGENT_TOKEN"

# Get task status
curl http://localhost:8080/a2a/tasks/{task_id} \
  -H "Authorization: Bearer $AGENT_TOKEN"

# Cancel a task
curl -X POST http://localhost:8080/a2a/tasks/{task_id}/cancel \
  -H "Authorization: Bearer $AGENT_TOKEN"
```

## NHI Vault (Secret Management)

xavyo provides an encrypted vault for managing NHI secrets (API keys, tokens, certificates). Secrets are encrypted at rest using AES-256-GCM with a server-side master key.

### Secrets

```bash
# Store a secret
curl -X POST http://localhost:8080/nhi/{nhi_id}/vault/secrets \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "database-password",
    "secret_value": "s3cr3t-p@ssw0rd",
    "secret_type": "password",
    "expires_at": "2026-06-30T23:59:59Z"
  }'

# List secrets (metadata only, no plaintext values)
curl http://localhost:8080/nhi/{nhi_id}/vault/secrets \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Rotate a secret (replace value, same metadata)
curl -X POST http://localhost:8080/nhi/{nhi_id}/vault/secrets/{secret_id}/rotate \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"new_value": "n3w-s3cr3t-v@lue"}'

# Delete a secret
curl -X DELETE http://localhost:8080/nhi/{nhi_id}/vault/secrets/{secret_id} \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### Leases

Leases provide time-limited access to secrets. When a lease expires or is revoked, the consumer loses access.

```bash
# Create a lease (time-limited access to a secret)
curl -X POST http://localhost:8080/nhi/{nhi_id}/vault/leases \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "secret_id": "a1b2c3d4-...",
    "ttl_seconds": 3600,
    "consumer_nhi_id": "e5f6g7h8-..."
  }'

# List active leases
curl http://localhost:8080/nhi/{nhi_id}/vault/leases \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Renew a lease before it expires
curl -X POST http://localhost:8080/nhi/{nhi_id}/vault/leases/{lease_id}/renew \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Revoke a lease immediately
curl -X DELETE http://localhost:8080/nhi/{nhi_id}/vault/leases/{lease_id} \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

:::warning
The vault requires the `VAULT_MASTER_KEY` environment variable to be set (32 bytes, base64-encoded). Without it, vault endpoints return `500 Internal Server Error`. When an NHI is suspended, deprecated, or archived, all its active vault leases are automatically revoked.
:::

## Best Practices

1. **Assign owners to all NHIs** -- Every service account and agent should have a human owner responsible for its lifecycle
2. **Use least-privilege permissions** -- Grant only the minimum permissions needed for each agent or service account. Use user-to-NHI permissions to restrict who can invoke each NHI
3. **Rotate credentials regularly** -- Use the vault for secret management with time-limited leases. Monitor the staleness report for inactive identities
4. **Require HITL for high-risk tools** -- Mark destructive or sensitive tools with `requires_approval: true`
5. **Run quarterly certification campaigns** -- Regularly review all NHI access with structured campaigns
6. **Monitor anomaly detection** -- Subscribe to `agent.anomaly.detected` webhook events and investigate deviations promptly
7. **Suspend before deleting** -- When investigating potential compromise, suspend the identity first to preserve audit trails. Suspension automatically revokes vault leases
8. **Map NHI-to-NHI permissions** -- Explicitly grant `calling` permissions between agents and tools. Deny-by-default prevents unauthorized inter-agent communication
9. **Use MCP Discovery for tool governance** -- Import tools from AgentGateway via `/nhi/mcp-discovery/import` to bring them under xavyo governance. Run `/nhi/mcp-discovery/sync-check` periodically to detect drift
