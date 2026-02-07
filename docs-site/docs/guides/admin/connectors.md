---
title: Connectors & Provisioning
description: Guide to managing SCIM outbound targets, attribute mappings, synchronization, reconciliation, provisioning operations, job tracking, and webhook delivery in xavyo-idp.
sidebar_position: 5
---

# Connectors & Provisioning

## Overview

xavyo-idp includes a connector framework for outbound provisioning to external systems. The primary connector type is SCIM 2.0, which enables automatic user and group lifecycle management in downstream applications such as SaaS platforms, directories, and HR systems.

The connector subsystem consists of several components:

- **SCIM Outbound Targets** -- Define remote SCIM endpoints and authentication
- **Attribute Mappings** -- Control how internal user fields map to SCIM attributes
- **Synchronization** -- Trigger and monitor sync operations between xavyo-idp and targets
- **Reconciliation Engine** -- Detect and resolve discrepancies between local and remote state
- **Provisioning Operations** -- Track individual create/update/delete operations
- **Job Tracking** -- Monitor background provisioning jobs and dead-letter queues

All connector operations are tenant-isolated and require administrator authentication.

## SCIM Outbound Targets

### Creating a Target

Register an external SCIM endpoint as a provisioning target. xavyo-idp supports bearer token and OAuth 2.0 client credentials for authentication.

```bash
# Bearer token authentication
curl -X POST https://your-domain.com/admin/scim-targets \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Okta SCIM Endpoint",
    "base_url": "https://okta.example.com/scim/v2",
    "auth_method": "bearer",
    "credentials": {
      "type": "bearer",
      "token": "your-scim-bearer-token"
    },
    "deprovisioning_strategy": "deactivate",
    "tls_verify": true,
    "rate_limit_per_minute": 120,
    "request_timeout_secs": 30,
    "max_retries": 3
  }'
```

**Response (201 Created):**
```json
{
  "id": "target-uuid",
  "name": "Okta SCIM Endpoint",
  "base_url": "https://okta.example.com/scim/v2",
  "auth_method": "bearer",
  "deprovisioning_strategy": "deactivate",
  "status": "active",
  "created_at": "2026-02-07T12:00:00Z"
}
```

### OAuth 2.0 Client Credentials Authentication

For targets that require OAuth 2.0 authentication, supply the token endpoint and client credentials:

```bash
curl -X POST https://your-domain.com/admin/scim-targets \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "Azure AD SCIM",
    "base_url": "https://graph.microsoft.com/scim/v2",
    "auth_method": "oauth2",
    "credentials": {
      "type": "oauth2",
      "client_id": "your-client-id",
      "client_secret": "your-client-secret",
      "token_endpoint": "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
      "scopes": ["https://graph.microsoft.com/.default"]
    },
    "deprovisioning_strategy": "delete"
  }'
```

### Deprovisioning Strategies

| Strategy | Behavior |
|----------|----------|
| `deactivate` | Sets the user to `active: false` in the remote system |
| `delete` | Permanently removes the user from the remote system |

### Target Management Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create target | POST | `/admin/scim-targets` |
| List targets | GET | `/admin/scim-targets` |
| Get target | GET | `/admin/scim-targets/{id}` |
| Update target | PUT | `/admin/scim-targets/{id}` |
| Delete target | DELETE | `/admin/scim-targets/{id}` |
| Health check | POST | `/admin/scim-targets/{id}/health-check` |

### Listing and Filtering Targets

```bash
# List all targets with pagination
curl "https://your-domain.com/admin/scim-targets?limit=20&offset=0" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Filter by status
curl "https://your-domain.com/admin/scim-targets?status=active" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Health Checks

Verify connectivity to a SCIM target:

```bash
curl -X POST https://your-domain.com/admin/scim-targets/{target_id}/health-check \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

**Response:**
```json
{
  "status": "healthy",
  "latency_ms": 142,
  "checked_at": "2026-02-07T12:00:00Z"
}
```

## Attribute Mappings

Attribute mappings control how xavyo-idp user fields translate to SCIM attributes when provisioning to external targets. Each target has its own set of mappings.

### Viewing Mappings

```bash
curl https://your-domain.com/admin/scim-targets/{target_id}/mappings \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Filter by resource type
curl "https://your-domain.com/admin/scim-targets/{target_id}/mappings?resource_type=user" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Replacing Mappings

```bash
curl -X PUT https://your-domain.com/admin/scim-targets/{target_id}/mappings \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "mappings": [
      {
        "source_field": "email",
        "target_scim_path": "userName",
        "mapping_type": "direct",
        "resource_type": "user"
      },
      {
        "source_field": "display_name",
        "target_scim_path": "displayName",
        "mapping_type": "direct",
        "resource_type": "user"
      },
      {
        "source_field": "first_name",
        "target_scim_path": "name.givenName",
        "mapping_type": "direct",
        "resource_type": "user"
      }
    ]
  }'
```

### Resetting to Defaults

```bash
curl -X POST https://your-domain.com/admin/scim-targets/{target_id}/mappings/defaults \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Mapping Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| List mappings | GET | `/admin/scim-targets/{id}/mappings` |
| Replace mappings | PUT | `/admin/scim-targets/{id}/mappings` |
| Reset to defaults | POST | `/admin/scim-targets/{id}/mappings/defaults` |

## Synchronization

### Triggering a Sync

```bash
curl -X POST https://your-domain.com/admin/scim-targets/{target_id}/sync \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

**Response (202 Accepted):**
```json
{
  "sync_run_id": "run-uuid",
  "status": "started"
}
```

:::info
If a sync is already in progress for the target, the API returns `409 Conflict`.
:::

### Monitoring Sync Runs

```bash
# List sync runs
curl https://your-domain.com/admin/scim-targets/{target_id}/sync-runs \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Get a specific sync run
curl https://your-domain.com/admin/scim-targets/{target_id}/sync-runs/{run_id} \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Provisioning State and Logs

Track the current provisioning state and historical log for each target:

```bash
# Current provisioning state
curl "https://your-domain.com/admin/scim-targets/{target_id}/provisioning-state?resource_type=user&limit=50" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Provisioning log (historical operations)
curl "https://your-domain.com/admin/scim-targets/{target_id}/log?resource_type=user&operation_type=create&limit=20" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Connector-Level Sync

For connectors registered through the connector framework (not SCIM targets), use the connector sync endpoints:

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Get sync config | GET | `/connectors/{id}/sync/config` |
| Update sync config | PUT | `/connectors/{id}/sync/config` |
| Get sync status | GET | `/connectors/{id}/sync/status` |
| Trigger sync | POST | `/connectors/{id}/sync/trigger` |
| List changes | GET | `/connectors/{id}/sync/changes` |
| List conflicts | GET | `/connectors/{id}/sync/conflicts` |
| Resolve conflict | POST | `/connectors/{id}/sync/conflicts/{conflict_id}` |
| Enable sync | POST | `/connectors/{id}/sync/enable` |
| Disable sync | POST | `/connectors/{id}/sync/disable` |
| Reset sync token | POST | `/connectors/{id}/sync/token` |
| Retry failed change | POST | `/connectors/{id}/sync/changes/{change_id}/retry` |
| Link change | POST | `/connectors/{id}/sync/changes/{change_id}/link` |

## Reconciliation Engine

The reconciliation engine compares the state of users and groups in xavyo-idp with the state in external systems, identifies discrepancies, and provides remediation actions.

### Triggering Reconciliation

```bash
curl -X POST https://your-domain.com/connectors/{connector_id}/reconciliation/runs \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "mode": "full",
    "dry_run": true
  }'
```

**Response (202 Accepted):**
```json
{
  "id": "run-uuid",
  "mode": "full",
  "status": "running",
  "dry_run": true,
  "started_at": "2026-02-07T12:00:00Z"
}
```

For SCIM outbound targets, use the dedicated reconciliation endpoint:

```bash
curl -X POST https://your-domain.com/admin/scim-targets/{target_id}/reconcile \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Reconciliation Runs

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Trigger run | POST | `/connectors/{id}/reconciliation/runs` |
| List runs | GET | `/connectors/{id}/reconciliation/runs` |
| Get run | GET | `/connectors/{id}/reconciliation/runs/{run_id}` |
| Cancel run | POST | `/connectors/{id}/reconciliation/runs/{run_id}/cancel` |
| Resume run | POST | `/connectors/{id}/reconciliation/runs/{run_id}/resume` |
| Get report | GET | `/connectors/{id}/reconciliation/runs/{run_id}/report` |

### Discrepancy Management

When reconciliation detects differences between local and remote state, it records discrepancies that administrators can review and remediate.

```bash
# List discrepancies
curl "https://your-domain.com/connectors/{connector_id}/reconciliation/discrepancies?discrepancy_type=mismatch&resolution_status=pending&limit=20" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Preview remediation actions
curl -X POST https://your-domain.com/connectors/{connector_id}/reconciliation/discrepancies/preview \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "discrepancy_ids": ["disc-uuid-1", "disc-uuid-2"]
  }'

# Bulk remediate
curl -X POST https://your-domain.com/connectors/{connector_id}/reconciliation/discrepancies/bulk-remediate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "items": [
      {"discrepancy_id": "disc-uuid-1", "action": "sync_to_target"},
      {"discrepancy_id": "disc-uuid-2", "action": "sync_from_target"}
    ],
    "dry_run": false
  }'

# Ignore a discrepancy
curl -X POST https://your-domain.com/connectors/{connector_id}/reconciliation/discrepancies/{discrepancy_id}/ignore \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Discrepancy Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| List discrepancies | GET | `/connectors/{id}/reconciliation/discrepancies` |
| Get discrepancy | GET | `/connectors/{id}/reconciliation/discrepancies/{disc_id}` |
| Preview remediation | POST | `/connectors/{id}/reconciliation/discrepancies/preview` |
| Remediate one | POST | `/connectors/{id}/reconciliation/discrepancies/{disc_id}/remediate` |
| Bulk remediate | POST | `/connectors/{id}/reconciliation/discrepancies/bulk-remediate` |
| Ignore discrepancy | POST | `/connectors/{id}/reconciliation/discrepancies/{disc_id}/ignore` |
| Get statistics | GET | `/connectors/{id}/reconciliation/statistics` |

### Reconciliation Schedules

Automate reconciliation by creating schedules:

```bash
# Create a schedule
curl -X POST https://your-domain.com/connectors/{connector_id}/reconciliation/schedule \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "mode": "full",
    "cron_expression": "0 2 * * *",
    "enabled": true
  }'
```

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Get schedule | GET | `/connectors/{id}/reconciliation/schedule` |
| Create/Update schedule | POST/PUT | `/connectors/{id}/reconciliation/schedule` |
| Delete schedule | DELETE | `/connectors/{id}/reconciliation/schedule` |
| Global schedules | GET | `/reconciliation/schedules` |
| Trend data | GET | `/reconciliation/trend` |

## Provisioning Operations

Track individual provisioning operations across all connectors:

```bash
# List operations
curl "https://your-domain.com/operations?status=pending&limit=20" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Get operation details
curl https://your-domain.com/operations/{operation_id} \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Retry a failed operation
curl -X POST https://your-domain.com/operations/{operation_id}/retry \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Cancel a pending operation
curl -X POST https://your-domain.com/operations/{operation_id}/cancel \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Operation Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| List operations | GET | `/operations` |
| Get operation | GET | `/operations/{id}` |
| Retry operation | POST | `/operations/{id}/retry` |
| Cancel operation | POST | `/operations/{id}/cancel` |
| Bulk retry | POST | `/operations/bulk-retry` |
| Bulk cancel | POST | `/operations/bulk-cancel` |
| Get statistics | GET | `/operations/statistics` |
| List by connector | GET | `/operations/connector/{connector_id}` |
| List by user | GET | `/operations/user/{user_id}` |

## Job Tracking & Dead-Letter Queue

### Connector Jobs

Monitor background provisioning jobs:

```bash
# List jobs
curl "https://your-domain.com/connectors/jobs?status=running&limit=20" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Get job details
curl https://your-domain.com/connectors/jobs/{job_id} \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Cancel a job
curl -X POST https://your-domain.com/connectors/jobs/{job_id}/cancel \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Dead-Letter Queue

Failed provisioning operations that exceed retry limits are sent to the DLQ for manual review:

```bash
# List DLQ items
curl https://your-domain.com/connectors/dlq \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Retry a DLQ item
curl -X POST https://your-domain.com/connectors/dlq/{item_id}/retry \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Discard a DLQ item
curl -X DELETE https://your-domain.com/connectors/dlq/{item_id} \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Job & DLQ Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| List jobs | GET | `/connectors/jobs` |
| Get job | GET | `/connectors/jobs/{id}` |
| Cancel job | POST | `/connectors/jobs/{id}/cancel` |
| List DLQ items | GET | `/connectors/dlq` |
| Retry DLQ item | POST | `/connectors/dlq/{id}/retry` |
| Discard DLQ item | DELETE | `/connectors/dlq/{id}` |

## Webhook Delivery

### Dead-Letter Queue

Webhook delivery failures that exceed retry limits are captured in a dedicated DLQ:

```bash
# List failed webhook deliveries
curl https://your-domain.com/webhooks/dlq \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Retry a failed delivery
curl -X POST https://your-domain.com/webhooks/dlq/{item_id}/retry \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Circuit Breakers

Circuit breakers automatically disable webhook delivery to consistently failing endpoints, preventing cascading failures:

```bash
# List circuit breaker states
curl https://your-domain.com/webhooks/circuit-breakers \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"

# Reset a circuit breaker
curl -X POST https://your-domain.com/webhooks/circuit-breakers/{id}/reset \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID"
```

### Webhook Endpoints

| Operation | Method | Endpoint |
|-----------|--------|----------|
| List DLQ items | GET | `/webhooks/dlq` |
| Get DLQ item | GET | `/webhooks/dlq/{id}` |
| Retry DLQ item | POST | `/webhooks/dlq/{id}/retry` |
| Bulk retry DLQ | POST | `/webhooks/dlq/bulk-retry` |
| Purge DLQ | DELETE | `/webhooks/dlq` |
| List circuit breakers | GET | `/webhooks/circuit-breakers` |
| Reset circuit breaker | POST | `/webhooks/circuit-breakers/{id}/reset` |

## Connector Lifecycle

### Creating a Connector

```bash
curl -X POST https://your-domain.com/connectors \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "name": "HR System Connector",
    "connector_type": "scim",
    "base_url": "https://hr.example.com/scim/v2",
    "credentials_encrypted": "base64-encrypted-credentials",
    "credentials_key_version": 1,
    "enabled": true
  }'
```

### Connector Management

| Operation | Method | Endpoint |
|-----------|--------|----------|
| Create connector | POST | `/connectors` |
| List connectors | GET | `/connectors` |
| Get connector | GET | `/connectors/{id}` |
| Update connector | PUT | `/connectors/{id}` |
| Delete connector | DELETE | `/connectors/{id}` |
| Activate | POST | `/connectors/{id}/activate` |
| Deactivate | POST | `/connectors/{id}/deactivate` |
| Health check | GET | `/connectors/{id}/health` |

## Security Considerations

- **Admin authentication required**: All connector management, sync, and reconciliation mutation endpoints require the `admin` role. Non-admin users receive `403 Forbidden`.
- **Credential security**: SCIM target credentials are encrypted at rest. Bearer tokens and OAuth client secrets are never returned in GET responses after initial creation.
- **Rate limiting**: Configurable per-target rate limits (`rate_limit_per_minute`) prevent overwhelming remote SCIM endpoints.
- **Request timeouts**: HTTP client timeouts (default 10 seconds) are enforced on all outbound requests to prevent hanging connections.
- **TLS verification**: The `tls_verify` flag controls whether the connector validates the remote endpoint's TLS certificate. Always enable this in production.
- **Tenant isolation**: All connector, target, and reconciliation data is scoped to the authenticated tenant through PostgreSQL Row-Level Security.
- **Reconciliation error mapping**: Reconciliation endpoints return proper HTTP status codes: `404` for not found, `400` for invalid input, `409` for conflicts (e.g., run already in progress).

## Related

- [User Management](./user-management.md) -- SCIM inbound provisioning for user and group creation
- [Security Hardening](./security-hardening.md) -- Key management and encryption configuration
- [Governance](./governance.md) -- Lifecycle policies that trigger provisioning operations
