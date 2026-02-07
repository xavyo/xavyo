---
title: Quick Tour
description: A guided walkthrough of xavyo's capabilities using real API calls against a local instance.
sidebar_position: 3
---

# Quick Tour

This walkthrough demonstrates xavyo's core capabilities through real API calls. Each section builds on the previous one, taking you from tenant setup through governance operations.

## Prerequisites

Before starting, ensure you have a running xavyo instance:

```bash
# Start infrastructure (PostgreSQL, Kafka, Mailpit)
docker compose -f docker/docker-compose.yml up -d

# Run database migrations
cargo run -p xavyo-db -- migrate

# Start the API server
cargo run -p idp-api
```

The API server runs on `http://localhost:8080`. Mailpit (for capturing verification emails) runs its web UI on `http://localhost:8025`.

All examples use `curl`. Set the base URL and system tenant ID as variables:

```bash
API="http://localhost:8080"
TENANT="00000000-0000-0000-0000-000000000001"
```

## 1. Register and Authenticate a User

### Sign Up

Create a new user account. xavyo enforces password complexity (uppercase, lowercase, digit, special character, minimum 8 characters).

```bash
curl -s -X POST "$API/auth/signup" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT" \
  -d '{
    "email": "alice@example.com",
    "password": "MyP@ssw0rd_2026",
    "first_name": "Alice",
    "last_name": "Johnson"
  }'
```

Response:
```json
{
  "user_id": "a1b2c3d4-...",
  "email": "alice@example.com",
  "message": "Verification email sent"
}
```

### Verify Email

xavyo sends a verification email through your configured SMTP provider (Mailpit in development). Extract the token from the email and verify:

```bash
# In development, retrieve the token from Mailpit
TOKEN=$(curl -s "http://localhost:8025/api/v1/messages" \
  | jq -r '.messages[0].ID' \
  | xargs -I{} curl -s "http://localhost:8025/api/v1/message/{}" \
  | jq -r '.Text' \
  | grep -oP 'token=\K[A-Za-z0-9_-]+')

curl -s -X POST "$API/auth/verify-email" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT" \
  -d "{\"token\": \"$TOKEN\"}"
```

### Log In

Authenticate and receive a JWT access token and refresh token:

```bash
curl -s -X POST "$API/auth/login" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT" \
  -d '{
    "email": "alice@example.com",
    "password": "MyP@ssw0rd_2026"
  }'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "dGhpcyBpcyBhIHJlZnJl...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

Save the access token for subsequent requests:

```bash
JWT="eyJhbGciOiJIUzI1NiIs..."
```

## 2. Manage Users and Groups

### Create Users (Admin)

With an admin-role JWT, create users directly:

```bash
curl -s -X POST "$API/users" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{
    "email": "bob@example.com",
    "password": "MyP@ssw0rd_2026",
    "first_name": "Bob",
    "last_name": "Smith"
  }'
```

### List Users

```bash
curl -s "$API/users?limit=10&offset=0" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT"
```

### Create a Group

Groups organize users for access management. xavyo supports hierarchical groups:

```bash
curl -s -X POST "$API/scim/v2/Users" \
  -H "Content-Type: application/scim+json" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -d '{
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    "displayName": "Engineering",
    "members": []
  }'
```

Or through the native groups API -- groups can be managed through SCIM 2.0 or the admin REST API depending on your integration pattern.

## 3. Set Up Governance

### Register an Application

Before defining entitlements, register the application they belong to:

```bash
curl -s -X POST "$API/governance/applications" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{
    "name": "Payment System",
    "app_type": "internal",
    "description": "Core payment processing application"
  }'
```

Save the application ID from the response:

```bash
APP_ID="..."
```

### Define Entitlements

Create the access rights that users can be granted:

```bash
# Create a low-risk entitlement
curl -s -X POST "$API/governance/entitlements" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d "{
    \"application_id\": \"$APP_ID\",
    \"name\": \"View Transactions\",
    \"description\": \"Read-only access to transaction history\",
    \"risk_level\": \"low\"
  }"

# Create a high-risk entitlement
curl -s -X POST "$API/governance/entitlements" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d "{
    \"application_id\": \"$APP_ID\",
    \"name\": \"Approve Payments\",
    \"description\": \"Authority to approve payment disbursements\",
    \"risk_level\": \"high\"
  }"
```

### Create a Role

Bundle entitlements into a role:

```bash
curl -s -X POST "$API/governance/roles" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{
    "name": "Payment Analyst",
    "description": "Can view transactions but not approve payments"
  }'
```

### Create a Separation of Duties Rule

Prevent toxic access combinations:

```bash
curl -s -X POST "$API/governance/sod-rules" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d "{
    \"name\": \"Payment SoD\",
    \"description\": \"Cannot both create and approve payments\",
    \"severity\": \"high\",
    \"left_entitlement_id\": \"$CREATE_PAYMENT_ENT_ID\",
    \"right_entitlement_id\": \"$APPROVE_PAYMENT_ENT_ID\"
  }"
```

### Check for SoD Violations

Before assigning an entitlement, check if it would create a violation:

```bash
curl -s -X POST "$API/governance/sod-check" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d "{
    \"user_id\": \"$USER_ID\",
    \"entitlement_id\": \"$APPROVE_PAYMENT_ENT_ID\"
  }"
```

## 4. Assign and Govern Access

### Assign an Entitlement

```bash
curl -s -X POST "$API/governance/assignments" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d "{
    \"entitlement_id\": \"$ENT_ID\",
    \"target_id\": \"$USER_ID\",
    \"target_type\": \"user\"
  }"
```

### View a User's Effective Access

See all entitlements a user holds -- including those inherited through groups and roles:

```bash
curl -s "$API/governance/users/$USER_ID/effective-access" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT"
```

### Calculate a User's Risk Score

```bash
curl -s -X POST "$API/governance/users/$USER_ID/risk-score/calculate" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT"
```

## 5. Set Up a Connector

### Create a Connector Configuration

Connect xavyo to an external identity source:

```bash
curl -s -X POST "$API/connectors" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{
    "name": "Corporate LDAP",
    "connector_type": "ldap",
    "config": {
      "host": "ldap.corp.example.com",
      "port": 636,
      "use_ssl": true,
      "bind_dn": "cn=admin,dc=corp,dc=example,dc=com",
      "base_dn": "dc=corp,dc=example,dc=com"
    }
  }'
```

### Test Connectivity

```bash
curl -s -X POST "$API/connectors/$CONNECTOR_ID/test" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT"
```

### Trigger Synchronization

```bash
curl -s -X POST "$API/connectors/$CONNECTOR_ID/sync/trigger" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT"
```

### Trigger Reconciliation

Compare xavyo's data with the external system to find discrepancies:

```bash
curl -s -X POST "$API/connectors/$CONNECTOR_ID/reconciliation/trigger" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT"
```

## 6. Run a Certification Campaign

### Create a Campaign

```bash
curl -s -X POST "$API/governance/certification-campaigns" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{
    "name": "Q1 2026 Access Review",
    "description": "Quarterly access certification for all users",
    "campaign_type": "user_access"
  }'
```

### Launch the Campaign

```bash
curl -s -X POST "$API/governance/certification-campaigns/$CAMPAIGN_ID/launch" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT"
```

### Review Certification Items

```bash
curl -s "$API/governance/certification-campaigns/$CAMPAIGN_ID/items" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT"
```

### Make a Certification Decision

```bash
curl -s -X POST "$API/governance/certification-items/$ITEM_ID/decide" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{
    "decision": "certify",
    "comment": "Access still required for Q1 project"
  }'
```

## 7. Manage Non-Human Identities

### Register an AI Agent

```bash
curl -s -X POST "$API/nhi/agents" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d "{
    \"name\": \"deployment-bot\",
    \"agent_type\": \"autonomous\",
    \"description\": \"Automated deployment pipeline agent\",
    \"risk_level\": \"medium\",
    \"owner_id\": \"$ADMIN_USER_ID\"
  }"
```

### Rotate Agent Credentials

```bash
curl -s -X POST "$API/nhi/agents/$AGENT_ID/credentials/rotate" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{
    "credential_type": "api_key",
    "name": "deploy-key-v2",
    "grace_period_hours": 24
  }'
```

### Create a Service Account

```bash
curl -s -X POST "$API/nhi/service-accounts" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d "{
    \"name\": \"payment-service-prod\",
    \"description\": \"Production payment processing service\",
    \"owner_id\": \"$ADMIN_USER_ID\"
  }"
```

### Check NHI Staleness

Identify service accounts and agents that have not been used recently:

```bash
curl -s "$API/nhi/staleness-report" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT"
```

## 8. Explore Additional Capabilities

### GDPR Data Subject Report

Generate a report of all data held about a specific user:

```bash
curl -s -X POST "$API/governance/gdpr/report" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d "{\"user_id\": \"$USER_ID\"}"
```

### Webhook Subscriptions

Subscribe to identity events:

```bash
curl -s -X POST "$API/webhooks/subscriptions" \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT" \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{
    "url": "https://your-app.example.com/webhooks",
    "events": ["user.created", "user.deactivated", "entitlement.assigned"],
    "secret": "your-webhook-secret"
  }'
```

### OpenID Connect Discovery

xavyo acts as a standards-compliant OIDC provider:

```bash
curl -s "$API/.well-known/openid-configuration"
```

### SAML Metadata

For SAML federation:

```bash
curl -s "$API/saml/metadata"
```

## What's Next

This tour covered the core workflows. For deeper exploration:

- **[Identity Governance](../concepts/identity-governance.md)** -- Understand the regulatory drivers behind access governance.
- **[Lifecycle Management](../concepts/lifecycle-management.md)** -- Learn about automated Joiner/Mover/Leaver workflows.
- **[Non-Human Identities](../concepts/non-human-identities.md)** -- Explore comprehensive NHI lifecycle management.
- **[API Reference](/docs/reference/api/xavyo-api)** -- Browse the full OpenAPI specification with 933 operations.
