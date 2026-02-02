# xavyo Architecture

> Unified identity platform for humans, machines, and AI agents

## Overview

xavyo is a multi-tenant Identity and Access Management (IAM) platform built in Rust. It provides:

- **Authentication**: OAuth2/OIDC, SAML, social login, passwordless
- **Provisioning**: Connector framework for LDAP, Entra ID, REST APIs
- **Governance**: Access requests, certifications, compliance reporting
- **AI Agent Security**: Tool authorization, dynamic secrets, PKI certificates

## System Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                          API Gateway                                 │
│                    (Axum + Tower middleware)                        │
└────────────────────────────┬────────────────────────────────────────┘
                             │
┌────────────────────────────┴────────────────────────────────────────┐
│                         API Layer                                    │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │
│  │ api-auth │ │api-oauth │ │api-users │ │api-agents│ │api-scim  │  │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘  │
└───────┼────────────┼────────────┼────────────┼────────────┼─────────┘
        │            │            │            │            │
┌───────┴────────────┴────────────┴────────────┴────────────┴─────────┐
│                       Domain Layer                                   │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐        │
│  │authorization│ │ governance │ │provisioning│ │  webhooks  │        │
│  └──────┬─────┘ └──────┬─────┘ └──────┬─────┘ └──────┬─────┘        │
└─────────┼──────────────┼──────────────┼──────────────┼───────────────┘
          │              │              │              │
┌─────────┴──────────────┴──────────────┴──────────────┴───────────────┐
│                      Connector Layer                                  │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐         │
│  │ conn-ldap  │ │ conn-entra │ │ conn-rest  │ │ conn-db    │         │
│  └──────┬─────┘ └──────┬─────┘ └──────┬─────┘ └──────┬─────┘         │
└─────────┼──────────────┼──────────────┼──────────────┼────────────────┘
          │              │              │              │
┌─────────┴──────────────┴──────────────┴──────────────┴────────────────┐
│                      Foundation Layer                                  │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐   │
│  │  core  │ │  auth  │ │   db   │ │ tenant │ │ events │ │secrets │   │
│  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘ └────────┘   │
└───────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    │     PostgreSQL 15+ (RLS)      │
                    │     + Kafka (optional)        │
                    └───────────────────────────────┘
```

## Layer Responsibilities

### Foundation Layer
Core infrastructure that all other layers depend on:

| Crate | Responsibility |
|-------|---------------|
| `xavyo-core` | Shared types: TenantId, UserId, errors |
| `xavyo-auth` | JWT validation, password hashing, JWKS |
| `xavyo-db` | PostgreSQL models, migrations, RLS |
| `xavyo-tenant` | Multi-tenant middleware extraction |
| `xavyo-events` | Kafka producer/consumer with idempotence |
| `xavyo-secrets` | External secret providers (Vault, AWS) |

### Domain Layer
Business logic independent of HTTP transport:

| Crate | Responsibility |
|-------|---------------|
| `xavyo-authorization` | Policy evaluation (PDP), entitlement checks |
| `xavyo-governance` | Access requests, certifications, SoD rules |
| `xavyo-provisioning` | Sync engine, reconciliation, correlation |
| `xavyo-connector` | Abstract connector traits |
| `xavyo-webhooks` | Event subscriptions, delivery, retry |
| `xavyo-siem` | Audit log export (syslog, Splunk, webhook) |

### Connector Layer
Identity source implementations:

| Crate | Target System |
|-------|--------------|
| `xavyo-connector-ldap` | LDAP/Active Directory |
| `xavyo-connector-entra` | Microsoft Entra ID |
| `xavyo-connector-rest` | Generic REST APIs |
| `xavyo-connector-database` | SQL databases |

### API Layer
REST endpoints exposed to clients:

| Crate | Endpoints |
|-------|-----------|
| `xavyo-api-auth` | `/auth/*` - login, MFA, sessions |
| `xavyo-api-oauth` | `/oauth/*` - authorize, token, userinfo |
| `xavyo-api-users` | `/users/*` - CRUD, attributes |
| `xavyo-api-agents` | `/agents/*` - AI agent security |
| `xavyo-api-scim` | `/scim/*` - SCIM 2.0 inbound |

## Request Flow

A typical authenticated request flows through:

```
1. HTTP Request
   ↓
2. Tower Middleware Stack
   ├── Request ID injection
   ├── CORS headers
   ├── Rate limiting
   └── Tenant extraction (X-Tenant-ID header)
   ↓
3. JWT Validation (xavyo-auth)
   └── Extract claims → Extension<JwtClaims>
   ↓
4. Axum Handler
   └── Extract tenant_id from claims
   ↓
5. Domain Service
   └── Business logic with tenant isolation
   ↓
6. Database Query (xavyo-db)
   └── RLS enforces tenant_id filter
   ↓
7. Event Emission (optional)
   └── Kafka event with tenant context
```

## Multi-Tenancy Model

Every request is isolated to a single tenant:

1. **Request**: `X-Tenant-ID` header or JWT `tid` claim
2. **Middleware**: Extracts into `Extension<TenantId>`
3. **Handler**: Passes tenant_id to all service calls
4. **Database**: RLS policy filters by `current_setting('app.current_tenant')`

```rust
// Handler pattern
async fn handler(
    Extension(claims): Extension<JwtClaims>,
    State(state): State<AppState>,
) -> Result<Json<Response>> {
    let tenant_id = claims.tenant_id()?;
    let result = state.service.get_resource(tenant_id, resource_id).await?;
    Ok(Json(result))
}
```

## Security Architecture

### Authentication Methods
- Password + MFA (TOTP, WebAuthn)
- OAuth2/OIDC (authorization code, device code)
- SAML 2.0 IdP
- Social login (Google, Microsoft, etc.)
- Passwordless (magic links)
- API keys (for service accounts)

### Authorization Model
- RBAC with hierarchical roles
- Entitlement-based access
- Policy conditions (time, location, risk)
- SoD (Separation of Duties) enforcement

### Secrets Management
- Never store plaintext secrets
- AES-GCM encryption at rest
- External providers: HashiCorp Vault, AWS Secrets Manager
- Dynamic credentials with short TTL

## Technology Stack

| Component | Technology |
|-----------|------------|
| Language | Rust 1.75+ |
| Web Framework | Axum 0.7 + Tower |
| Database | PostgreSQL 15+ with RLS |
| Event Streaming | Apache Kafka (optional) |
| Serialization | serde + JSON |
| API Docs | utoipa (OpenAPI 3.0) |
| Testing | cargo test + integration tests |

## Configuration

All services configured via environment variables:

```bash
DATABASE_URL=postgres://user:pass@localhost/xavyo
KAFKA_BROKERS=localhost:9092
JWT_SECRET=<base64-encoded-secret>
ENCRYPTION_KEY=<32-byte-key>
```

## Related Documentation

- [Crate Index](crates/index.md) - All crates with descriptions
- [Dependency Graph](crates/dependency-graph.md) - Visual dependencies
- [Multi-Tenancy Pattern](../CLAUDE.md#multi-tenancy-requirements-mandatory) - Implementation guide
