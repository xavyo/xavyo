# Crate Index

All 32 crates in xavyo organized by architectural layer.

## Foundation Layer

Core infrastructure that all other layers depend on.

| Crate | Description | Status |
|-------|-------------|--------|
| [xavyo-core](../../crates/xavyo-core/CRATE.md) | Shared types: TenantId, UserId, errors | Stable |
| [xavyo-auth](../../crates/xavyo-auth/CRATE.md) | JWT validation, password hashing, JWKS | Stable |
| [xavyo-db](../../crates/xavyo-db/CRATE.md) | PostgreSQL models, migrations, RLS | Stable |
| [xavyo-tenant](../../crates/xavyo-tenant/CRATE.md) | Multi-tenant middleware extraction | Stable |
| [xavyo-events](../../crates/xavyo-events/CRATE.md) | Kafka producer/consumer with idempotence | Stable |
| [xavyo-nhi](../../crates/xavyo-nhi/CRATE.md) | Non-human identity types and traits | Stable |

## Domain Layer

Business logic independent of HTTP transport.

| Crate | Description | Status |
|-------|-------------|--------|
| [xavyo-connector](../../crates/xavyo-connector/CRATE.md) | Abstract connector traits and types | Stable |
| [xavyo-provisioning](../../crates/xavyo-provisioning/CRATE.md) | Sync engine, reconciliation, Rhai scripts | Stable |
| [xavyo-governance](../../crates/xavyo-governance/CRATE.md) | Access requests, certifications, SoD | Stable |
| [xavyo-authorization](../../crates/xavyo-authorization/CRATE.md) | Policy evaluation (PDP), entitlements | Stable |
| [xavyo-webhooks](../../crates/xavyo-webhooks/CRATE.md) | Event subscriptions and delivery | Stable |
| [xavyo-siem](../../crates/xavyo-siem/CRATE.md) | Audit log export (syslog, Splunk) | Stable |
| [xavyo-secrets](../../crates/xavyo-secrets/CRATE.md) | External secret providers | Stable |
| [xavyo-scim-client](../../crates/xavyo-scim-client/CRATE.md) | Outbound SCIM provisioning | Stable |

## Connector Layer

Identity source implementations.

| Crate | Description | Status |
|-------|-------------|--------|
| [xavyo-connector-ldap](../../crates/xavyo-connector-ldap/CRATE.md) | LDAP/Active Directory connector | Stable |
| [xavyo-connector-entra](../../crates/xavyo-connector-entra/CRATE.md) | Microsoft Entra ID connector | Stable |
| [xavyo-connector-rest](../../crates/xavyo-connector-rest/CRATE.md) | Generic REST API connector | Stable |
| [xavyo-connector-database](../../crates/xavyo-connector-database/CRATE.md) | SQL database connector | Stable |

## API Layer

REST endpoints exposed to clients.

| Crate | Description | Status |
|-------|-------------|--------|
| [xavyo-api-auth](../../crates/xavyo-api-auth/CRATE.md) | Login, MFA, sessions, password reset | Stable |
| [xavyo-api-oauth](../../crates/xavyo-api-oauth/CRATE.md) | OAuth2/OIDC provider endpoints | Stable |
| [xavyo-api-users](../../crates/xavyo-api-users/CRATE.md) | User CRUD and attributes | Stable |
| [xavyo-api-scim](../../crates/xavyo-api-scim/CRATE.md) | SCIM 2.0 inbound provisioning | Stable |
| [xavyo-api-saml](../../crates/xavyo-api-saml/CRATE.md) | SAML 2.0 IdP endpoints | Stable |
| [xavyo-api-social](../../crates/xavyo-api-social/CRATE.md) | Social login providers | Stable |
| [xavyo-api-agents](../../crates/xavyo-api-agents/CRATE.md) | AI agent security platform | Stable |
| [xavyo-api-governance](../../crates/xavyo-api-governance/CRATE.md) | IGA workflows and reporting | Stable |
| [xavyo-api-connectors](../../crates/xavyo-api-connectors/CRATE.md) | Connector management API | Stable |
| [xavyo-api-tenants](../../crates/xavyo-api-tenants/CRATE.md) | Tenant provisioning API | Stable |
| [xavyo-api-authorization](../../crates/xavyo-api-authorization/CRATE.md) | Authorization policy API | Stable |
| [xavyo-api-import](../../crates/xavyo-api-import/CRATE.md) | Bulk user import API | Stable |
| [xavyo-api-oidc-federation](../../crates/xavyo-api-oidc-federation/CRATE.md) | OIDC federation endpoints | Stable |
| [xavyo-api-nhi](../../crates/xavyo-api-nhi/CRATE.md) | Non-human identity API | Stable |

## Dependency Rules

1. **Foundation** crates have no internal dependencies (except xavyo-core)
2. **Domain** crates depend on Foundation only
3. **Connector** crates depend on xavyo-connector (Domain)
4. **API** crates depend on Foundation and Domain as needed

See [Dependency Graph](dependency-graph.md) for visual representation.
