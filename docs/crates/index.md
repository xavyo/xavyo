# Crate Index

All 35 crates in xavyo organized by architectural layer.

See [Maturity Matrix](maturity-matrix.md) for detailed assessment criteria.

## Foundation Layer

Core infrastructure that all other layers depend on.

| Crate | Description | Status |
|-------|-------------|--------|
| [xavyo-core](../../crates/xavyo-core/CRATE.md) | Shared types: TenantId, UserId, errors | 🟢 stable |
| [xavyo-auth](../../crates/xavyo-auth/CRATE.md) | JWT validation, password hashing, JWKS | 🟢 stable |
| [xavyo-db](../../crates/xavyo-db/CRATE.md) | PostgreSQL models, migrations, RLS | 🟢 stable |
| [xavyo-tenant](../../crates/xavyo-tenant/CRATE.md) | Multi-tenant middleware extraction | 🟢 stable |
| [xavyo-events](../../crates/xavyo-events/CRATE.md) | Kafka producer/consumer with idempotence | 🟢 stable |
| [xavyo-nhi](../../crates/xavyo-nhi/CRATE.md) | Non-human identity types and traits | 🟢 stable |

## Domain Layer

Business logic independent of HTTP transport.

| Crate | Description | Status |
|-------|-------------|--------|
| [xavyo-connector](../../crates/xavyo-connector/CRATE.md) | Abstract connector traits and types | 🟢 stable |
| [xavyo-provisioning](../../crates/xavyo-provisioning/CRATE.md) | Sync engine, reconciliation, Rhai scripts | 🟢 stable |
| [xavyo-governance](../../crates/xavyo-governance/CRATE.md) | Access requests, certifications, SoD | 🟢 stable |
| [xavyo-authorization](../../crates/xavyo-authorization/CRATE.md) | Authorization engine (PDP) | 🟢 stable |
| [xavyo-webhooks](../../crates/xavyo-webhooks/CRATE.md) | Event subscriptions and delivery | 🟢 stable |
| [xavyo-siem](../../crates/xavyo-siem/CRATE.md) | Audit log export (syslog, Splunk) | 🟢 stable |
| [xavyo-ssf](../../crates/xavyo-ssf/CRATE.md) | CAEP/Shared Signals: SETs, subject IDs, emitter | 🔴 alpha |
| [xavyo-secrets](../../crates/xavyo-secrets/CRATE.md) | External secret providers | 🟢 stable |
| [xavyo-scim-client](../../crates/xavyo-scim-client/CRATE.md) | Outbound SCIM provisioning | 🟢 stable |
| [xavyo-scim-types](../../crates/xavyo-scim-types/CRATE.md) | Shared SCIM 2.0 DTOs (RFC 7643/7644) | 🟢 stable |
| [xavyo-ext-authz](../../crates/xavyo-ext-authz/CRATE.md) | Envoy ext_authz v3 gRPC server for AgentGateway | 🟢 stable |

## Connector Layer

Identity source implementations.

| Crate | Description | Status |
|-------|-------------|--------|
| [xavyo-connector-ldap](../../crates/xavyo-connector-ldap/CRATE.md) | LDAP/Active Directory connector | 🟢 stable |
| [xavyo-connector-entra](../../crates/xavyo-connector-entra/CRATE.md) | Microsoft Entra ID connector (crate/API; no UI form) | 🟢 stable |
| [xavyo-connector-rest](../../crates/xavyo-connector-rest/CRATE.md) | Generic REST API connector (crate/API; not a production UI path) | 🟢 stable |
| [xavyo-connector-database](../../crates/xavyo-connector-database/CRATE.md) | SQL database connector (crate/API; not a production UI path) | 🟢 stable |

## API Layer

REST endpoints exposed to clients.

| Crate | Description | Status |
|-------|-------------|--------|
| [xavyo-api-auth](../../crates/xavyo-api-auth/CRATE.md) | Login, MFA, sessions, password reset | 🟢 stable |
| [xavyo-api-oauth](../../crates/xavyo-api-oauth/CRATE.md) | OAuth2/OIDC provider endpoints | 🟢 stable |
| [xavyo-api-users](../../crates/xavyo-api-users/CRATE.md) | User CRUD and attributes | 🟢 stable |
| [xavyo-api-scim](../../crates/xavyo-api-scim/CRATE.md) | SCIM 2.0 inbound provisioning | 🟢 stable |
| [xavyo-api-saml](../../crates/xavyo-api-saml/CRATE.md) | SAML 2.0 IdP endpoints | 🟢 stable |
| [xavyo-api-social](../../crates/xavyo-api-social/CRATE.md) | Social login providers | 🟢 stable |
| [xavyo-api-governance](../../crates/xavyo-api-governance/CRATE.md) | IGA workflows and reporting | 🟢 stable |
| [xavyo-api-connectors](../../crates/xavyo-api-connectors/CRATE.md) | Connector management API | 🟢 stable |
| [xavyo-api-tenants](../../crates/xavyo-api-tenants/CRATE.md) | Tenant provisioning API | 🟢 stable |
| [xavyo-api-authorization](../../crates/xavyo-api-authorization/CRATE.md) | Authorization policy API | 🟢 stable |
| [xavyo-api-import](../../crates/xavyo-api-import/CRATE.md) | Bulk user import API | 🟢 stable |
| [xavyo-api-oidc-federation](../../crates/xavyo-api-oidc-federation/CRATE.md) | OIDC federation endpoints | 🟢 stable |
| [xavyo-api-nhi](../../crates/xavyo-api-nhi/CRATE.md) | Non-human identity API | 🟢 stable |
| [xavyo-api-ssf](../../crates/xavyo-api-ssf/CRATE.md) | SSF transmitter: streams, push CAEP signals | 🔴 alpha |

## Dependency Rules

1. **Foundation** crates have no internal dependencies (except xavyo-core)
2. **Domain** crates depend on Foundation only
3. **Connector** crates depend on xavyo-connector (Domain)
4. **API** crates depend on Foundation and Domain as needed

See [Dependency Graph](dependency-graph.md) for visual representation.
