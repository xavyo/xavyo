---
title: What is xavyo?
description: An introduction to xavyo, the unified identity governance and administration platform for humans, machines, and AI agents.
sidebar_position: 1
---

# What is xavyo?

xavyo is a unified Identity Governance and Administration (IGA) platform built to manage the full lifecycle of every identity in your organization -- human users, service accounts, and AI agents alike. It is written in Rust across 32 crates, exposes a pure REST API surface with 736 endpoints, and enforces tenant isolation at the database level through PostgreSQL Row-Level Security.

## The Identity Challenge

Modern organizations face an identity crisis that traditional tools were never designed to solve.

**Identity sprawl is accelerating.** The average enterprise manages thousands of human identities across dozens of applications. But human identities are no longer the majority. Service accounts, API keys, CI/CD pipelines, robotic process automation bots, and AI agents now outnumber human users in many organizations. Each of these Non-Human Identities (NHIs) carries credentials, holds permissions, and poses security risk -- yet most go unaudited, unrotated, and ungoverned.

**Regulatory pressure keeps rising.** Frameworks like SOX, GDPR, NIS2, and SOC 2 demand that organizations prove who has access to what, why they have it, and that toxic combinations of access are prevented. Manual spreadsheets and ad-hoc scripts cannot satisfy these requirements at scale.

**Point solutions create gaps.** Organizations typically cobble together separate products for authentication (IAM), access governance (IGA), and privileged access management (PAM). Each product has its own identity silo, its own policy engine, and its own audit trail. The seams between these products are where breaches happen.

## What Is IGA?

Identity Governance and Administration is the discipline of ensuring that the right people and machines have the right access to the right resources at the right time -- and that this state can be continuously verified and audited.

IGA goes beyond authentication ("prove who you are") and authorization ("check what you can do"). It addresses the lifecycle questions that matter for compliance and security:

- **Who approved this access?** Every entitlement assignment traces back to a request, an approval workflow, and a business justification.
- **Is this access still needed?** Certification campaigns require managers and application owners to periodically review and re-certify access.
- **Does this access create risk?** Separation of Duties rules detect and prevent toxic combinations -- such as a user who can both create vendors and approve payments.
- **What happens when someone leaves?** Joiner/Mover/Leaver workflows automate access provisioning and deprovisioning in response to HR lifecycle events.

## How xavyo Addresses the Convergence

xavyo collapses the traditional IAM / IGA / PAM boundaries into a single platform:

| Capability | Traditional Approach | xavyo Approach |
|---|---|---|
| Authentication | Separate IAM product | Built-in: OAuth2/OIDC (with RP-Initiated Logout), SAML 2.0 (with SLO), social login, passwordless, WebAuthn, MFA |
| Access Governance | Separate IGA product | Built-in: entitlements, roles, role inducements, SoD rules, certifications, access requests, GDPR compliance, lifecycle workflows, bulk actions, power of attorney |
| Privileged Access | Separate PAM product | Built-in: credential rotation, risk-based access, escalation policies |
| Non-Human Identities | Unmanaged or ad-hoc | First-class: unified model for agents, tools, and service accounts with lifecycle management, NHI-to-NHI permissions, MCP discovery, A2A protocol, certifications |
| Provisioning | Connectors bolted on | Built-in: LDAP/AD, Microsoft Entra ID, REST, database connectors with reconciliation, SCIM 2.0 inbound and outbound |

## Key Differentiators

### API-First, No UI Lock-In

xavyo is a pure backend platform. Every capability is exposed through a REST API -- there is no bundled frontend. This is a deliberate architectural choice:

- **Build your own experience.** Embed identity governance into your existing admin portal, build a custom access request UI, or integrate with your internal tooling. You are not locked into a vendor's UX decisions.
- **Automate everything.** Every operation that a human can perform through a UI can be performed programmatically. Terraform providers, CLI tools, and CI/CD pipelines can manage identity at the same fidelity as a governance administrator.
- **736 API endpoints** covering authentication, user management, group hierarchy, OAuth2/OIDC (with RP-Initiated Logout), SAML 2.0 (with Single Logout), SCIM 2.0, governance (roles, entitlements, inducements, certifications, SoD, GDPR, access requests, bulk actions, power of attorney, archetypes), NHI (unified model for agents/tools/service-accounts with lifecycle, permissions, MCP, A2A), provisioning (connectors, SCIM), webhooks, and more.

### Rust Performance and Safety

xavyo is built entirely in Rust across 32 crates with 665K lines of code, 198 SQL migrations, and 7,400+ tests (5,576 unit/integration + 1,907 functional). This is not a cosmetic choice -- it delivers concrete benefits:

- **Memory safety without garbage collection.** No null pointer exceptions, no data races, no GC pauses. The type system catches entire categories of bugs at compile time.
- **Predictable latency.** No stop-the-world pauses means consistent response times under load, which matters for authentication endpoints that sit in the critical path of every user session.
- **Compile-time SQL checking.** Database queries are verified against the actual schema at build time using SQLx, eliminating an entire class of runtime SQL errors.

### Comprehensive Non-Human Identity Support

Most identity platforms treat service accounts as an afterthought. xavyo treats NHIs as first-class citizens with dedicated lifecycle management:

- **AI Agent governance.** Register agents with risk levels, define tool permissions, track behavioral baselines, detect anomalies, and run security assessments.
- **Service account lifecycle.** Create accounts with ownership, purpose, and expiration metadata. Track usage, calculate risk scores, and run certification campaigns.
- **Credential rotation.** Automatic key rotation with configurable intervals and grace periods. Old credentials are invalidated; owners are notified.
- **NHI certification campaigns.** Periodic review campaigns ensure that every service account is still needed and its access is appropriate.

### Multi-Tenant by Design

Every row in every table is scoped to a tenant. This is not an application-level filter that could be bypassed -- it is enforced by PostgreSQL Row-Level Security policies at the database engine level. A query that forgets to include `tenant_id` returns zero rows rather than leaking data across tenants.

This architecture makes xavyo suitable for:

- **SaaS providers** who need to offer identity services to multiple customers from a single deployment.
- **Large enterprises** who need to isolate business units, subsidiaries, or regional organizations.
- **MSPs and consultancies** who manage identity infrastructure for multiple clients.

## Positioning in the Market

xavyo occupies a unique position at the intersection of established identity categories:

- **Compared to Okta / Auth0:** xavyo provides the same authentication capabilities (OAuth2, SAML, OIDC, social login, MFA) but adds full IGA governance -- entitlements, SoD, certifications, lifecycle workflows -- that workforce identity providers do not offer.
- **Compared to SailPoint / Saviynt:** xavyo provides the same governance capabilities (access requests, certifications, SoD, role mining, provisioning) but is API-first, built on modern infrastructure, and includes native authentication rather than depending on a separate IdP.
- **Compared to Microsoft Entra ID:** xavyo is cloud-agnostic and provides deeper governance features (parameterized roles, meta-roles, micro-certifications, NHI lifecycle) while connecting to Entra ID as a provisioning target through its connector framework.

## Architecture Overview

xavyo follows a layered architecture with strict dependency boundaries:

```
API Layer (14 crates)
  Axum HTTP handlers, request validation, OpenAPI documentation
      |
Domain Layer (8 crates)
  Business logic: governance, authorization, provisioning, webhooks, SIEM
      |
Connector Layer (4 crates)
  Identity source adapters: LDAP/AD, Entra ID, REST, database
      |
Foundation Layer (6 crates)
  Core types, JWT/auth, database/RLS, tenant middleware, events, secrets
      |
PostgreSQL 15+ (with Row-Level Security)  +  Kafka (optional)
```

All layers communicate through well-defined Rust traits and types. The API layer never accesses the database directly -- it calls domain services, which call the foundation layer. This separation means that the governance engine, the provisioning engine, and the authentication engine can evolve independently while sharing the same tenant isolation infrastructure.

## What's Next

- **[Key Concepts](./key-concepts.md)** -- Learn the core domain model: tenants, users, roles, entitlements, connectors, and more.
- **[Quick Tour](./quick-tour.md)** -- Walk through the platform capabilities with real API calls.
- **[Identity Governance](../concepts/identity-governance.md)** -- Understand the regulatory and operational drivers behind IGA.
