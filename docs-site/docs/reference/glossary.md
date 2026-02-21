---
title: Glossary
description: Definitions of key terms and concepts used throughout the xavyo identity platform documentation.
sidebar_position: 3
---

# Glossary

## A

### A2A (Agent-to-Agent) Protocol
A protocol for asynchronous task management between AI agents. xavyo implements A2A task endpoints for creating, monitoring, and cancelling tasks between registered agents. See [NHI Guide](/docs/guides/developer/nhi-machine-identities).

### Access Request
A formal request by a user to obtain a role, entitlement, or resource. Access requests go through an approval workflow before access is provisioned. See [Access Requests Guide](/docs/guides/end-user/access-requests).

### Access Token
A short-lived JWT (default: 1 hour) that authenticates API requests. Issued after successful login and MFA verification. Contains claims like `sub` (user ID), `tid` (tenant ID), and `roles`.

### AI Agent
An autonomous software entity registered in xavyo's NHI system. Agents have security boundaries, permission grants, behavioral baselines, and can be subject to human-in-the-loop approval gates. See [NHI Guide](/docs/guides/developer/nhi-machine-identities).

### API Key
A long-lived credential for machine-to-machine authentication, passed via the `X-API-Key` header. API keys are scoped to a tenant and can have restricted permissions.

### Approval Workflow
The process by which access requests, NHI actions, or other governance operations are reviewed and decided upon by designated approvers.

### Archetype
See [Identity Archetype](#identity-archetype).

### Audit Log
An immutable record of administrative and security-relevant actions. Used for compliance, incident investigation, and operational monitoring.

## B

### Behavioral Baseline
A profile of normal behavior patterns for an AI agent, established through observation. Deviations from the baseline trigger anomaly alerts.

### Bulk Action
An operation that applies a change to multiple resources simultaneously (e.g., bulk role assignment, bulk certification decisions). Supports expression-based targeting, preview before execution, and per-item tracking.

## C

### Catalog
See [Service Catalog](#service-catalog).

### Certification Campaign
A structured review process where a designated reviewer examines NHI access and decides to certify (retain) or revoke each identity's access.

### Circuit Breaker
A protection mechanism for webhooks. After a configurable number of consecutive delivery failures (default: 10), the subscription is automatically disabled to prevent wasted resources.

### Claims
Key-value pairs embedded in a JWT token. Standard claims include `sub` (subject/user ID), `tid` (tenant ID), `roles` (role names), `exp` (expiration), and `iss` (issuer).

### Client Credentials
An OAuth 2.0 grant type for machine-to-machine authentication where the application authenticates directly with its client ID and secret, without a user context.

### Connector
An integration component that connects xavyo to external systems (HR systems, directories, SaaS applications) for provisioning and reconciliation.

## D

### Data Protection Classification
A GDPR-aligned categorization applied to entitlements indicating the sensitivity of personal data they process. Levels: `none`, `personal`, `sensitive`, `special_category`. Drives governance rigor and feeds into GDPR compliance reports. See [Compliance & GDPR](/docs/concepts/compliance-gdpr).

### Dead Letter Queue (DLQ)
A storage area for webhook deliveries that have failed all retry attempts. DLQ entries can be inspected and replayed through the admin API.

### Delegated Administration
A system where super admins assign scoped administrative permissions to other users through role templates and assignments.

### Device Code Flow
An OAuth 2.0 grant type (RFC 8628) for input-constrained devices (smart TVs, CLI tools) where the user authenticates on a separate device.

### Device Trust
A mechanism where xavyo tracks recognized devices and can apply different authentication policies (e.g., reduced MFA prompts) for trusted devices.

## E

### Entitlement
A specific permission or access right that can be assigned to users. Entitlements are managed through the governance system and can be requested through the service catalog.

### Escalation
The automatic elevation of a pending access request to a higher-level approver when the original approver has not acted within the configured timeout period.

### Event Publisher
The internal service that emits webhook events when significant actions occur in the system (user created, login failed, access granted, etc.).

## F

### FIDO2
See [WebAuthn](#webauthn).

## G

### Governance
The set of policies, processes, and controls for managing identity lifecycle, access rights, compliance, and risk. Includes access requests, certifications, role management, and SoD validation.

## H

### HITL (Human-in-the-Loop)
A control pattern where high-risk AI agent actions require explicit human approval before execution. See [NHI Guide](/docs/guides/developer/nhi-machine-identities#human-in-the-loop-hitl-configuration).

### HMAC-SHA256
Hash-based Message Authentication Code using SHA-256. Used to sign webhook payloads for authenticity verification.

## I

### Identity Archetype
A template that defines the default attributes, lifecycle policies, and governance rules for a category of identities (e.g., employee, contractor, service account).

### Identity Provider (IdP)
A system that authenticates users and provides identity information. xavyo acts as an IdP (issuing tokens) and can also federate with external IdPs via SAML and OIDC.

### Induced Role
A role that is automatically granted to a user when they are assigned an inducing role. See [Role Inducement](#role-inducement).

### Inducement
A mechanism that automatically grants or revokes entitlements or roles based on conditions (e.g., group membership, identity archetype).

## J

### JWT (JSON Web Token)
A compact, signed token format (RFC 7519) used for access tokens and partial tokens. xavyo signs JWTs using RS256 (RSA with SHA-256).

### JWKS (JSON Web Key Set)
A set of public keys published at `/.well-known/jwks.json` that clients use to verify JWT signatures.

## L

### Lifecycle
The stages an identity goes through from creation to deletion: onboarding, active, suspended, offboarding, deleted. Managed through lifecycle configurations and state machines.

## M

### MCP (Model Context Protocol)
A standard protocol for AI agents to discover and invoke tools. xavyo integrates with AgentGateway to provide MCP-based tool discovery and import into the NHI system. See [Non-Human Identities](/docs/concepts/non-human-identities).

### MFA (Multi-Factor Authentication)
Authentication requiring two or more verification factors. xavyo supports TOTP (authenticator apps) and WebAuthn (security keys / biometrics). See [MFA Setup Guide](/docs/guides/end-user/mfa-setup).

### Multi-Tenancy
The architectural pattern where a single xavyo instance serves multiple organizations (tenants), with strict data isolation enforced at the database level through Row-Level Security (RLS).

## N

### NHI (Non-Human Identity)
A machine identity (service account, AI agent, or tool) managed through xavyo's NHI API. See [NHI Guide](/docs/guides/developer/nhi-machine-identities).

### Nonce
A single-use random value included in OIDC authentication flows to prevent replay attacks.

## O

### OAuth 2.0
An authorization framework (RFC 6749) that xavyo implements for token issuance. Supported grant types: Authorization Code (with PKCE), Client Credentials, Refresh Token, and Device Code.

### OIDC (OpenID Connect)
An identity layer on top of OAuth 2.0 that provides authentication. xavyo publishes discovery documents at `/.well-known/openid-configuration`.

## P

### Partial Token
A short-lived JWT (5 minutes) issued after successful password authentication when MFA is required. Must be exchanged for a full access token by completing MFA verification.

### Password Policy
Tenant-configurable rules for password strength, history, expiration, and minimum age. Enforced during signup, registration, and password change.

### post_logout_redirect_uri
An OIDC parameter specifying the URL where the user should be redirected after RP-Initiated Logout completes. Must be registered with the OAuth client for security. See [RP-Initiated Logout](#rp-initiated-logout).

### PKCE (Proof Key for Code Exchange)
An OAuth 2.0 extension (RFC 7636) that prevents authorization code interception attacks. Required for public clients (SPAs, mobile apps).

### Problem Details
An RFC 7807 standard for machine-readable error responses. xavyo uses the `application/problem+json` content type for all error responses.

### Provisioning
The automated process of creating, updating, or deleting accounts in downstream systems when access is granted or revoked.

## R

### RBAC (Role-Based Access Control)
An access control model where permissions are assigned to roles, and roles are assigned to users. xavyo supports RBAC through governance roles and user role assignments.

### Reconciliation
A process that compares identity data between xavyo and connected external systems to detect and resolve discrepancies.

### Recovery Codes
Single-use backup codes generated during MFA setup. Used to regain account access when the primary MFA factor (authenticator app or security key) is unavailable.

### Refresh Token
A long-lived opaque token (default: 30 days) used to obtain new access tokens without re-authenticating. Stored as a SHA-256 hash in the database. Supports rotation with family revocation on reuse.

### RLS (Row-Level Security)
A PostgreSQL feature that enforces tenant data isolation at the database level. Every table with tenant data has RLS policies that filter rows by the current tenant context.

### Role
A named set of permissions that can be assigned to users. Roles are stored in the `user_roles` table. Common roles include `user`, `admin`, and `super_admin`.

### Role Inducement
A configuration that automatically grants an induced role or entitlement when a user is assigned the inducing role. When the inducing role is removed, the induced access is revoked. See [Identity Governance](/docs/concepts/identity-governance).

### RP-Initiated Logout
An OIDC logout flow initiated by the Relying Party (client application). The RP redirects the user to the IdP's end_session_endpoint with an `id_token_hint` and optional `post_logout_redirect_uri`. See [SLO](#slo-single-logout).

## S

### SAML (Security Assertion Markup Language)
An XML-based standard for exchanging authentication data. xavyo supports both SP-initiated and IdP-initiated SAML flows.

### SCIM (System for Cross-domain Identity Management)
A REST API standard (RFC 7643/7644) for automated user and group provisioning. xavyo implements a SCIM 2.0 server. See [SCIM Integration Guide](/docs/guides/developer/scim-integration).

### Service Account
A non-human identity used by automated processes (CI/CD pipelines, background jobs, integrations). Managed through the NHI API.

### Service Catalog
A curated list of roles, entitlements, and resources that users can browse and request through the self-service access request system.

### SLO (Single Logout)
A protocol mechanism that propagates a logout event to all session participants. In SAML, SLO uses LogoutRequest/LogoutResponse messages. In OIDC, SLO is achieved through RP-Initiated Logout with the end_session_endpoint. See also [RP-Initiated Logout](#rp-initiated-logout).

### SLO Binding
The transport mechanism used for SAML Single Logout messages. Common bindings include HTTP-Redirect (for small messages via URL query parameters) and HTTP-POST (for larger messages via form submission).

### SoD (Separation of Duties)
A governance control that prevents a single user or NHI from holding conflicting permissions (e.g., both "create purchase order" and "approve purchase order"). xavyo supports SoD for both human identities (entitlement-based) and NHIs (tool permission-based).

### Storm-2372
A device code phishing attack technique. xavyo implements mitigations including origin IP comparison, stale request detection, and risk scoring.

## T

### Tenant
An isolated organizational unit within xavyo. Each tenant has its own users, groups, policies, and configurations. Data isolation is enforced through RLS.

### Tenant ID
A UUID that identifies a tenant. Included in JWT tokens as the `tid` claim and in unauthenticated requests via the `X-Tenant-ID` header.

### TOTP (Time-based One-Time Password)
An MFA method (RFC 6238) where an authenticator app generates 6-digit codes that change every 30 seconds, synchronized by a shared secret.

### Token Rotation
A security practice where refresh tokens are replaced with new ones on each use. If a rotated-out token is reused, the entire token family is revoked (indicating potential theft).

## W

### WebAuthn
A W3C standard for passwordless and MFA authentication using hardware security keys or platform authenticators (biometrics). Also known as FIDO2.

### Webhook
An HTTP callback that delivers real-time event notifications to registered endpoints. xavyo supports 36 event types with HMAC-SHA256 signature verification. See [Webhooks Guide](/docs/guides/developer/webhooks).
