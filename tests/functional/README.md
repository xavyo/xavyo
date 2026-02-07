# Functional Test Suite for xavyo IDP

## Overview

This directory contains comprehensive functional test specifications for the xavyo Identity Platform.
Tests are organized by domain and cover nominal cases, edge cases, and compliance with industry standards.

## Standards & Compliance References

- **NIST SP 800-63B** — Digital Identity Guidelines (Authentication & Lifecycle)
- **OWASP ASVS v4.0** — Application Security Verification Standard
- **ISO 27001 Annex A.9** — Access Control
- **SOC 2 Type II** — Trust Service Criteria (Security, Availability, Confidentiality)
- **OpenID Connect Core 1.0** — OIDC Conformance
- **OAuth 2.0 (RFC 6749, 6750, 7636)** — Authorization Framework
- **SAML 2.0 (OASIS)** — Security Assertion Markup Language
- **SCIM 2.0 (RFC 7643, 7644)** — System for Cross-domain Identity Management
- **FIDO2/WebAuthn (W3C)** — Web Authentication
- **GDPR Articles 15-20** — Data Subject Rights

## Test File Format

Each `.md` file contains test cases in the following format:

```
### TC-{DOMAIN}-{NUMBER}: {Test Name}
- **Category**: Nominal | Edge Case | Security | Compliance
- **Standard**: Reference to applicable standard
- **Preconditions**: Required state before test
- **Input**: HTTP request or CLI command
- **Steps**: Sequence of actions
- **Expected Output**: Response status, body, side effects
- **Teardown**: Cleanup actions
```

## Directory Structure

```
tests/functional/
├── auth/              # Authentication (login, signup, password reset, email verification)
├── oauth/             # OAuth 2.0 flows (client credentials, device code, authorization code)
├── oidc/              # OpenID Connect (ID tokens, userinfo, discovery, JWKS)
├── saml/              # SAML 2.0 (SSO, SLO, metadata, assertions)
├── scim/              # SCIM 2.0 (users, groups, bulk, filtering)
├── mfa/               # Multi-Factor Authentication (TOTP, WebAuthn, recovery)
├── users/             # User management (CRUD, search, lifecycle)
├── groups/            # Group management (CRUD, membership)
├── tenants/           # Tenant management (creation, isolation, settings)
├── sessions/          # Session management (creation, revocation, limits)
├── agents/            # NHI Agent management (registration, credentials, tools)
├── governance/        # IGA (roles, entitlements, SoD, campaigns, workflows)
├── connectors/        # Provisioning connectors (LDAP, Entra, REST)
├── webhooks/          # Webhook delivery and management
├── social/            # Social login providers (Google, Microsoft, GitHub, Apple)
├── api-keys/          # API key management (creation, rotation, scoping)
├── import-export/     # Bulk import/export operations
├── gdpr/              # GDPR data subject rights
├── policies/          # Security policies (password, MFA, session)
└── operations/        # Provisioning operations and job tracking
```

## Execution

These tests are specification-only. They define WHAT to test, not HOW.
Future implementation will use `cargo test` with HTTP client calls against a running instance.

## Test Case Inventory

**62 test files** across **20 domains** — **1,969 test cases total**

| Domain | Files | Test Cases | Key Standards |
|--------|-------|------------|---------------|
| Auth (signup, login, password reset, email verification, token refresh) | 5 | 118 | NIST SP 800-63B, OWASP ASVS 2.1/2.5/3.5, RFC 6749 |
| MFA (TOTP, WebAuthn/FIDO2) | 2 | 43 | RFC 6238, W3C WebAuthn Level 2, NIST AAL2/AAL3 |
| OAuth (client credentials, device code, authorization code, token mgmt) | 4 | 180 | RFC 6749/6750/7636/7662/7009/8628 |
| OIDC (discovery, ID tokens, userinfo, federation) | 4 | 138 | OpenID Connect Core 1.0, RFC 7517/7519 |
| SCIM (users, groups, bulk, filtering, schemas) | 5 | 183 | RFC 7643/7644 |
| SAML (SP-initiated SSO, IdP-initiated SSO, metadata, certs, SLO) | 5 | 176 | SAML 2.0, OASIS, X.509 |
| Users (CRUD, search, lifecycle, profile/self-service) | 4 | 169 | ISO 27001 A.9.2, NIST SP 800-53 AC-2 |
| Groups (CRUD, membership) | 2 | 83 | ISO 27001 A.9.2.2, RBAC |
| Agents/NHI (agents, credentials, tools, service accounts, certification) | 5 | 182 | NIST SP 800-207, ISO 27001 A.9.4 |
| Governance/IGA (archetypes, roles, entitlements, SoD, certification, lifecycle, access requests, constructions, inducements, bulk actions, delegation, templates) | 12 | 357 | SOX 404, SOC 2 CC6.1/CC6.3, ISO 27001 A.9, NIST SP 800-53 |
| Sessions | 1 | 30 | OWASP ASVS 3.3/3.7 |
| Social (Google, Microsoft, GitHub, Apple) | 1 | 25 | OpenID Connect, OAuth 2.0 |
| API Keys (management, usage) | 2 | 45 | OWASP ASVS 3.5, ISO 27001 A.9.4.2 |
| Connectors (configuration, sync) | 2 | 45 | SCIM 2.0, LDAP |
| Webhooks (management, delivery/DLQ) | 2 | 45 | HMAC-SHA256 signing |
| Import/Export | 1 | 25 | CSV injection protection, GDPR |
| Tenants (management, settings) | 2 | 50 | SOC 2 CC6.3, multi-tenancy isolation |
| GDPR (data subject rights) | 1 | 20 | GDPR Articles 15-20, ISO 27701 |
| Operations (provisioning) | 1 | 20 | ITIL change management |
| Policies (password, MFA) | 2 | 35 | NIST SP 800-63B, OWASP ASVS 2.1 |
| **Total** | **62** | **1,969** | |
