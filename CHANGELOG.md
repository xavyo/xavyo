# Changelog

All notable changes to xavyo will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-02-28

### Added

- **Agent Blueprints** (`nhi_agent_blueprint`): reusable agent configuration templates that pre-define `agent_type`, `model_provider`, `model_name`, `max_token_lifetime_secs`, `requires_human_approval`, `default_entitlements`, and `default_delegation`. Pass `blueprint_id` to `POST /nhi/provision-agent` to apply blueprint defaults (explicit request fields take precedence). CRUD API at `/nhi/blueprints`. 5 unit tests.
- **Token Vault — external OAuth tokens** (`token_vault_service`): secure storage and exchange of external provider tokens for NHI identities. AES-GCM encryption at rest, auto-refresh when expired, Zeroize pattern for sensitive data. Endpoints: `POST/GET /nhi/:id/vault/external-tokens`, `DELETE /nhi/:id/vault/external-tokens/:token_id`, `POST /nhi/:id/vault/token-exchange`. 6 unit tests.
- **RFC 8693 Token Exchange enhancements**: `may_act` pre-authorization constraint (§4.4) on `JwtClaims` — restricts which actors can exchange a subject token. `actor_token_type` validation (§2.1) — rejects unsupported token types. Resource parameter validation against grant's `allowed_resource_types` (RFC 8707). Audience/resource propagation to issued tokens. 3 new `may_act` tests + existing tests updated.
- **`MayActClaim` struct** (`claims.rs`): `sub: Vec<String>` with `is_actor_allowed()` method. Serialized as `may_act` claim in JWT. Builder support via `.may_act()`.
- **Cedar policy engine integration** (`xavyo-authorization`): `cedar` feature flag enables `CedarPolicyEngine` for fine-grained policy evaluation. `PolicyDecisionPoint::with_cedar()` wires Cedar evaluation after native policies. Cedar deny overrides; Cedar allow supplements native authorization (defense-in-depth). `DecisionSource::Cedar` variant for audit. 35 Cedar tests.
- **RFC 9728 Protected Resource Metadata** (`/.well-known/oauth-protected-resource`): MCP clients discover which authorization server to use. Advertises supported scopes (`crm:read`, `crm:write`, `tools:execute`), bearer methods, signing algorithms, JWKS URI, introspection endpoint.
- **MCP Client Metadata** (`/.well-known/mcp-client-metadata`): zero-registration MCP client discovery. Advertises client capabilities (PKCE, grant types, redirect URIs, scopes) for MCP authorization servers. 4 new discovery tests.
- `OAuthState::with_frontend_url()` for configurable OAuth consent/login page redirects.

### Changed

- `ProvisionAgentRequest` gains optional `blueprint_id` field for blueprint-based provisioning.
- `JwtClaims` gains optional `may_act: Option<MayActClaim>` field.
- `JwtClaimsBuilder` gains `.may_act()` builder method.
- `TokenExchangeRequest` gains optional `resource` field (RFC 8707).
- `DecisionSource` enum gains `Cedar` variant.
- Token exchange handler validates `actor_token_type` per RFC 8693 §2.1 (was previously unchecked).
- OAuth authorize endpoint accepts `?tenant=` query parameter as fallback when `X-Tenant-ID` header is absent (browser-redirect flows cannot set custom headers).
- OAuth consent redirect uses configurable `frontend_url` base and `/oauth/authorize` path.

## [0.1.1] - 2026-02-06

### Added

- **`xavyo verify` command** — new top-level command with two subcommands:
  - `xavyo verify status` — check email verification status via `GET /me/profile`
  - `xavyo verify resend [--email <address>]` — resend verification email (infers email from session if omitted)
- **`--json` flag** on verify commands for machine-readable output
- **Profile API client** (`api/profile.rs`) — `get_profile()` for authenticated profile retrieval
- **Resend verification API client** (`api/auth.rs`) — `resend_verification()` with tenant header support

### Changed

- **Setup wizard** now includes email verification as Step 2 (between authentication and tenant creation)
  - Interactive mode prompts to continue or wait when email is unverified
  - Check mode (`xavyo setup --check`) reports email verification status
  - "You're all set!" message now requires auth + email verified + tenant (consistent with check mode)
- **Post-signup messaging** now shows `xavyo verify status` and `xavyo verify resend` commands

### Fixed

- Removed unused `Config::load()` call in setup wizard

## [0.1.0] - 2026-02-06

Initial public release of xavyo — the Identity Platform for the AI Agent Era.

### Platform

- **32 Rust crates** organized in 4 layers (Foundation, Domain, Connector, API)
- **3 applications**: `idp-api` (main service), `gateway` (API gateway), `xavyo-cli` (CLI tool)
- **PostgreSQL 15+** with Row-Level Security (RLS) for tenant isolation
- **149 database migrations** with comprehensive schema evolution
- **Multi-tenant by design** — every query scoped to `tenant_id`
- **OpenAPI specification** auto-generated via utoipa (2.4 MB)

### Identity & Access Management

- Full RBAC with role hierarchy and inheritance
- JWT-based authentication with refresh tokens
- API key management with scoped permissions and usage tracking
- OAuth 2.0 authorization server (client credentials, device code)
- OIDC federation with ID token signature verification (JWKS + RS256)
- SAML 2.0 Identity Provider with certificate lifecycle management
- Social login providers (Google, Microsoft, GitHub, Apple)
- SCIM 2.0 server for identity provisioning
- MFA support (TOTP, WebAuthn) with per-tenant policies
- Password policies with configurable complexity rules
- Session management with concurrent session limits
- Email verification and password reset flows

### AI Agent Security (NHI)

- Non-Human Identity (NHI) registry for agents, service accounts, and tools
- Agent credential management with rotation and revocation
- Certificate Authority (CA) for agent mTLS certificates
- Secret type definitions with permission-based access control
- Agent-to-tool authorization with role mappings
- Identity federation for cross-system agent authentication
- NHI certification campaigns

### Enterprise Governance (IGA)

- **Identity Archetypes** (F-058) — sub-type system for employees, contractors, service accounts
- **Lifecycle State Machine** (F-059) — configurable states, transitions, and scheduled changes
- **Parametric Roles** (F-060) — role definitions with runtime parameters
- **Power of Attorney** (F-061) — identity delegation with time-bounded scope
- **Self-Service Request Catalog** (F-062) — categorized items with approval workflows
- **Role Inducements** (F-063) — automatic entitlement assignment via construction patterns
- **Bulk Action Engine** (F-064) — batch operations with progress tracking
- **Enhanced Correlation Rules** (F-065) — organization-level security policy management
- **Organization Security Policies** (F-066) — per-org password, MFA, and session policies
- **GDPR/Data Protection** (F-067) — data subject reports and consent metadata
- **Object Templates** (F-068) — reusable configuration templates for identity objects
- Separation of Duties (SoD) rule engine with violation detection
- Certification campaigns with reviewer assignment
- Risk scoring and anomaly alerting
- Approval workflows with multi-level chains
- Access request lifecycle (request, approve, provision, revoke)
- Entitlement management with risk classification
- Delegation management with approval and revocation

### Provisioning

- Connector framework with LDAP, Entra ID, REST, and Database connectors
- Operation queue with retry, cancel, and dead letter queue (DLQ)
- Job tracking for long-running connector synchronization
- Shadow link management for identity correlation
- Webhook delivery with circuit breaker and DLQ
- SIEM integration (Splunk HEC, generic webhook)

### CLI (`xavyo-cli`)

- 31 top-level commands with 70+ subcommands
- Multi-tenant context switching (`tenant switch`)
- Interactive shell/REPL mode
- Batch operations for agents and tools
- Full governance management (roles, entitlements, archetypes, lifecycle, SoD, campaigns, templates, catalog, bulk actions, delegations, GDPR, risk, reports, workflows)
- Operations and job tracking (list, get, retry, cancel, DLQ replay)
- JSON output mode for scripting (`--json`)
- Session-based authentication with API keys

### Security Hardening

- Cross-tenant authorization bypass fixes (6 handlers)
- SQL injection mitigations across 136+ dynamic query files
- Error message sanitization (12 API error.rs files) — no internal details leaked
- RLS NULLIF pattern fix across 150 tables (migration 1182)
- RLS WITH CHECK clause enforcement (migration 1185)
- SQL-level token expiry filtering on 6 token types
- TOCTOU race condition fixes (license operations, access requests)
- Admin role enforcement on all mutation handlers across all crates
- Open redirect prevention on OAuth/OIDC/Social callbacks
- SSRF protection on ticketing webhook URLs
- SAML decompression bomb protection (1 MB limit)
- OIDC nonce and state replay prevention
- Defense-in-depth: CSPRNG tokens, HTTP client timeouts (10s), DB pool limits, pagination clamping, `#[serde(skip_serializing)]` on secrets, `Cache-Control: no-store` headers

### Developer Experience

- `overflow-checks = true` in release profile
- `#[non_exhaustive]` on 30 error enums
- Workspace-level clippy lints (correctness=deny, suspicious=deny, 11 pedantic)
- `Vec::with_capacity()` for known-size collections
- Zero `.unwrap()` calls in production code
- Comprehensive documentation: README, ARCHITECTURE, ROADMAP, CRATE.md per crate

### Testing

- 1,095 test functions across 281 test files
- 177 API endpoints tested (100% pass rate)
- 49 IGA feature acceptance tests (100% pass rate)
- 838 CLI command tests
- Authorization performance benchmarks (<10ms target verified)

### Known Limitations

- OAuth authorize endpoint is a placeholder (returns error)
- Provisioning connectors (create/delete/inactivate) log and skip (stubs)
- SAML XML Signature Wrapping (XSW) — uses string-based processing
- 2 alpha connectors (REST, Database) — skeleton implementations
- No web UI (API-only by design, per project constitution)

[0.1.1]: https://github.com/xavyo/xavyo-idp/releases/tag/v0.1.1
[0.1.0]: https://github.com/xavyo/xavyo-idp/releases/tag/v0.1.0
