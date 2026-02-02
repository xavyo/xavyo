# xavyo-idp Development Guidelines

Auto-generated from all feature plans. Last updated: 2026-01-31

## LLM-Friendly Documentation

For detailed crate-level documentation optimized for LLM consumption, see:

- **[llms.txt](llms.txt)** - Navigation index for all 32 crates with quick reference
- **[llms-full.txt](llms-full.txt)** - Complete documentation (4600+ lines)
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** - System architecture overview
- **[docs/crates/index.md](docs/crates/index.md)** - Crate index by layer
- **[docs/crates/dependency-graph.md](docs/crates/dependency-graph.md)** - Visual dependency graph
- **Per-crate docs**: Each crate has a `CRATE.md` file at its root (e.g., `crates/xavyo-core/CRATE.md`)

## Active Technologies
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/JwtClaims), xavyo-db (PostgreSQL), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), serde/serde_json (serialization), sqlx (compile-time queries), chrono (timestamps), uuid (identifiers), reqwest (HTTP client for ticketing APIs), aes-gcm (credential encryption) (064-semi-manual-resources)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/JwtClaims), xavyo-db (PostgreSQL), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), xavyo-connector (OperationType, HookPhase), xavyo-provisioning (HookManager, HookExecutor, HookContext), rhai (scripting engine), serde/serde_json (serialization), sqlx (compile-time queries), chrono (timestamps), uuid (identifiers) (066-provisioning-scripts)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/JwtClaims), xavyo-db (PostgreSQL), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), xavyo-provisioning (Rhai executor for expressions), xavyo-connector (connector types), strsim 0.11 (fuzzy matching), rust_decimal (score precision), serde/serde_json (serialization), sqlx (compile-time queries), chrono (timestamps), uuid (identifiers), unicode-normalization (NFC normalization) (067-correlation-engine)
- PostgreSQL 15+ with SQLx compile-time checking, `pg_trgm` extension for trigram similarity (067-correlation-engine)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/JwtClaims), xavyo-db (PostgreSQL/SQLx), tower-http (CORS, headers), uuid, chrono (069-security-hardening)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/JwtClaims), xavyo-db (PostgreSQL/SQLx), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), serde/serde_json (serialization/JSONB), sqlx (compile-time queries), chrono (timestamps/date validation), uuid (identifiers), regex (pattern validation), utoipa (OpenAPI) (070-custom-user-attributes)
- PostgreSQL 15+ with SQLx compile-time checking, JSONB column with GIN indexing (070-custom-user-attributes)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/JwtClaims), xavyo-db (PostgreSQL/SQLx), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), serde/serde_json (serialization), sqlx (compile-time queries), chrono (timestamps), uuid (identifiers), utoipa (OpenAPI) (071-org-hierarchy)
- PostgreSQL 15+ with SQLx compile-time checking, self-referencing FK with recursive CTEs (071-org-hierarchy)
- Rust 1.75+ (per constitution) + Axum 0.7, Tower 0.4, tower-http 0.5, opentelemetry 0.31, opentelemetry_sdk 0.31, opentelemetry-otlp 0.31, tracing-opentelemetry 0.32, prometheus-client 0.22 (072-opentelemetry-observability)
- N/A — no database changes. Telemetry is ephemeral (exported to external collectors) (072-opentelemetry-observability)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/JwtClaims, AuthService, MfaService, AuditService, SessionService), xavyo-api-governance (RiskScoreService, RiskAlertService), xavyo-db (PostgreSQL, GovRiskEvent, GovRiskThreshold models), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), serde/serde_json (serialization), sqlx (compile-time queries), chrono (timestamps), uuid (identifiers) (073-adaptive-auth)
- PostgreSQL 15+ with SQLx compile-time checking, RLS enabled on all tenant-scoped tables (073-adaptive-auth)
- Rust 1.75+ (per constitution) + Axum 0.7 + Tower (framework), SQLx 0.7 (database), tokio (async runtime, timeouts), serde/serde_json (serialization), utoipa (OpenAPI), xavyo-events (Kafka health types) (074-deep-health-checks)
- PostgreSQL 15+ via SQLx (health check target, not data storage) (074-deep-health-checks)
- Rust 1.75+ (Cargo workspace with 22+ crates, 665 packages in dependency tree) + cargo-audit 0.21+, cargo-deny 0.16+ (075-dependency-security-audit)
- N/A (configuration files only — deny.toml, Makefile) (075-dependency-security-audit)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), ldap3 0.11 (LDAP client), xavyo-connector (framework traits), xavyo-connector-ldap (existing LDAP implementation), xavyo-provisioning (sync pipeline, reconciliation), xavyo-db (PostgreSQL/SQLx), xavyo-auth (JWT/JwtClaims), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), aes-gcm (credential encryption), serde/serde_json (serialization), chrono (timestamps), uuid (identifiers), tracing (logging) (076-active-directory-connector)
- PostgreSQL 15+ with SQLx compile-time checking and RLS for tenant isolation. No new tables required — reuses existing connector_configurations, reconciliation_runs, sync_tokens, attribute_mappings, shadow_accounts, users, groups, group_memberships. (076-active-directory-connector)
- Rust 1.75+ (per constitution) + reqwest (HTTP client), serde/serde_json (serialization), chrono (timestamps), uuid (identifiers), tokio (async runtime), tracing (instrumentation), xavyo-connector (framework traits), xavyo-core (TenantId, types) (077-entra-id-connector)
- PostgreSQL 15+ via existing connector_configurations table (no new tables — config stored as JSON, credentials encrypted via aes-gcm) (077-entra-id-connector)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/JwtClaims), xavyo-db (PostgreSQL), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), xavyo-events (Kafka EventConsumer/EventProducer), reqwest (HTTP client for webhook/Splunk HEC), tokio (async runtime, TCP/UDP sockets), tokio-native-tls (TLS for syslog TCP), aes-gcm (credential encryption), governor (rate limiting), serde/serde_json (serialization), sqlx (compile-time queries), chrono (timestamps), uuid (identifiers), csv (CSV export) (078-siem-audit-export)
- PostgreSQL 15+ with SQLx compile-time checking. 4 new tables: `siem_destinations`, `siem_export_events`, `siem_delivery_health`, `siem_batch_exports`. All with RLS. (078-siem-audit-export)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/token), xavyo-db (PostgreSQL/SQLx), xavyo-api-auth (auth handlers/services), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), lettre (SMTP email), serde/serde_json (serialization), chrono (timestamps), uuid (identifiers), sha2 (token hashing), subtle (constant-time comparison), rand (secure random generation), base64 (URL-safe encoding) (079-passwordless-auth)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), reqwest (HTTP client for Vault/AWS APIs), tokio (async runtime, file watching), serde/serde_json (config serialization), notify (file system watching), aws-sdk-secretsmanager (AWS SDK), thiserror (error types), tracing (logging) (080-secrets-kms-integration)
- N/A (in-memory cache only; secrets loaded from external providers) (080-secrets-kms-integration)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/JwtClaims), xavyo-db (PostgreSQL/SQLx), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), xavyo-events (Kafka EventProducer), serde/serde_json (serialization), sqlx (compile-time queries), chrono (timestamps), uuid (identifiers), regex (slug validation) (081-custom-user-attributes)
- PostgreSQL 15+ with JSONB, GIN indexing, RLS (081-custom-user-attributes)
- Rust 1.75+ (per constitution) + Axum + Tower (framework) + xavyo-auth (JWT/JwtClaims), xavyo-db (PostgreSQL), xavyo-tenant (middleware), xavyo-core (TenantId, UserId), moka (async LRU cache for policies/mappings), serde/serde_json, sqlx (compile-time queries), chrono (timestamps), uuid (identifiers), utoipa (OpenAPI) (083-authorization-engine)
- PostgreSQL 15+ with SQLx compile-time checking — 3 new tables (authorization_policies, policy_conditions, entitlement_action_mappings) (083-authorization-engine)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/JwtClaims), xavyo-db (PostgreSQL/SQLx), xavyo-api-oauth (OAuth2 crate), xavyo-api-auth (revocation cache, middleware), serde/serde_json, uuid, chrono, moka (already in workspace) (084-oauth2-token-revocation)
- PostgreSQL 15+ via SQLx — existing tables: `revoked_tokens`, `oauth_refresh_tokens`, `oauth_clients` (084-oauth2-token-revocation)
- Rust 1.75+ (per constitution) + Axum + Tower (web framework), xavyo-auth (JWT/JwtClaims), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), xavyo-events (Event trait, EventEnvelope, EventProducer), reqwest (HTTP client for delivery), aes-gcm (secret encryption), hmac + sha2 (payload signing), tokio (async runtime, broadcast channel), serde/serde_json (serialization), sqlx (compile-time queries), chrono (timestamps), uuid (identifiers), utoipa (OpenAPI), validator (input validation), thiserror (error types) (085-webhooks-event-subscriptions)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/JwtClaims), xavyo-db (PostgreSQL/SQLx), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), xavyo-webhooks (EventPublisher), csv (CSV parsing), sha2 (token hashing, file hashing), rand (token generation), lettre (email via existing EmailSender trait), ammonia (HTML sanitization), serde/serde_json, chrono, uuid, axum-extra (Multipart) (086-bulk-user-import)
- PostgreSQL 15+ with SQLx compile-time checking, RLS on all tenant-scoped tables (086-bulk-user-import)
- Rust 1.75+ (per constitution) + Axum + Tower (web framework), reqwest (HTTP client), aes-gcm (credential encryption via `xavyo-connector::crypto`), rdkafka (Kafka consumer via `xavyo-events`), serde/serde_json (serialization), sqlx (compile-time queries), chrono (timestamps), uuid (identifiers), tokio (async runtime), tracing (logging) (087-scim-outbound-client)
- Rust 1.75+ (per constitution) + SQLx 0.7 (compile-time checked queries), serde/serde_json (serialization), chrono (timestamps), uuid (identifiers) (089-ai-agent-security)
- PostgreSQL 15+ with RLS, JSONB for flexible schemas (089-ai-agent-security)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/JwtClaims), xavyo-db (PostgreSQL), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), serde/serde_json (serialization), chrono (timestamps), uuid (identifiers), utoipa (OpenAPI) (090-ai-agent-api)
- PostgreSQL 15+ via existing F089 models (AiAgent, AiTool, AiAgentToolPermission, AiAgentAuditEvent) (090-ai-agent-api)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/JwtClaims), xavyo-db (PostgreSQL), xavyo-api-agents (F090 crate), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), serde/serde_json (serialization), sqlx (compile-time queries), chrono (timestamps), uuid (identifiers), reqwest (webhook HTTP client), jsonschema (parameter validation), utoipa (OpenAPI) (091-mcp-a2a-protocol)
- PostgreSQL 15+ via SQLx - 1 new table (a2a_tasks) with RLS (091-mcp-a2a-protocol)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-api-agents (existing agent platform), xavyo-db (PostgreSQL/SQLx), reqwest (webhooks), tokio (async runtime, timers) (092-hitl-approval)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/JwtClaims), xavyo-db (PostgreSQL/SQLx), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), xavyo-api-agents (existing agent crate), serde/serde_json (serialization), chrono (timestamps), uuid (identifiers) (093-security-assessment-api)
- PostgreSQL 15+ via SQLx (reads from existing ai_agents, ai_tools, ai_agent_tool_permissions, ai_agent_audit_events tables) (093-security-assessment-api)
- Rust 1.75+ (per constitution) + Axum + Tower, SQLx 0.7, tokio, tracing, uuid (095-system-tenant-bootstrap)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-api-oauth (existing OAuth crate), xavyo-db (PostgreSQL/SQLx), xavyo-auth (JWT/JwtClaims), xavyo-tenant (middleware), rand (secure code generation), chrono (timestamps), uuid (identifiers) (096-device-code-oauth)
- PostgreSQL 15+ via SQLx - 1 new table (device_codes) with RLS (096-device-code-oauth)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/JwtClaims), xavyo-db (PostgreSQL/SQLx), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), serde/serde_json (serialization), sqlx (compile-time queries), chrono (timestamps), uuid (identifiers), sha2 (API key hashing), rand (key generation) (097-tenant-provisioning-api)
- Rust 1.75+ (per constitution) + clap (CLI parsing), reqwest (HTTP client), keyring (secure storage), serde/serde_json (serialization), tokio (async runtime), open (browser launch), dirs (platform paths) (098-xavyo-cli)
- Local filesystem (~/.xavyo/) with optional keyring integration (098-xavyo-cli)
- Rust 1.75+ (per constitution) + clap v4 (CLI), reqwest (HTTP), tokio (async), serde (serialization), dialoguer (interactive prompts) (099-cli-agent-commands)
- Reuses F098 credential storage (~/.config/xavyo/) (099-cli-agent-commands)
- Rust 1.75+ (per constitution) + clap 4 (CLI), reqwest (HTTP client), sha2 (checksum), semver (version comparison), indicatif (progress bars) (107-cli-upgrade)
- N/A (reads from GitHub Releases API, writes to local filesystem) (107-cli-upgrade)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), SQLx (database), serde/serde_json (serialization), uuid, chrono, utoipa (OpenAPI) (108-unified-nhi)
- Rust 1.75+ (per constitution) + Axum 0.7, Tower 0.4, xavyo-auth (JWT, password hashing), xavyo-api-auth (email, rate limiting), xavyo-db (User model) (111-self-service-signup)
- PostgreSQL 15+ via SQLx (existing tables: users, email_verification_tokens) (111-self-service-signup)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-api-oauth (device handlers), xavyo-api-auth (AuthService, SessionService, MfaService), xavyo-db (PostgreSQL/SQLx) (112-device-code-login)
- PostgreSQL 15+ via SQLx (existing device_codes, sessions tables) (112-device-code-login)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), sqlx (database), sha2 (hashing), xavyo-db (ApiKey model), xavyo-core (TenantId, UserId types) (113-api-key-auth)
- PostgreSQL 15+ via existing api_keys table (113-api-key-auth)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-api-oauth (DeviceCodeService, DeviceConfirmationService, DeviceRiskService), xavyo-db (PostgreSQL/SQLx, KnownUserIp, DeviceCodeConfirmation models), xavyo-api-auth (EmailSender, SessionService), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), sha2 (token hashing), rand (secure token generation), base64 (URL-safe encoding), chrono (timestamps), uuid (identifiers), async-trait (service traits), tracing (audit logging) (117-storm2372-remediation)
- PostgreSQL 15+ via SQLx with RLS - 2 new tables (device_code_confirmations, known_user_ips) (117-storm2372-remediation)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-api-agents (DynamicCredentialService, SecretTypeService, SecretPermissionService, SecretProviderService), xavyo-secrets (DynamicSecretProvider trait, OpenBaoSecretProvider, InfisicalSecretProvider, InternalSecretProvider), xavyo-db (PostgreSQL/SQLx), xavyo-auth (JWT/JwtClaims), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), aes-gcm (credential encryption), reqwest (HTTP client for external providers), dashmap (rate limiting), serde/serde_json (serialization), sqlx (compile-time queries), chrono (timestamps), uuid (identifiers) (120-dynamic-secrets-provisioning)
- PostgreSQL 15+ via SQLx with RLS - 5 new tables (secret_type_configurations, agent_secret_permissions, dynamic_credentials, credential_request_audit, secret_provider_configs) (120-dynamic-secrets-provisioning)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-api-agents (F120 base), xavyo-auth (JWT/JWKS), aws-sdk-sts (new), reqwest (HTTP client), jsonwebtoken (token verification) (121-workload-identity-federation)
- TypeScript 5.x, Node.js 18+ + n8n-workflow, n8n-core (n8n community node SDK), axios (HTTP client) (122-n8n-secure-agent-plugin)
- N/A (stateless plugin; uses n8n's credential store and Xavyo API) (122-n8n-secure-agent-plugin)
- TypeScript 5.x, Node.js 18+ + n8n-workflow, n8n-core (n8n community node SDK), axios (HTTP client), existing XavyoApiClient from F122/F123 (125-n8n-get-secret)
- N/A (stateless plugin; uses Xavyo API for credential retrieval) (125-n8n-get-secret)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-api-agents (existing agent platform), openssl (existing in workspace for x509), rcgen (certificate generation), x509-parser (parsing/validation), xavyo-db (PostgreSQL/SQLx), xavyo-auth (JWT/JwtClaims), xavyo-secrets (CA key storage) (127-agent-pki-certificates)
- PostgreSQL 15+ with SQLx compile-time checking, 3 new tables (agent_certificates, certificate_authorities, certificate_revocations) with RLS (127-agent-pki-certificates)

- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT), xavyo-db (PostgreSQL), xavyo-tenant (middleware), chrono (time), lettre (email notifications), serde/serde_json (serialization) (053-deputy-poa)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT), xavyo-db (PostgreSQL/SQLx), xavyo-tenant (middleware), xavyo-governance (existing IGA crate), serde/serde_json, uuid, chrono, lettre (SMTP) (054-workflow-escalation)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/JwtClaims), xavyo-db (PostgreSQL), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), xavyo-events (Kafka), serde/serde_json (serialization), sqlx (compile-time queries), chrono (timestamps) (055-micro-certification)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/JwtClaims), xavyo-db (PostgreSQL), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), serde/serde_json (serialization), sqlx (compile-time queries), chrono (timestamps), uuid (identifiers) (056-meta-roles)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/JwtClaims), xavyo-db (PostgreSQL), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), serde/serde_json (serialization), sqlx (compile-time queries), chrono (timestamps), uuid (identifiers), validator (input validation) (057-parametric-roles)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/JwtClaims), xavyo-db (PostgreSQL), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), serde/serde_json (serialization), sqlx (compile-time queries), chrono (timestamps), uuid (identifiers), regex (expression patterns) (058-object-templates)

- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-provisioning (queue, correlation, shadow), xavyo-connector (target system access), xavyo-db (PostgreSQL/SQLx), xavyo-events (Kafka) (049-reconciliation-engine)

- Rust 1.75+ (per constitution) + serde, serde_json, uuid (v4 feature), thiserror (002-xavyo-core-types)
- N/A (types library only) (002-xavyo-core-types)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/password), xavyo-db (PostgreSQL), xavyo-tenant (middleware), xavyo-core (types) (006-api-auth-endpoints)
- PostgreSQL 15+ with SQLx compile-time checking (per constitution) (006-api-auth-endpoints)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/password), xavyo-db (PostgreSQL), xavyo-tenant (middleware), xavyo-core (types), lettre (SMTP client) (007-password-reset-email-verification)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), utoipa + utoipa-swagger-ui (OpenAPI), tracing + tracing-subscriber (logging), tower-http (CORS, request-id) (008-idp-api-service)
- PostgreSQL 15+ via SQLx (reuse xavyo-db) (008-idp-api-service)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/password), xavyo-db (PostgreSQL), xavyo-core (types), serde, uuid (010-oauth2-oidc-provider)
- PostgreSQL 15+ via SQLx (reuse xavyo-db, new tables for oauth_clients, authorization_codes, refresh_tokens) (010-oauth2-oidc-provider)
- TypeScript 5.x + React 19 + React 19, Tailwind CSS 3.4+, class-variance-authority (CVA), clsx, tailwind-merge (011-design-system-ui)
- N/A (stateless UI library) (011-design-system-ui)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT), xavyo-db (PostgreSQL), xavyo-tenant (middleware), reqwest (HTTP client for OAuth2), aes-gcm (encryption) (012-social-login)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), samael (SAML), xavyo-auth (JWT/password), xavyo-db (PostgreSQL), xavyo-tenant (middleware), xavyo-core (types) (013-saml-idp)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT), xavyo-db (PostgreSQL), xavyo-tenant (middleware), xavyo-core (types), reqwest (HTTP client), serde_json (JSON), aes-gcm (encryption) (014-oidc-federation)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), serde_json (SCIM parsing), sqlx (PostgreSQL), xavyo-core (types), xavyo-db (models), xavyo-tenant (middleware) (015-scim-provisioning)
- Rust 1.75+ (per constitution) + rdkafka (Kafka client), serde/serde_json (serialization), sqlx (idempotence table), tokio (async runtime), uuid (event IDs), chrono (timestamps), thiserror (errors), xavyo-core (TenantId, UserId types), xavyo-db (database pool) (016-kafka-event-bus)
- PostgreSQL 15+ via SQLx for `processed_events` table (016-kafka-event-bus)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT), xavyo-tenant (middleware), hyper (HTTP client), tower-governor (rate limiting), utoipa (OpenAPI) (017-api-gateway)
- N/A (stateless gateway; rate limit state in-memory with option for Redis) (017-api-gateway)
- TypeScript 5.x, Node.js 18+ + Next.js 15, React 19, @module-federation/nextjs-mf, @xavyo/ui, @xavyo/auth-clien (019-module-federation-shell)
- N/A (shell is stateless, relies on remote modules for data) (019-module-federation-shell)
- Shell scripts (Bash), Docker Compose for orchestration + Docker, Docker Compose, PostgreSQL 15+, existing Rust backend (idp-api) (020-integration-test-setup)
- PostgreSQL 15 (containerized) (020-integration-test-setup)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (password hashing), xavyo-db (PostgreSQL), xavyo-tenant (middleware), xavyo-core (types), lettre (SMTP for lockout notifications) (024-password-policies-lockout)
- PostgreSQL 15+ via SQLx with RLS for tenant isolation (024-password-policies-lockout)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT), xavyo-db (PostgreSQL), xavyo-tenant (middleware), xavyo-core (types), maxminddb (optional geo-lookup) (025-login-history-audit)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/password), xavyo-db (PostgreSQL), xavyo-tenant (middleware), xavyo-core (types), lettre (SMTP) (027-self-service-profile)
- Rust 1.75+ (per project standard) + Axum + Tower (framework), xavyo-auth (JWT), xavyo-db (PostgreSQL/SQLx), xavyo-tenant (middleware), xavyo-core (types), ipnetwork (CIDR parsing) (028-ip-restrictions)
- PostgreSQL 15+ with SQLx compile-time checking, Row-Level Security (RLS) (028-ip-restrictions)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/JwtClaims), xavyo-db (PostgreSQL), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), serde/serde_json, sqlx (029-delegated-admin)
- PostgreSQL 15+ with SQLx compile-time checking (per constitution), RLS enabled (029-delegated-admin)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/JwtClaims), xavyo-db (PostgreSQL), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), serde/serde_json, sqlx, axum-multipart (file uploads), handlebars (template rendering), image (image validation), sha2 (checksums), ammonia (CSS sanitization) (030-custom-branding)
- PostgreSQL 15+ with SQLx compile-time checking (per constitution), local filesystem for assets (S3 abstraction for future) (030-custom-branding)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), webauthn-rs 0.5+ (WebAuthn), xavyo-auth (JWT), xavyo-db (PostgreSQL) (032-mfa-webauthn)
- PostgreSQL 15+ with SQLx compile-time checking, RLS for tenant isolation (032-mfa-webauthn)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), SQLx 0.7 (PostgreSQL), xavyo-core (TenantId, UserId), xavyo-db (models), xavyo-tenant (middleware), xavyo-auth (JWT), serde/serde_json, uuid, chrono, utoipa (OpenAPI) (033-entitlement-management)
- PostgreSQL 15+ with SQLx compile-time checking and RLS for tenant isolation (033-entitlement-management)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT), xavyo-db (PostgreSQL/SQLx), xavyo-tenant (middleware), xavyo-governance (existing IGA crate), serde/serde_json, uuid, chrono, thiserror (034-sod-rules)
- PostgreSQL 15+ with SQLx compile-time checking, RLS enabled for tenant isolation (034-sod-rules)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/JwtClaims), xavyo-db (PostgreSQL), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), serde/serde_json, sqlx, chrono (timestamps) (035-access-request-workflows)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/JwtClaims), xavyo-db (PostgreSQL), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), serde/serde_json (serialization), sqlx (compile-time queries), chrono (timestamps), csv (CSV export), lettre (email notifications) (042-compliance-reporting)
- Rust 1.75+ (per constitution) + Axum + Tower (web), ldap3 (LDAP), sqlx (database connector), reqwest (REST), aes-gcm (credential encryption), rdkafka (Kafka) (045-connector-framework)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-connector (base), xavyo-db (PostgreSQL), xavyo-api-connectors (API layer) (046-schema-discovery)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-connector (connector traits), xavyo-provisioning (correlation, conflict, shadow), xavyo-db (PostgreSQL/SQLx), xavyo-events (Kafka), chrono (timestamps), serde/serde_json (serialization), tokio (async runtime), tracing (logging) (048-live-synchronization)
- Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-auth (JWT/JwtClaims), xavyo-db (PostgreSQL/SQLx), xavyo-api-agents (agent services), xavyo-tenant (middleware), xavyo-core (TenantId, UserId types), aws-sdk-sts (AWS STS for AssumeRoleWithWebIdentity), aws-config (AWS region configuration), async-trait (provider traits), serde/serde_json (serialization), sqlx (compile-time queries), chrono (timestamps), uuid (identifiers), tracing (instrumentation) (121-workload-identity-federation)
- PostgreSQL 15+ with SQLx compile-time checking. 4 new tables: `identity_provider_configs`, `iam_role_mappings`, `identity_credential_requests`, `identity_audit_events`. All with RLS for tenant isolation. (121-workload-identity-federation)

- **Rust 1.75+** - Backend applications and shared libraries
- **TypeScript 5.x** - Frontend applications and shared packages
- **Node.js 18+** - JavaScript runtime
- **NX 19+** - Monorepo build orchestration
- **Cargo** - Rust package manager and build tool
- **Next.js 15** - React framework for web applications
- **Axum** - Rust web framework (for future backend apps)
- **Vitest** - TypeScript test runner
- **Tailwind CSS** - Utility-first CSS framework

## Project Structure

```text
/
├── apps/                        # All applications (Rust + TypeScript)
│   ├── idp-api/                # Rust Axum app
│   │   ├── Cargo.toml
│   │   ├── src/main.rs
│   │   └── project.json        # NX project config
│   └── idp-web/                # Next.js 15 app
│       ├── package.json
│       ├── src/app/
│       └── project.json
│
├── crates/                      # Rust libraries
│   └── xavyo-core/             # Shared Rust types
│       ├── Cargo.toml
│       └── src/lib.rs
│
├── packages/                    # TypeScript shared packages
│   └── ui/                     # Design system
│       ├── package.json
│       ├── src/index.ts
│       └── project.json
│
├── docs/                        # Documentation
│   ├── quickstart.md
│   └── adding-projects.md
│
├── specs/                       # Feature specifications
│
├── Cargo.toml                  # Rust workspace root
├── package.json                # Node.js workspace root
├── nx.json                     # NX configuration
├── tsconfig.base.json          # Shared TypeScript config
└── .github/workflows/ci.yml    # CI pipeline
```

## Commands

### Build

```bash
nx build idp-api          # Build Rust app
nx build idp-web          # Build Next.js app
nx run-many --target=build # Build all
```

### Test

```bash
cargo test --workspace           # All Rust tests
nx run-many --target=test        # All TypeScript tests
nx test ui                       # Specific package
```

### Lint & Format

```bash
cargo fmt --check                # Check Rust formatting
cargo clippy --workspace         # Rust linting
nx format:check                  # Check TypeScript formatting
nx run-many --target=lint        # TypeScript linting
```

### Development

```bash
nx serve idp-web                 # Start Next.js dev server
cargo run -p idp-api             # Run Rust app
nx graph                         # View dependency graph
```

### CI (Affected Only)

```bash
nx affected --target=build       # Build affected projects
nx affected --target=test        # Test affected projects
```

## Code Style

- **Rust**: Follow `cargo fmt` and `cargo clippy` conventions
- **TypeScript**: Follow Prettier and ESLint rules (strict mode enabled)
- **Commits**: Use conventional commits (feat:, fix:, docs:, etc.)

## Recent Changes
- 127-agent-pki-certificates: Added Rust 1.75+ (per constitution) + Axum + Tower (framework), xavyo-api-agents (existing agent platform), openssl (existing in workspace for x509), rcgen (certificate generation), x509-parser (parsing/validation), xavyo-db (PostgreSQL/SQLx), xavyo-auth (JWT/JwtClaims), xavyo-secrets (CA key storage)
- 125-n8n-get-secret: Added TypeScript 5.x, Node.js 18+ + n8n-workflow, n8n-core (n8n community node SDK), axios (HTTP client), existing XavyoApiClient from F122/F123
- 122-n8n-secure-agent-plugin: Added TypeScript 5.x, Node.js 18+ + n8n-workflow, n8n-core (n8n community node SDK), axios (HTTP client)


<!-- MANUAL ADDITIONS START -->

## Command Execution (MANDATORY)

When implementing features or fixing issues, you MUST always run the appropriate commands to verify your work:

### Required Verification Steps

1. **After writing code**: Run `cargo check -p <crate>` to verify compilation
2. **After fixing errors**: Run `cargo check` again to confirm all errors are resolved
3. **Before committing**: Run the full verification suite:
   - `cargo test -p <affected-crates>` - Run relevant tests
   - `cargo clippy -p <affected-crates> -- -D warnings` - Check for lints
   - `cargo fmt --check` - Verify formatting

### Never Skip Commands

- **NEVER** assume code compiles without running `cargo check`
- **NEVER** assume tests pass without running `cargo test`
- **NEVER** commit code that hasn't been verified with clippy and fmt
- **ALWAYS** run commands after each significant code change
- **ALWAYS** check command output for errors before proceeding

### Timeout Handling

If a command times out or is interrupted:
- Re-run the command to completion
- Do not proceed until you have verified the result

## Documentation Updates (MANDATORY BEFORE COMMIT)

Before committing changes, you MUST update documentation if your changes affect:

### Crate Documentation (`CRATE.md`)

If you modify a crate, update its `crates/<crate-name>/CRATE.md`:
- **Public API**: Add/update types, traits, functions in the Public API section
- **Dependencies**: Update if new internal or external dependencies are added
- **Usage Example**: Update if the API usage pattern changes
- **Feature Flags**: Document any new feature flags
- **Anti-Patterns**: Add warnings for common mistakes

### Maturity Level Updates

Update the **Status** section in `CRATE.md` when:
- A crate moves from alpha to beta (core functionality complete, 20+ tests)
- A crate moves from beta to stable (comprehensive tests, no critical TODOs)
- Significant functionality is added or removed

Also update these files to keep maturity indicators in sync:
- `docs/crates/index.md` - Update the Status column
- `docs/crates/maturity-matrix.md` - Update the matrix tables
- `llms.txt` - Update inline maturity badges

### LLM Documentation

If CRATE.md files are modified, regenerate `llms-full.txt`:
```bash
cat > llms-full.txt << 'EOF'
# xavyo - Complete Crate Documentation
...header...
EOF
for f in crates/*/CRATE.md; do cat "$f"; echo -e "\n---\n"; done >> llms-full.txt
```

### General Documentation

Update `docs/` files when:
- Architecture changes → `docs/ARCHITECTURE.md`
- New crate added → `docs/crates/index.md`, `docs/crates/dependency-graph.md`
- API patterns change → `CLAUDE.md` (this file)

### Documentation Checklist

Before committing, verify:
- [ ] All modified crates have updated CRATE.md
- [ ] Maturity levels reflect current state (stable/beta/alpha)
- [ ] llms-full.txt regenerated if CRATE.md files changed
- [ ] llms.txt updated if crate maturity changed
- [ ] docs/crates/index.md and maturity-matrix.md are in sync

## API-First, No UI (NON-NEGOTIABLE)

This platform is an **API-only backend**. There will NEVER be a UI unless there is absolutely no alternative.

- All features MUST be exposed exclusively as REST APIs
- **NO** frontend application, admin panel, or dashboard will be developed
- **NO** React, Next.js, or any frontend framework code will be added
- The existing `apps/idp-web/` and `packages/ui/` are FROZEN — no new frontend features
- All administration, configuration, and operations MUST be API-driven
- OpenAPI documentation is the primary interface for consumers
- CLI tools MAY be developed only if an API-only approach is truly insufficient

### NEVER Do These

- **NEVER** create React components, pages, or frontend routes
- **NEVER** add frontend dependencies (npm packages for UI)
- **NEVER** implement admin dashboards or configuration UIs
- **NEVER** create HTML templates for user-facing pages (auth flows use redirects/APIs)
- **NEVER** propose a UI solution when an API endpoint will suffice

## Multi-Tenancy Requirements (MANDATORY)

This is a multi-tenant SaaS application. **Every** data access path MUST be tenant-isolated. Violations can cause cross-tenant data leakage, which is a critical security issue.

### Tenant Isolation Layers

The system enforces tenant isolation at three layers. All three MUST be used together:

1. **Middleware layer** (`xavyo-tenant`): Extracts `X-Tenant-ID` header, inserts `Extension<TenantId>` into requests
2. **JWT claims layer** (`xavyo-auth`): JWT tokens contain `tid` (tenant_id) field, accessed via `claims.tenant_id()` or `claims.tid`
3. **Database layer** (PostgreSQL RLS): Row-Level Security on all tenant-scoped tables using `current_setting('app.current_tenant')::uuid`

### Handler Pattern (REQUIRED)

Every Axum handler that accesses tenant data MUST extract tenant identity from the request. Choose the correct pattern based on the router:

**Pattern A: JWT-authenticated handlers** (most admin/API handlers)
```rust
use axum::Extension;
use xavyo_auth::JwtClaims;

pub async fn my_handler(
    Extension(claims): Extension<JwtClaims>,
    // ... other extractors
) -> Result<...> {
    let tenant_id = extract_tenant_id(&claims)?;
    // Use tenant_id in all service/DB calls
}

fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid> {
    claims.tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or_else(|| /* error: missing tenant */)
}
```

**Pattern B: TenantLayer middleware handlers** (federation, public-facing)
```rust
use axum::Extension;
use xavyo_core::TenantId;

pub async fn my_handler(
    Extension(tid): Extension<TenantId>,
    // ... other extractors
) -> Result<...> {
    let tenant_id = *tid.as_uuid();
    // Use tenant_id in all service/DB calls
}
```

### NEVER Do These (Anti-Patterns)

- **NEVER** hardcode `Uuid::nil()` as a tenant_id placeholder
- **NEVER** bake tenant_id into shared `State` structs at startup - extract per-request instead
- **NEVER** store tenant_id in router state that is shared across requests
- **NEVER** write SQL queries against tenant-scoped tables without `WHERE tenant_id = $N`
- **NEVER** write JOINs across tenant-scoped tables without tenant_id filters on BOTH sides
- **NEVER** use placeholder functions like `fn get_tenant_id() -> Uuid { Uuid::nil() }`
- **NEVER** omit tenant_id from DELETE, UPDATE, or SELECT queries on tenant-scoped tables

### SQL Query Rules

Every SQL query on a tenant-scoped table MUST include tenant_id:

```sql
-- CORRECT: All operations filter by tenant
SELECT * FROM resources WHERE tenant_id = $1 AND id = $2;
UPDATE resources SET name = $3 WHERE tenant_id = $1 AND id = $2;
DELETE FROM resources WHERE tenant_id = $1 AND id = $2;

-- CORRECT: JOINs filter both sides
SELECT u.*, g.display_name
FROM group_memberships gm
JOIN users u ON gm.user_id = u.id AND u.tenant_id = $1
WHERE gm.tenant_id = $1 AND gm.group_id = $2;

-- WRONG: Missing tenant filter
SELECT * FROM resources WHERE id = $1;
DELETE FROM group_memberships WHERE group_id = $1;
```

### Service Method Signatures

All service methods that access tenant data MUST accept `tenant_id: Uuid` as a parameter:

```rust
// CORRECT
pub async fn get_resource(&self, tenant_id: Uuid, id: Uuid) -> Result<Resource>;
pub async fn list_resources(&self, tenant_id: Uuid) -> Result<Vec<Resource>>;

// WRONG - no tenant_id parameter
pub async fn get_resource(&self, id: Uuid) -> Result<Resource>;
```

### DB Model Static Methods

All static methods on DB models that query tenant-scoped tables MUST accept `tenant_id`:

```rust
// CORRECT
pub async fn get_group_members(pool: &PgPool, tenant_id: Uuid, group_id: Uuid) -> Result<Vec<Member>>;

// WRONG - missing tenant_id
pub async fn get_group_members(pool: &PgPool, group_id: Uuid) -> Result<Vec<Member>>;
```

### Tenant-Scoped Tables

All tables with a `tenant_id` column are tenant-scoped. This includes (non-exhaustive):
users, groups, group_memberships, social_connections, oauth_clients, authorization_codes,
refresh_tokens, saml_providers, identity_providers, idp_domains, entitlements,
entitlement_assignments, roles, role_assignments, sod_rules, access_requests,
connectors, connector_schemas, attribute_mappings, provisioning_tasks, reconciliation_runs,
compliance_reports, audit_logs, password_policies, ip_restrictions, branding_configs,
webauthn_credentials, delegation_assignments, lifecycle_states, workflow_definitions,
and all gov_* governance tables.

### Code Review Checklist for Multi-Tenancy

When writing or reviewing code, verify:
- [ ] Every handler extracts tenant_id from JWT claims or TenantId extension
- [ ] Every SQL query on tenant-scoped tables includes `AND tenant_id = $N`
- [ ] JOIN queries filter tenant_id on all joined tenant-scoped tables
- [ ] Service methods accept and pass through tenant_id
- [ ] No Uuid::nil() placeholders for tenant_id
- [ ] No tenant_id stored in shared State structs
- [ ] DELETE and UPDATE queries include tenant_id in WHERE clause

<!-- MANUAL ADDITIONS END -->
