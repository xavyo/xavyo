<p align="center">
  <img src="logo-xavyo.png" alt="xavyo" width="400" />
</p>

<h3 align="center">The Identity Platform for the AI Agent Era</h3>

<p align="center">
  Secure your AI agents, humans, and machines with a unified identity platform.<br/>
  Built in Rust for performance. Designed for the future.
</p>

<p align="center">
  <a href="https://github.com/xavyo/xavyo/blob/master/LICENSE"><img src="https://img.shields.io/badge/license-BSL--1.1-blue.svg" alt="License" /></a>
  <a href="https://github.com/xavyo/xavyo"><img src="https://img.shields.io/badge/rust-1.75+-orange.svg" alt="Rust 1.75+" /></a>
  <a href="https://github.com/xavyo/xavyo"><img src="https://img.shields.io/badge/status-production--ready-green.svg" alt="Production Ready" /></a>
  <a href="https://discord.gg/xavyo"><img src="https://img.shields.io/badge/discord-join-7289da.svg" alt="Discord" /></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#why-xavyo">Why xavyo</a> •
  <a href="#documentation">Docs</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## The Problem

AI agents are proliferating across enterprises. Each agent needs:
- **Identity** — Who is this agent? Who owns it?
- **Credentials** — How does it authenticate to cloud services?
- **Permissions** — What tools and data can it access?
- **Audit Trail** — What actions did it take and why?

Traditional IAM solutions weren't built for this. They focus on humans, not machines. Not agents.

## The Solution

**xavyo** is a unified identity platform that secures humans, machines, and AI agents with the same robust infrastructure:

```
┌─────────────────────────────────────────────────────────────────────┐
│                           xavyo                                    │
├─────────────────────────────────────────────────────────────────────┤
│  Humans              │  AI Agents            │  Services            │
│  ─────────────────   │  ─────────────────    │  ─────────────────   │
│  • SSO (OIDC/SAML)   │  • Agent Identity     │  • Service Accounts  │
│  • MFA / Passkeys    │  • Dynamic Creds      │  • API Keys          │
│  • Social Login      │  • Tool Permissions   │  • mTLS Certificates │
│  • Self-Service      │  • Audit Logging      │  • Workload Identity │
└─────────────────────────────────────────────────────────────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
            ┌─────────────┐             ┌─────────────┐
            │   Your      │             │   Cloud     │
            │   Apps      │             │   Services  │
            └─────────────┘             └─────────────┘
```

---

## Features

### Authentication & SSO
| Feature | Description |
|---------|-------------|
| **OAuth2/OIDC Provider** | Authorization Code + PKCE, Client Credentials, Device Code, Token Exchange, Refresh Tokens |
| **SAML 2.0 IdP** | SP-initiated and IdP-initiated SSO with signature validation and group assertions |
| **SAML Single Logout** | SP-initiated and IdP-initiated SLO with per-SP session tracking |
| **OIDC RP-Initiated Logout** | End Session endpoint with `id_token_hint`, `post_logout_redirect_uri`, `client_id` |
| **Multi-Factor Auth** | TOTP, WebAuthn/Passkeys, Recovery Codes with configurable enforcement |
| **Social Login** | Google, Microsoft, Apple — with JWKS signature verification and nonce validation |
| **Passwordless** | Magic links and passkey-first authentication |
| **Session Management** | Active session tracking, revocation, concurrent session limits |
| **Security Policies** | Configurable password, session, MFA, and lockout policies per tenant |

### AI Agent Security (NHI — Non-Human Identity)
| Feature | Description |
|---------|-------------|
| **Unified NHI Model** | Single identity model for agents, tools, and service accounts with type-specific extensions |
| **Lifecycle Management** | State machine: active, inactive, suspended, deprecated, archived — with full transition audit |
| **Dynamic Credentials** | Short-lived AWS STS, Azure, GCP credentials via OAuth2 token exchange |
| **Tool Permissions** | Fine-grained grant/revoke of agent-to-tool and NHI-to-NHI calling permissions |
| **User Permissions** | Control which users can use/manage/admin each NHI identity |
| **Risk Scoring** | Per-NHI risk assessment with inactivity detection and orphan account discovery |
| **Certifications** | Certification campaigns for periodic NHI review and attestation |
| **SoD Rules** | Segregation of Duties enforcement for NHI identities |
| **MCP Discovery** | Model Context Protocol tool discovery endpoint for AI agent integration |
| **A2A Protocol** | Agent-to-Agent communication with agent card discovery and webhook delivery |
| **Workload Identity** | Cloud-native identity federation (AWS, Azure, GCP) |
| **PKI Certificates** | X.509 certificate issuance for agent mTLS authentication |

### Identity Governance & Administration (IGA)
| Feature | Description |
|---------|-------------|
| **Roles & Entitlements** | RBAC with application-scoped entitlements and role-entitlement mappings |
| **Role Inducements** | Automatic role grants — when a parent role is assigned, induced roles are automatically granted |
| **Role Inheritance** | Hierarchical role structures with inheritance blocks |
| **Role Mining** | Analytics-driven role discovery from existing access patterns |
| **Access Requests** | Self-service request catalog with configurable approval workflows and escalation |
| **Segregation of Duties** | SoD rule enforcement with exemptions and violation detection |
| **Access Certifications** | Periodic review campaigns with micro-certification support |
| **GDPR Compliance** | Data protection classification on entitlements, GDPR compliance reports, per-user data protection summaries |
| **Lifecycle Workflows** | Joiner/mover/leaver automation with birthright policies and state machines |
| **Risk Assessment** | Multi-factor risk scoring with alerts, thresholds, and peer group analysis |
| **Outlier Detection** | Statistical detection of anomalous access patterns |
| **Power of Attorney** | Delegated administration with time-bounded authority |
| **Identity Archetypes** | Template-based identity provisioning (Employee, Contractor, etc.) |
| **Personas** | Multiple persona management per identity |
| **Meta-Roles & Parametric Roles** | Dynamic role generation and parameter-driven role assignment |
| **Bulk Actions** | Batch operations for mass assignment, revocation, and lifecycle transitions |
| **Object Templates** | Reusable templates for governance objects |
| **Policy Simulation** | What-if analysis for access changes before applying them |

### Provisioning & Connectors
| Feature | Description |
|---------|-------------|
| **Connector Framework** | Pluggable architecture for target system integration |
| **Built-in Connectors** | LDAP, Active Directory, REST APIs, Databases, Microsoft Entra ID |
| **SCIM 2.0 Server** | Inbound provisioning from Azure AD, Okta, Google Workspace |
| **SCIM 2.0 Client** | Outbound provisioning to SCIM-compliant targets |
| **Reconciliation** | Scheduled reconciliation with conflict detection and resolution |
| **Provisioning Jobs** | Job tracking with dead-letter queue and retry logic |
| **Import/Export** | Bulk CSV import and declarative YAML export for users, groups, applications |

### Enterprise Features
| Feature | Description |
|---------|-------------|
| **Multi-Tenant** | Full tenant isolation with PostgreSQL Row-Level Security on every table |
| **Tenant Settings** | Per-tenant configuration for branding, session policies, and features |
| **User Invitations** | Email-based invitation flow with role preservation |
| **API Keys** | Scoped API keys with usage statistics and introspection |
| **Webhooks** | Event-driven notifications with circuit breaker, DLQ, and retry |
| **SIEM Integration** | Structured audit events for security monitoring |
| **Audit Logging** | Comprehensive audit trail for all operations |
| **Correlation Engine** | Cross-system identity correlation and matching |
| **Token Delegation** | OAuth2 token exchange for on-behalf-of and delegation flows |
| **Ext-AuthZ Gateway** | External authorization service for API gateway integration |

### OIDC Federation
| Feature | Description |
|---------|-------------|
| **Identity Providers** | Configure external OIDC identity providers for federated login |
| **Attribute Mapping** | Map external claims to internal user attributes |
| **JIT Provisioning** | Just-in-time user creation from federated logins |
| **JWKS Verification** | Full signature verification of ID tokens via JWKS |

### CLI (`xavyo`)
| Feature | Description |
|---------|-------------|
| **31 Commands** | Full API coverage — agents, users, groups, governance, NHI, connectors, and more |
| **Setup Wizard** | Interactive onboarding: signup, email verification, tenant creation |
| **Multi-Tenant Switching** | `tenant switch` to change context between organizations |
| **Declarative Config** | `apply` and `export` for GitOps workflows |
| **Watch Mode** | `watch` a YAML config file and auto-apply changes |
| **Templates** | Pre-configured templates for quick setup |
| **JSON Output** | `--json` flag on all commands for scripting and CI pipelines |
| **Shell Completions** | Bash, Zsh, Fish, PowerShell via `completions` command |
| **Doctor** | Connection and configuration diagnostics |

---

## Quick Start

### Docker (recommended)

Get running in **2 minutes** — no Rust toolchain needed:

```bash
# 1. Clone
git clone https://github.com/xavyo/xavyo.git && cd xavyo

# 2. Generate JWT keys
bash docker/generate-keys.sh

# 3. Start everything
docker compose -f docker/docker-compose.yml up -d

# 4. Verify
curl http://localhost:8080/readyz
```

**That's it!** API running at `http://localhost:8080`

### Without Docker (from source)

```bash
# 1. Clone
git clone https://github.com/xavyo/xavyo.git && cd xavyo

# 2. Generate JWT keys
bash docker/generate-keys.sh

# 3. Start PostgreSQL
docker compose -f docker/docker-compose.yml up -d postgres

# 4. Setup environment & run
cp .env.example .env
cargo run -p idp-api
```

Swagger UI: `http://localhost:8080/docs/`

### Using the CLI

```bash
# Install the CLI
cargo install --path apps/xavyo-cli

# Interactive setup (signup, verify email, create tenant)
xavyo setup

# Or step by step:
xavyo signup                    # Create an account
xavyo verify status             # Check email verification
xavyo verify resend             # Resend verification email
xavyo login                     # Authenticate via device code flow
xavyo init "My Organization"    # Create a tenant

# Check setup status
xavyo setup --check
```

### Test it works

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: 00000000-0000-0000-0000-000000000001" \
  -d '{"email":"admin@test.xavyo.com","password":"Test123!"}'
```

---

## Why xavyo?

| | xavyo | Traditional IAM | DIY |
|---|:---:|:---:|:---:|
| **AI Agent Identity** | Native | Bolt-on | Build it |
| **NHI Lifecycle Management** | Built-in | N/A | Complex |
| **Dynamic Cloud Credentials** | Built-in | Separate tool | Complex |
| **IGA (Governance)** | Full suite | Separate product | Enormous effort |
| **Multi-Tenant by Design** | RLS isolation | Varies | Hard |
| **SAML + OIDC + Social** | All built-in | Usually one | Build each |
| **Open Source** | BSL 1.1 | Proprietary | Yes |
| **Performance** | Rust/Axum | JVM overhead | Varies |
| **Self-Hosted** | Full control | Limited | Yes |

### Built for Scale

- **Rust** — Memory-safe, no GC pauses, predictable latency
- **Axum** — Async-first HTTP framework with Tower middleware
- **PostgreSQL RLS** — Tenant isolation enforced at the database level
- **32 crates** — Modular architecture, each crate independently testable
- **198 SQL migrations** — Battle-tested, production-grade schema
- **665K lines of Rust** — Comprehensive implementation, not a prototype
- **7,400+ tests** — 5,576 unit/integration + 1,907 functional tests across 14 batches

---

## API Surface

xavyo exposes a comprehensive REST API with full OpenAPI/Swagger documentation.

| Domain | Endpoints | Description |
|--------|-----------|-------------|
| **Authentication** | `/auth/*` | Login, logout, register, MFA, password reset, email verification |
| **OAuth2/OIDC** | `/oauth/*` | Authorize, token, userinfo, JWKS, discovery, end session, introspect |
| **SAML 2.0** | `/saml/*` | SSO, SLO, metadata, certificate management, SP configuration |
| **Users & Groups** | `/users/*`, `/groups/*` | CRUD, role assignments, group memberships, password management |
| **Sessions** | `/sessions/*` | Active session listing, revocation, concurrent limits |
| **NHI (Non-Human)** | `/nhi/*` | Unified CRUD, lifecycle transitions, permissions, risk, certifications |
| **Governance** | `/governance/*` | Roles, entitlements, access requests, SoD, certifications, GDPR |
| **Connectors** | `/connectors/*` | Configuration, reconciliation, provisioning jobs, DLQ |
| **SCIM 2.0** | `/scim/*` | Users, groups, service provider config, schemas |
| **Webhooks** | `/webhooks/*` | Subscriptions, DLQ, circuit breaker |
| **Social Login** | `/social/*` | Google, Microsoft, Apple federation |
| **OIDC Federation** | `/federation/*` | External IdP configuration and metadata |
| **Tenants** | `/tenants/*` | Multi-tenant management, settings, invitations |
| **Import** | `/import/*` | Bulk CSV import with validation |
| **API Keys** | `/api-keys/*` | Scoped key management, usage stats, introspection |
| **Authorization** | `/authorization/*` | Policy evaluation, external authz |
| **Audit** | `/audit/*` | Event log querying |
| **Security Policies** | `/policies/*` | Password, session, MFA, lockout configuration |
| **Operations** | `/operations/*` | Provisioning operation tracking |

---

## Documentation

| Resource | Description |
|----------|-------------|
| **[llms.txt](llms.txt)** | LLM-friendly navigation index for all 32 crates |
| **[llms-full.txt](llms-full.txt)** | Complete documentation (~15,500 words) |
| **[Architecture](docs/ARCHITECTURE.md)** | System architecture overview |
| **[Crate Index](docs/crates/index.md)** | All crates organized by layer |
| **[Dependency Graph](docs/crates/dependency-graph.md)** | Visual dependency relationships |
| **[API Reference](http://localhost:8080/docs/)** | Swagger UI (when running) |

Each crate has a standardized `CRATE.md` file at its root (e.g., [`crates/xavyo-core/CRATE.md`](crates/xavyo-core/CRATE.md)).

---

## Architecture

```
xavyo/
├── apps/
│   ├── idp-api/           # Main API service (Axum)
│   ├── gateway/           # API Gateway
│   ├── ext-authz/         # External Authorization service
│   └── xavyo-cli/         # CLI tool (31 commands)
│
├── crates/                # 32 Rust crates
│   ├── Core
│   │   ├── xavyo-core/        # Shared types (TenantId, UserId, errors)
│   │   ├── xavyo-auth/        # JWT, passwords, MFA, passkeys
│   │   ├── xavyo-db/          # PostgreSQL + 198 migrations
│   │   ├── xavyo-tenant/      # Multi-tenant middleware
│   │   └── xavyo-events/      # Kafka event bus
│   │
│   ├── API Layer
│   │   ├── xavyo-api-auth/         # Authentication endpoints
│   │   ├── xavyo-api-oauth/        # OAuth2/OIDC provider
│   │   ├── xavyo-api-saml/         # SAML 2.0 IdP + SLO
│   │   ├── xavyo-api-social/       # Social login (Google, MS, Apple)
│   │   ├── xavyo-api-users/        # User & group management
│   │   ├── xavyo-api-scim/         # SCIM 2.0 server
│   │   ├── xavyo-api-governance/   # IGA engine (40+ endpoints)
│   │   ├── xavyo-api-nhi/          # Non-Human Identity API
│   │   ├── xavyo-api-connectors/   # Connector & job management
│   │   ├── xavyo-api-import/       # Bulk import
│   │   ├── xavyo-api-tenants/      # Tenant & API key management
│   │   ├── xavyo-api-authorization/# Policy evaluation
│   │   └── xavyo-api-oidc-federation/ # External IdP federation
│   │
│   ├── Services
│   │   ├── xavyo-governance/       # Governance business logic
│   │   ├── xavyo-authorization/    # Authorization engine
│   │   ├── xavyo-nhi/              # NHI domain logic
│   │   ├── xavyo-provisioning/     # Provisioning orchestration
│   │   ├── xavyo-webhooks/         # Webhook delivery + DLQ
│   │   ├── xavyo-siem/             # SIEM integration
│   │   ├── xavyo-secrets/          # Secret management
│   │   └── xavyo-scim-client/      # Outbound SCIM client
│   │
│   └── Connectors
│       ├── xavyo-connector/          # Connector trait framework
│       ├── xavyo-connector-ldap/     # LDAP/AD connector
│       ├── xavyo-connector-entra/    # Microsoft Entra ID connector
│       ├── xavyo-connector-rest/     # Generic REST connector
│       ├── xavyo-connector-database/ # Database connector
│       └── xavyo-ext-authz/         # External authorization
│
├── docker/                # Docker & development environment
├── tests/functional/      # 1,907 functional tests (14 batches)
└── specs/                 # Feature specifications
```

**32 crates** | **198 SQL migrations** | **1,739 source files** | **665K lines of Rust**

---

## Contributing

We'd love your help making xavyo better!

### Good First Issues

Look for issues tagged [`good first issue`](https://github.com/xavyo/xavyo/labels/good%20first%20issue).

### How to Contribute

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feat/amazing-feature`)
3. **Code** — follow `cargo fmt` and `cargo clippy`
4. **Test** — run `cargo test --workspace`
5. **Commit** — use [conventional commits](https://conventionalcommits.org) (`feat:`, `fix:`, `docs:`)
6. **Push** and open a **Pull Request**

### Development Setup

```bash
# Build everything
cargo build --workspace

# Run tests
cargo test --workspace

# Lint
cargo clippy --workspace -- -D warnings

# Format
cargo fmt --all
```

---

## Roadmap

- [ ] **Kubernetes Operator** — Deploy xavyo on K8s with CRDs
- [ ] **Agent SDK** — Python, TypeScript, Go SDKs for agents
- [ ] **Policy Engine** — OPA/Rego integration for fine-grained policies
- [ ] **Terraform Provider** — Infrastructure as Code support
- [ ] **Web Console** — Admin UI (SvelteKit, in development)

Have ideas? [Open a discussion](https://github.com/xavyo/xavyo/discussions)!

---

## License

**Business Source License 1.1 (BSL 1.1)**

- **Self-hosted deployment** — permitted
- **Internal use** — permitted
- **Modifications** — permitted
- **Hosted service** — requires commercial license
- **Converts to Apache 2.0** on 2030-02-01

See [LICENSE](LICENSE) for full terms.

### Commercial Licensing

Need to run xavyo as a hosted service? Contact us:

pascal@heartbit.ai

---

<p align="center">
  <sub>Built with care by <a href="https://heartbit.ai">Heartbit Inc.</a></sub>
</p>
