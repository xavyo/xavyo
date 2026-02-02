<p align="center">
  <img src="docs/assets/xavyo-logo.svg" alt="xavyo" width="400" />
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
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-features">Features</a> •
  <a href="#-why-xavyo">Why xavyo</a> •
  <a href="#-documentation">Docs</a> •
  <a href="#-contributing">Contributing</a>
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
│                           xavyo                                  │
├─────────────────────────────────────────────────────────────────────┤
│  🧑 Humans          │  🤖 AI Agents        │  🖥️ Services           │
│  ─────────────────  │  ─────────────────   │  ─────────────────     │
│  • SSO (OIDC/SAML)  │  • Agent Identity    │  • Service Accounts    │
│  • MFA / Passkeys   │  • Dynamic Creds     │  • API Keys            │
│  • Social Login     │  • Tool Permissions  │  • mTLS Certificates   │
│  • Self-Service     │  • Audit Logging     │  • Workload Identity   │
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

## ✨ Features

### 🔐 Authentication & SSO
| Feature | Description |
|---------|-------------|
| **OAuth2/OIDC Provider** | Full compliance with Authorization Code + PKCE, Client Credentials, Device Code |
| **SAML 2.0 IdP** | SP-initiated and IdP-initiated SSO for enterprise apps |
| **Multi-Factor Auth** | TOTP, WebAuthn/Passkeys, Recovery Codes |
| **Social Login** | Google, Microsoft, Apple — plug and play |
| **Passwordless** | Magic links and passkey-first authentication |

### 🤖 AI Agent Security
| Feature | Description |
|---------|-------------|
| **Agent Identity** | Register, track, and manage AI agent identities |
| **Dynamic Credentials** | Short-lived AWS STS, Azure, GCP credentials on-demand |
| **Tool Permissions** | Fine-grained control over what tools agents can use |
| **Workload Identity** | Cloud-native identity federation for agents |
| **PKI Certificates** | X.509 certificates for agent mTLS authentication |

### 🏢 Enterprise & Governance
| Feature | Description |
|---------|-------------|
| **Multi-Tenant** | Full tenant isolation with PostgreSQL Row-Level Security |
| **SCIM 2.0** | Automated provisioning from Azure AD, Okta, etc. |
| **Access Workflows** | Request → Approve → Provision with escalation |
| **Segregation of Duties** | Prevent toxic combinations automatically |
| **Connectors** | LDAP, Active Directory, databases, REST APIs |

---

## 🚀 Quick Start

Get running in **5 minutes**:

```bash
# 1. Clone
git clone https://github.com/xavyo/xavyo.git && cd xavyo

# 2. Generate JWT keys
openssl genpkey -algorithm RSA -out keys/test-private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in keys/test-private.pem -out keys/test-public.pem

# 3. Start PostgreSQL
docker compose -f docker/docker-compose.yml up -d postgres

# 4. Setup environment & run
cp .env.example .env
cargo run -p idp-api
```

**That's it!** API running at `http://localhost:8080`

📖 **Swagger UI**: `http://localhost:8080/swagger-ui/`

### Test it works

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: 00000000-0000-0000-0000-000000000001" \
  -d '{"email":"admin@test.xavyo.com","password":"Test123!"}'
```

---

## 🎯 Why xavyo?

| | xavyo | Traditional IAM | DIY |
|---|:---:|:---:|:---:|
| **AI Agent Identity** | ✅ Native | ❌ Bolt-on | 🔧 Build it |
| **Dynamic Cloud Credentials** | ✅ Built-in | ❌ Separate tool | 🔧 Complex |
| **Multi-Tenant by Design** | ✅ RLS isolation | ⚠️ Varies | 🔧 Hard |
| **Open Source** | ✅ BSL 1.1 | ❌ Proprietary | ✅ |
| **Performance** | ✅ Rust/Axum | ⚠️ JVM overhead | ⚠️ Varies |
| **Self-Hosted** | ✅ Full control | ⚠️ Limited | ✅ |

### Built for Scale

- **Rust** — Memory-safe, no GC pauses, predictable latency
- **Axum** — Async-first, tower middleware ecosystem
- **PostgreSQL RLS** — Tenant isolation at the database level
- **100+ migrations** — Battle-tested schema

---

## 📚 Documentation

| Resource | Link |
|----------|------|
| **API Reference** | [Swagger UI](http://localhost:8080/swagger-ui/) |
| **OpenAPI Spec** | [`docs/api/openapi.json`](docs/api/openapi.json) |
| **Architecture** | [Architecture Guide](docs/architecture.md) |

---

## 🏗️ Architecture

```
xavyo/
├── apps/
│   ├── idp-api/           # Main API service (Axum)
│   ├── gateway/           # API Gateway
│   └── xavyo-cli/         # CLI tool
│
├── crates/
│   ├── xavyo-core/        # Shared types & errors
│   ├── xavyo-auth/        # JWT, passwords, MFA
│   ├── xavyo-db/          # PostgreSQL + 127 migrations
│   ├── xavyo-tenant/      # Multi-tenant middleware
│   ├── xavyo-events/      # Kafka event bus
│   ├── xavyo-api-auth/    # Auth endpoints
│   ├── xavyo-api-oauth/   # OAuth2/OIDC provider
│   ├── xavyo-api-agents/  # AI Agent platform
│   ├── xavyo-api-scim/    # SCIM provisioning
│   ├── xavyo-connector/   # Connector framework
│   └── xavyo-governance/  # IGA engine
│
└── docker/                # Development environment
```

**34 Rust crates** | **127 SQL migrations** | **1,400+ source files**

---

## 🤝 Contributing

We'd love your help making xavyo better!

### Good First Issues

Look for issues tagged [`good first issue`](https://github.com/xavyo/xavyo/labels/good%20first%20issue) — these are great starting points.

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

## 🗺️ Roadmap

- [ ] **Kubernetes Operator** — Deploy xavyo on K8s with CRDs
- [ ] **Agent SDK** — Python, TypeScript, Go SDKs for agents
- [ ] **Policy Engine** — OPA/Rego integration for fine-grained policies
- [ ] **Terraform Provider** — Infrastructure as Code support
- [ ] **Web Console** — Admin UI (API-first, UI second)

Have ideas? [Open a discussion](https://github.com/xavyo/xavyo/discussions)!

---

## 📜 License

**Business Source License 1.1 (BSL 1.1)**

- ✅ **Self-hosted deployment** — permitted
- ✅ **Internal use** — permitted
- ✅ **Modifications** — permitted
- ❌ **Hosted service** — requires commercial license
- 🔄 **Converts to Apache 2.0** on 2030-02-01

See [LICENSE](LICENSE) for full terms.

### Commercial Licensing

Need to run xavyo as a hosted service? Contact us:

📧 **pascal@heartbit.ai**

---

<p align="center">
  <sub>Built with ❤️ by <a href="https://heartbit.ai">Hearbit Inc.</a></sub>
</p>
