# xavyo Installation Guide

This guide covers all ways to run xavyo: Docker (quickest), from source (for development), or standalone distribution.

## Docker Quick Start (recommended)

The fastest way to get xavyo running. No Rust toolchain required.

### Prerequisites

| Tool | Version | Check Command |
|------|---------|---------------|
| Docker | 24.0+ | `docker --version` |
| Docker Compose | 2.20+ | `docker compose version` |

### Steps

```bash
# 1. Clone
git clone https://github.com/xavyo/xavyo.git && cd xavyo

# 2. Generate JWT keys
bash docker/generate-keys.sh

# 3. Start everything (PostgreSQL, Kafka, Mailpit, OpenLDAP, API)
docker compose -f docker/docker-compose.yml up -d

# 4. Verify
curl http://localhost:8080/readyz
```

The API is now running at `http://localhost:8080` with Swagger UI at `http://localhost:8080/docs/`.

A default admin user is created automatically:

| | Default |
|---|---------|
| **Email** | `admin@xavyo.local` |
| **Password** | `Admin@1234` |
| **Role** | `super_admin` |
| **Tenant** | System (`00000000-0000-0000-0000-000000000001`) |

```bash
# Login
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: 00000000-0000-0000-0000-000000000001" \
  -d '{"email":"admin@xavyo.local","password":"Admin@1234"}'
```

Override with custom credentials via environment variables:

```bash
ADMIN_EMAIL=me@example.com ADMIN_PASSWORD='MyS3cure!Pass' \
  docker compose -f docker/docker-compose.yml up -d
```

### Standalone Distribution (no source code)

For end users who just want to run xavyo without cloning the repository:

```bash
# 1. Download the compose file
curl -O https://raw.githubusercontent.com/xavyo/xavyo/master/docker/docker-compose.dist.yml

# 2. Generate JWT keys
mkdir -p keys
openssl genpkey -algorithm RSA -out keys/jwt_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in keys/jwt_private.pem -out keys/jwt_public.pem

# 3. Start (pulls pre-built image from GHCR)
docker compose -f docker-compose.dist.yml up -d

# 4. Verify
curl http://localhost:8080/readyz
```

The pre-built image is published to `ghcr.io/xavyo/xavyo-idp` on every release. The default admin credentials (`admin@xavyo.local` / `Admin@1234`) are the same as above — override with `ADMIN_EMAIL` and `ADMIN_PASSWORD`.

### Bootstrap Admin User

On first startup, if `ADMIN_EMAIL` and `ADMIN_PASSWORD` are set, a `super_admin` user is created under the system tenant with email pre-verified for immediate login. The operation is idempotent — on subsequent restarts the existing user is left unchanged.

To disable automatic admin creation, unset both variables:

```bash
ADMIN_EMAIL= ADMIN_PASSWORD= docker compose -f docker/docker-compose.yml up -d
```

### Docker Image Details

| Property | Value |
|----------|-------|
| **Base image** | Debian bookworm-slim |
| **Image size** | ~422 MB |
| **Runtime user** | `xavyo` (UID 1000, non-root) |
| **Exposed port** | 8080 |
| **Healthcheck** | `GET /readyz` every 10s |
| **Registry** | `ghcr.io/xavyo/xavyo-idp` |

---

## Development Setup (from source)

For contributors and developers who need to build and modify xavyo.

### Prerequisites

| Tool | Version | Check Command |
|------|---------|---------------|
| Docker | 24.0+ | `docker --version` |
| Docker Compose | 2.20+ | `docker compose version` |
| Rust | 1.75+ | `rustc --version` |
| OpenSSL | 1.1+ | `openssl version` |
| Git | 2.30+ | `git --version` |
| Node.js | 18+ | `node --version` (for documentation site only) |

### 1. Clone the Repository

```bash
git clone https://github.com/xavyo/xavyo.git
cd xavyo
```

### 2. Generate JWT Signing Keys

```bash
bash docker/generate-keys.sh
```

Or manually:

```bash
mkdir -p docker/keys
openssl genpkey -algorithm RSA -out docker/keys/jwt_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in docker/keys/jwt_private.pem -out docker/keys/jwt_public.pem
chmod 600 docker/keys/jwt_private.pem
```

### 3. Generate Encryption Keys

xavyo requires several encryption keys (all hex-encoded, 32 bytes):

```bash
# Generate all encryption keys at once
echo "SAML_ENCRYPTION_KEY=$(openssl rand -hex 32)" >> .env
echo "FEDERATION_ENCRYPTION_KEY=$(openssl rand -hex 32)" >> .env
echo "MFA_ENCRYPTION_KEY=$(openssl rand -hex 32)" >> .env
echo "CONNECTOR_ENCRYPTION_KEY=$(openssl rand -hex 32)" >> .env
echo "WEBHOOK_ENCRYPTION_KEY=$(openssl rand -hex 32)" >> .env
echo "CSRF_SECRET=$(openssl rand -hex 32)" >> .env

# Social login encryption key (base64-encoded, 32 bytes)
echo "SOCIAL_ENCRYPTION_KEY=$(openssl rand -base64 32)" >> .env
echo "SOCIAL_STATE_SECRET=$(openssl rand -base64 32)" >> .env
```

> **Warning**: Never use all-zero or patterned keys in production. The API will refuse to start if default insecure keys are detected in production mode (`APP_ENV=production`).

### 4. Configure Environment

Copy the example environment file and adjust:

```bash
cp .env.example .env
```

Key variables:

```bash
# Database (matches docker-compose defaults)
DATABASE_URL=postgres://xavyo:xavyo_test_password@localhost:5434/xavyo_test
APP_DATABASE_URL=postgres://xavyo_app:xavyo_app_password@localhost:5434/xavyo_test

# JWT keys (paste the content of your key files)
JWT_PRIVATE_KEY="$(cat docker/keys/jwt_private.pem)"
JWT_PUBLIC_KEY="$(cat docker/keys/jwt_public.pem)"
JWT_KEY_ID=dev-key-1

# API server
PORT=8080
APP_ENV=development
RUST_LOG=info,xavyo=debug

# Email (Mailpit catches all emails in development)
EMAIL_SMTP_HOST=localhost
EMAIL_SMTP_PORT=1025
EMAIL_SMTP_TLS=false
EMAIL_SMTP_USERNAME=dev
EMAIL_SMTP_PASSWORD=dev
EMAIL_FROM_ADDRESS=noreply@xavyo.local
FRONTEND_BASE_URL=http://localhost:3000
```

### 5. Start Infrastructure Services

Start infrastructure services (without the API container — you'll run it from source):

```bash
docker compose -f docker/docker-compose.yml up -d postgres mailpit kafka openldap
```

Or start only what you need:

```bash
# PostgreSQL only (minimum for API)
docker compose -f docker/docker-compose.yml up -d postgres

# PostgreSQL + Mailpit (for email features)
docker compose -f docker/docker-compose.yml up -d postgres mailpit
```

Wait for services to be ready:

```bash
docker compose -f docker/docker-compose.yml ps
```

### 6. Run the API

Migrations run automatically on first startup:

```bash
cargo run -p idp-api
```

### 7. Verify Installation

```bash
# Health check
curl http://localhost:8080/health

# OpenAPI documentation
open http://localhost:8080/docs/

# Signup a test user
curl -X POST http://localhost:8080/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@test.xavyo.com","password":"MyP@ssw0rd_2026","display_name":"Admin"}'
```

> **Note**: Email must be verified before login. Check Mailpit at http://localhost:8025 for the verification email.

## Docker Compose Services

The `docker/docker-compose.yml` provides the full development stack:

| Service | Port(s) | Description | Required |
|---------|---------|-------------|----------|
| **idp-api** | 8080 | xavyo API server (built from source) | Yes |
| **postgres** | 5434 → 5432 | PostgreSQL 15 with RLS | Yes |
| **mailpit** | 1025 (SMTP), 8025 (Web UI) | Email testing (catches all outbound email) | For email features |
| **kafka** | 9094 → 9094 | Apache Kafka 3.7 (KRaft mode, no Zookeeper) | For event streaming |
| **openldap** | 1389 → 389, 1636 → 636 | OpenLDAP directory server | For LDAP connector testing |

All ports are configurable via environment variables (e.g., `POSTGRES_PORT`, `MAILPIT_SMTP_PORT`, `KAFKA_PORT`, `LDAP_PORT`).

### Service Credentials

| Service | Default Credentials | Environment Variable |
|---------|-------------------|---------------------|
| PostgreSQL | `xavyo` / `xavyo_test_password` | `POSTGRES_USER`, `POSTGRES_PASSWORD` |
| OpenLDAP Admin | `cn=admin,dc=xavyo,dc=dev` / `admin_password` | `LDAP_ADMIN_PASSWORD` |
| OpenLDAP Readonly | `readonly` / `readonly_password` | `LDAP_READONLY_USER_PASSWORD` |
| Mailpit SMTP | Any credentials accepted | N/A |

> **Note**: All Docker passwords are parameterized and can be overridden via environment variables. See `docker/docker-compose.yml` for the `${VAR:-default}` syntax.

### Useful URLs

| URL | Description |
|-----|-------------|
| http://localhost:8080/readyz | API readiness check |
| http://localhost:8080/health | API health check |
| http://localhost:8080/docs/ | Interactive API documentation (Swagger UI) |
| http://localhost:8025 | Mailpit Web UI (email testing) |
| http://localhost:4000 | Documentation site (if running) |

## Building the Docker Image

To build the production Docker image locally:

```bash
docker compose -f docker/docker-compose.yml build idp-api
```

Or directly:

```bash
docker build -f docker/Dockerfile -t xavyo-idp .
```

The multi-stage build uses `cargo-chef` for dependency caching. Rebuilds after source-only changes complete in under a minute.

## Documentation Site

The project includes a comprehensive Docusaurus documentation site with 866 pages:

```bash
cd docs-site
npm install
npm run build
npm run serve -- --port 4000
```

Then open http://localhost:4000. The site includes:
- Getting started guides and key concepts
- Admin guides for all platform features
- Developer guides with API integration patterns
- 837 auto-generated API reference pages from the OpenAPI spec
- Error code reference, rate limits, and glossary

## Development Workflow

### Build

```bash
cargo build --workspace
```

### Run Tests

```bash
# Unit tests
cargo test --workspace

# Functional test suite (1,755 tests across 12 batches)
# Requires running API + PostgreSQL
bash tests/functional/run-all-batches.sh
```

### Run with Hot Reload

```bash
cargo install cargo-watch
cargo watch -x "run -p idp-api"
```

### Lint

```bash
cargo clippy --workspace -- -D warnings
```

### Format

```bash
cargo fmt --all --check
```

### Regenerate OpenAPI Spec

```bash
cargo test -p idp-api export_openapi -- --ignored
# Output: docs/api/openapi.json (700 paths, 933 operations)
```

## Troubleshooting

### Database Connection Failed

```
Error: Failed to connect to database
```

Check that PostgreSQL is running on port 5434 (not the default 5432):

```bash
docker compose -f docker/docker-compose.yml ps postgres
docker compose -f docker/docker-compose.yml logs postgres
```

Verify your `DATABASE_URL` uses port 5434: `postgres://xavyo:xavyo_test_password@localhost:5434/xavyo_test`

### JWT Key Error

```
Error: Failed to parse JWT private key
```

Ensure the key is properly formatted in `.env`. The entire key including `-----BEGIN/END-----` markers must be included. Alternatively, reference the key file path.

### Insecure Default Keys Rejected

```
FATAL: insecure default(s) detected in production mode
```

In production (`APP_ENV=production`), all encryption keys must be explicitly set. Generate proper keys using `openssl rand -hex 32`. This also triggers when `APP_ENV=development` but the database URL points to a remote host (defense-in-depth).

### Port Already in Use

```
Error: Address already in use (os error 98)
```

```bash
lsof -i :8080
kill -9 <PID>
# Or change the port: PORT=8081
```

### Email Not Working

Ensure Mailpit is running and `.env` has:
```bash
EMAIL_SMTP_HOST=localhost
EMAIL_SMTP_PORT=1025
EMAIL_SMTP_TLS=false   # Required for Mailpit
```

Check http://localhost:8025 for captured emails.

### Reset Everything

```bash
docker compose -f docker/docker-compose.yml down -v
docker compose -f docker/docker-compose.yml up -d
cargo run -p idp-api  # Re-runs all migrations
```

## Next Steps

- Browse the [Documentation Site](http://localhost:4000) for comprehensive guides
- Read the [API Reference](http://localhost:8080/docs/) interactively
- Review [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines
- Check [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for system architecture

## Support

- **Issues**: [GitHub Issues](https://github.com/xavyo/xavyo/issues)
- **Discussions**: [GitHub Discussions](https://github.com/xavyo/xavyo/discussions)
- **Security**: See [SECURITY.md](SECURITY.md) for reporting vulnerabilities
