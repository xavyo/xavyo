---
title: Installation
description: Set up the xavyo identity platform — backend API and web frontend — for local development.
sidebar_position: 1
---

# Installation

This guide walks you through setting up the complete xavyo platform for local development: the **backend API** (Rust/Axum) and the **web frontend** (SvelteKit).

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| [Docker](https://docs.docker.com/get-docker/) + Compose | 20.10+ | PostgreSQL, Kafka, Mailpit, OpenLDAP |
| [Rust](https://rustup.rs/) | 1.75+ | Backend API |
| [Node.js](https://nodejs.org/) | 18+ | Frontend |
| [OpenSSL](https://www.openssl.org/) | any | JWT key generation |
| [Git](https://git-scm.com/) | any | Source code |

## 1. Clone the Repositories

```bash
# Backend API
git clone https://github.com/xavyo/xavyo-idp.git
cd xavyo-idp

# Frontend (in a separate directory)
git clone https://github.com/xavyo/xavyo-web.git ../xavyo-web
```

## 2. Start Infrastructure Services

The backend ships a Docker Compose file that provides PostgreSQL, Kafka, Mailpit (dev email), and OpenLDAP.

```bash
docker compose -f docker/docker-compose.yml up -d postgres mailpit kafka
```

Wait for services to become healthy:

```bash
docker compose -f docker/docker-compose.yml ps
```

| Service | Port | Purpose |
|---------|------|---------|
| PostgreSQL | `5434` | Database (user: `xavyo`, db: `xavyo_test`) |
| Kafka | `9094` | Event streaming (KRaft mode, no Zookeeper) |
| Mailpit SMTP | `1025` | Catches all outbound dev emails |
| Mailpit Web UI | `8025` | Browse captured emails at http://localhost:8025 |
| OpenLDAP | `1389` | Directory connector testing (optional) |

## 3. Generate JWT Keys

xavyo signs tokens with RSA-256. Generate a key pair:

```bash
bash docker/generate-keys.sh
```

This creates `docker/keys/jwt_private.pem` and `docker/keys/jwt_public.pem`. If keys already exist, the script skips regeneration.

Alternatively, generate keys manually:

```bash
mkdir -p keys
openssl genpkey -algorithm RSA -out keys/private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in keys/private.pem -out keys/public.pem
chmod 600 keys/private.pem
```

## 4. Configure the Backend

Copy the example environment file and adjust as needed:

```bash
cp .env.example .env
```

The defaults work out of the box with Docker Compose. Key variables:

```bash
# Database — matches docker-compose defaults
DATABASE_URL=postgres://xavyo:xavyo_test_password@localhost:5434/xavyo_test

# JWT keys — point to your generated keys
JWT_PRIVATE_KEY_PATH=./keys/private.pem
JWT_PUBLIC_KEY_PATH=./keys/public.pem
JWT_ISSUER=https://idp.xavyo.com
JWT_AUDIENCE=https://api.xavyo.com

# Server
API_HOST=0.0.0.0
API_PORT=8080
CORS_ORIGINS=http://localhost:3000

# Email — Mailpit (dev)
EMAIL_SMTP_HOST=localhost
EMAIL_SMTP_PORT=1025
EMAIL_SMTP_TLS=false
EMAIL_SMTP_USERNAME=dev
EMAIL_SMTP_PASSWORD=dev
EMAIL_FROM_ADDRESS=noreply@xavyo.local
FRONTEND_BASE_URL=http://localhost:3000

RUST_LOG=info
```

:::tip
If you generated keys with `docker/generate-keys.sh`, update the paths:
```
JWT_PRIVATE_KEY_PATH=./docker/keys/jwt_private.pem
JWT_PUBLIC_KEY_PATH=./docker/keys/jwt_public.pem
```
:::

## 5. Run the Backend

```bash
cargo run -p idp-api
```

On first start, the server automatically:
1. Runs all database migrations (198+ migrations)
2. Creates the system tenant
3. Bootstraps the CLI OAuth client
4. Starts background jobs (token cleanup, escalations, vault lease management)

Once you see `Listening on 0.0.0.0:8080`, the API is ready.

### Verify the Backend

```bash
# Health check
curl http://localhost:8080/readyz

# OpenID Connect discovery
curl http://localhost:8080/.well-known/openid-configuration

# Swagger UI
open http://localhost:8080/docs/
```

## 6. Configure the Frontend

```bash
cd ../xavyo-web
cp .env.example .env
```

The frontend needs one environment variable pointing to the backend:

```bash
API_BASE_URL=http://localhost:8080
```

## 7. Run the Frontend

```bash
npm install
npm run dev
```

The SvelteKit dev server starts at http://localhost:3000 with hot reload.

### Verify the Frontend

Open http://localhost:3000 in your browser. You should see the xavyo login page.

## 8. Create Your First User

With both services running, sign up a user via the API:

```bash
# Get the system tenant ID
TENANT_ID="00000000-0000-0000-0000-000000000001"

# Sign up
curl -X POST http://localhost:8080/auth/signup \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: $TENANT_ID" \
  -d '{
    "email": "admin@example.com",
    "password": "MyP@ssw0rd_2026",
    "first_name": "Admin",
    "last_name": "User"
  }'
```

Then verify the email via Mailpit:

```bash
# Check captured emails
curl -s http://localhost:8025/api/v1/messages | jq '.[0].Subject'

# Or open the Mailpit UI
open http://localhost:8025
```

Click the verification link in the email, then log in at http://localhost:3000.

## Production Build

### Backend

```bash
cargo build --release -p idp-api
# Binary at: target/release/idp-api
```

### Frontend

```bash
cd xavyo-web
npm run build
# Output: production Node.js server (adapter-node)

# Preview locally
npm run preview
```

## Useful Commands

### Backend

```bash
# Type-check (fast)
cargo check -p idp-api

# Run tests
cargo test -p <crate-name>
cargo test --workspace

# Lint
cargo clippy -p idp-api -- -D warnings

# Format
cargo fmt --check
```

### Frontend

```bash
# Type-check
npm run check

# Unit tests
npm run test:unit

# Watch mode
npm run test:unit:watch
```

### Infrastructure

```bash
# Start all services
docker compose -f docker/docker-compose.yml up -d

# View logs
docker compose -f docker/docker-compose.yml logs -f postgres

# Reset database (destroys all data)
docker compose -f docker/docker-compose.yml down -v
docker compose -f docker/docker-compose.yml up -d

# Clear captured emails
curl -X DELETE http://localhost:8025/api/v1/messages
```

## Troubleshooting

### Port conflicts

If port 5434 (PostgreSQL) or 8080 (API) is already in use, change the port in `.env` or `docker-compose.yml`.

### Database connection refused

Ensure PostgreSQL is running and healthy:

```bash
docker compose -f docker/docker-compose.yml ps postgres
```

### Email not sending

Verify `EMAIL_SMTP_TLS=false` in your `.env`. Mailpit does not support TLS. Check Mailpit is running:

```bash
curl http://localhost:8025/api/v1/messages
```

### Frontend cannot reach backend

Check that `API_BASE_URL=http://localhost:8080` is set in `xavyo-web/.env` and that CORS is configured:

```bash
# In xavyo-idp/.env
CORS_ORIGINS=http://localhost:3000
```

### Migrations fail

Ensure the database user has superuser privileges for migrations. The Docker Compose default user (`xavyo`) has the required permissions.

## Architecture Overview

```
xavyo-idp (Backend)          xavyo-web (Frontend)
├── apps/idp-api/             ├── src/
│   └── src/main.rs           │   ├── lib/api/        # API clients
├── crates/                   │   ├── lib/components/  # UI components
│   ├── xavyo-auth/           │   ├── routes/          # SvelteKit pages
│   ├── xavyo-db/             │   └── app.html
│   ├── xavyo-api-nhi/        ├── package.json
│   ├── xavyo-api-governance/ └── svelte.config.js
│   └── ... (32 crates)
├── docker/
│   └── docker-compose.yml
└── .env.example

PostgreSQL :5434 ──── idp-api :8080 ──── xavyo-web :3000
Kafka      :9094 ─┘
Mailpit    :1025 ─┘
```

## Next Steps

- [Key Concepts](/docs/getting-started/key-concepts) -- Understand the core architecture
- [Quick Tour](/docs/getting-started/quick-tour) -- Walk through the API with curl
- [API Overview](/docs/guides/developer/api-overview) -- Full API documentation
- [Tenant Setup](/docs/guides/admin/tenant-setup) -- Configure your first tenant
