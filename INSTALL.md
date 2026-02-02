# xavyo Development Environment Setup

This guide walks you through setting up a local development environment for xavyo using Docker.

## Prerequisites

Before starting, ensure you have the following installed:

| Tool | Version | Check Command |
|------|---------|---------------|
| Docker | 24.0+ | `docker --version` |
| Docker Compose | 2.20+ | `docker compose version` |
| Rust | 1.75+ | `rustc --version` |
| OpenSSL | 1.1+ | `openssl version` |
| Git | 2.30+ | `git --version` |

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/xavyo/xavyo.git
cd xavyo
```

### 2. Generate JWT Signing Keys

xavyo uses RSA keys for JWT signing. Generate a key pair:

```bash
mkdir -p keys
openssl genpkey -algorithm RSA -out keys/test-private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in keys/test-private.pem -out keys/test-public.pem
chmod 600 keys/test-private.pem
```

### 3. Configure Environment

Copy the example environment file and adjust as needed:

```bash
cp .env.example .env
```

Key variables to configure:

```bash
# Database connection
DATABASE_URL=postgres://xavyo:xavyo@localhost:5432/xavyo

# JWT keys (paste the content of your key files)
JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----"

JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----"

# MFA encryption key (32 bytes, base64 encoded)
MFA_ENCRYPTION_KEY=your-32-byte-base64-encoded-key

# Credential encryption key (32 bytes hex)
CREDENTIAL_ENCRYPTION_KEY=0000000000000000000000000000000000000000000000000000000000000000

# Environment
APP_ENV=development
RUST_LOG=info,xavyo=debug
```

To generate encryption keys:

```bash
# MFA key (base64)
openssl rand -base64 32

# Credential key (hex)
openssl rand -hex 32
```

### 4. Start Infrastructure Services

Start PostgreSQL and other services using Docker Compose:

```bash
docker compose -f docker/docker-compose.yml up -d postgres
```

Wait for PostgreSQL to be ready:

```bash
docker compose -f docker/docker-compose.yml logs -f postgres
# Wait until you see: "database system is ready to accept connections"
# Press Ctrl+C to exit logs
```

### 5. Run Database Migrations

Migrations run automatically on first API startup, or you can run them manually:

```bash
cargo run -p idp-api
# The API will apply migrations on startup
```

### 6. Verify Installation

Check that the API is running:

```bash
# Health check
curl http://localhost:8080/health

# OpenAPI documentation
open http://localhost:8080/swagger-ui/
```

Test authentication:

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Tenant-Id: 00000000-0000-0000-0000-000000000001" \
  -d '{"email":"admin@test.xavyo.com","password":"Test123!"}'
```

## Docker Compose Services

The `docker/docker-compose.yml` file includes:

| Service | Port | Description |
|---------|------|-------------|
| postgres | 5432 | PostgreSQL 15 database |
| kafka | 9092 | Apache Kafka (optional) |
| zookeeper | 2181 | Zookeeper for Kafka |

### Start All Services

```bash
docker compose -f docker/docker-compose.yml up -d
```

### Start Only PostgreSQL

```bash
docker compose -f docker/docker-compose.yml up -d postgres
```

### View Logs

```bash
docker compose -f docker/docker-compose.yml logs -f
```

### Stop Services

```bash
docker compose -f docker/docker-compose.yml down
```

### Reset Database

```bash
docker compose -f docker/docker-compose.yml down -v
docker compose -f docker/docker-compose.yml up -d postgres
```

## Development Workflow

### Build

```bash
cargo build --workspace
```

### Run Tests

```bash
cargo test --workspace
```

### Run with Hot Reload

Install `cargo-watch` for automatic recompilation:

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
cargo fmt --all
```

## Troubleshooting

### Database Connection Failed

```
Error: Failed to connect to database
```

**Solution**: Ensure PostgreSQL is running and the `DATABASE_URL` is correct.

```bash
docker compose -f docker/docker-compose.yml ps
docker compose -f docker/docker-compose.yml logs postgres
```

### JWT Key Error

```
Error: Failed to parse JWT private key
```

**Solution**: Ensure the key is properly formatted in `.env`. The entire key including `-----BEGIN/END-----` markers must be included.

### Port Already in Use

```
Error: Address already in use (os error 98)
```

**Solution**: Another process is using port 8080. Find and stop it:

```bash
lsof -i :8080
kill -9 <PID>
```

Or change the port in `.env`:

```bash
PORT=8081
```

### Permission Denied on Keys

```
Error: Permission denied reading private key
```

**Solution**: Fix file permissions:

```bash
chmod 600 keys/test-private.pem
chmod 644 keys/test-public.pem
```

## Next Steps

- Read the [API documentation](http://localhost:8080/swagger-ui/)
- Review [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines
- Check [docs/architecture.md](docs/architecture.md) for system architecture

## Support

- **Issues**: [GitHub Issues](https://github.com/xavyo/xavyo/issues)
- **Discussions**: [GitHub Discussions](https://github.com/xavyo/xavyo/discussions)
- **Security**: See [SECURITY.md](SECURITY.md) for reporting vulnerabilities
