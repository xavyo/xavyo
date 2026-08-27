# First Production Deployment

Operational guide for deploying xavyo IDP beyond local development. See also [INSTALL.md](../../INSTALL.md) for Docker quick start.

## Pre-flight checklist

- [ ] `APP_ENV=production`
- [ ] Strong unique values for all encryption keys (no docker-compose defaults)
- [ ] JWT keys generated (`openssl genpkey` or `bash docker/generate-keys.sh`)
- [ ] `POSTGRES_PASSWORD` and `DATABASE_URL` use strong credentials
- [ ] `APP_DATABASE_URL` configured for RLS-enforced app user (recommended)
- [ ] SMTP configured and tested
- [ ] `CORS_ORIGINS` lists explicit frontend URLs (no `*`)
- [ ] `ISSUER_URL` and `FRONTEND_URL` match public HTTPS URLs
- [ ] Health probes configured: `/livez`, `/readyz`, `/metrics`
- [ ] Backup strategy for PostgreSQL in place

## Secrets inventory

| Variable | Purpose | Generate |
|----------|---------|----------|
| `JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY` | Access token signing | `bash docker/generate-keys.sh` |
| `CSRF_SECRET` | OAuth consent CSRF | `openssl rand -hex 32` |
| `SOCIAL_ENCRYPTION_KEY` | OAuth token storage | `openssl rand -base64 32` |
| `SAML_ENCRYPTION_KEY` | IdP private keys | `openssl rand -hex 32` |
| `FEDERATION_ENCRYPTION_KEY` | OIDC federation secrets | `openssl rand -hex 32` |
| `MFA_ENCRYPTION_KEY` | TOTP secrets | `openssl rand -hex 32` |
| `CONNECTOR_ENCRYPTION_KEY` | Connector credentials | `openssl rand -hex 32` |
| `WEBHOOK_ENCRYPTION_KEY` | Webhook secrets | `openssl rand -hex 32` |
| `XAVYO_SIEM_ENCRYPTION_KEY` | SIEM destination credentials | `openssl rand -base64 32` |
| `XAVYO_TICKETING_ENCRYPTION_KEY` | Ticketing integration credentials | `openssl rand -base64 32` |
| `ADMIN_PASSWORD` | Bootstrap admin (first start only) | `openssl rand -base64 24` |
| `POSTGRES_PASSWORD` | Database | `openssl rand -base64 24` |

`validate_security_config()` rejects known insecure defaults when `APP_ENV=production`.

## PostgreSQL

- Use managed Postgres 15+ with daily backups and point-in-time recovery where available.
- Run init schema via application migrations on first `idp-api` start.
- Create a non-superuser `xavyo_app` role for `APP_DATABASE_URL` so RLS policies apply to API queries.
- Connection pooling: size pools to expected concurrency (default app pool: 10).

## JWT rotation

Set `JWT_SIGNING_KEYS` JSON array for multi-key rotation. Retired keys remain in JWKS until tokens expire.

## Upgrade procedure

1. Take a Postgres backup/snapshot.
2. Deploy new `idp-api` image (migrations run automatically on startup).
3. Verify `GET /readyz` returns `healthy`.
4. Smoke test admin login.
5. Roll back by redeploying previous image if migrations are backward-compatible; otherwise restore DB snapshot.

## Health monitoring

| Endpoint | Purpose |
|----------|---------|
| `GET /livez` | Process alive (restart if fails) |
| `GET /readyz` | Ready for traffic (DB required; Kafka only if `KAFKA_BOOTSTRAP_SERVERS` set) |
| `GET /health` | Detailed health JSON |
| `GET /metrics` | Prometheus metrics |

Alert on: `readyz` unhealthy > 2 min, DB check failures, elevated 5xx rate.

## Incident basics

- **Tenant suspension**: use admin API or database `tenants` status field per your runbook.
- **Admin lockout**: set `ADMIN_EMAIL` / `ADMIN_PASSWORD` and restart API (bootstrap is idempotent), or reset password via DB with Argon2 hash.
- **Kafka optional**: omit `KAFKA_BOOTSTRAP_SERVERS` for deployments without event streaming; `/readyz` stays healthy with Postgres + Mailpit/SMTP only.

## Distribution paths

- **Source + compose**: `docker/docker-compose.yml`
- **Standalone**: `docker/docker-compose.dist.yml` (GHCR image `ghcr.io/xavyo/xavyo-idp`)

See `docker/.env.dist.example` for production env template.
