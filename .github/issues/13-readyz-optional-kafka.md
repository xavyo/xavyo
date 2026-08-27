**Epic:** #98 · **Phase:** 3 — Ops

## Problem

`/readyz` should reflect only **required** dependencies. If Kafka is optional (no `KAFKA_BOOTSTRAP_SERVERS`), readiness should not fail when Kafka is unreachable.

There is a TODO in `apps/idp-api/src/main.rs`:

```rust
// TODO(F074): Wire Kafka health callback once xavyo-events exposes a health check method.
```

## Proposed solution

1. Define required vs optional dependencies in `HealthCheckConfig`
2. `/readyz` checks: Postgres (required), Kafka (only if configured)
3. Add test: no Kafka env → readyz passes without Kafka running

## Acceptance criteria

- [ ] Minimal docker compose (postgres + mailpit only) → `/readyz` 200
- [ ] Kafka configured but down → readyz reflects degraded/unhealthy per design
- [ ] Documented in ops runbook

## Files

- `apps/idp-api/src/health.rs`
- `apps/idp-api/src/config.rs`
