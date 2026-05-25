# xavyo-api-ssf

> OpenID Shared Signals Framework (SSF 1.0) Transmitter API: stream management, transmitter metadata, and the push delivery of CAEP Security Event Tokens.

## Purpose

The HTTP surface that lets relying parties (receivers) register and manage SSF streams (SSF 1.0 §8) and discover the transmitter's configuration (§7). When an application flow emits a CAEP signal, this crate signs it via `xavyo-ssf` and pushes the resulting Security Event Token to each subscribed receiver's endpoint — with an SSRF guard that refuses private/loopback/link-local destinations and re-checks the resolved IP at delivery time (DNS-rebinding defence).

Stream/subject storage lives in `xavyo-db` (`ssf_streams` / `ssf_subjects`); the SET construction and signing live in `xavyo-ssf`. This crate is the wiring: tenant-scoped handlers, the push transmitter, and a `CaepEmitter` implementation backed by it.

## Layer

api

## Status

🔴 **alpha**

20 unit tests (SSRF guard, model serialization, transmitter SET building, poll token hashing/parsing). Push (RFC 8935) + poll (RFC 8936) delivery, the poll-queue TTL bound, and stream-verification events (SSF §7.1.4) are all implemented (the verification event payload is tested in `xavyo-ssf`). No HTTP+Postgres integration tests yet — API will change.

## Dependencies

### Internal (xavyo)
- `xavyo-ssf` — SET builder/signer, `CaepEmitter`, subject identifiers
- `xavyo-auth` — JWT claims for tenant extraction
- `xavyo-core` — `TenantId` and shared error types
- `xavyo-db` — stream/subject persistence

### External (key)
- `axum` — HTTP routing and extractors
- `reqwest` — push delivery to receiver endpoints
- `serde` / `serde_json` — request/response models
- `utoipa` — OpenAPI schema

## Public API

### Routers

```rust
/// Stream management (SSF §8). Mount at `/ssf` behind auth + Extension<TenantId>.
///   POST/GET  /streams          create / list streams
///   GET/DELETE /stream          read / delete a stream
///   GET/POST  /status           stream status
///   POST      /subjects:add     add a subject to a stream
///   POST      /subjects:remove  remove a subject from a stream
///   POST      /verify           request a stream-verification event (SSF §7.1.4)
pub fn ssf_router() -> Router<SsfState>;

/// Poll-based delivery (RFC 8936). Receiver-facing — authenticates with the
/// per-stream bearer token, NOT the tenant JWT. Mount at `/ssf` OUTSIDE the
/// tenant-auth middleware (e.g. `ssf_router(...).layer(auth).merge(ssf_poll_router(...))`).
///   POST /poll   ack the prior batch + pull queued SETs (jti -> JWS)
pub fn ssf_poll_router(state: SsfState) -> Router;

/// Transmitter metadata (SSF §7). Mount at `/.well-known`.
///   GET /.well-known/ssf-configuration
pub fn ssf_well_known_router() -> Router<SsfState>;
```

### Types

```rust
/// Shared state for the SSF handlers (DB pool, transmitter, issuer).
pub struct SsfState { /* ... */ }

/// Signs (via xavyo-ssf) and pushes SETs to receiver endpoints.
pub struct SsfTransmitter { /* ... */ }

/// A `CaepEmitter` impl that fans a signal out to the tenant's streams.
pub struct SsfStreamEmitter { /* ... */ }

/// Push delivery failures (network, non-2xx, SSRF rejection).
pub enum DeliveryError { /* ... */ }

/// API-edge error type (tenant-safe messages).
pub enum SsfApiError { /* ... */ }
```

### SSRF guard

```rust
/// True only for globally-routable addresses (not private/loopback/link-local/CGNAT).
pub fn is_public_ip(ip: IpAddr) -> bool;

/// Reject a receiver URL that is non-HTTPS or resolves to a non-public address.
pub fn validate_receiver_url(raw: &str) -> Result<(), SsfApiError>;
```

## Usage Example

```rust
use xavyo_api_ssf::{ssf_router, ssf_well_known_router, SsfState, SsfTransmitter};

let transmitter = SsfTransmitter::new(pool.clone(), signing_key, kid, issuer.clone());
let state = SsfState::new(pool, transmitter, issuer);

let app = Router::new()
    .nest("/ssf", ssf_router().layer(/* JWT auth + Extension<TenantId> */))
    .merge(ssf_well_known_router())
    .with_state(state);
```

`SsfStreamEmitter` is injected (as `Arc<dyn CaepEmitter>`) into `xavyo-api-auth`'s session and password services, so a logout or password change automatically pushes the corresponding CAEP SET to every subscribed receiver.

## Integration Points

- **Consumed by**: `apps/idp-api` (mounts both routers; injects `SsfStreamEmitter` into the auth services).
- **Provides**: SSF stream management API, `/.well-known/ssf-configuration`, and push delivery of CAEP signals.
- **Requires**: the IdP RSA signing key (for SETs), a Postgres pool, and a tenant context on every stream request.

## Feature Flags

- `integration` — gates Postgres-backed integration tests (none yet; reserved).

## Anti-Patterns

- Never deliver to a receiver URL without re-validating the resolved IP at send time — DNS can rebind between registration and delivery.
- Never accept a plain-HTTP receiver endpoint; SSF push requires TLS.
- Never run a stream query without the request's `tenant_id` — streams are tenant-scoped (RLS + explicit `WHERE`).
- Never block the emitting request on delivery; the transmitter is fire-and-forget.

## Related Crates

- `xavyo-ssf` — SET signing, CAEP events, subject identifiers, `CaepEmitter`
- `xavyo-api-auth` — session/credential flows that emit signals through this transmitter
- `xavyo-webhooks` — the other outbound event-delivery surface (generic webhooks vs. standardized SETs)
