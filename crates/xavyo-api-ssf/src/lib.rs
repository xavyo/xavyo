//! OpenID Shared Signals Framework (SSF) Transmitter API for xavyo.
//!
//! HTTP surface for managing SSF streams (OpenID SSF 1.0 §8) and publishing the
//! transmitter configuration metadata (§7). The signed Security Event Tokens
//! themselves are built by [`xavyo_ssf`]; storage lives in `xavyo-db`
//! (`ssf_streams` / `ssf_subjects`). The push [`transmitter`] signs and delivers
//! SETs (with an SSRF/DNS-rebinding guard), and [`emitter::SsfStreamEmitter`]
//! implements `CaepEmitter` so application flows fan signals out to a tenant's
//! streams. Poll-based delivery (RFC 8936) is in [`poll`]; verification events
//! are a later increment.
//!
//! Mount:
//! - [`router::ssf_router`] at `/ssf` (behind auth + `Extension<TenantId>`)
//! - [`poll::ssf_poll_router`] at `/ssf` (receiver-facing; per-stream bearer
//!   token auth — mount OUTSIDE the tenant-auth middleware)
//! - [`router::ssf_well_known_router`] at `/.well-known`

/// `CaepEmitter` impl backed by the push transmitter.
pub mod emitter;
pub mod error;
pub mod handlers;
pub mod models;
/// Poll-based delivery (RFC 8936): per-stream bearer-token auth + poll endpoint.
pub mod poll;
pub mod router;
/// SSRF guard for receiver endpoints.
pub mod ssrf;
/// Push transmitter (signs + delivers SETs).
pub mod transmitter;

pub use emitter::SsfStreamEmitter;
pub use error::SsfApiError;
pub use handlers::SsfState;
pub use poll::ssf_poll_router;
pub use router::{ssf_router, ssf_well_known_router};
pub use transmitter::{DeliveryError, SsfTransmitter};
