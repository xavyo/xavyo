//! OpenID Shared Signals Framework (SSF) Transmitter API for xavyo.
//!
//! HTTP surface for managing SSF streams (OpenID SSF 1.0 §8) and publishing the
//! transmitter configuration metadata (§7). The signed Security Event Tokens
//! themselves are built by [`xavyo_ssf`]; storage lives in `xavyo-db`
//! (`ssf_streams` / `ssf_subjects`). The push transmitter + emission hooks are a
//! later increment.
//!
//! Mount:
//! - [`router::ssf_router`] at `/ssf` (behind auth + `Extension<TenantId>`)
//! - [`router::ssf_well_known_router`] at `/.well-known`

pub mod error;
pub mod handlers;
pub mod models;
pub mod router;
/// SSRF guard for receiver endpoints.
pub mod ssrf;

pub use error::SsfApiError;
pub use handlers::SsfState;
pub use router::{ssf_router, ssf_well_known_router};
