//! Proxy components for backend communication.

pub mod client;
pub mod router;

pub use client::ProxyClient;
pub use router::BackendRouter;
