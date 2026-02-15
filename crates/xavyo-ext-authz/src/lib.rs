//! Envoy ext_authz v3 gRPC server for AgentGateway ↔ Xavyo-IDP integration.
//!
//! Implements the `envoy.service.auth.v3.Authorization/Check` RPC to serve as
//! the identity and authorization brain for AgentGateway.

pub mod activity;
pub mod config;
pub mod error;
pub mod nhi_cache;
pub mod request;
pub mod response;
pub mod server;

/// Generated protobuf types for `envoy.service.auth.v3`.
#[allow(
    clippy::all,
    clippy::pedantic,
    non_camel_case_types,
    unused_imports,
    missing_docs
)]
pub mod proto {
    tonic::include_proto!("envoy.service.auth.v3");
}
