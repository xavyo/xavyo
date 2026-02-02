//! SCIM 2.0 API for xavyo
//!
//! This crate implements the SCIM 2.0 protocol (RFC 7644) for automated
//! user and group provisioning from enterprise identity providers.
//!
//! # Features
//!
//! - User provisioning (create, read, update, delete)
//! - Group provisioning with membership management
//! - SCIM filter syntax parsing and SQL generation
//! - Bearer token authentication with tenant isolation
//! - Rate limiting (25 req/s per tenant)
//! - Comprehensive audit logging
//!
//! # Usage
//!
//! ```rust,ignore
//! use xavyo_api_scim::router;
//!
//! let scim_router = router::scim_router(app_state);
//! ```

pub mod error;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod router;
pub mod services;

pub use error::ScimError;
pub use router::{scim_admin_router, scim_resource_router, scim_router, ScimConfig};
