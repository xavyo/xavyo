//! Tenant Provisioning API for xavyo.
//!
//! Provides self-service tenant provisioning endpoints that enable authenticated
//! users to create their own isolated tenants.
//!
//! ## Features
//!
//! - **POST /tenants/provision**: Create a new tenant with admin user, API key,
//!   OAuth client, and default security policies
//!
//! ## Authentication
//!
//! Provisioning requires authentication against the system tenant. Users must first
//! authenticate via device code flow or other OAuth methods against the system tenant
//! before they can provision their own tenant.
//!
//! ## Rate Limiting
//!
//! The provisioning endpoint is rate limited to 10 requests per IP per hour to
//! prevent abuse.

pub mod error;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod router;
pub mod services;

pub use error::TenantError;
pub use middleware::{
    provision_rate_limit_middleware, provision_rate_limiter, suspension_check_middleware,
    PROVISION_RATE_LIMIT_MAX, PROVISION_RATE_LIMIT_WINDOW_SECS,
};
pub use router::{api_keys_router, oauth_clients_router, system_admin_router, tenant_router};
