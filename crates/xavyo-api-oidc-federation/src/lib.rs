//! OIDC Federation API for xavyo.
//!
//! This crate provides external Identity Provider federation via OIDC,
//! enabling tenants to connect their existing `IdPs` (Azure AD, Okta, Google Workspace, etc.)
//! for federated single sign-on.
//!
//! # Features
//!
//! - **Multi-provider support**: Azure AD, Okta, Google Workspace, any OIDC-compliant `IdP`
//! - **Home Realm Discovery**: Automatic `IdP` routing based on email domain
//! - **Just-In-Time provisioning**: Automatic user creation from `IdP` claims
//! - **Claim mapping**: Configurable mapping from `IdP` claims to Xavyo attributes
//! - **Secure by design**: PKCE, encrypted secrets, signed state, audit logging
//!
//! # Example
//!
//! ```rust,ignore
//! use xavyo_api_oidc_federation::router::{federation_router, FederationState};
//!
//! let state = FederationState::new(pool, auth_service, config);
//! let app = Router::new()
//!     .nest("/api/v1", federation_router(state.clone()));
//! ```

pub mod error;
pub mod handlers;
pub mod models;
pub mod router;
pub mod services;

pub use error::{FederationError, FederationResult};
pub use router::{
    admin_routes, auth_routes, create_federation_router, FederationConfig, FederationState,
};
