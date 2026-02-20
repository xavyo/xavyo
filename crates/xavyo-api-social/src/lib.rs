//! Social authentication API library for xavyo.
//!
//! This crate provides social login functionality via Google, Microsoft (Azure AD),
//! and Apple identity providers. It handles OAuth2/OIDC flows, account linking,
//! and encrypted token storage.
//!
//! # Features
//!
//! - **Multi-provider support**: Google, Microsoft, Apple
//! - **Secure token storage**: AES-256-GCM encryption with per-tenant keys
//! - **Account linking**: Automatic detection and linking of existing accounts
//! - **CSRF protection**: Signed JWT state parameter
//! - **PKCE support**: Enhanced security for Google, Microsoft, Apple (GitHub lacks PKCE support)
//! - **Multi-tenant**: Per-tenant provider configuration
//!
//! # Example
//!
//! ```rust,ignore
//! use xavyo_api_social::router::social_router;
//!
//! let app = Router::new()
//!     .nest("/auth/social", social_router(state.clone()));
//! ```

pub mod error;
pub mod extractors;
pub mod handlers;
pub mod models;
pub mod providers;
pub mod router;
pub mod services;

pub use error::{ProviderType, SocialError, SocialResult};
pub use router::{
    admin_social_router, authenticated_social_router, public_social_router, social_router,
    AuthService, SocialConfig, SocialState,
};
