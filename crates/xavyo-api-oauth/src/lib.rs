//! OAuth2/OIDC Provider API for xavyo.
//!
//! This crate implements an `OAuth2` Authorization Server with `OpenID` Connect support.
//!
//! # Supported Grant Types
//!
//! - **Authorization Code + PKCE**: For web and mobile applications
//! - **Client Credentials**: For service-to-service authentication
//! - **Refresh Token**: For obtaining new access tokens
//! - **Device Code (RFC 8628)**: For CLI and headless applications
//!
//! # Endpoints
//!
//! ## OAuth2/OIDC Endpoints (mounted at /oauth)
//!
//! - `GET /oauth/authorize` - Authorization endpoint
//! - `POST /oauth/token` - Token endpoint (supports `device_code` grant)
//! - `GET /oauth/userinfo` - `UserInfo` endpoint
//! - `POST /oauth/device/code` - RFC 8628 Device Authorization endpoint
//!
//! ## Device Verification Endpoints (mounted at /device)
//!
//! - `GET /device` - Device verification page (enter user code)
//! - `POST /device/verify` - Verify user code
//! - `POST /device/authorize` - Authorize or deny device
//!
//! ## Well-Known Endpoints (mounted at /.well-known)
//!
//! - `GET /.well-known/openid-configuration` - OIDC Discovery
//! - `GET /.well-known/jwks.json` - JSON Web Key Set
//!
//! # Example
//!
//! ```rust,ignore
//! use xavyo_api_oauth::{oauth_router, device_router, well_known_router, OAuthState};
//! use axum::Router;
//!
//! let state = OAuthState::new(pool, issuer, private_key, public_key, key_id, csrf_secret);
//! let app = Router::new()
//!     .nest("/oauth", oauth_router(state.clone()))
//!     .nest("/device", device_router(state.clone()))
//!     .nest("/.well-known", well_known_router(state));
//! ```

pub mod csrf;
pub mod error;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod router;
pub mod services;
pub mod utils;

pub use error::OAuthError;
pub use middleware::{
    clear_session_cookie, create_session_cookie, extract_session_cookie, set_session_cookie,
    SESSION_COOKIE_MAX_AGE, SESSION_COOKIE_NAME,
};
pub use router::{
    device_router, oauth_router, user_oauth_router, well_known_router, OAuthSigningKey, OAuthState,
};
pub use utils::{extract_country_code, extract_origin_ip, UNKNOWN_COUNTRY};
