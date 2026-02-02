//! Middleware components for OAuth2/OIDC API.

pub mod session_cookie;

pub use session_cookie::{
    clear_session_cookie, create_session_cookie, extract_session_cookie, set_session_cookie,
    SESSION_COOKIE_MAX_AGE, SESSION_COOKIE_NAME,
};
