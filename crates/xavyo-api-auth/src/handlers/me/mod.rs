//! Self-service profile handlers (F027).
//!
//! Handlers for /me/* endpoints allowing users to manage their own profile.
//!
//! - `profile` - GET/PUT /me/profile
//! - `email` - POST /me/email/change, POST /me/email/verify
//! - `security` - GET /me/security, GET /me/mfa
//! - `password` - PUT /me/password (delegates to existing handler)
//! - `shortcuts` - GET /me/sessions, GET /me/devices (aliases)

pub mod email;
pub mod password;
pub mod profile;
pub mod security;
pub mod shortcuts;

pub use email::{initiate_email_change, verify_email_change};
pub use password::me_password_change;
pub use profile::{get_profile, update_profile};
pub use security::{get_mfa_status, get_security_overview};
pub use shortcuts::{get_me_devices, get_me_sessions};
