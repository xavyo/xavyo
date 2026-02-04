//! `WebAuthn` MFA handlers.
//!
//! Endpoints for WebAuthn/FIDO2 credential registration, authentication, and management.

pub mod authenticate;
pub mod credentials;
pub mod register;

pub use authenticate::{finish_webauthn_authentication, start_webauthn_authentication};
pub use credentials::{
    delete_webauthn_credential, list_webauthn_credentials, update_webauthn_credential,
};
pub use register::{finish_webauthn_registration, start_webauthn_registration};
