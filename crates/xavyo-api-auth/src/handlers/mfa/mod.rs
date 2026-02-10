//! MFA (Multi-Factor Authentication) handlers.
//!
//! Endpoints for TOTP setup, verification, recovery codes, and `WebAuthn`.

pub mod disable;
pub mod recovery;
pub mod setup;
pub mod status;
pub mod verify;
pub mod verify_setup;
pub mod webauthn;

pub use disable::disable_mfa;
pub use recovery::{regenerate_recovery_codes, verify_recovery_code};
pub use setup::setup_totp;
pub use status::get_mfa_status;
pub use verify::verify_totp;
pub use verify_setup::verify_totp_setup;

// WebAuthn exports
pub use webauthn::{
    delete_webauthn_credential, finish_webauthn_authentication, finish_webauthn_registration,
    list_webauthn_credentials, start_webauthn_authentication, start_webauthn_registration,
    update_webauthn_credential,
};
