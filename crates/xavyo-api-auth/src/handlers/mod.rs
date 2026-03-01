//! HTTP handlers for authentication endpoints.
//!
//! Each handler corresponds to an authentication API endpoint:
//! - `register_handler` - POST /auth/register
//! - `login_handler` - POST /auth/login
//! - `refresh_handler` - POST /auth/refresh
//! - `logout_handler` - POST /auth/logout
//! - `forgot_password_handler` - POST /auth/forgot-password
//! - `reset_password_handler` - POST /auth/reset-password
//! - `verify_email_handler` - POST /auth/verify-email
//! - `resend_verification_handler` - POST /auth/resend-verification
//! - Session handlers: list, revoke, `revoke_all`, policy
//! - Admin handlers: password policy, lockout policy, unlock user
//! - Password change handler
//! - Audit handlers: login history, admin audit (F025)
//! - Alert handlers: security alerts (F025)
//! - Device handlers: list, trust, rename, revoke (F026)
//! - Me handlers: profile, email change, security overview (F027)
//! - IP restriction handlers: settings, rules, validate (F028)
//! - Delegated admin handlers: permissions, templates, assignments, audit (F029)
//! - Branding handlers: visual branding, public branding (F030)

pub mod admin;
pub mod admin_invite;
pub mod alerts;
pub mod audit;
pub mod branding;
pub mod branding_assets;
pub mod delegated_admin;
pub mod devices;
pub mod email_templates;
pub mod forgot_password;
pub mod ip_restrictions;
pub mod key_management;
pub mod login;
pub mod logout;
pub mod me;
pub mod mfa;
pub mod password_change;
pub mod passwordless;
pub mod passwordless_policy;
pub mod public_branding;
pub mod refresh;
pub mod register;
pub mod resend_verification;
pub mod reset_password;
pub mod revocation;
pub mod session;
pub mod signup;
pub mod verify_email;

pub use admin::{
    // WebAuthn admin handlers (F032)
    admin_list_webauthn_credentials,
    admin_revoke_webauthn_credential,
    // Organization security policy handlers (F-066)
    create_org_policy,
    delete_org_policy,
    get_effective_org_policy,
    get_effective_user_policy,
    get_lockout_policy,
    get_mfa_policy,
    get_org_policy,
    get_password_policy,
    get_user_mfa_status,
    get_webauthn_policy,
    list_org_policies,
    admin_reset_password,
    unlock_user,
    update_lockout_policy,
    update_mfa_policy,
    update_password_policy,
    update_webauthn_policy,
    upsert_org_policy,
    validate_org_policy,
};
pub use alerts::{acknowledge_alert, get_security_alerts};
pub use audit::{get_admin_login_attempts, get_login_attempt_stats, get_login_history};
pub use branding::{get_branding, update_branding};
pub use branding_assets::{delete_asset, get_asset, list_assets, upload_asset};
pub use delegated_admin::{
    check_permission, create_assignment, create_role_template, delete_role_template,
    get_assignment, get_audit_log, get_permissions_by_category, get_role_template,
    get_user_permissions, list_assignments, list_permissions, list_role_templates,
    revoke_assignment, update_role_template,
};
pub use devices::{
    admin_list_user_devices, admin_revoke_device, get_device_policy, list_devices, rename_device,
    revoke_device, trust_device, untrust_device, update_device_policy,
};
pub use email_templates::{
    get_template, list_templates, preview_template, reset_template, update_template,
};
pub use forgot_password::forgot_password_handler;
pub use ip_restrictions::{
    create_ip_rule, delete_ip_rule, get_ip_rule, get_ip_settings, list_ip_rules, update_ip_rule,
    update_ip_settings, validate_ip,
};
pub use key_management::{
    list_keys_handler, revoke_key_handler as key_revoke_handler, rotate_key_handler,
};
pub use login::login_handler;
pub use logout::logout_handler;
pub use me::{
    get_me_devices, get_me_sessions, get_mfa_status as get_me_mfa_status, get_profile,
    get_security_overview, initiate_email_change, me_password_change, update_profile,
    verify_email_change,
};
pub use mfa::{
    // WebAuthn handlers (F032)
    delete_webauthn_credential,
    disable_mfa,
    finish_webauthn_authentication,
    finish_webauthn_registration,
    get_mfa_status,
    list_webauthn_credentials,
    regenerate_recovery_codes,
    setup_totp,
    start_webauthn_authentication,
    start_webauthn_registration,
    update_webauthn_credential,
    verify_recovery_code,
    verify_totp,
    verify_totp_setup,
};
pub use password_change::password_change_handler;
pub use passwordless::{
    request_email_otp_handler, request_magic_link_handler, verify_email_otp_handler,
    verify_magic_link_handler,
};
pub use passwordless_policy::{
    get_available_methods_handler, get_passwordless_policy_handler,
    update_passwordless_policy_handler,
};
pub use public_branding::get_public_branding;
pub use refresh::refresh_handler;
pub use register::register_handler;
pub use resend_verification::resend_verification_handler;
pub use reset_password::reset_password_handler;
pub use revocation::{revocation_router, revoke_token_handler, revoke_user_tokens_handler};
pub use session::{
    get_session_policy, list_sessions, revoke_all_sessions, revoke_session, update_session_policy,
};
pub use signup::{signup_handler, validate_display_name, validate_password_complexity};
pub use verify_email::verify_email_handler;

// Admin Invitation exports (F-ADMIN-INVITE)
pub use admin_invite::{
    accept_invitation_handler, cancel_invitation_handler, create_invitation_handler,
    list_invitations_handler, resend_invitation_handler, AdminInviteState,
};
