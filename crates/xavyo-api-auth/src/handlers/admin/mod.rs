//! Admin handlers for tenant management.
//!
//! Includes:
//! - Password policy management (GET/PUT /admin/tenants/:tenant_id/password-policy)
//! - Lockout policy management (GET/PUT /admin/tenants/:tenant_id/lockout-policy)
//! - MFA policy management (GET/PUT /admin/tenants/:tenant_id/mfa-policy)
//! - `WebAuthn` policy management (GET/PUT /admin/tenants/:tenant_id/webauthn-policy) (F032)
//! - User unlock (POST /`admin/users/:user_id/unlock`)
//! - Organization security policies (F-066)

pub mod lockout_policy;
pub mod mfa_policy;
pub mod org_security_policy;
pub mod password_policy;
pub mod unlock_user;
pub mod user_mfa_status;
pub mod webauthn_policy;

pub use lockout_policy::{get_lockout_policy, update_lockout_policy};
pub use mfa_policy::{get_mfa_policy, update_mfa_policy};
pub use org_security_policy::{
    create_org_policy, delete_org_policy, get_effective_org_policy, get_effective_user_policy,
    get_org_policy, list_org_policies, upsert_org_policy, validate_org_policy,
};
pub use password_policy::{get_password_policy, update_password_policy};
pub use unlock_user::unlock_user;
pub use user_mfa_status::get_user_mfa_status;
pub use webauthn_policy::{
    admin_list_user_credentials as admin_list_webauthn_credentials,
    admin_revoke_credential as admin_revoke_webauthn_credential, get_webauthn_policy,
    update_webauthn_policy,
};
