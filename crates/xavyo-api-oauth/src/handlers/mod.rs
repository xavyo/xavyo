//! OAuth2/OIDC endpoint handlers.

pub mod admin_sessions;
pub mod authorize;
pub mod authorize_grant;
pub mod client_admin;
pub mod client_auth;
pub mod device;
pub mod device_login;
pub mod discovery;
pub mod introspection;
pub mod logout;
pub mod revocation;
pub mod token;
pub mod userinfo;

pub use admin_sessions::{
    admin_revoke_user_handler, delete_session_handler, list_active_sessions_handler,
};
pub use authorize::{authorize_handler, consent_handler};
pub use authorize_grant::{authorize_grant_handler, authorize_info_handler};
pub use client_admin::{
    create_client_handler, delete_client_handler, get_client_handler, list_clients_handler,
    regenerate_secret_handler, update_client_handler, RegenerateSecretResponse,
};
pub use client_auth::{
    authenticate_client, extract_client_credentials, extract_tenant_from_header,
};
pub use device::{
    check_device_authorization, device_authorization_handler, device_authorize_handler,
    device_confirm_handler, device_resend_confirmation_handler, device_verification_page_handler,
    device_verify_code_handler, exchange_device_code_for_tokens, ConfirmTokenPath,
    DeviceAuthorizationRequest, DeviceAuthorizationResponse, DeviceAuthorizeRequest,
    DeviceCodeErrorResponse, DeviceVerificationQuery, DeviceVerifyRequest,
    ResendConfirmationRequest, DEVICE_CODE_GRANT_TYPE,
};
pub use device_login::{
    device_login_handler, device_login_page_handler, device_mfa_handler, device_mfa_page_handler,
    get_user_from_session,
};
pub use discovery::{discovery_handler, jwks_handler};
pub use introspection::introspect_token_handler;
pub use logout::end_session_handler;
pub use revocation::revoke_token_handler;
pub use token::token_handler;
pub use userinfo::userinfo_handler;
