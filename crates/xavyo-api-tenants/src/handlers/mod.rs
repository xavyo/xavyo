//! HTTP handlers for tenant provisioning API.

pub mod api_keys;
pub mod delete;
pub mod invitations;
pub mod oauth_clients;
pub mod plan;
pub mod provision;
pub mod settings;
pub mod suspend;
pub mod usage;

pub use api_keys::{
    create_api_key_handler, deactivate_api_key_handler, get_api_key_usage_handler,
    introspect_api_key_handler, list_api_keys_handler, rotate_api_key_handler,
};
pub use delete::{delete_tenant_handler, list_deleted_tenants_handler, restore_tenant_handler};
// F-057: Tenant Invitations
pub use invitations::{
    accept_invitation_handler, cancel_invitation_handler, create_invitation_handler,
    list_invitations_handler,
};
pub use oauth_clients::{
    deactivate_oauth_client_handler, list_oauth_clients_handler, rotate_oauth_secret_handler,
};
pub use plan::{
    cancel_downgrade_handler, downgrade_plan_handler, get_plan_history_handler, list_plans_handler,
    upgrade_plan_handler,
};
pub use provision::provision_handler;
pub use settings::{
    get_settings_handler, get_tenant_user_settings_handler, update_settings_handler,
    update_tenant_user_settings_handler,
};
pub use suspend::{get_tenant_status_handler, reactivate_tenant_handler, suspend_tenant_handler};
pub use usage::{get_tenant_usage_handler, get_tenant_usage_history_handler};
