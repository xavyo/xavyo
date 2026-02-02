//! Device management handlers (F026).

pub mod admin_devices;
pub mod user_devices;

pub use user_devices::{list_devices, rename_device, revoke_device, trust_device, untrust_device};

pub use admin_devices::{
    admin_list_user_devices, admin_revoke_device, get_device_policy, update_device_policy,
};
