//! HTTP handlers for the User Management API.

pub mod attribute_audit;
pub mod attribute_definitions;
pub mod create;
pub mod delete;
pub mod get;
pub mod group_hierarchy;
pub mod list;
pub mod update;
pub mod user_custom_attributes;

pub use attribute_audit::audit_missing_required_attributes;
pub use attribute_definitions::{
    create_attribute_definition, delete_attribute_definition, get_attribute_definition,
    list_attribute_definitions, seed_wellknown, update_attribute_definition,
};
pub use create::create_user_handler;
pub use delete::delete_user_handler;
pub use get::get_user_handler;
pub use group_hierarchy::{
    get_ancestors, get_children, get_subtree, get_subtree_members, list_groups, list_root_groups,
    move_group,
};
pub use list::list_users_handler;
pub use update::update_user_handler;
pub use user_custom_attributes::{
    bulk_update_custom_attribute, get_user_custom_attributes, patch_user_custom_attributes,
    set_user_custom_attributes,
};
