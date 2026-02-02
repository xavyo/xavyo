//! Active Directory specific modules
//!
//! Extends the base LDAP connector with AD-specific capabilities:
//! - userAccountControl bitfield parsing
//! - uSNChanged-based incremental sync
//! - Nested group resolution
//! - Outbound provisioning with unicodePwd support
//! - AD-specific schema definitions

pub mod connector;
pub mod groups;
pub mod password;
pub mod schema;
pub mod sync;
pub mod user_account_control;

// Re-export key types
pub use connector::{AdConnector, AdServerInfo, ConnectionTestResult};
pub use groups::{
    build_group_sync_result, compute_membership_diff, group_sync_attributes, highest_group_usn,
    map_ad_group, mapped_group_to_sync_change, resolve_nested_members, MappedGroup, MembershipDiff,
    NestedGroupResult,
};
pub use password::{
    build_password_change, build_password_modify, build_user_dn, encode_ad_password,
    map_platform_to_ad_attributes, new_account_uac, validate_password_connection,
};
pub use schema::{ad_default_schema, ad_group_object_class, ad_user_object_class, group_type};
pub use sync::{
    build_dn_lookup, build_sync_result, highest_usn, map_ad_user, mapped_user_to_sync_change,
    process_user_batch_resilient, resolve_manager_references, user_sync_attributes, AdRetryConfig,
    AdSyncStatistics, ManagerResolutionResult, MappedUser, SyncRecordError, UsnCheckpoint,
};
pub use user_account_control::UserAccountControl;
