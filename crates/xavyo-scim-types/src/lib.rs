//! SCIM 2.0 (RFC 7643/7644) data-transfer objects.
//!
//! Shared between the SCIM server (`xavyo-api-scim`) and the SCIM outbound
//! client (`xavyo-scim-client`). Pure types: no DB, no HTTP, no business
//! logic. If you find yourself wanting to add `xavyo-db` or `xavyo-tenant`
//! here, you're in the wrong crate.

pub mod scim_group;
pub mod scim_response;
pub mod scim_user;

pub use scim_group::{
    CreateScimGroupRequest, ReplaceScimGroupRequest, ScimGroup, ScimGroupMember,
    XavyoGroupExtension,
};
pub use scim_response::{
    ScimGroupListResponse, ScimListResponse, ScimPagination, ScimPatchOp, ScimPatchRequest,
    ScimUserListResponse,
};
pub use scim_user::{
    CreateScimUserRequest, ReplaceScimUserRequest, ScimEmail, ScimMeta, ScimName, ScimUser,
    ScimUserGroup,
};
