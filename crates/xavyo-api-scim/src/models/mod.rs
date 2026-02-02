//! SCIM schema models for API requests and responses.

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
