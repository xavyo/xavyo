//! SCIM schema models for API requests and responses.
//!
//! The actual DTOs live in `xavyo-scim-types` so that the outbound SCIM
//! client (`xavyo-scim-client`) can share them without taking a circular
//! dependency on this server crate. This module re-exports the types for
//! backwards compatibility with existing call sites in `xavyo-api-scim`.

pub use xavyo_scim_types::{
    CreateScimGroupRequest, CreateScimUserRequest, ReplaceScimGroupRequest, ReplaceScimUserRequest,
    ScimEmail, ScimGroup, ScimGroupListResponse, ScimGroupMember, ScimListResponse, ScimMeta,
    ScimName, ScimPagination, ScimPatchOp, ScimPatchRequest, ScimUser, ScimUserGroup,
    ScimUserListResponse, XavyoGroupExtension,
};
