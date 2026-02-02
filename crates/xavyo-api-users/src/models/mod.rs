//! Request and response models for the User Management API.

pub mod attribute_definitions;
pub mod group_hierarchy;
pub mod requests;
pub mod responses;

pub use attribute_definitions::{
    parse_custom_attr_filters, AttributeDefinitionListResponse, AttributeDefinitionResponse,
    BulkUpdateFailure, BulkUpdateFilter, BulkUpdateRequest, BulkUpdateResponse,
    CreateAttributeDefinitionRequest, CustomAttributeFilter, DeleteAttributeDefinitionQuery,
    FilterOperator, ListAttributeDefinitionsQuery, MissingAttributeAuditResponse,
    PatchCustomAttributesRequest, SeedWellKnownResponse, SeededAttribute,
    SetCustomAttributesRequest, SkippedAttribute, UpdateAttributeDefinitionRequest,
    UserCustomAttributesResponse, UserMissingAttributes, ValidationRules,
};
pub use group_hierarchy::{
    AncestorEntry, AncestorPathResponse, GroupDetail, GroupListResponse, HierarchyPaginationParams,
    ListGroupsQuery, MoveGroupRequest, Pagination, PaginationWithTotal, SubtreeEntry,
    SubtreeMember, SubtreeMembershipResponse, SubtreeResponse,
};
pub use requests::{CreateUserRequest, ListUsersQuery, UpdateUserRequest};
pub use responses::{LifecycleStateInfo, PaginationMeta, UserListResponse, UserResponse};
