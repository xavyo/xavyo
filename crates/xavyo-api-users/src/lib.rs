//! User Management CRUD API for xavyo.
//!
//! This crate provides REST API endpoints for user management (admin only):
//! - List users (GET /users)
//! - Create user (POST /users)
//! - Get user (GET /users/:id)
//! - Update user (PUT /users/:id)
//! - Delete/deactivate user (DELETE /users/:id)
//!
//! All endpoints require authentication with "admin" role.
//!
//! # Example
//!
//! ```rust,ignore
//! use xavyo_api_users::router::users_router;
//! use axum::Router;
//!
//! let app = Router::new()
//!     .nest("/users", users_router(state));
//! ```

pub mod error;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod router;
pub mod services;
pub mod validation;

// Re-export public API
pub use error::{ApiUsersError, AttributeFieldError, ProblemDetails};
pub use models::{
    parse_custom_attr_filters, AncestorEntry, AncestorPathResponse,
    AttributeDefinitionListResponse, AttributeDefinitionResponse, BulkUpdateFailure,
    BulkUpdateFilter, BulkUpdateRequest, BulkUpdateResponse, CreateAttributeDefinitionRequest,
    CreateUserRequest, CustomAttributeFilter, DeleteAttributeDefinitionQuery, FilterOperator,
    GroupDetail, GroupListResponse, HierarchyPaginationParams, LifecycleStateInfo,
    ListAttributeDefinitionsQuery, ListGroupsQuery, ListUsersQuery, MissingAttributeAuditResponse,
    MoveGroupRequest, Pagination, PaginationMeta, PaginationWithTotal,
    PatchCustomAttributesRequest, SetCustomAttributesRequest, SubtreeEntry, SubtreeMember,
    SubtreeMembershipResponse, SubtreeResponse, UpdateAttributeDefinitionRequest,
    UpdateUserRequest, UserCustomAttributesResponse, UserListResponse, UserMissingAttributes,
    UserResponse, ValidationRules,
};
pub use router::{
    attribute_definitions_router, bulk_operations_router, groups_router, users_router, UsersState,
};
pub use services::{
    AttributeAuditService, AttributeDefinitionService, AttributeValidationService,
    GroupHierarchyService, UserAttributeService, UserService,
};
