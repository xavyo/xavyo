//! User Management API router configuration.
//!
//! Configures routes for user management endpoints:
//! - GET /users - List users (with pagination and search)
//! - POST /users - Create a new user
//! - GET /users/:id - Get user details
//! - PUT /users/:id - Update user
//! - DELETE /users/:id - Deactivate user (soft delete)
//!
//! And attribute definition endpoints (F070):
//! - POST /attribute-definitions - Create definition
//! - GET /attribute-definitions - List definitions
//! - GET /attribute-definitions/:id - Get definition
//! - PUT /attribute-definitions/:id - Update definition
//! - DELETE /attribute-definitions/:id - Delete definition

use crate::handlers::{
    audit_missing_required_attributes, bulk_update_custom_attribute, create_attribute_definition,
    create_user_handler, delete_attribute_definition, delete_user_handler, get_ancestors,
    get_attribute_definition, get_children, get_subtree, get_subtree_members,
    get_user_custom_attributes, get_user_handler, list_attribute_definitions, list_groups,
    list_root_groups, list_users_handler, move_group, patch_user_custom_attributes, seed_wellknown,
    set_user_custom_attributes, update_attribute_definition, update_user_handler,
};
use crate::middleware::admin_guard;
use crate::services::{
    AttributeAuditService, AttributeDefinitionService, GroupHierarchyService, UserAttributeService,
    UserService,
};
use axum::{
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use sqlx::PgPool;
use std::sync::Arc;

/// Application state for user management routes.
#[derive(Clone)]
pub struct UsersState {
    /// Database connection pool.
    pub pool: PgPool,
    /// User service for CRUD operations.
    pub user_service: Arc<UserService>,
    /// Attribute definition service for custom attribute schema management (F070).
    pub attribute_definition_service: Arc<AttributeDefinitionService>,
    /// User attribute service for custom attribute storage/retrieval (F070).
    pub user_attribute_service: Arc<UserAttributeService>,
    /// Attribute audit service for compliance auditing (F070).
    pub attribute_audit_service: Arc<AttributeAuditService>,
    /// Group hierarchy service for org hierarchy management (F071).
    pub group_hierarchy_service: Arc<GroupHierarchyService>,
}

impl UsersState {
    /// Create a new users state.
    pub fn new(pool: PgPool) -> Self {
        let user_service = Arc::new(UserService::new(pool.clone()));
        let attribute_definition_service = Arc::new(AttributeDefinitionService::new(pool.clone()));
        let user_attribute_service = Arc::new(UserAttributeService::new(pool.clone()));
        let attribute_audit_service = Arc::new(AttributeAuditService::new(pool.clone()));
        let group_hierarchy_service = Arc::new(GroupHierarchyService::new(pool.clone()));
        Self {
            pool,
            user_service,
            attribute_definition_service,
            user_attribute_service,
            attribute_audit_service,
            group_hierarchy_service,
        }
    }
}

/// Create the user management router with all endpoints.
///
/// # Endpoints
///
/// All endpoints require authentication with "admin" role.
///
/// - `GET /users` - List users with pagination and email filter
/// - `POST /users` - Create a new user
/// - `GET /users/:id` - Get user details
/// - `PUT /users/:id` - Update user
/// - `DELETE /users/:id` - Deactivate user (soft delete)
///
/// # Arguments
///
/// * `state` - The users state containing services
///
/// # Returns
///
/// A configured Axum router for the `/users` prefix.
pub fn users_router(state: UsersState) -> Router {
    Router::new()
        // US1: List users
        .route("/", get(list_users_handler))
        // US2: Create user
        .route("/", post(create_user_handler))
        // US3: Get user
        .route("/:id", get(get_user_handler))
        // US4: Update user
        .route("/:id", put(update_user_handler))
        // US5: Delete (deactivate) user
        .route("/:id", delete(delete_user_handler))
        // F070: User custom attributes
        .route(
            "/:id/custom-attributes",
            get(get_user_custom_attributes)
                .put(set_user_custom_attributes)
                .patch(patch_user_custom_attributes),
        )
        // Admin guard middleware requires "admin" role in JWT claims
        .layer(middleware::from_fn(admin_guard))
        .layer(axum::Extension(state.user_service))
        .layer(axum::Extension(state.attribute_definition_service.clone()))
        .layer(axum::Extension(state.user_attribute_service))
        .layer(axum::Extension(state.pool))
}

/// Create the bulk operations router (F070 - US4).
///
/// # Endpoints
///
/// All endpoints require authentication with "admin" role.
///
/// - `POST /custom-attributes/bulk-update` - Bulk update a custom attribute
pub fn bulk_operations_router(state: UsersState) -> Router {
    Router::new()
        .route("/bulk-update", post(bulk_update_custom_attribute))
        .layer(middleware::from_fn(admin_guard))
        .layer(axum::Extension(state.user_attribute_service))
        .layer(axum::Extension(state.pool))
}

/// Create the attribute definition router (F070).
///
/// # Endpoints
///
/// All endpoints require authentication with "admin" role.
///
/// - `POST /attribute-definitions` - Create an attribute definition
/// - `GET /attribute-definitions` - List attribute definitions
/// - `GET /attribute-definitions/:id` - Get an attribute definition
/// - `PUT /attribute-definitions/:id` - Update an attribute definition
/// - `DELETE /attribute-definitions/:id` - Delete an attribute definition
/// - `GET /attribute-definitions/audit/missing-required` - Audit users missing required attributes
/// - `POST /attribute-definitions/seed-wellknown` - Seed well-known enterprise attributes (F081)
pub fn attribute_definitions_router(state: UsersState) -> Router {
    Router::new()
        .route("/", post(create_attribute_definition))
        .route("/", get(list_attribute_definitions))
        .route(
            "/audit/missing-required",
            get(audit_missing_required_attributes),
        )
        // F081: Seed well-known attributes (MUST be before /:id to avoid path capture)
        .route("/seed-wellknown", post(seed_wellknown))
        .route("/:id", get(get_attribute_definition))
        .route("/:id", put(update_attribute_definition))
        .route("/:id", delete(delete_attribute_definition))
        .layer(middleware::from_fn(admin_guard))
        .layer(axum::Extension(state.attribute_definition_service))
        .layer(axum::Extension(state.attribute_audit_service))
        .layer(axum::Extension(state.pool))
}

/// Create the group hierarchy router (F071).
///
/// # Endpoints
///
/// All endpoints require authentication with "admin" role.
///
/// - `GET /groups` - List groups with optional type filter
/// - `GET /groups/roots` - List root groups (no parent)
/// - `GET /groups/:group_id/children` - List direct children
/// - `GET /groups/:group_id/ancestors` - Get ancestor path
/// - `GET /groups/:group_id/subtree` - Get full subtree
/// - `GET /groups/:group_id/subtree-members` - Get all users in subtree
/// - `PUT /groups/:group_id/parent` - Move group to new parent
pub fn groups_router(state: UsersState) -> Router {
    Router::new()
        // IMPORTANT: Register /roots BEFORE /:group_id to prevent path capture
        .route("/roots", get(list_root_groups))
        .route("/", get(list_groups))
        .route("/:group_id/parent", put(move_group))
        .route("/:group_id/children", get(get_children))
        .route("/:group_id/ancestors", get(get_ancestors))
        .route("/:group_id/subtree", get(get_subtree))
        .route("/:group_id/subtree-members", get(get_subtree_members))
        .layer(middleware::from_fn(admin_guard))
        .layer(axum::Extension(state.group_hierarchy_service))
        .layer(axum::Extension(state.pool))
}

#[cfg(test)]
mod tests {
    // Router tests require database setup
    // These are placeholder tests for the module structure

    #[test]
    fn users_state_creation() {
        // This test verifies the UsersState struct can be created
        // Full testing requires database connections
    }
}
