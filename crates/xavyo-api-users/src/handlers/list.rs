//! List users endpoint handler.
//!
//! GET /users - List users with pagination, optional email filter, and custom attribute filters.

use crate::error::ApiUsersError;
use crate::models::{parse_custom_attr_filters, ListUsersQuery, UserListResponse};
use crate::services::UserService;
use axum::{
    extract::{Query, RawQuery},
    Extension, Json,
};
use std::sync::Arc;
use xavyo_auth::JwtClaims;

/// Lists users belonging to the authenticated admin's tenant.
///
/// Supports filtering by custom attributes using `custom_attr.{name}` query parameters:
/// - `custom_attr.department=Engineering` — equality filter
/// - `custom_attr.hire_date.lt=2024-01-01` — less-than filter
/// - `custom_attr.age.gte=18` — greater-than-or-equal filter
///
/// Multiple custom attribute filters are combined with AND logic.
#[utoipa::path(
    get,
    path = "/users",
    params(
        ListUsersQuery,
        ("custom_attr.*" = Option<String>, Query, description = "Filter by custom attribute values. Use custom_attr.{name} for equality, custom_attr.{name}.lt/gt/lte/gte for range comparisons."),
    ),
    responses(
        (status = 200, description = "List of users", body = UserListResponse),
        (status = 400, description = "Invalid filter parameter"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "Users"
)]
pub async fn list_users_handler(
    Extension(claims): Extension<JwtClaims>,
    Extension(user_service): Extension<Arc<UserService>>,
    Query(query): Query<ListUsersQuery>,
    RawQuery(raw_query): RawQuery,
) -> Result<Json<UserListResponse>, ApiUsersError> {
    // Get tenant from claims (already validated by admin_guard middleware)
    let tenant_id = claims.tenant_id().ok_or(ApiUsersError::Unauthorized)?;

    // Parse custom attribute filters from the raw query string
    let custom_attr_filters = raw_query
        .as_deref()
        .map(parse_custom_attr_filters)
        .unwrap_or_default();

    tracing::info!(
        admin_id = %claims.sub,
        tenant_id = %tenant_id,
        offset = query.offset(),
        limit = query.limit(),
        email_filter = ?query.email,
        custom_attr_filter_count = custom_attr_filters.len(),
        "Listing users"
    );

    let response = user_service
        .list_users(tenant_id, &query, &custom_attr_filters)
        .await?;

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    // Handler tests require integration test setup with database
    // See crates/xavyo-api-users/tests/list_users_test.rs
}
