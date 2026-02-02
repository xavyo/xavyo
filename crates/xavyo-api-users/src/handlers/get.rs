//! Get user endpoint handler.
//!
//! GET /users/:id - Get user details.

use crate::error::ApiUsersError;
use crate::models::UserResponse;
use crate::services::UserService;
use axum::{extract::Path, Extension, Json};
use std::sync::Arc;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::UserId;

/// Returns details of a specific user in the admin's tenant.
#[utoipa::path(
    get,
    path = "/users/{id}",
    params(
        ("id" = String, Path, description = "User ID"),
    ),
    responses(
        (status = 200, description = "User details", body = UserResponse),
        (status = 400, description = "Invalid user ID format"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
        (status = 404, description = "User not found"),
    ),
    security(("bearerAuth" = [])),
    tag = "Users"
)]
pub async fn get_user_handler(
    Extension(claims): Extension<JwtClaims>,
    Extension(user_service): Extension<Arc<UserService>>,
    Path(id): Path<String>,
) -> Result<Json<UserResponse>, ApiUsersError> {
    // Get tenant from claims
    let tenant_id = claims.tenant_id().ok_or(ApiUsersError::Unauthorized)?;

    // Parse user ID
    let user_uuid = Uuid::parse_str(&id)
        .map_err(|_| ApiUsersError::Validation("Invalid user ID format".to_string()))?;
    let user_id = UserId::from_uuid(user_uuid);

    tracing::info!(
        admin_id = %claims.sub,
        tenant_id = %tenant_id,
        user_id = %user_id,
        "Getting user"
    );

    let response = user_service.get_user(tenant_id, user_id).await?;

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    // Handler tests require integration test setup with database
    // See crates/xavyo-api-users/tests/get_user_test.rs
}
