//! Update user endpoint handler.
//!
//! PUT /users/:id - Update user details.

use crate::error::ApiUsersError;
use crate::models::{UpdateUserRequest, UserResponse};
use crate::services::UserService;
use axum::{extract::Path, Extension, Json};
use std::sync::Arc;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::UserId;
use xavyo_webhooks::{EventPublisher, WebhookEvent};

/// Updates a user's email, roles, or active status.
#[utoipa::path(
    put,
    path = "/users/{id}",
    params(
        ("id" = String, Path, description = "User ID"),
    ),
    request_body = UpdateUserRequest,
    responses(
        (status = 200, description = "User updated", body = UserResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
        (status = 404, description = "User not found"),
        (status = 409, description = "Email already exists in tenant"),
    ),
    security(("bearerAuth" = [])),
    tag = "Users"
)]
pub async fn update_user_handler(
    Extension(claims): Extension<JwtClaims>,
    Extension(user_service): Extension<Arc<UserService>>,
    publisher: Option<Extension<EventPublisher>>,
    Path(id): Path<String>,
    Json(request): Json<UpdateUserRequest>,
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
        email = ?request.email,
        roles = ?request.roles,
        is_active = ?request.is_active,
        "Updating user"
    );

    let response = user_service
        .update_user(tenant_id, user_id, &request)
        .await?;

    // F085: Publish user.updated (or user.disabled/user.enabled) webhook event
    if let Some(Extension(publisher)) = publisher {
        let event_type = match request.is_active {
            Some(false) => "user.disabled",
            Some(true) => "user.enabled",
            None => "user.updated",
        };
        publisher.publish(WebhookEvent {
            event_id: Uuid::new_v4(),
            event_type: event_type.to_string(),
            tenant_id: *tenant_id.as_uuid(),
            actor_id: Uuid::parse_str(&claims.sub).ok(),
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "user_id": response.id,
                "email": response.email,
                "enabled": response.is_active,
            }),
        });
    }

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    // Handler tests require integration test setup with database
    // See crates/xavyo-api-users/tests/update_user_test.rs
}
