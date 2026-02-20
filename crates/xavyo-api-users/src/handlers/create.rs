//! Create user endpoint handler.
//!
//! POST /users - Create a new user in the tenant.

use crate::error::ApiUsersError;
use crate::models::{CreateUserRequest, UserResponse};
use crate::services::UserService;
use axum::{http::StatusCode, Extension, Json};
use std::sync::Arc;
use xavyo_auth::JwtClaims;
use xavyo_webhooks::{EventPublisher, WebhookEvent};

/// Creates a new user in the authenticated admin's tenant.
#[utoipa::path(
    post,
    path = "/users",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created", body = UserResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
        (status = 409, description = "Email already exists in tenant"),
    ),
    security(("bearerAuth" = [])),
    tag = "Users"
)]
pub async fn create_user_handler(
    Extension(claims): Extension<JwtClaims>,
    Extension(user_service): Extension<Arc<UserService>>,
    publisher: Option<Extension<EventPublisher>>,
    Json(request): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserResponse>), ApiUsersError> {
    // Get tenant from claims (already validated by admin_guard middleware)
    let tenant_id = claims.tenant_id().ok_or(ApiUsersError::Unauthorized)?;

    tracing::info!(
        admin_id = %claims.sub,
        tenant_id = %tenant_id,
        "Creating user"
    );
    tracing::debug!(roles = ?request.roles, "Create user role assignment");

    let response = user_service
        .create_user(tenant_id, &request, &claims.roles)
        .await?;

    // A6: Record durable admin audit event
    if let Ok(actor_id) = uuid::Uuid::parse_str(&claims.sub) {
        user_service
            .record_audit_event(
                tenant_id,
                actor_id,
                "user.created",
                response.id,
                serde_json::json!({
                    "email": response.email,
                    "roles": response.roles,
                }),
            )
            .await;
    }

    // F085: Publish user.created webhook event
    if let Some(Extension(publisher)) = publisher {
        publisher.publish(WebhookEvent {
            event_id: uuid::Uuid::new_v4(),
            event_type: "user.created".to_string(),
            tenant_id: *tenant_id.as_uuid(),
            actor_id: uuid::Uuid::parse_str(&claims.sub).ok(),
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "user_id": response.id,
                "email": response.email,
                "enabled": response.is_active,
            }),
        });
    }

    Ok((StatusCode::CREATED, Json(response)))
}

#[cfg(test)]
mod tests {
    // Handler tests require integration test setup with database
    // See crates/xavyo-api-users/tests/create_user_test.rs
}
