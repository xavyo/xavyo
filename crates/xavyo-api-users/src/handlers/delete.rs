//! Delete (deactivate) user endpoint handler.
//!
//! DELETE /users/:id - Soft delete a user.

use crate::error::ApiUsersError;
use crate::services::UserService;
use axum::{extract::Path, http::StatusCode, Extension};
use std::sync::Arc;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::UserId;
use xavyo_webhooks::{EventPublisher, WebhookEvent};

/// Soft deletes a user by setting `is_active=false`.
#[utoipa::path(
    delete,
    path = "/users/{id}",
    params(
        ("id" = String, Path, description = "User ID"),
    ),
    responses(
        (status = 204, description = "User deactivated"),
        (status = 400, description = "Invalid user ID format"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
        (status = 404, description = "User not found"),
    ),
    security(("bearerAuth" = [])),
    tag = "Users"
)]
pub async fn delete_user_handler(
    Extension(claims): Extension<JwtClaims>,
    Extension(user_service): Extension<Arc<UserService>>,
    publisher: Option<Extension<EventPublisher>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiUsersError> {
    // Get tenant from claims
    let tenant_id = claims.tenant_id().ok_or(ApiUsersError::Unauthorized)?;

    // Parse user ID
    let user_uuid = Uuid::parse_str(&id)
        .map_err(|_| ApiUsersError::Validation("Invalid user ID format".to_string()))?;
    let user_id = UserId::from_uuid(user_uuid);

    // Parse caller ID for self-deactivation check
    let caller_uuid = super::extract_user_id(&claims)?;

    tracing::info!(
        admin_id = %claims.sub,
        tenant_id = %tenant_id,
        user_id = %user_id,
        "Deactivating user"
    );

    user_service
        .deactivate_user(tenant_id, user_id, caller_uuid)
        .await?;

    user_service
        .record_audit_event(
            tenant_id,
            caller_uuid,
            "user.deactivated",
            user_uuid,
            serde_json::json!({}),
        )
        .await?;

    // F085: Publish user.deleted webhook event
    if let Some(Extension(publisher)) = publisher {
        publisher.publish(WebhookEvent {
            event_id: Uuid::new_v4(),
            event_type: "user.deleted".to_string(),
            tenant_id: *tenant_id.as_uuid(),
            actor_id: Some(caller_uuid),
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "user_id": user_uuid,
            }),
        });
    } else {
        tracing::debug!("Webhook publisher not configured — user.deleted event not emitted");
    }

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    #[test]
    fn delete_awaits_admin_audit() {
        let src = include_str!("delete.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("record_audit_event(") && production.contains(".await?;"),
            "user delete must fail closed when admin audit persist errors"
        );
        assert!(
            !production.contains("tokio::spawn"),
            "must not fire-and-forget user.deactivated audit"
        );
        assert!(
            production.contains("extract_user_id(")
                && !production.contains("parse_str(&claims.sub).ok()"),
            "user delete webhook must not drop a malformed JWT sub"
        );
    }
}
