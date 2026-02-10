//! Profile management handlers (F027).
//!
//! GET /me/profile - Get current user's profile
//! PUT /me/profile - Update current user's profile

use crate::error::ApiAuthError;
use crate::models::{ProfileResponse, UpdateProfileRequest};
use crate::services::ProfileService;
use axum::{Extension, Json};
use std::sync::Arc;
use validator::Validate;
use xavyo_core::{TenantId, UserId};

/// Handle GET /me/profile request.
///
/// Returns the current user's profile information.
///
/// # Response
///
/// - 200 OK: Profile returned successfully
/// - 401 Unauthorized: Not authenticated
#[utoipa::path(
    get,
    path = "/me/profile",
    responses(
        (status = 200, description = "Profile returned successfully", body = ProfileResponse),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "User Profile"
)]
pub async fn get_profile(
    Extension(profile_service): Extension<Arc<ProfileService>>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(user_id): Extension<UserId>,
) -> Result<Json<ProfileResponse>, ApiAuthError> {
    let profile = profile_service
        .get_profile(*user_id.as_uuid(), *tenant_id.as_uuid())
        .await?;

    Ok(Json(profile))
}

/// Handle PUT /me/profile request.
///
/// Updates the current user's profile fields.
///
/// # Request Body
///
/// ```json
/// {
///     "display_name": "Johnny D",
///     "first_name": "Johnny",
///     "last_name": "Doe",
///     "avatar_url": "https://gravatar.com/avatar/abc123"
/// }
/// ```
///
/// # Response
///
/// - 200 OK: Profile updated successfully
/// - 400 Bad Request: Validation error
/// - 401 Unauthorized: Not authenticated
#[utoipa::path(
    put,
    path = "/me/profile",
    request_body = UpdateProfileRequest,
    responses(
        (status = 200, description = "Profile updated successfully", body = ProfileResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Not authenticated"),
    ),
    tag = "User Profile"
)]
pub async fn update_profile(
    Extension(profile_service): Extension<Arc<ProfileService>>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(user_id): Extension<UserId>,
    Json(request): Json<UpdateProfileRequest>,
) -> Result<Json<ProfileResponse>, ApiAuthError> {
    // Validate request
    request.validate().map_err(|e| {
        let errors: Vec<String> = e
            .field_errors()
            .values()
            .flat_map(|errors| {
                errors
                    .iter()
                    .filter_map(|e| e.message.as_ref().map(std::string::ToString::to_string))
            })
            .collect();
        ApiAuthError::Validation(errors.join(", "))
    })?;

    let profile = profile_service
        .update_profile(*user_id.as_uuid(), *tenant_id.as_uuid(), request)
        .await?;

    Ok(Json(profile))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_response_serialization() {
        let response = ProfileResponse {
            id: uuid::Uuid::new_v4(),
            email: "test@example.com".to_string(),
            display_name: Some("Test User".to_string()),
            first_name: Some("Test".to_string()),
            last_name: Some("User".to_string()),
            avatar_url: Some("https://example.com/avatar.png".to_string()),
            email_verified: true,
            created_at: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"email\":\"test@example.com\""));
        assert!(json.contains("\"display_name\":\"Test User\""));
    }
}
