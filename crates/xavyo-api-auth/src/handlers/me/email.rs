//! Email change handlers (F027).
//!
//! POST /me/email/change - Initiate email change
//! POST /me/email/verify - Verify email change with token

use crate::error::ApiAuthError;
use crate::models::{
    EmailChangeCompletedResponse, EmailChangeInitiatedResponse, EmailChangeRequest,
    EmailVerifyChangeRequest,
};
use crate::services::{EmailChangeService, EmailSender};
use axum::{Extension, Json};
use std::sync::Arc;
use validator::Validate;
use xavyo_core::{TenantId, UserId};

/// Handle POST /me/email/change request.
///
/// Initiates an email change request by sending a verification email
/// to the new address.
///
/// # Request Body
///
/// ```json
/// {
///     "new_email": "newemail@example.com",
///     "current_password": "SecurePass123!"
/// }
/// ```
///
/// # Response
///
/// - 200 OK: Verification email sent
/// - 400 Bad Request: Validation error or same email
/// - 401 Unauthorized: Invalid password or not authenticated
/// - 409 Conflict: Email already in use
#[utoipa::path(
    post,
    path = "/me/email/change",
    request_body = EmailChangeRequest,
    responses(
        (status = 200, description = "Verification email sent", body = EmailChangeInitiatedResponse),
        (status = 400, description = "Validation error or same email"),
        (status = 401, description = "Invalid password or not authenticated"),
        (status = 409, description = "Email already in use"),
    ),
    tag = "User Profile"
)]
pub async fn initiate_email_change(
    Extension(email_change_service): Extension<Arc<EmailChangeService>>,
    Extension(email_sender): Extension<Arc<dyn EmailSender>>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(user_id): Extension<UserId>,
    Json(request): Json<EmailChangeRequest>,
) -> Result<Json<EmailChangeInitiatedResponse>, ApiAuthError> {
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

    let response = email_change_service
        .initiate_email_change(
            *user_id.as_uuid(),
            *tenant_id.as_uuid(),
            &request.new_email,
            &request.current_password,
            email_sender.as_ref(),
        )
        .await?;

    Ok(Json(response))
}

/// Handle POST /me/email/verify request.
///
/// Verifies the email change using the token sent to the new email address.
///
/// # Request Body
///
/// ```json
/// {
///     "token": "abc123def456..."
/// }
/// ```
///
/// # Response
///
/// - 200 OK: Email changed successfully
/// - 400 Bad Request: Invalid or expired token
/// - 401 Unauthorized: Not authenticated
/// - 409 Conflict: Email taken during verification
#[utoipa::path(
    post,
    path = "/me/email/verify",
    request_body = EmailVerifyChangeRequest,
    responses(
        (status = 200, description = "Email changed successfully", body = EmailChangeCompletedResponse),
        (status = 400, description = "Invalid or expired token"),
        (status = 401, description = "Not authenticated"),
        (status = 409, description = "Email taken during verification"),
    ),
    tag = "User Profile"
)]
pub async fn verify_email_change(
    Extension(email_change_service): Extension<Arc<EmailChangeService>>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(user_id): Extension<UserId>,
    Json(request): Json<EmailVerifyChangeRequest>,
) -> Result<Json<EmailChangeCompletedResponse>, ApiAuthError> {
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

    let response = email_change_service
        .verify_email_change(*user_id.as_uuid(), *tenant_id.as_uuid(), &request.token)
        .await?;

    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_change_request_serialization() {
        let request = EmailChangeRequest {
            new_email: "newemail@example.com".to_string(),
            current_password: "password123".to_string(),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"new_email\":\"newemail@example.com\""));
    }
}
