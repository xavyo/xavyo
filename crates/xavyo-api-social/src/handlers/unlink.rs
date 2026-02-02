//! Account unlinking handlers.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use tracing::info;

use crate::error::{ProviderType, SocialError};
use crate::extractors::AuthenticatedUser;
use crate::SocialState;

/// Unlink a social account from the current user.
///
/// Will fail if this is the user's only authentication method.
#[utoipa::path(
    delete,
    path = "/auth/social/unlink/{provider}",
    params(
        ("provider" = String, Path, description = "Social provider to unlink"),
    ),
    responses(
        (status = 204, description = "Account unlinked"),
        (status = 400, description = "Cannot unlink - no other auth method"),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "No connection found for this provider"),
    ),
    security(("bearerAuth" = [])),
    tag = "Account Linking"
)]
pub async fn unlink_account(
    State(state): State<SocialState>,
    user: AuthenticatedUser,
    Path(provider): Path<String>,
) -> Result<impl IntoResponse, SocialError> {
    let provider_type: ProviderType = provider.parse()?;
    let user_id = user.user_id;
    let tenant_id = user.tenant_id;

    info!(
        user_id = %user_id,
        provider = %provider_type,
        "Unlinking social account"
    );

    // Delete the connection (will check if can_unlink internally)
    state
        .connection_service
        .delete_connection(tenant_id, user_id, provider_type)
        .await?;

    info!(
        user_id = %user_id,
        provider = %provider_type,
        "Successfully unlinked social account"
    );

    Ok(StatusCode::NO_CONTENT)
}
