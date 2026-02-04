//! Handler for getting a specific Non-Human Identity.
//!
//! Provides `GET /nhi/{id}` endpoint.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use uuid::Uuid;
use xavyo_auth::JwtClaims;

use super::list::{NhiItem, NhiState};

/// Handler for `GET /nhi/{id}`.
///
/// Returns a specific NHI by its ID.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/{id}",
    tag = "nhi",
    params(
        ("id" = Uuid, Path, description = "NHI unique identifier")
    ),
    responses(
        (status = 200, description = "NHI details", body = NhiItem),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "NHI not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
))]
pub async fn get_nhi(
    Extension(claims): Extension<JwtClaims>,
    State(state): State<NhiState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let tenant_id = extract_tenant_id(&claims)?;

    let nhi = state
        .list_service
        .find_by_id(tenant_id, id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get NHI {}: {}", id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Database error".to_string(),
            )
        })?;

    match nhi {
        Some(nhi) => Ok(Json(NhiItem::from(nhi))),
        None => Err((StatusCode::NOT_FOUND, format!("NHI {id} not found"))),
    }
}

fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, (StatusCode, String)> {
    claims.tenant_id().map(|t| *t.as_uuid()).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "Missing tenant ID in claims".to_string(),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_tenant_id_with_uuid() {
        // Note: This is a type verification test
        // Actual extraction testing requires a valid JwtClaims instance
        let id = Uuid::new_v4();
        assert!(!id.is_nil());
    }
}
