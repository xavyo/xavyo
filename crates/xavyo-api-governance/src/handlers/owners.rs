//! Entitlement owner handlers for governance API.

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use uuid::Uuid;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{EntitlementResponse, SetOwnerRequest};
use crate::router::GovernanceState;

/// Set owner for an entitlement.
#[utoipa::path(
    put,
    path = "/governance/entitlements/{id}/owner",
    tag = "Governance - Entitlement Owners",
    params(
        ("id" = Uuid, Path, description = "Entitlement ID")
    ),
    request_body = SetOwnerRequest,
    responses(
        (status = 200, description = "Owner set", body = EntitlementResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Entitlement not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn set_owner(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<SetOwnerRequest>,
) -> ApiResult<Json<EntitlementResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let entitlement = state
        .entitlement_service
        .set_owner(tenant_id, id, request.owner_id)
        .await?;

    Ok(Json(entitlement.into()))
}

/// Remove owner from an entitlement.
#[utoipa::path(
    delete,
    path = "/governance/entitlements/{id}/owner",
    tag = "Governance - Entitlement Owners",
    params(
        ("id" = Uuid, Path, description = "Entitlement ID")
    ),
    responses(
        (status = 200, description = "Owner removed", body = EntitlementResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Entitlement not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_owner(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<EntitlementResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let entitlement = state
        .entitlement_service
        .remove_owner(tenant_id, id)
        .await?;

    Ok(Json(entitlement.into()))
}
