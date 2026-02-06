//! `SoD` exemption handlers for governance API.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    CreateSodExemptionRequest, ListSodExemptionsQuery, SodExemptionListResponse,
    SodExemptionResponse,
};
use crate::router::GovernanceState;
use crate::services::SodExemptionService;

/// List `SoD` exemptions with optional filtering and pagination.
#[utoipa::path(
    get,
    path = "/governance/sod-exemptions",
    tag = "Governance - SoD Exemptions",
    params(ListSodExemptionsQuery),
    responses(
        (status = 200, description = "List of SoD exemptions", body = SodExemptionListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_exemptions(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListSodExemptionsQuery>,
) -> ApiResult<Json<SodExemptionListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let (exemptions, total) = state
        .sod_exemption_service
        .list_exemptions(
            tenant_id,
            query.rule_id,
            query.user_id,
            query.status,
            limit,
            offset,
        )
        .await?;

    Ok(Json(SodExemptionListResponse {
        items: exemptions
            .iter()
            .map(SodExemptionService::to_api_response)
            .collect(),
        total,
        limit,
        offset,
    }))
}

/// Get an `SoD` exemption by ID.
#[utoipa::path(
    get,
    path = "/governance/sod-exemptions/{id}",
    tag = "Governance - SoD Exemptions",
    params(
        ("id" = Uuid, Path, description = "SoD Exemption ID")
    ),
    responses(
        (status = 200, description = "SoD exemption details", body = SodExemptionResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "SoD exemption not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_exemption(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<SodExemptionResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let exemption = state
        .sod_exemption_service
        .get_exemption(tenant_id, id)
        .await?;

    Ok(Json(SodExemptionService::to_api_response(&exemption)))
}

/// Create a new `SoD` exemption.
///
/// Grants a time-limited exception for a user to hold conflicting entitlements.
#[utoipa::path(
    post,
    path = "/governance/sod-exemptions",
    tag = "Governance - SoD Exemptions",
    request_body = CreateSodExemptionRequest,
    responses(
        (status = 201, description = "Exemption created", body = SodExemptionResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "SoD rule not found"),
        (status = 409, description = "Exemption already exists for this user/rule"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_exemption(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateSodExemptionRequest>,
) -> ApiResult<(StatusCode, Json<SodExemptionResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let approver_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let exemption = state
        .sod_exemption_service
        .create_exemption(
            tenant_id,
            request.rule_id,
            request.user_id,
            approver_id,
            request.justification,
            request.expires_at,
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(SodExemptionService::to_api_response(&exemption)),
    ))
}

/// Revoke an `SoD` exemption.
///
/// The exemption will be marked as revoked and can no longer be used.
#[utoipa::path(
    post,
    path = "/governance/sod-exemptions/{id}/revoke",
    tag = "Governance - SoD Exemptions",
    params(
        ("id" = Uuid, Path, description = "SoD Exemption ID")
    ),
    responses(
        (status = 200, description = "Exemption revoked", body = SodExemptionResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "SoD exemption not found"),
        (status = 409, description = "Exemption is already inactive"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_exemption(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<SodExemptionResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let revoked_by = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let exemption = state
        .sod_exemption_service
        .revoke_exemption(tenant_id, id, revoked_by)
        .await?;

    Ok(Json(SodExemptionService::to_api_response(&exemption)))
}
