//! Role entitlement mapping handlers for governance API.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;
use xavyo_db::models::CreateGovRoleEntitlement;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    CreateRoleEntitlementRequest, ListRoleEntitlementsQuery, RoleEntitlementListResponse,
    RoleEntitlementResponse,
};
use crate::router::GovernanceState;

/// List role-entitlement mappings with optional filtering and pagination.
#[utoipa::path(
    get,
    path = "/governance/role-entitlements",
    tag = "Governance - Role Entitlements",
    params(ListRoleEntitlementsQuery),
    responses(
        (status = 200, description = "List of role-entitlement mappings", body = RoleEntitlementListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_role_entitlements(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListRoleEntitlementsQuery>,
) -> ApiResult<Json<RoleEntitlementListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let (mappings, total) = state
        .role_entitlement_service
        .list_role_entitlements(
            tenant_id,
            query.entitlement_id,
            query.role_name,
            query.limit,
            query.offset,
        )
        .await?;

    Ok(Json(RoleEntitlementListResponse {
        items: mappings.into_iter().map(Into::into).collect(),
        total,
        limit: query.limit,
        offset: query.offset,
    }))
}

/// Create a new role-entitlement mapping.
#[utoipa::path(
    post,
    path = "/governance/role-entitlements",
    tag = "Governance - Role Entitlements",
    request_body = CreateRoleEntitlementRequest,
    responses(
        (status = 201, description = "Role-entitlement mapping created", body = RoleEntitlementResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Entitlement not found"),
        (status = 409, description = "Mapping already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_role_entitlement(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateRoleEntitlementRequest>,
) -> ApiResult<(StatusCode, Json<RoleEntitlementResponse>)> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let created_by = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let input = CreateGovRoleEntitlement {
        entitlement_id: request.entitlement_id,
        role_name: request.role_name,
        created_by,
    };

    let mapping = state
        .role_entitlement_service
        .create_role_entitlement(tenant_id, input)
        .await?;

    Ok((StatusCode::CREATED, Json(mapping.into())))
}

/// Delete a role-entitlement mapping.
#[utoipa::path(
    delete,
    path = "/governance/role-entitlements/{id}",
    tag = "Governance - Role Entitlements",
    params(
        ("id" = Uuid, Path, description = "Mapping ID")
    ),
    responses(
        (status = 204, description = "Mapping deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Mapping not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_role_entitlement(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state
        .role_entitlement_service
        .delete_role_entitlement(tenant_id, id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}
