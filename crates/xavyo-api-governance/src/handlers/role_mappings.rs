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
use xavyo_db::{GovApplication, GovEntitlement};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    CreateRoleEntitlementRequest, ListRoleEntitlementsQuery, RoleEntitlementListResponse,
    RoleEntitlementResponse,
};
use crate::router::GovernanceState;

async fn role_mapping_details(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    mapping: xavyo_db::models::GovRoleEntitlement,
) -> ApiResult<RoleEntitlementResponse> {
    let entitlement = GovEntitlement::find_by_id(pool, tenant_id, mapping.entitlement_id)
        .await?
        .ok_or_else(|| {
            ApiGovernanceError::NotFound(format!(
                "Entitlement {} not found",
                mapping.entitlement_id
            ))
        })?;
    let application_name = GovApplication::find_by_id(pool, tenant_id, entitlement.application_id)
        .await?
        .map(|app| app.name);
    Ok(RoleEntitlementResponse {
        id: mapping.id,
        tenant_id: mapping.tenant_id,
        entitlement_id: mapping.entitlement_id,
        entitlement_name: entitlement.name,
        application_name,
        role_name: mapping.role_name,
        created_at: mapping.created_at,
        created_by: mapping.created_by,
    })
}

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

    let mut items = Vec::with_capacity(mappings.len());
    for mapping in mappings {
        items.push(role_mapping_details(state.pool(), tenant_id, mapping).await?);
    }

    Ok(Json(RoleEntitlementListResponse {
        items,
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
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

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

    Ok((
        StatusCode::CREATED,
        Json(role_mapping_details(state.pool(), tenant_id, mapping).await?),
    ))
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
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

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

#[cfg(test)]
mod tests {
    #[test]
    fn role_mapping_handlers_return_entitlement_details() {
        let src = include_str!("role_mappings.rs");
        let production = src.split("mod tests").next().expect("production source");
        for (fn_name, label) in [
            (
                "pub async fn list_role_entitlements",
                "GET /governance/role-entitlements",
            ),
            (
                "pub async fn create_role_entitlement",
                "POST /governance/role-entitlements",
            ),
        ] {
            let body = production
                .split(fn_name)
                .nth(1)
                .and_then(|s| s.split("pub async fn ").next())
                .unwrap_or_else(|| panic!("{fn_name}"));
            assert!(
                body.contains("role_mapping_details(")
                    && !body.contains("Into::into")
                    && !body.contains("mapping.into()"),
                "{label} must return entitlement_name and application_name"
            );
        }
    }
}
