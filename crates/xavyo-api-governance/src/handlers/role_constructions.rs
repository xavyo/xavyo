//! Role construction handlers for F-063: Role Inducements.
//!
//! Provides HTTP handlers for managing role constructions.

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
    ConstructionListResponse, ConstructionResponse, CreateConstructionRequest,
    EffectiveConstructionResponse, EffectiveConstructionsResponse, ListConstructionsQuery,
    SourceRoleInfo, UpdateConstructionRequest, UserEffectiveConstructionResponse,
    UserEffectiveConstructionsResponse,
};
use crate::router::GovernanceState;

/// List role constructions with filtering and pagination.
#[utoipa::path(
    get,
    path = "/governance/roles/{role_id}/constructions",
    tag = "Governance - Role Constructions",
    params(
        ("role_id" = Uuid, Path, description = "Role ID"),
        ListConstructionsQuery
    ),
    responses(
        (status = 200, description = "List of constructions", body = ConstructionListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_role_constructions(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
    Query(query): Query<ListConstructionsQuery>,
) -> ApiResult<Json<ConstructionListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let response = state
        .role_construction_service
        .list_by_role(tenant_id, role_id, &query)
        .await?;

    Ok(Json(response))
}

/// Get effective constructions for a role.
///
/// Returns all constructions that would be triggered when this role is assigned,
/// including constructions from any induced roles.
#[utoipa::path(
    get,
    path = "/governance/roles/{role_id}/effective-constructions",
    tag = "Governance - Role Constructions",
    params(
        ("role_id" = Uuid, Path, description = "Role ID")
    ),
    responses(
        (status = 200, description = "Effective constructions", body = EffectiveConstructionsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_role_effective_constructions(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
) -> ApiResult<Json<EffectiveConstructionsResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Get effective constructions using the construction service
    let constructions = state
        .role_construction_service
        .get_effective_constructions(tenant_id, role_id, &state.role_inducement_service)
        .await?;

    // Convert to response with source role info
    let effective_constructions = constructions
        .into_iter()
        .map(|c| EffectiveConstructionResponse {
            is_direct: c.role_id == role_id,
            source_role_id: c.role_id,
            source_role_name: String::new(), // Would need role lookup for full info
            construction: c,
        })
        .collect();

    Ok(Json(EffectiveConstructionsResponse {
        constructions: effective_constructions,
    }))
}

/// Get a role construction by ID.
#[utoipa::path(
    get,
    path = "/governance/roles/{role_id}/constructions/{construction_id}",
    tag = "Governance - Role Constructions",
    params(
        ("role_id" = Uuid, Path, description = "Role ID"),
        ("construction_id" = Uuid, Path, description = "Construction ID")
    ),
    responses(
        (status = 200, description = "Construction details", body = ConstructionResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role or construction not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_role_construction(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((role_id, construction_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<ConstructionResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let construction = state
        .role_construction_service
        .get_construction(tenant_id, role_id, construction_id)
        .await?;

    Ok(Json(construction))
}

/// Create a new role construction.
#[utoipa::path(
    post,
    path = "/governance/roles/{role_id}/constructions",
    tag = "Governance - Role Constructions",
    params(
        ("role_id" = Uuid, Path, description = "Role ID")
    ),
    request_body = CreateConstructionRequest,
    responses(
        (status = 201, description = "Construction created", body = ConstructionResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role or connector not found"),
        (status = 409, description = "Construction already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_role_construction(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
    Json(request): Json<CreateConstructionRequest>,
) -> ApiResult<(StatusCode, Json<ConstructionResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Validate request
    request
        .validate()
        .map_err(|e| ApiGovernanceError::Validation(e.to_string()))?;

    let construction = state
        .role_construction_service
        .create_construction(tenant_id, role_id, request, user_id)
        .await?;

    Ok((StatusCode::CREATED, Json(construction)))
}

/// Update a role construction.
#[utoipa::path(
    put,
    path = "/governance/roles/{role_id}/constructions/{construction_id}",
    tag = "Governance - Role Constructions",
    params(
        ("role_id" = Uuid, Path, description = "Role ID"),
        ("construction_id" = Uuid, Path, description = "Construction ID")
    ),
    request_body = UpdateConstructionRequest,
    responses(
        (status = 200, description = "Construction updated", body = ConstructionResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role or construction not found"),
        (status = 409, description = "Version conflict"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_role_construction(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((role_id, construction_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateConstructionRequest>,
) -> ApiResult<Json<ConstructionResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Validate request
    request
        .validate()
        .map_err(|e| ApiGovernanceError::Validation(e.to_string()))?;

    let construction = state
        .role_construction_service
        .update_construction(tenant_id, role_id, construction_id, request)
        .await?;

    Ok(Json(construction))
}

/// Delete a role construction.
#[utoipa::path(
    delete,
    path = "/governance/roles/{role_id}/constructions/{construction_id}",
    tag = "Governance - Role Constructions",
    params(
        ("role_id" = Uuid, Path, description = "Role ID"),
        ("construction_id" = Uuid, Path, description = "Construction ID")
    ),
    responses(
        (status = 204, description = "Construction deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role or construction not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_role_construction(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((role_id, construction_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state
        .role_construction_service
        .delete_construction(tenant_id, role_id, construction_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Enable a role construction.
#[utoipa::path(
    post,
    path = "/governance/roles/{role_id}/constructions/{construction_id}/enable",
    tag = "Governance - Role Constructions",
    params(
        ("role_id" = Uuid, Path, description = "Role ID"),
        ("construction_id" = Uuid, Path, description = "Construction ID")
    ),
    responses(
        (status = 200, description = "Construction enabled", body = ConstructionResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role or construction not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn enable_role_construction(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((role_id, construction_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<ConstructionResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let construction = state
        .role_construction_service
        .enable_construction(tenant_id, role_id, construction_id)
        .await?;

    Ok(Json(construction))
}

/// Disable a role construction.
#[utoipa::path(
    post,
    path = "/governance/roles/{role_id}/constructions/{construction_id}/disable",
    tag = "Governance - Role Constructions",
    params(
        ("role_id" = Uuid, Path, description = "Role ID"),
        ("construction_id" = Uuid, Path, description = "Construction ID")
    ),
    responses(
        (status = 200, description = "Construction disabled", body = ConstructionResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role or construction not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn disable_role_construction(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((role_id, construction_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<ConstructionResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let construction = state
        .role_construction_service
        .disable_construction(tenant_id, role_id, construction_id)
        .await?;

    Ok(Json(construction))
}

/// Get effective constructions for a user.
///
/// Returns all constructions that apply to a user based on their role assignments,
/// including constructions from induced roles. This shows what accounts/resources
/// would be provisioned for the user.
#[utoipa::path(
    get,
    path = "/governance/users/{user_id}/effective-constructions",
    tag = "Governance - Role Constructions",
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User's effective constructions", body = UserEffectiveConstructionsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "User not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_user_effective_constructions(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(user_id): Path<Uuid>,
) -> ApiResult<Json<UserEffectiveConstructionsResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let constructions = state
        .inducement_trigger_service
        .get_user_effective_constructions(tenant_id, user_id)
        .await?;

    // Wrap each construction in UserEffectiveConstructionResponse
    // Note: In a full implementation, we'd track which roles provide each construction
    let user_constructions = constructions
        .into_iter()
        .map(|c| UserEffectiveConstructionResponse {
            construction: c.clone(),
            source_roles: vec![SourceRoleInfo {
                role_id: c.role_id,
                role_name: String::new(), // Would need role lookup
            }],
        })
        .collect();

    Ok(Json(UserEffectiveConstructionsResponse {
        user_id,
        constructions: user_constructions,
    }))
}
