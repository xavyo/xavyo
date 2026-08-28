//! Role construction handlers for F-063: Role Inducements.
//!
//! Provides HTTP handlers for managing role constructions.

use std::collections::HashMap;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;
use xavyo_db::models::GovRole;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    ConstructionListResponse, ConstructionResponse, CreateConstructionRequest,
    EffectiveConstructionResponse, EffectiveConstructionsResponse, ListConstructionsQuery,
    SourceRoleInfo, UpdateConstructionRequest, UserEffectiveConstructionResponse,
    UserEffectiveConstructionsResponse,
};
use crate::router::GovernanceState;

async fn load_role_names(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    role_ids: impl IntoIterator<Item = Uuid>,
) -> ApiResult<HashMap<Uuid, String>> {
    let mut names = HashMap::new();
    for role_id in role_ids {
        if names.contains_key(&role_id) {
            continue;
        }
        if let Some(role) = GovRole::find_by_id(pool, tenant_id, role_id).await? {
            names.insert(role_id, role.name);
        }
    }
    Ok(names)
}

fn role_display_name(names: &HashMap<Uuid, String>, role_id: Uuid) -> String {
    names
        .get(&role_id)
        .cloned()
        .unwrap_or_else(|| format!("Unknown ({role_id})"))
}

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

    let role_ids: Vec<Uuid> = constructions.iter().map(|c| c.role_id).collect();
    let role_names = load_role_names(state.pool(), tenant_id, role_ids).await?;

    // Convert to response with source role info
    let effective_constructions = constructions
        .into_iter()
        .map(|c| EffectiveConstructionResponse {
            is_direct: c.role_id == role_id,
            source_role_id: c.role_id,
            source_role_name: role_display_name(&role_names, c.role_id),
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

    let role_ids: Vec<Uuid> = constructions.iter().map(|c| c.role_id).collect();
    let role_names = load_role_names(state.pool(), tenant_id, role_ids).await?;

    // Wrap each construction in UserEffectiveConstructionResponse
    let user_constructions = constructions
        .into_iter()
        .map(|c| UserEffectiveConstructionResponse {
            source_roles: vec![SourceRoleInfo {
                role_id: c.role_id,
                role_name: role_display_name(&role_names, c.role_id),
            }],
            construction: c,
        })
        .collect();

    Ok(Json(UserEffectiveConstructionsResponse {
        user_id,
        constructions: user_constructions,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_display_name_falls_back_to_unknown() {
        let id = Uuid::new_v4();
        let mut names = HashMap::new();
        names.insert(id, "Engineer".to_string());
        assert_eq!(role_display_name(&names, id), "Engineer");
        let missing = Uuid::new_v4();
        assert_eq!(
            role_display_name(&names, missing),
            format!("Unknown ({missing})")
        );
    }

    #[test]
    fn effective_constructions_look_up_source_role_names() {
        let src = include_str!("role_constructions.rs");
        let production = src.split("mod tests").next().expect("production source");
        let role = production
            .split("pub async fn get_role_effective_constructions")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("get_role_effective_constructions");
        assert!(
            role.contains("load_role_names(")
                && role.contains("role_display_name(")
                && !role.contains("source_role_name: String::new()"),
            "GET /governance/roles/{{id}}/effective-constructions must look up source role names"
        );
        let user = production
            .split("pub async fn get_user_effective_constructions")
            .nth(1)
            .expect("get_user_effective_constructions");
        assert!(
            user.contains("load_role_names(")
                && user.contains("role_display_name(")
                && !user.contains("role_name: String::new()"),
            "GET /governance/users/{{id}}/effective-constructions must look up source role names"
        );
    }
}
