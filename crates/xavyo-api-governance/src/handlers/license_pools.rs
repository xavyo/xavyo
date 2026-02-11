//! HTTP handlers for License Pool management (F065).
//!
//! Provides endpoints for managing software license pools including
//! CRUD operations, archival, and capacity tracking.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;
use xavyo_auth::JwtClaims;

use crate::{
    error::{ApiGovernanceError, ApiResult},
    models::license::{
        CreateLicensePoolRequest, LicensePoolListResponse, LicensePoolResponse,
        ListLicensePoolsParams, UpdateLicensePoolRequest,
    },
    router::GovernanceState,
};

/// List license pools with optional filtering.
#[utoipa::path(
    get,
    path = "/governance/license-pools",
    tag = "Governance - License Management",
    params(
        ("vendor" = Option<String>, Query, description = "Filter by vendor name"),
        ("license_type" = Option<String>, Query, description = "Filter by license type (named, concurrent)"),
        ("status" = Option<String>, Query, description = "Filter by status (active, expired, archived)"),
        ("limit" = Option<i64>, Query, description = "Maximum results to return (default: 20, max: 100)"),
        ("offset" = Option<i64>, Query, description = "Results to skip for pagination")
    ),
    responses(
        (status = 200, description = "License pools retrieved", body = LicensePoolListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_license_pools(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<ListLicensePoolsParams>,
) -> ApiResult<Json<LicensePoolListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state.license_pool_service.list(tenant_id, params).await?;

    Ok(Json(result))
}

/// Get a license pool by ID.
#[utoipa::path(
    get,
    path = "/governance/license-pools/{id}",
    tag = "Governance - License Management",
    params(
        ("id" = Uuid, Path, description = "License pool ID")
    ),
    responses(
        (status = 200, description = "License pool retrieved", body = LicensePoolResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "License pool not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_license_pool(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<LicensePoolResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .license_pool_service
        .get_required(tenant_id, id)
        .await?;

    Ok(Json(result))
}

/// Create a new license pool.
#[utoipa::path(
    post,
    path = "/governance/license-pools",
    tag = "Governance - License Management",
    request_body = CreateLicensePoolRequest,
    responses(
        (status = 201, description = "License pool created", body = LicensePoolResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Pool name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_license_pool(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateLicensePoolRequest>,
) -> ApiResult<(StatusCode, Json<LicensePoolResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .license_pool_service
        .create(tenant_id, user_id, request)
        .await?;

    Ok((StatusCode::CREATED, Json(result.pool)))
}

/// Update a license pool.
#[utoipa::path(
    put,
    path = "/governance/license-pools/{id}",
    tag = "Governance - License Management",
    params(
        ("id" = Uuid, Path, description = "License pool ID")
    ),
    request_body = UpdateLicensePoolRequest,
    responses(
        (status = 200, description = "License pool updated", body = LicensePoolResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "License pool not found"),
        (status = 409, description = "Pool name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_license_pool(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateLicensePoolRequest>,
) -> ApiResult<Json<LicensePoolResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .license_pool_service
        .update(tenant_id, id, user_id, request)
        .await?;

    Ok(Json(result.pool))
}

/// Delete a license pool.
///
/// Only pools with no active assignments can be deleted.
/// Consider archiving instead for pools with historical data.
#[utoipa::path(
    delete,
    path = "/governance/license-pools/{id}",
    tag = "Governance - License Management",
    params(
        ("id" = Uuid, Path, description = "License pool ID")
    ),
    responses(
        (status = 204, description = "License pool deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "License pool not found"),
        (status = 409, description = "Pool has active assignments"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_license_pool(
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
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    state
        .license_pool_service
        .delete(tenant_id, id, user_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Archive a license pool.
///
/// Archived pools preserve all data but cannot accept new assignments.
/// This is the recommended approach for pools you no longer need but want to keep for audit purposes.
#[utoipa::path(
    post,
    path = "/governance/license-pools/{id}/archive",
    tag = "Governance - License Management",
    params(
        ("id" = Uuid, Path, description = "License pool ID")
    ),
    responses(
        (status = 200, description = "License pool archived", body = LicensePoolResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "License pool not found"),
        (status = 409, description = "Pool is already archived"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn archive_license_pool(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<LicensePoolResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .license_pool_service
        .archive(tenant_id, id, user_id)
        .await?;

    Ok(Json(result))
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn test_handler_module_exists() {
        // Placeholder test to verify the module compiles
    }
}
