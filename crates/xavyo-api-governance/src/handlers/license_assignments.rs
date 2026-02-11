//! HTTP handlers for License Assignment management (F065).
//!
//! Provides endpoints for managing license assignments including
//! individual and bulk assignment, deallocation, and listing.

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
        AssignLicenseRequest, BulkAssignLicenseRequest, BulkOperationResult,
        BulkReclaimLicenseRequest, LicenseAssignmentListResponse, LicenseAssignmentResponse,
        ListLicenseAssignmentsParams,
    },
    router::GovernanceState,
};

/// Assign a license from a pool to a user.
#[utoipa::path(
    post,
    path = "/governance/license-assignments",
    tag = "Governance - License Management",
    request_body = AssignLicenseRequest,
    responses(
        (status = 201, description = "License assigned", body = LicenseAssignmentResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Pool not found"),
        (status = 409, description = "License already assigned or incompatibility conflict"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_assignment(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<AssignLicenseRequest>,
) -> ApiResult<(StatusCode, Json<LicenseAssignmentResponse>)> {
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
        .license_assignment_service
        .assign(tenant_id, user_id, request)
        .await?;

    Ok((StatusCode::CREATED, Json(result)))
}

/// List license assignments with optional filtering.
#[utoipa::path(
    get,
    path = "/governance/license-assignments",
    tag = "Governance - License Management",
    params(
        ("license_pool_id" = Option<Uuid>, Query, description = "Filter by license pool"),
        ("user_id" = Option<Uuid>, Query, description = "Filter by user"),
        ("status" = Option<String>, Query, description = "Filter by status (active, reclaimed, expired, released)"),
        ("source" = Option<String>, Query, description = "Filter by source (manual, automatic, entitlement)"),
        ("limit" = Option<i64>, Query, description = "Maximum results to return (default: 20, max: 100)"),
        ("offset" = Option<i64>, Query, description = "Results to skip for pagination")
    ),
    responses(
        (status = 200, description = "License assignments retrieved", body = LicenseAssignmentListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_assignments(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<ListLicenseAssignmentsParams>,
) -> ApiResult<Json<LicenseAssignmentListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .license_assignment_service
        .list(tenant_id, params)
        .await?;

    Ok(Json(result))
}

/// Get a license assignment by ID.
#[utoipa::path(
    get,
    path = "/governance/license-assignments/{id}",
    tag = "Governance - License Management",
    params(
        ("id" = Uuid, Path, description = "License assignment ID")
    ),
    responses(
        (status = 200, description = "License assignment retrieved", body = LicenseAssignmentResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "License assignment not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_assignment(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<LicenseAssignmentResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .license_assignment_service
        .get_required(tenant_id, id)
        .await?;

    Ok(Json(result))
}

/// Deallocate (release) a license assignment.
///
/// Marks the assignment as released and decrements the pool's allocated count.
#[utoipa::path(
    delete,
    path = "/governance/license-assignments/{id}",
    tag = "Governance - License Management",
    params(
        ("id" = Uuid, Path, description = "License assignment ID")
    ),
    responses(
        (status = 204, description = "License assignment deallocated"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "License assignment not found"),
        (status = 409, description = "Assignment is not active"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn deallocate_assignment(
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
        .license_assignment_service
        .deallocate(tenant_id, id, user_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Assign licenses to multiple users at once.
///
/// Iterates over the user list, attempting to assign each one.
/// Collects successes and failures rather than failing fast.
#[utoipa::path(
    post,
    path = "/governance/license-assignments/bulk",
    tag = "Governance - License Management",
    request_body = BulkAssignLicenseRequest,
    responses(
        (status = 201, description = "Bulk assignment completed", body = BulkOperationResult),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn bulk_assign(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<BulkAssignLicenseRequest>,
) -> ApiResult<(StatusCode, Json<BulkOperationResult>)> {
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
        .license_assignment_service
        .bulk_assign(tenant_id, user_id, request)
        .await?;

    Ok((StatusCode::CREATED, Json(result)))
}

/// Reclaim multiple license assignments.
///
/// Iterates over the assignment IDs, reclaiming each one with a manual reason.
/// Collects successes and failures rather than failing fast.
#[utoipa::path(
    post,
    path = "/governance/license-assignments/bulk-reclaim",
    tag = "Governance - License Management",
    request_body = BulkReclaimLicenseRequest,
    responses(
        (status = 200, description = "Bulk reclamation completed", body = BulkOperationResult),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn bulk_reclaim(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<BulkReclaimLicenseRequest>,
) -> ApiResult<Json<BulkOperationResult>> {
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
        .license_assignment_service
        .bulk_reclaim(tenant_id, user_id, request)
        .await?;

    Ok(Json(result))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_handler_module_exists() {
        // Placeholder test to verify the module compiles
    }
}
