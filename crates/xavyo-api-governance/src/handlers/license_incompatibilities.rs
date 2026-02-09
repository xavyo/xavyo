//! HTTP handlers for License Incompatibility rules (F065).
//!
//! Provides endpoints for managing license incompatibility rules that
//! prevent users from holding conflicting license types.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;
use xavyo_auth::JwtClaims;

#[allow(unused_imports)]
use crate::models::IncompatibilityListResponse;
use crate::{
    error::{ApiGovernanceError, ApiResult},
    models::license::{
        CreateLicenseIncompatibilityRequest, LicenseIncompatibilityListResponse,
        LicenseIncompatibilityResponse, ListLicenseIncompatibilitiesParams,
    },
    router::GovernanceState,
};

/// List license incompatibility rules.
#[utoipa::path(
    get,
    path = "/governance/license-incompatibilities",
    tag = "Governance - License Management",
    params(
        ("pool_id" = Option<Uuid>, Query, description = "Filter by pool (matches either pool_a or pool_b)"),
        ("limit" = Option<i64>, Query, description = "Maximum results to return (default: 20, max: 100)"),
        ("offset" = Option<i64>, Query, description = "Results to skip for pagination")
    ),
    responses(
        (status = 200, description = "Incompatibility rules retrieved", body = IncompatibilityListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_incompatibilities(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<ListLicenseIncompatibilitiesParams>,
) -> ApiResult<Json<LicenseIncompatibilityListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .license_incompatibility_service
        .list(tenant_id, params)
        .await?;

    Ok(Json(result))
}

/// Get an incompatibility rule by ID.
#[utoipa::path(
    get,
    path = "/governance/license-incompatibilities/{id}",
    tag = "Governance - License Management",
    params(
        ("id" = Uuid, Path, description = "Incompatibility rule ID")
    ),
    responses(
        (status = 200, description = "Incompatibility rule retrieved", body = LicenseIncompatibilityResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Incompatibility rule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_incompatibility(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<LicenseIncompatibilityResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .license_incompatibility_service
        .get_required(tenant_id, id)
        .await?;

    Ok(Json(result))
}

/// Create a new incompatibility rule.
///
/// Defines that two license pools cannot be assigned to the same user.
#[utoipa::path(
    post,
    path = "/governance/license-incompatibilities",
    tag = "Governance - License Management",
    request_body = CreateLicenseIncompatibilityRequest,
    responses(
        (status = 201, description = "Incompatibility rule created", body = LicenseIncompatibilityResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Pool not found"),
        (status = 409, description = "Rule already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_incompatibility(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateLicenseIncompatibilityRequest>,
) -> ApiResult<(StatusCode, Json<LicenseIncompatibilityResponse>)> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .license_incompatibility_service
        .create(tenant_id, user_id, request)
        .await?;

    Ok((StatusCode::CREATED, Json(result)))
}

/// Delete an incompatibility rule.
#[utoipa::path(
    delete,
    path = "/governance/license-incompatibilities/{id}",
    tag = "Governance - License Management",
    params(
        ("id" = Uuid, Path, description = "Incompatibility rule ID")
    ),
    responses(
        (status = 204, description = "Incompatibility rule deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Incompatibility rule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_incompatibility(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    state
        .license_incompatibility_service
        .delete(tenant_id, id, user_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_handler_module_exists() {
        // Placeholder test to verify the module compiles
    }
}
