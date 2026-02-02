//! HTTP handlers for semi-manual resource configuration (F064).

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;
use xavyo_auth::JwtClaims;

use crate::{
    error::{ApiGovernanceError, ApiResult},
    models::{
        ConfigureSemiManualRequest, ListSemiManualApplicationsQuery, SemiManualApplicationResponse,
        SemiManualApplicationsListResponse,
    },
    router::GovernanceState,
};

/// List applications configured as semi-manual.
#[utoipa::path(
    get,
    path = "/governance/semi-manual/applications",
    tag = "Governance - Semi-manual Resources",
    params(
        ("limit" = Option<i64>, Query, description = "Maximum results to return"),
        ("offset" = Option<i64>, Query, description = "Results to skip")
    ),
    responses(
        (status = 200, description = "Semi-manual applications retrieved", body = SemiManualApplicationsListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_semi_manual_applications(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListSemiManualApplicationsQuery>,
) -> ApiResult<Json<SemiManualApplicationsListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .semi_manual_resource_service
        .list_semi_manual_applications(tenant_id, &query)
        .await?;

    Ok(Json(result))
}

/// Get semi-manual configuration for an application.
#[utoipa::path(
    get,
    path = "/governance/semi-manual/applications/{id}",
    tag = "Governance - Semi-manual Resources",
    params(
        ("id" = Uuid, Path, description = "Application ID")
    ),
    responses(
        (status = 200, description = "Semi-manual configuration retrieved", body = SemiManualApplicationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Application not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_semi_manual_config(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<SemiManualApplicationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .semi_manual_resource_service
        .get_semi_manual_config(tenant_id, id)
        .await?;

    Ok(Json(result))
}

/// Configure an application as semi-manual.
#[utoipa::path(
    put,
    path = "/governance/semi-manual/applications/{id}",
    tag = "Governance - Semi-manual Resources",
    params(
        ("id" = Uuid, Path, description = "Application ID")
    ),
    request_body = ConfigureSemiManualRequest,
    responses(
        (status = 200, description = "Semi-manual configuration updated", body = SemiManualApplicationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Application not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn configure_semi_manual(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<ConfigureSemiManualRequest>,
) -> ApiResult<Json<SemiManualApplicationResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .semi_manual_resource_service
        .configure_semi_manual(tenant_id, id, request)
        .await?;

    Ok(Json(result))
}

/// Remove semi-manual configuration from an application.
#[utoipa::path(
    delete,
    path = "/governance/semi-manual/applications/{id}",
    tag = "Governance - Semi-manual Resources",
    params(
        ("id" = Uuid, Path, description = "Application ID")
    ),
    responses(
        (status = 200, description = "Semi-manual configuration removed", body = SemiManualApplicationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Application not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_semi_manual_config(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<SemiManualApplicationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .semi_manual_resource_service
        .remove_semi_manual_config(tenant_id, id)
        .await?;

    Ok(Json(result))
}
