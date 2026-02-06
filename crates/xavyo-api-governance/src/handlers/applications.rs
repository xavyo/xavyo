//! Application handlers for governance API.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;
use xavyo_db::models::{CreateGovApplication, UpdateGovApplication};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    ApplicationListResponse, ApplicationResponse, CreateApplicationRequest, ListApplicationsQuery,
    UpdateApplicationRequest,
};
use crate::router::GovernanceState;

/// List applications with optional filtering and pagination.
#[utoipa::path(
    get,
    path = "/governance/applications",
    tag = "Governance - Applications",
    params(ListApplicationsQuery),
    responses(
        (status = 200, description = "List of applications", body = ApplicationListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_applications(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListApplicationsQuery>,
) -> ApiResult<Json<ApplicationListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let (applications, total) = state
        .application_service
        .list_applications(
            tenant_id,
            query.status,
            query.app_type,
            query.limit,
            query.offset,
        )
        .await?;

    Ok(Json(ApplicationListResponse {
        items: applications.into_iter().map(Into::into).collect(),
        total,
        limit: query.limit,
        offset: query.offset,
    }))
}

/// Get an application by ID.
#[utoipa::path(
    get,
    path = "/governance/applications/{id}",
    tag = "Governance - Applications",
    params(
        ("id" = Uuid, Path, description = "Application ID")
    ),
    responses(
        (status = 200, description = "Application details", body = ApplicationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Application not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_application(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApplicationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let application = state
        .application_service
        .get_application(tenant_id, id)
        .await?;

    Ok(Json(application.into()))
}

/// Create a new application.
#[utoipa::path(
    post,
    path = "/governance/applications",
    tag = "Governance - Applications",
    request_body = CreateApplicationRequest,
    responses(
        (status = 201, description = "Application created", body = ApplicationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Application name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_application(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateApplicationRequest>,
) -> ApiResult<(StatusCode, Json<ApplicationResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = CreateGovApplication {
        name: request.name,
        app_type: request.app_type,
        description: request.description,
        owner_id: request.owner_id,
        external_id: request.external_id,
        metadata: request.metadata,
        is_delegable: request.is_delegable.unwrap_or(true),
        is_semi_manual: false,
        ticketing_config_id: None,
        sla_policy_id: None,
        requires_approval_before_ticket: false,
    };

    let application = state
        .application_service
        .create_application(tenant_id, input)
        .await?;

    Ok((StatusCode::CREATED, Json(application.into())))
}

/// Update an application.
#[utoipa::path(
    put,
    path = "/governance/applications/{id}",
    tag = "Governance - Applications",
    params(
        ("id" = Uuid, Path, description = "Application ID")
    ),
    request_body = UpdateApplicationRequest,
    responses(
        (status = 200, description = "Application updated", body = ApplicationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Application not found"),
        (status = 409, description = "Application name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_application(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateApplicationRequest>,
) -> ApiResult<Json<ApplicationResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = UpdateGovApplication {
        name: request.name,
        status: request.status,
        description: request.description,
        owner_id: request.owner_id,
        external_id: request.external_id,
        metadata: request.metadata,
        is_delegable: request.is_delegable,
        is_semi_manual: None,
        ticketing_config_id: None,
        sla_policy_id: None,
        requires_approval_before_ticket: None,
    };

    let application = state
        .application_service
        .update_application(tenant_id, id, input)
        .await?;

    Ok(Json(application.into()))
}

/// Delete an application.
#[utoipa::path(
    delete,
    path = "/governance/applications/{id}",
    tag = "Governance - Applications",
    params(
        ("id" = Uuid, Path, description = "Application ID")
    ),
    responses(
        (status = 204, description = "Application deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Application not found"),
        (status = 412, description = "Cannot delete application with entitlements"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_application(
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
        .application_service
        .delete_application(tenant_id, id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}
