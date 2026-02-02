use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;
use xavyo_auth::JwtClaims;

use crate::{
    error::{ApiGovernanceError, ApiResult},
    models::correlation::{
        ConfirmCaseRequest, CorrelationCaseDetailResponse, CreateIdentityFromCaseRequest,
        ListCorrelationCasesQuery, ReassignCaseRequest, RejectCaseRequest,
    },
    router::GovernanceState,
    services::CorrelationCaseListResponse,
};

/// List all correlation cases for manual review
#[utoipa::path(
    get,
    path = "/governance/correlation/cases",
    tag = "Governance - Correlation Review",
    params(ListCorrelationCasesQuery),
    responses(
        (status = 200, description = "Correlation cases retrieved", body = CorrelationCaseListResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_correlation_cases(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListCorrelationCasesQuery>,
) -> ApiResult<Json<CorrelationCaseListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let response = state
        .correlation_case_service
        .list_cases(tenant_id, &query)
        .await?;

    Ok(Json(response))
}

/// Get detailed information about a specific correlation case
#[utoipa::path(
    get,
    path = "/governance/correlation/cases/{case_id}",
    tag = "Governance - Correlation Review",
    params(
        ("case_id" = Uuid, Path, description = "Correlation case ID")
    ),
    responses(
        (status = 200, description = "Correlation case details retrieved", body = CorrelationCaseDetailResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Case not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_correlation_case(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(case_id): Path<Uuid>,
) -> ApiResult<Json<CorrelationCaseDetailResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let response = state
        .correlation_case_service
        .get_case(tenant_id, case_id)
        .await?;

    Ok(Json(response))
}

/// Confirm a correlation case by selecting a matching candidate
#[utoipa::path(
    post,
    path = "/governance/correlation/cases/{case_id}/confirm",
    tag = "Governance - Correlation Review",
    params(
        ("case_id" = Uuid, Path, description = "Correlation case ID")
    ),
    request_body = ConfirmCaseRequest,
    responses(
        (status = 200, description = "Correlation case confirmed", body = CorrelationCaseDetailResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Case not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn confirm_correlation_case(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(case_id): Path<Uuid>,
    Json(request): Json<ConfirmCaseRequest>,
) -> ApiResult<Json<CorrelationCaseDetailResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let response = state
        .correlation_case_service
        .confirm_case(
            tenant_id,
            case_id,
            request.candidate_id,
            user_id,
            request.reason,
        )
        .await?;

    Ok(Json(response))
}

/// Reject a correlation case (no match found)
#[utoipa::path(
    post,
    path = "/governance/correlation/cases/{case_id}/reject",
    tag = "Governance - Correlation Review",
    params(
        ("case_id" = Uuid, Path, description = "Correlation case ID")
    ),
    request_body = RejectCaseRequest,
    responses(
        (status = 200, description = "Correlation case rejected", body = CorrelationCaseDetailResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Case not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn reject_correlation_case(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(case_id): Path<Uuid>,
    Json(request): Json<RejectCaseRequest>,
) -> ApiResult<Json<CorrelationCaseDetailResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let response = state
        .correlation_case_service
        .reject_case(tenant_id, case_id, user_id, request.reason)
        .await?;

    Ok(Json(response))
}

/// Create a new identity from a correlation case
#[utoipa::path(
    post,
    path = "/governance/correlation/cases/{case_id}/create-identity",
    tag = "Governance - Correlation Review",
    params(
        ("case_id" = Uuid, Path, description = "Correlation case ID")
    ),
    request_body = CreateIdentityFromCaseRequest,
    responses(
        (status = 200, description = "Identity created from case", body = CorrelationCaseDetailResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Case not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_identity_from_case(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(case_id): Path<Uuid>,
    Json(request): Json<CreateIdentityFromCaseRequest>,
) -> ApiResult<Json<CorrelationCaseDetailResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let response = state
        .correlation_case_service
        .create_identity_from_case(tenant_id, case_id, user_id, request.reason)
        .await?;

    Ok(Json(response))
}

/// Reassign a correlation case to another reviewer
#[utoipa::path(
    post,
    path = "/governance/correlation/cases/{case_id}/reassign",
    tag = "Governance - Correlation Review",
    params(
        ("case_id" = Uuid, Path, description = "Correlation case ID")
    ),
    request_body = ReassignCaseRequest,
    responses(
        (status = 200, description = "Correlation case reassigned", body = CorrelationCaseDetailResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Case not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn reassign_correlation_case(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(case_id): Path<Uuid>,
    Json(request): Json<ReassignCaseRequest>,
) -> ApiResult<Json<CorrelationCaseDetailResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let response = state
        .correlation_case_service
        .reassign_case(tenant_id, case_id, request.assigned_to, request.reason)
        .await?;

    Ok(Json(response))
}
