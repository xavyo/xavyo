//! Service account handlers for managing non-human identities.

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
    CertifyServiceAccountResponse, ListServiceAccountsQuery, RegisterServiceAccountRequest,
    ServiceAccountListResponse, ServiceAccountResponse, ServiceAccountSummary,
    UpdateServiceAccountRequest,
};
use crate::router::GovernanceState;

/// List service accounts with optional filtering.
#[utoipa::path(
    get,
    path = "/governance/service-accounts",
    tag = "Governance - Service Accounts",
    params(ListServiceAccountsQuery),
    responses(
        (status = 200, description = "List of service accounts", body = ServiceAccountListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_service_accounts(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListServiceAccountsQuery>,
) -> ApiResult<Json<ServiceAccountListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .service_account_service
        .list(tenant_id, &query)
        .await?;

    Ok(Json(result))
}

/// Get service account summary statistics.
#[utoipa::path(
    get,
    path = "/governance/service-accounts/summary",
    tag = "Governance - Service Accounts",
    responses(
        (status = 200, description = "Service account summary", body = ServiceAccountSummary),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_service_account_summary(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<ServiceAccountSummary>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let summary = state.service_account_service.get_summary(tenant_id).await?;

    Ok(Json(summary))
}

/// Get a service account by ID.
#[utoipa::path(
    get,
    path = "/governance/service-accounts/{id}",
    tag = "Governance - Service Accounts",
    params(
        ("id" = Uuid, Path, description = "Service account ID")
    ),
    responses(
        (status = 200, description = "Service account details", body = ServiceAccountResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Service account not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_service_account(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ServiceAccountResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let account = state.service_account_service.get(tenant_id, id).await?;

    Ok(Json(account))
}

/// Register a new service account.
#[utoipa::path(
    post,
    path = "/governance/service-accounts",
    tag = "Governance - Service Accounts",
    request_body = RegisterServiceAccountRequest,
    responses(
        (status = 201, description = "Service account registered", body = ServiceAccountResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "User already registered as service account"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn register_service_account(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<RegisterServiceAccountRequest>,
) -> ApiResult<(StatusCode, Json<ServiceAccountResponse>)> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let account = state
        .service_account_service
        .register(tenant_id, request)
        .await?;

    Ok((StatusCode::CREATED, Json(account)))
}

/// Update a service account.
#[utoipa::path(
    put,
    path = "/governance/service-accounts/{id}",
    tag = "Governance - Service Accounts",
    params(
        ("id" = Uuid, Path, description = "Service account ID")
    ),
    request_body = UpdateServiceAccountRequest,
    responses(
        (status = 200, description = "Service account updated", body = ServiceAccountResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Service account not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_service_account(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateServiceAccountRequest>,
) -> ApiResult<Json<ServiceAccountResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let account = state
        .service_account_service
        .update(tenant_id, id, request)
        .await?;

    Ok(Json(account))
}

/// Certify a service account ownership.
#[utoipa::path(
    post,
    path = "/governance/service-accounts/{id}/certify",
    tag = "Governance - Service Accounts",
    params(
        ("id" = Uuid, Path, description = "Service account ID")
    ),
    responses(
        (status = 200, description = "Service account certified", body = CertifyServiceAccountResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Service account not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn certify_service_account(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<CertifyServiceAccountResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let certified_by =
        Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let account = state
        .service_account_service
        .certify(tenant_id, id, certified_by)
        .await?;

    Ok(Json(CertifyServiceAccountResponse {
        account,
        message: "Service account ownership certified successfully".to_string(),
    }))
}

/// Suspend a service account.
#[utoipa::path(
    post,
    path = "/governance/service-accounts/{id}/suspend",
    tag = "Governance - Service Accounts",
    params(
        ("id" = Uuid, Path, description = "Service account ID")
    ),
    responses(
        (status = 200, description = "Service account suspended", body = ServiceAccountResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Service account not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn suspend_service_account(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ServiceAccountResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let account = state.service_account_service.suspend(tenant_id, id).await?;

    Ok(Json(account))
}

/// Reactivate a suspended service account.
#[utoipa::path(
    post,
    path = "/governance/service-accounts/{id}/reactivate",
    tag = "Governance - Service Accounts",
    params(
        ("id" = Uuid, Path, description = "Service account ID")
    ),
    responses(
        (status = 200, description = "Service account reactivated", body = ServiceAccountResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Service account not found or not suspended"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn reactivate_service_account(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ServiceAccountResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let account = state
        .service_account_service
        .reactivate(tenant_id, id)
        .await?;

    Ok(Json(account))
}

/// Unregister (delete) a service account.
#[utoipa::path(
    delete,
    path = "/governance/service-accounts/{id}",
    tag = "Governance - Service Accounts",
    params(
        ("id" = Uuid, Path, description = "Service account ID")
    ),
    responses(
        (status = 204, description = "Service account unregistered"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Service account not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn unregister_service_account(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state
        .service_account_service
        .unregister(tenant_id, id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Mark expired service accounts.
#[utoipa::path(
    post,
    path = "/governance/service-accounts/mark-expired",
    tag = "Governance - Service Accounts",
    responses(
        (status = 200, description = "Number of accounts marked expired", body = u64),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn mark_expired_accounts(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<u64>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let count = state
        .service_account_service
        .mark_expired(tenant_id)
        .await?;

    Ok(Json(count))
}
