//! Entitlement handlers for governance API.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;
use xavyo_db::models::{CreateGovEntitlement, UpdateGovEntitlement};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    validate_gdpr_create, validate_gdpr_update, CreateEntitlementRequest, EntitlementListResponse,
    EntitlementResponse, GdprReport, ListEntitlementsQuery, UpdateEntitlementRequest,
    UserDataProtectionSummary,
};
use crate::router::GovernanceState;

/// List entitlements with optional filtering and pagination.
#[utoipa::path(
    get,
    path = "/governance/entitlements",
    tag = "Governance - Entitlements",
    params(ListEntitlementsQuery),
    responses(
        (status = 200, description = "List of entitlements", body = EntitlementListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_entitlements(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListEntitlementsQuery>,
) -> ApiResult<Json<EntitlementListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let (entitlements, total) = state
        .entitlement_service
        .list_entitlements(
            tenant_id,
            query.application_id,
            query.status,
            query.risk_level,
            query.owner_id,
            query.classification,
            query.limit,
            query.offset,
        )
        .await?;

    Ok(Json(EntitlementListResponse {
        items: entitlements.into_iter().map(Into::into).collect(),
        total,
        limit: query.limit,
        offset: query.offset,
    }))
}

/// Get an entitlement by ID.
#[utoipa::path(
    get,
    path = "/governance/entitlements/{id}",
    tag = "Governance - Entitlements",
    params(
        ("id" = Uuid, Path, description = "Entitlement ID")
    ),
    responses(
        (status = 200, description = "Entitlement details", body = EntitlementResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Entitlement not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_entitlement(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<EntitlementResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let entitlement = state
        .entitlement_service
        .get_entitlement(tenant_id, id)
        .await?;

    Ok(Json(entitlement.into()))
}

/// Create a new entitlement.
#[utoipa::path(
    post,
    path = "/governance/entitlements",
    tag = "Governance - Entitlements",
    request_body = CreateEntitlementRequest,
    responses(
        (status = 201, description = "Entitlement created", body = EntitlementResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Application not found"),
        (status = 409, description = "Entitlement name already exists"),
        (status = 412, description = "Application is inactive"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_entitlement(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateEntitlementRequest>,
) -> ApiResult<(StatusCode, Json<EntitlementResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    request.validate()?;

    // Validate GDPR business rules
    validate_gdpr_create(
        request.data_protection_classification,
        request.legal_basis,
        request.retention_period_days,
    )
    .map_err(ApiGovernanceError::Validation)?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = CreateGovEntitlement {
        application_id: request.application_id,
        name: request.name,
        description: request.description,
        risk_level: request.risk_level,
        owner_id: request.owner_id,
        external_id: request.external_id,
        metadata: request.metadata,
        is_delegable: request.is_delegable.unwrap_or(true),
        data_protection_classification: request.data_protection_classification.unwrap_or_default(),
        legal_basis: request.legal_basis,
        retention_period_days: request.retention_period_days,
        data_controller: request.data_controller,
        data_processor: request.data_processor,
        purposes: request.purposes,
    };

    let entitlement = state
        .entitlement_service
        .create_entitlement(tenant_id, input)
        .await?;

    Ok((StatusCode::CREATED, Json(entitlement.into())))
}

/// Update an entitlement.
#[utoipa::path(
    put,
    path = "/governance/entitlements/{id}",
    tag = "Governance - Entitlements",
    params(
        ("id" = Uuid, Path, description = "Entitlement ID")
    ),
    request_body = UpdateEntitlementRequest,
    responses(
        (status = 200, description = "Entitlement updated", body = EntitlementResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Entitlement not found"),
        (status = 409, description = "Entitlement name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_entitlement(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateEntitlementRequest>,
) -> ApiResult<Json<EntitlementResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Fetch existing entitlement to get current classification for validation
    let existing = state
        .entitlement_service
        .get_entitlement(tenant_id, id)
        .await?;

    // Validate GDPR business rules against effective classification
    validate_gdpr_update(
        request.data_protection_classification,
        existing.data_protection_classification,
        request.legal_basis,
        request.retention_period_days,
    )
    .map_err(ApiGovernanceError::Validation)?;

    let input = UpdateGovEntitlement {
        name: request.name,
        description: request.description,
        risk_level: request.risk_level,
        status: request.status,
        owner_id: request.owner_id,
        external_id: request.external_id,
        metadata: request.metadata,
        is_delegable: request.is_delegable,
        data_protection_classification: request.data_protection_classification,
        legal_basis: request.legal_basis,
        retention_period_days: request.retention_period_days,
        data_controller: request.data_controller,
        data_processor: request.data_processor,
        purposes: request.purposes,
    };

    let entitlement = state
        .entitlement_service
        .update_entitlement(tenant_id, id, input)
        .await?;

    Ok(Json(entitlement.into()))
}

/// Delete an entitlement.
#[utoipa::path(
    delete,
    path = "/governance/entitlements/{id}",
    tag = "Governance - Entitlements",
    params(
        ("id" = Uuid, Path, description = "Entitlement ID")
    ),
    responses(
        (status = 204, description = "Entitlement deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Entitlement not found"),
        (status = 412, description = "Cannot delete entitlement with assignments"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_entitlement(
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
        .entitlement_service
        .delete_entitlement(tenant_id, id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Generate a GDPR compliance report for the tenant.
#[utoipa::path(
    get,
    path = "/governance/gdpr/report",
    tag = "Governance - GDPR",
    responses(
        (status = 200, description = "GDPR compliance report", body = GdprReport),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn gdpr_report(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<GdprReport>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let report = state.gdpr_report_service.generate_report(tenant_id).await?;

    Ok(Json(report))
}

/// Get per-user data protection summary.
#[utoipa::path(
    get,
    path = "/governance/gdpr/users/{user_id}/data-protection",
    tag = "Governance - GDPR",
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User data protection summary", body = UserDataProtectionSummary),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn user_data_protection(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(user_id): Path<Uuid>,
) -> ApiResult<Json<UserDataProtectionSummary>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let summary = state
        .gdpr_report_service
        .get_user_data_protection_summary(tenant_id, user_id)
        .await?;

    Ok(Json(summary))
}
