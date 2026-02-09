//! HTTP handlers for License Entitlement Link management (F065).
//!
//! Provides endpoints for managing license-entitlement links including
//! CRUD operations and enabling/disabling links.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;
use xavyo_auth::JwtClaims;

use crate::{
    error::{ApiGovernanceError, ApiResult},
    models::license::{
        CreateLicenseEntitlementLinkRequest, EntitlementLinkListResponse,
        LicenseEntitlementLinkResponse, ListEntitlementLinksParams,
    },
    router::GovernanceState,
};

/// Request body for enabling/disabling a link.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SetLinkEnabledRequest {
    pub enabled: bool,
}

/// List license-entitlement links with optional filtering.
#[utoipa::path(
    get,
    path = "/governance/license-entitlement-links",
    tag = "Governance - License Management",
    params(
        ("license_pool_id" = Option<Uuid>, Query, description = "Filter by license pool"),
        ("entitlement_id" = Option<Uuid>, Query, description = "Filter by entitlement"),
        ("enabled" = Option<bool>, Query, description = "Filter by enabled status"),
        ("limit" = Option<i64>, Query, description = "Maximum results to return (default: 20, max: 100)"),
        ("offset" = Option<i64>, Query, description = "Results to skip for pagination")
    ),
    responses(
        (status = 200, description = "Entitlement links retrieved", body = EntitlementLinkListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_links(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<ListEntitlementLinksParams>,
) -> ApiResult<Json<EntitlementLinkListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .license_entitlement_service
        .list_links(tenant_id, params)
        .await?;

    Ok(Json(result))
}

/// Get a license-entitlement link by ID.
#[utoipa::path(
    get,
    path = "/governance/license-entitlement-links/{id}",
    tag = "Governance - License Management",
    params(
        ("id" = Uuid, Path, description = "License entitlement link ID")
    ),
    responses(
        (status = 200, description = "Entitlement link retrieved", body = LicenseEntitlementLinkResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Entitlement link not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_link(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<LicenseEntitlementLinkResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .license_entitlement_service
        .get_link_required(tenant_id, id)
        .await?;

    Ok(Json(result))
}

/// Create a new license-entitlement link.
///
/// Links a license pool to an entitlement so that licenses are automatically
/// allocated/deallocated when the entitlement is granted/revoked.
#[utoipa::path(
    post,
    path = "/governance/license-entitlement-links",
    tag = "Governance - License Management",
    request_body = CreateLicenseEntitlementLinkRequest,
    responses(
        (status = 201, description = "Entitlement link created", body = LicenseEntitlementLinkResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Pool or entitlement not found"),
        (status = 409, description = "Link already exists for this pool-entitlement pair"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_link(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateLicenseEntitlementLinkRequest>,
) -> ApiResult<(StatusCode, Json<LicenseEntitlementLinkResponse>)> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .license_entitlement_service
        .create_link(tenant_id, user_id, request)
        .await?;

    Ok((StatusCode::CREATED, Json(result)))
}

/// Delete a license-entitlement link.
///
/// Removes the link between a license pool and an entitlement.
/// Existing assignments created via this link are not affected.
#[utoipa::path(
    delete,
    path = "/governance/license-entitlement-links/{id}",
    tag = "Governance - License Management",
    params(
        ("id" = Uuid, Path, description = "License entitlement link ID")
    ),
    responses(
        (status = 204, description = "Entitlement link deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Entitlement link not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_link(
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
        .license_entitlement_service
        .delete_link(tenant_id, id, user_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Enable or disable a license-entitlement link.
///
/// When disabled, the link will not be considered during automatic
/// license allocation for the linked entitlement.
#[utoipa::path(
    put,
    path = "/governance/license-entitlement-links/{id}/enabled",
    tag = "Governance - License Management",
    params(
        ("id" = Uuid, Path, description = "License entitlement link ID")
    ),
    request_body = SetLinkEnabledRequest,
    responses(
        (status = 200, description = "Entitlement link enabled/disabled", body = LicenseEntitlementLinkResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Entitlement link not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn set_link_enabled(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<SetLinkEnabledRequest>,
) -> ApiResult<Json<LicenseEntitlementLinkResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .license_entitlement_service
        .set_link_enabled(tenant_id, id, request.enabled, user_id)
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
