//! HTTP handlers for IP restriction endpoints (F028).
//!
//! Admin endpoints for managing IP-based access control:
//! - GET /admin/ip-restrictions/settings
//! - PUT /admin/ip-restrictions/settings
//! - GET /admin/ip-restrictions/rules
//! - POST /admin/ip-restrictions/rules
//! - GET /admin/ip-restrictions/rules/:id
//! - PUT /admin/ip-restrictions/rules/:id
//! - DELETE /admin/ip-restrictions/rules/:id
//! - POST /admin/ip-restrictions/validate

use axum::{
    extract::{Path, Query},
    http::StatusCode,
    Extension, Json,
};
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;

use crate::error::ApiAuthError;
use crate::models::{
    CreateIpRuleRequest, IpRuleResponse, IpSettingsResponse, ListRulesQuery, ListRulesResponse,
    UpdateIpRuleRequest, UpdateIpSettingsRequest, ValidateIpRequest, ValidateIpResponse,
};
use crate::services::IpRestrictionService;

// ============================================================================
// Settings Handlers
// ============================================================================

/// Retrieve current IP restriction settings for the tenant.
#[utoipa::path(
    get,
    path = "/admin/ip-restrictions/settings",
    responses(
        (status = 200, description = "IP settings retrieved", body = IpSettingsResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "IP Restrictions"
)]
pub async fn get_ip_settings(
    Extension(tenant_id): Extension<TenantId>,
    Extension(ip_service): Extension<Arc<IpRestrictionService>>,
) -> Result<Json<IpSettingsResponse>, ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let settings = ip_service.get_settings(tenant_uuid).await?;
    Ok(Json(settings))
}

/// Update IP restriction settings for the tenant.
#[utoipa::path(
    put,
    path = "/admin/ip-restrictions/settings",
    request_body = UpdateIpSettingsRequest,
    responses(
        (status = 200, description = "IP settings updated", body = IpSettingsResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "IP Restrictions"
)]
pub async fn update_ip_settings(
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Extension(ip_service): Extension<Arc<IpRestrictionService>>,
    Json(request): Json<UpdateIpSettingsRequest>,
) -> Result<Json<IpSettingsResponse>, ApiAuthError> {
    if !claims.has_role("admin") {
        return Err(ApiAuthError::PermissionDenied(
            "Admin role required".to_string(),
        ));
    }
    let tenant_uuid = *tenant_id.as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).ok();

    let settings = ip_service
        .update_settings(tenant_uuid, request, user_id)
        .await?;

    Ok(Json(settings))
}

// ============================================================================
// Rules Handlers
// ============================================================================

/// List all IP restriction rules for the tenant.
#[utoipa::path(
    get,
    path = "/admin/ip-restrictions/rules",
    params(ListRulesQuery),
    responses(
        (status = 200, description = "List of IP rules", body = ListRulesResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "IP Restrictions"
)]
pub async fn list_ip_rules(
    Extension(tenant_id): Extension<TenantId>,
    Extension(ip_service): Extension<Arc<IpRestrictionService>>,
    Query(query): Query<ListRulesQuery>,
) -> Result<Json<ListRulesResponse>, ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let rules = ip_service.list_rules(tenant_uuid, query).await?;

    Ok(Json(ListRulesResponse { rules }))
}

/// Create a new IP restriction rule.
#[utoipa::path(
    post,
    path = "/admin/ip-restrictions/rules",
    request_body = CreateIpRuleRequest,
    responses(
        (status = 201, description = "IP rule created", body = IpRuleResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "IP Restrictions"
)]
pub async fn create_ip_rule(
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Extension(ip_service): Extension<Arc<IpRestrictionService>>,
    Json(request): Json<CreateIpRuleRequest>,
) -> Result<(StatusCode, Json<IpRuleResponse>), ApiAuthError> {
    if !claims.has_role("admin") {
        return Err(ApiAuthError::PermissionDenied(
            "Admin role required".to_string(),
        ));
    }
    // Validate request
    request
        .validate()
        .map_err(|e| ApiAuthError::Validation(e.to_string()))?;

    let tenant_uuid = *tenant_id.as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).ok();

    let rule = ip_service
        .create_rule(tenant_uuid, request, user_id)
        .await?;

    Ok((StatusCode::CREATED, Json(rule)))
}

/// Get a specific IP restriction rule.
#[utoipa::path(
    get,
    path = "/admin/ip-restrictions/rules/{id}",
    params(
        ("id" = Uuid, Path, description = "Rule ID"),
    ),
    responses(
        (status = 200, description = "IP rule retrieved", body = IpRuleResponse),
        (status = 404, description = "Rule not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "IP Restrictions"
)]
pub async fn get_ip_rule(
    Extension(tenant_id): Extension<TenantId>,
    Extension(ip_service): Extension<Arc<IpRestrictionService>>,
    Path(rule_id): Path<Uuid>,
) -> Result<Json<IpRuleResponse>, ApiAuthError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let rule = ip_service.get_rule(tenant_uuid, rule_id).await?;

    Ok(Json(rule))
}

/// Update an existing IP restriction rule.
#[utoipa::path(
    put,
    path = "/admin/ip-restrictions/rules/{id}",
    params(
        ("id" = Uuid, Path, description = "Rule ID"),
    ),
    request_body = UpdateIpRuleRequest,
    responses(
        (status = 200, description = "IP rule updated", body = IpRuleResponse),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Rule not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "IP Restrictions"
)]
pub async fn update_ip_rule(
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Extension(ip_service): Extension<Arc<IpRestrictionService>>,
    Path(rule_id): Path<Uuid>,
    Json(request): Json<UpdateIpRuleRequest>,
) -> Result<Json<IpRuleResponse>, ApiAuthError> {
    if !claims.has_role("admin") {
        return Err(ApiAuthError::PermissionDenied(
            "Admin role required".to_string(),
        ));
    }
    // Validate request
    request
        .validate()
        .map_err(|e| ApiAuthError::Validation(e.to_string()))?;

    let tenant_uuid = *tenant_id.as_uuid();
    let rule = ip_service
        .update_rule(tenant_uuid, rule_id, request)
        .await?;

    Ok(Json(rule))
}

/// Delete an IP restriction rule.
#[utoipa::path(
    delete,
    path = "/admin/ip-restrictions/rules/{id}",
    params(
        ("id" = Uuid, Path, description = "Rule ID"),
    ),
    responses(
        (status = 204, description = "IP rule deleted"),
        (status = 404, description = "Rule not found"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "IP Restrictions"
)]
pub async fn delete_ip_rule(
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Extension(ip_service): Extension<Arc<IpRestrictionService>>,
    Path(rule_id): Path<Uuid>,
) -> Result<StatusCode, ApiAuthError> {
    if !claims.has_role("admin") {
        return Err(ApiAuthError::PermissionDenied(
            "Admin role required".to_string(),
        ));
    }
    let tenant_uuid = *tenant_id.as_uuid();
    ip_service.delete_rule(tenant_uuid, rule_id).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Validate Handler
// ============================================================================

/// Validate an IP address against current rules (for testing).
#[utoipa::path(
    post,
    path = "/admin/ip-restrictions/validate",
    request_body = ValidateIpRequest,
    responses(
        (status = 200, description = "IP validation result", body = ValidateIpResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not authorized"),
    ),
    security(("bearerAuth" = [])),
    tag = "IP Restrictions"
)]
pub async fn validate_ip(
    Extension(tenant_id): Extension<TenantId>,
    Extension(ip_service): Extension<Arc<IpRestrictionService>>,
    Json(request): Json<ValidateIpRequest>,
) -> Result<Json<ValidateIpResponse>, ApiAuthError> {
    // Validate request
    request
        .validate()
        .map_err(|e| ApiAuthError::Validation(e.to_string()))?;

    let tenant_uuid = *tenant_id.as_uuid();
    let result = ip_service
        .validate_ip(tenant_uuid, &request.ip_address, request.role.as_deref())
        .await?;

    Ok(Json(result))
}
