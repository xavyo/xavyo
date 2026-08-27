//! HTTP handlers for SCIM target management (F087).
//!
//! Provides CRUD + health-check endpoints for SCIM 2.0 outbound provisioning targets.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use serde::Deserialize;
use utoipa::IntoParams;
use uuid::Uuid;
use xavyo_auth::JwtClaims;

use crate::error::{ConnectorApiError, Result};
use crate::services::{
    CreateScimTargetRequest, HealthCheckResponse, ScimTargetListResponse, ScimTargetResponse,
    ScimTargetService, UpdateScimTargetRequest,
};

/// State for SCIM target handlers.
#[derive(Clone)]
pub struct ScimTargetState {
    pub scim_target_service: std::sync::Arc<ScimTargetService>,
}

/// Query parameters for listing SCIM targets.
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListScimTargetsQuery {
    pub status: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

/// Extract `tenant_id` from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ConnectorApiError::Unauthorized {
            message: "Missing tenant_id in claims".to_string(),
        })
}

/// POST /admin/scim-targets — Create a new SCIM target.
#[utoipa::path(
    post,
    path = "/admin/scim-targets",
    tag = "SCIM Targets",
    request_body = CreateScimTargetRequest,
    responses(
        (status = 201, description = "SCIM target created", body = ScimTargetResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearerAuth" = []))
)]
pub async fn create_scim_target(
    State(state): State<ScimTargetState>,
    Extension(claims): Extension<JwtClaims>,
    Json(body): Json<CreateScimTargetRequest>,
) -> Result<(StatusCode, Json<ScimTargetResponse>)> {
    if !claims.has_role("admin") {
        return Err(ConnectorApiError::Forbidden);
    }
    let tenant_id = extract_tenant_id(&claims)?;
    let target = state
        .scim_target_service
        .create_target(tenant_id, body)
        .await?;
    Ok((StatusCode::CREATED, Json(target)))
}

/// GET /admin/scim-targets — List SCIM targets.
#[utoipa::path(
    get,
    path = "/admin/scim-targets",
    tag = "SCIM Targets",
    params(ListScimTargetsQuery),
    responses(
        (status = 200, description = "List of SCIM targets", body = ScimTargetListResponse),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearerAuth" = []))
)]
pub async fn list_scim_targets(
    State(state): State<ScimTargetState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListScimTargetsQuery>,
) -> Result<Json<ScimTargetListResponse>> {
    if !claims.has_role("admin") {
        return Err(ConnectorApiError::Forbidden);
    }
    let tenant_id = extract_tenant_id(&claims)?;
    let limit = query.limit.clamp(1, 100);
    let offset = query.offset.max(0);
    let status = parse_optional_scim_target_status(query.status.as_deref())?;
    let response = state
        .scim_target_service
        .list_targets(tenant_id, status, limit, offset)
        .await?;
    Ok(Json(response))
}

/// GET /admin/scim-targets/:id — Get a SCIM target by ID.
#[utoipa::path(
    get,
    path = "/admin/scim-targets/{target_id}",
    tag = "SCIM Targets",
    params(("target_id" = Uuid, Path, description = "SCIM target ID")),
    responses(
        (status = 200, description = "SCIM target details", body = ScimTargetResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Target not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn get_scim_target(
    State(state): State<ScimTargetState>,
    Extension(claims): Extension<JwtClaims>,
    Path(target_id): Path<Uuid>,
) -> Result<Json<ScimTargetResponse>> {
    if !claims.has_role("admin") {
        return Err(ConnectorApiError::Forbidden);
    }
    let tenant_id = extract_tenant_id(&claims)?;
    let target = state
        .scim_target_service
        .get_target(tenant_id, target_id)
        .await?;
    Ok(Json(target))
}

/// PUT /admin/scim-targets/:id — Update a SCIM target.
#[utoipa::path(
    put,
    path = "/admin/scim-targets/{target_id}",
    tag = "SCIM Targets",
    params(("target_id" = Uuid, Path, description = "SCIM target ID")),
    request_body = UpdateScimTargetRequest,
    responses(
        (status = 200, description = "SCIM target updated", body = ScimTargetResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Target not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn update_scim_target(
    State(state): State<ScimTargetState>,
    Extension(claims): Extension<JwtClaims>,
    Path(target_id): Path<Uuid>,
    Json(body): Json<UpdateScimTargetRequest>,
) -> Result<Json<ScimTargetResponse>> {
    if !claims.has_role("admin") {
        return Err(ConnectorApiError::Forbidden);
    }
    let tenant_id = extract_tenant_id(&claims)?;
    let target = state
        .scim_target_service
        .update_target(tenant_id, target_id, body)
        .await?;
    Ok(Json(target))
}

/// DELETE /admin/scim-targets/:id — Delete a SCIM target.
#[utoipa::path(
    delete,
    path = "/admin/scim-targets/{target_id}",
    tag = "SCIM Targets",
    params(("target_id" = Uuid, Path, description = "SCIM target ID")),
    responses(
        (status = 204, description = "SCIM target deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Target not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn delete_scim_target(
    State(state): State<ScimTargetState>,
    Extension(claims): Extension<JwtClaims>,
    Path(target_id): Path<Uuid>,
) -> Result<StatusCode> {
    if !claims.has_role("admin") {
        return Err(ConnectorApiError::Forbidden);
    }
    let tenant_id = extract_tenant_id(&claims)?;
    state
        .scim_target_service
        .delete_target(tenant_id, target_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// POST /admin/scim-targets/:id/health-check — Perform a health check.
#[utoipa::path(
    post,
    path = "/admin/scim-targets/{target_id}/health-check",
    tag = "SCIM Targets",
    params(("target_id" = Uuid, Path, description = "SCIM target ID")),
    responses(
        (status = 200, description = "Health check result", body = HealthCheckResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Target not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn health_check_scim_target(
    State(state): State<ScimTargetState>,
    Extension(claims): Extension<JwtClaims>,
    Path(target_id): Path<Uuid>,
) -> Result<Json<HealthCheckResponse>> {
    if !claims.has_role("admin") {
        return Err(ConnectorApiError::Forbidden);
    }
    let tenant_id = extract_tenant_id(&claims)?;
    let result = state
        .scim_target_service
        .health_check(tenant_id, target_id)
        .await?;
    Ok(Json(result))
}

/// Invalid SCIM target status filters must not silently list every target.
fn parse_optional_scim_target_status(status: Option<&str>) -> Result<Option<&str>> {
    match status {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) if matches!(s, "active" | "disabled" | "unreachable") => Ok(Some(s)),
        Some(s) => Err(ConnectorApiError::Validation(format!(
            "Invalid SCIM target status '{s}'. Must be one of: active, disabled, unreachable"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_scim_target_status_does_not_list_all_targets() {
        assert_eq!(parse_optional_scim_target_status(None).unwrap(), None);
        assert_eq!(
            parse_optional_scim_target_status(Some("active")).unwrap(),
            Some("active")
        );
        assert!(parse_optional_scim_target_status(Some("bogus")).is_err());
        let src = include_str!("scim_targets.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("parse_optional_scim_target_status(")
                && !production.contains("query.status.as_deref(), limit, offset"),
            "invalid SCIM target status must be 400, not an unfiltered list"
        );
    }
}
