//! HTTP handlers for SCIM provisioning log browsing (F087 - US6).
//!
//! Provides endpoints to list and view provisioning operation log entries.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::models::{ScimProvisioningLog, ScimTarget};

use crate::error::{ConnectorApiError, Result};
use crate::handlers::scim_targets::ScimTargetState;

/// Query parameters for listing provisioning log entries.
#[derive(Debug, Deserialize, IntoParams)]
pub struct ListProvisioningLogQuery {
    pub resource_type: Option<String>,
    pub operation_type: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

/// Response for provisioning log listing.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProvisioningLogListResponse {
    pub target_id: Uuid,
    pub items: Vec<ScimProvisioningLog>,
    pub total_count: i64,
    pub limit: i64,
    pub offset: i64,
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

/// GET /admin/scim-targets/:id/log — List provisioning log entries.
#[utoipa::path(
    get,
    path = "/admin/scim-targets/{target_id}/log",
    tag = "SCIM Target Logs",
    params(
        ("target_id" = Uuid, Path, description = "SCIM target ID"),
        ListProvisioningLogQuery
    ),
    responses(
        (status = 200, description = "Provisioning log list", body = ProvisioningLogListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Target not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn list_provisioning_log(
    State(state): State<ScimTargetState>,
    Extension(claims): Extension<JwtClaims>,
    Path(target_id): Path<Uuid>,
    Query(query): Query<ListProvisioningLogQuery>,
) -> Result<Json<ProvisioningLogListResponse>> {
    if !claims.has_role("admin") {
        return Err(ConnectorApiError::Forbidden);
    }
    let tenant_id = extract_tenant_id(&claims)?;
    let pool = state.scim_target_service.pool();

    // Verify target exists.
    ScimTarget::get_by_id(pool, tenant_id, target_id)
        .await?
        .ok_or_else(|| ConnectorApiError::NotFound {
            resource: "scim_target".to_string(),
            id: target_id.to_string(),
        })?;

    let limit = query.limit.min(100);
    let offset = query.offset.max(0);
    let resource_type = parse_optional_scim_log_resource_type(query.resource_type.as_deref())?;
    let operation_type = parse_optional_scim_operation_type(query.operation_type.as_deref())?;

    let (items, total_count) = ScimProvisioningLog::list_by_target(
        pool,
        tenant_id,
        target_id,
        resource_type,
        operation_type,
        limit,
        offset,
    )
    .await?;

    Ok(Json(ProvisioningLogListResponse {
        target_id,
        items,
        total_count,
        limit,
        offset,
    }))
}

/// GET /admin/scim-targets/:id/log/:log_id — Get a single log entry with full details.
#[utoipa::path(
    get,
    path = "/admin/scim-targets/{target_id}/log/{log_id}",
    tag = "SCIM Target Logs",
    params(
        ("target_id" = Uuid, Path, description = "SCIM target ID"),
        ("log_id" = Uuid, Path, description = "Log entry ID")
    ),
    responses(
        (status = 200, description = "Log entry details", body = ScimProvisioningLog),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Target or log entry not found")
    ),
    security(("bearerAuth" = []))
)]
pub async fn get_log_detail(
    State(state): State<ScimTargetState>,
    Extension(claims): Extension<JwtClaims>,
    Path((target_id, log_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ScimProvisioningLog>> {
    if !claims.has_role("admin") {
        return Err(ConnectorApiError::Forbidden);
    }
    let tenant_id = extract_tenant_id(&claims)?;
    let pool = state.scim_target_service.pool();

    // Verify target exists.
    ScimTarget::get_by_id(pool, tenant_id, target_id)
        .await?
        .ok_or_else(|| ConnectorApiError::NotFound {
            resource: "scim_target".to_string(),
            id: target_id.to_string(),
        })?;

    let log_entry = ScimProvisioningLog::get_by_id(pool, tenant_id, log_id)
        .await?
        .ok_or_else(|| ConnectorApiError::NotFound {
            resource: "scim_provisioning_log".to_string(),
            id: log_id.to_string(),
        })?;

    // Verify the log belongs to the correct target.
    if log_entry.target_id != target_id {
        return Err(ConnectorApiError::NotFound {
            resource: "scim_provisioning_log".to_string(),
            id: log_id.to_string(),
        });
    }

    Ok(Json(log_entry))
}

/// Invalid SCIM log `resource_type` filters must not silently list every entry.
fn parse_optional_scim_log_resource_type(value: Option<&str>) -> Result<Option<&str>> {
    match value {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) if matches!(s, "User" | "Group") => Ok(Some(s)),
        Some(s) => Err(ConnectorApiError::Validation(format!(
            "Invalid SCIM log resource type '{s}'. Must be one of: User, Group"
        ))),
    }
}

/// Invalid SCIM log `operation_type` filters must not silently list every entry.
fn parse_optional_scim_operation_type(value: Option<&str>) -> Result<Option<&str>> {
    match value {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s)
            if matches!(
                s,
                "create"
                    | "update"
                    | "deprovision"
                    | "delete"
                    | "lookup"
                    | "create_conflict_resolved"
                    | "add_members"
                    | "remove_members"
            ) =>
        {
            Ok(Some(s))
        }
        Some(s) => Err(ConnectorApiError::Validation(format!(
            "Invalid SCIM operation type '{s}'. Must be one of: create, update, deprovision, delete, lookup, create_conflict_resolved, add_members, remove_members"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_scim_log_filters_do_not_list_all_entries() {
        assert_eq!(parse_optional_scim_log_resource_type(None).unwrap(), None);
        assert_eq!(
            parse_optional_scim_log_resource_type(Some("User")).unwrap(),
            Some("User")
        );
        assert!(parse_optional_scim_log_resource_type(Some("bogus")).is_err());
        assert_eq!(parse_optional_scim_operation_type(None).unwrap(), None);
        assert_eq!(
            parse_optional_scim_operation_type(Some("create")).unwrap(),
            Some("create")
        );
        assert!(parse_optional_scim_operation_type(Some("bogus")).is_err());
        let src = include_str!("scim_log.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("parse_optional_scim_log_resource_type(")
                && production.contains("parse_optional_scim_operation_type(")
                && !production.contains("query.resource_type.as_deref(),")
                && !production.contains("query.operation_type.as_deref(),"),
            "invalid SCIM log filters must be 400, not an unfiltered list"
        );
    }
}
