//! HTTP handlers for provisioning script CRUD operations (F066).
//!
//! Provides endpoints for managing provisioning scripts, their versions,
//! activation/deactivation, rollback, and version comparison.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::models::gov_script_types::GovScriptStatus;

use crate::{
    error::{ApiGovernanceError, ApiResult},
    models::script::{
        CreateScriptRequest, DiffChangeType, DiffLine, RollbackRequest, ScriptListParams,
        ScriptListResponse, ScriptResponse, ScriptVersionListResponse, ScriptVersionResponse,
        UpdateScriptBodyRequest, UpdateScriptRequest, VersionComparisonResponse,
    },
    router::GovernanceState,
};

// ============================================================================
// Helper functions to convert DB models to API models
// ============================================================================

/// Convert a DB `GovProvisioningScript` to an API `ScriptResponse`.
fn map_script(
    script: xavyo_db::models::gov_provisioning_script::GovProvisioningScript,
) -> ScriptResponse {
    let status = serde_json::to_value(script.status)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default();

    ScriptResponse {
        id: script.id,
        tenant_id: script.tenant_id,
        name: script.name,
        description: script.description,
        current_version: script.current_version,
        status,
        is_system: script.is_system,
        created_by: script.created_by,
        created_at: script.created_at,
        updated_at: script.updated_at,
    }
}

/// Convert a DB `GovScriptVersion` to an API `ScriptVersionResponse`.
fn map_version(
    version: xavyo_db::models::gov_script_version::GovScriptVersion,
) -> ScriptVersionResponse {
    ScriptVersionResponse {
        id: version.id,
        script_id: version.script_id,
        version_number: version.version_number,
        script_body: version.script_body,
        change_description: version.change_description,
        created_by: version.created_by,
        created_at: version.created_at,
    }
}

/// Parse a status string to `GovScriptStatus`.
fn parse_status(status: &str) -> Option<GovScriptStatus> {
    serde_json::from_value(serde_json::Value::String(status.to_string())).ok()
}

/// Query parameters for comparing two script versions.
#[derive(Debug, serde::Deserialize)]
pub struct CompareVersionsParams {
    pub from: i32,
    pub to: i32,
}

/// List provisioning scripts with optional filtering and pagination.
#[utoipa::path(
    get,
    path = "/governance/provisioning-scripts",
    tag = "Governance - Provisioning Scripts",
    params(ScriptListParams),
    responses(
        (status = 200, description = "Scripts retrieved", body = ScriptListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_scripts(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<ScriptListParams>,
) -> ApiResult<Json<ScriptListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let status = params.status.as_deref().and_then(parse_status);
    let page = params.page.unwrap_or(1).max(1);
    let page_size = params.page_size.unwrap_or(50).min(100);
    let offset = (page - 1) * page_size;

    let (scripts, total) = state
        .script_service
        .list_scripts(tenant_id, status, params.search, page_size, offset)
        .await?;

    Ok(Json(ScriptListResponse {
        scripts: scripts.into_iter().map(map_script).collect(),
        total,
    }))
}

/// Create a new provisioning script.
#[utoipa::path(
    post,
    path = "/governance/provisioning-scripts",
    tag = "Governance - Provisioning Scripts",
    request_body = CreateScriptRequest,
    responses(
        (status = 201, description = "Script created", body = ScriptResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_script(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(body): Json<CreateScriptRequest>,
) -> ApiResult<(StatusCode, Json<ScriptResponse>)> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let (script, _version) = state
        .script_service
        .create_script(
            tenant_id,
            body.name,
            body.description,
            "// New script".to_string(),
            actor_id,
        )
        .await?;

    let _ = state
        .script_audit_service
        .record_created(tenant_id, script.id, actor_id, &script.name)
        .await;

    Ok((StatusCode::CREATED, Json(map_script(script))))
}

/// Get a provisioning script by ID.
#[utoipa::path(
    get,
    path = "/governance/provisioning-scripts/{id}",
    tag = "Governance - Provisioning Scripts",
    params(
        ("id" = Uuid, Path, description = "Script ID")
    ),
    responses(
        (status = 200, description = "Script retrieved", body = ScriptResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Script not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_script(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ScriptResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let script = state.script_service.get_script(tenant_id, id).await?;

    Ok(Json(map_script(script)))
}

/// Update a provisioning script's metadata.
#[utoipa::path(
    put,
    path = "/governance/provisioning-scripts/{id}",
    tag = "Governance - Provisioning Scripts",
    params(
        ("id" = Uuid, Path, description = "Script ID")
    ),
    request_body = UpdateScriptRequest,
    responses(
        (status = 200, description = "Script updated", body = ScriptResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Script not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_script(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateScriptRequest>,
) -> ApiResult<Json<ScriptResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let script = state
        .script_service
        .update_script(tenant_id, id, body.name, body.description)
        .await?;

    let _ = state
        .script_audit_service
        .record_updated(
            tenant_id,
            id,
            actor_id,
            serde_json::json!({ "script_id": id }),
        )
        .await;

    Ok(Json(map_script(script)))
}

/// Delete a provisioning script.
#[utoipa::path(
    delete,
    path = "/governance/provisioning-scripts/{id}",
    tag = "Governance - Provisioning Scripts",
    params(
        ("id" = Uuid, Path, description = "Script ID")
    ),
    responses(
        (status = 204, description = "Script deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Script not found"),
        (status = 409, description = "Script has active bindings"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_script(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Fetch the script name before deletion for audit purposes.
    let script = state.script_service.get_script(tenant_id, id).await?;

    state.script_service.delete_script(tenant_id, id).await?;

    let _ = state
        .script_audit_service
        .record_deleted(tenant_id, id, actor_id, &script.name)
        .await;

    Ok(StatusCode::NO_CONTENT)
}

/// Activate a provisioning script.
#[utoipa::path(
    post,
    path = "/governance/provisioning-scripts/{id}/activate",
    tag = "Governance - Provisioning Scripts",
    params(
        ("id" = Uuid, Path, description = "Script ID")
    ),
    responses(
        (status = 200, description = "Script activated", body = ScriptResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Script not found"),
        (status = 409, description = "Script already active"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn activate_script(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ScriptResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let script = state.script_service.activate_script(tenant_id, id).await?;

    let _ = state
        .script_audit_service
        .record_activated(tenant_id, id, actor_id)
        .await;

    Ok(Json(map_script(script)))
}

/// Deactivate a provisioning script.
#[utoipa::path(
    post,
    path = "/governance/provisioning-scripts/{id}/deactivate",
    tag = "Governance - Provisioning Scripts",
    params(
        ("id" = Uuid, Path, description = "Script ID")
    ),
    responses(
        (status = 200, description = "Script deactivated", body = ScriptResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Script not found"),
        (status = 409, description = "Script already inactive"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn deactivate_script(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ScriptResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let script = state
        .script_service
        .deactivate_script(tenant_id, id)
        .await?;

    let _ = state
        .script_audit_service
        .record_deactivated(tenant_id, id, actor_id)
        .await;

    Ok(Json(map_script(script)))
}

/// List all versions of a provisioning script.
#[utoipa::path(
    get,
    path = "/governance/provisioning-scripts/{id}/versions",
    tag = "Governance - Provisioning Scripts",
    params(
        ("id" = Uuid, Path, description = "Script ID")
    ),
    responses(
        (status = 200, description = "Script versions retrieved", body = ScriptVersionListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Script not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_script_versions(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ScriptVersionListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let versions = state.script_service.list_versions(tenant_id, id).await?;
    let total = versions.len() as i64;

    Ok(Json(ScriptVersionListResponse {
        versions: versions.into_iter().map(map_version).collect(),
        total,
    }))
}

/// Get a specific version of a provisioning script.
#[utoipa::path(
    get,
    path = "/governance/provisioning-scripts/{script_id}/versions/{version_number}",
    tag = "Governance - Provisioning Scripts",
    params(
        ("script_id" = Uuid, Path, description = "Script ID"),
        ("version_number" = i32, Path, description = "Version number")
    ),
    responses(
        (status = 200, description = "Script version retrieved", body = ScriptVersionResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Script or version not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_script_version(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((script_id, version_number)): Path<(Uuid, i32)>,
) -> ApiResult<Json<ScriptVersionResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let version = state
        .script_service
        .get_version(tenant_id, script_id, version_number)
        .await?;

    Ok(Json(map_version(version)))
}

/// Create a new version for a provisioning script (update script body).
#[utoipa::path(
    post,
    path = "/governance/provisioning-scripts/{id}/versions",
    tag = "Governance - Provisioning Scripts",
    params(
        ("id" = Uuid, Path, description = "Script ID")
    ),
    request_body = UpdateScriptBodyRequest,
    responses(
        (status = 201, description = "Script version created", body = ScriptVersionResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Script not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_script_version(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateScriptBodyRequest>,
) -> ApiResult<(StatusCode, Json<ScriptVersionResponse>)> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let version = state
        .script_service
        .update_script_body(
            tenant_id,
            id,
            body.script_body,
            body.change_description.clone(),
            actor_id,
        )
        .await?;

    let _ = state
        .script_audit_service
        .record_version_created(
            tenant_id,
            id,
            actor_id,
            version.version_number,
            version.change_description.as_deref(),
        )
        .await;

    Ok((StatusCode::CREATED, Json(map_version(version))))
}

/// Rollback a provisioning script to a previous version.
#[utoipa::path(
    post,
    path = "/governance/provisioning-scripts/{id}/rollback",
    tag = "Governance - Provisioning Scripts",
    params(
        ("id" = Uuid, Path, description = "Script ID")
    ),
    request_body = RollbackRequest,
    responses(
        (status = 200, description = "Script rolled back", body = ScriptVersionResponse),
        (status = 400, description = "Invalid rollback target"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Script or target version not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn rollback_script(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(body): Json<RollbackRequest>,
) -> ApiResult<Json<ScriptVersionResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Get the current version before rollback for audit logging.
    let current_script = state.script_service.get_script(tenant_id, id).await?;
    let from_version = current_script.current_version;

    let version = state
        .script_service
        .rollback_to_version(
            tenant_id,
            id,
            body.target_version,
            actor_id,
            body.reason.clone(),
        )
        .await?;

    let _ = state
        .script_audit_service
        .record_rollback(
            tenant_id,
            id,
            actor_id,
            from_version,
            body.target_version,
            body.reason.as_deref(),
        )
        .await;

    Ok(Json(map_version(version)))
}

/// Compare two versions of a provisioning script.
#[utoipa::path(
    get,
    path = "/governance/provisioning-scripts/{script_id}/versions/compare",
    tag = "Governance - Provisioning Scripts",
    params(
        ("script_id" = Uuid, Path, description = "Script ID"),
        ("from" = i32, Query, description = "First version number to compare"),
        ("to" = i32, Query, description = "Second version number to compare")
    ),
    responses(
        (status = 200, description = "Version comparison result", body = VersionComparisonResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Script or version not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn compare_versions(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(script_id): Path<Uuid>,
    Query(params): Query<CompareVersionsParams>,
) -> ApiResult<Json<VersionComparisonResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let version_a = state
        .script_service
        .get_version(tenant_id, script_id, params.from)
        .await?;

    let version_b = state
        .script_service
        .get_version(tenant_id, script_id, params.to)
        .await?;

    // Perform a simple line-by-line diff between the two versions.
    let lines_a: Vec<&str> = version_a.script_body.lines().collect();
    let lines_b: Vec<&str> = version_b.script_body.lines().collect();

    let mut diff_lines = Vec::new();
    let mut line_number = 1usize;

    let max_len = lines_a.len().max(lines_b.len());
    for i in 0..max_len {
        match (lines_a.get(i), lines_b.get(i)) {
            (Some(a), Some(b)) if a == b => {
                diff_lines.push(DiffLine {
                    line_number,
                    change_type: DiffChangeType::Unchanged,
                    content: a.to_string(),
                });
                line_number += 1;
            }
            (Some(a), Some(b)) => {
                diff_lines.push(DiffLine {
                    line_number,
                    change_type: DiffChangeType::Removed,
                    content: a.to_string(),
                });
                line_number += 1;
                diff_lines.push(DiffLine {
                    line_number,
                    change_type: DiffChangeType::Added,
                    content: b.to_string(),
                });
                line_number += 1;
            }
            (Some(a), None) => {
                diff_lines.push(DiffLine {
                    line_number,
                    change_type: DiffChangeType::Removed,
                    content: a.to_string(),
                });
                line_number += 1;
            }
            (None, Some(b)) => {
                diff_lines.push(DiffLine {
                    line_number,
                    change_type: DiffChangeType::Added,
                    content: b.to_string(),
                });
                line_number += 1;
            }
            (None, None) => break,
        }
    }

    Ok(Json(VersionComparisonResponse {
        version_a: params.from,
        version_b: params.to,
        diff_lines,
    }))
}
