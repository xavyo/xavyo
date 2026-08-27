//! HTTP handlers for script hook binding operations (F066).
//!
//! Manages the binding of provisioning scripts to connector lifecycle hooks.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::models::{BindingFilter, FailurePolicy, GovHookPhase, ScriptOperationType};

use crate::{
    error::{ApiGovernanceError, ApiResult},
    models::script::{
        BindingListParams, BindingListResponse, BindingResponse, CreateBindingRequest,
        UpdateBindingRequest,
    },
    router::GovernanceState,
};

/// List script hook bindings with optional filtering and pagination.
#[utoipa::path(
    get,
    path = "/governance/scripts/bindings",
    tag = "Governance - Provisioning Scripts",
    params(BindingListParams),
    responses(
        (status = 200, description = "List of script hook bindings", body = BindingListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_bindings(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<BindingListParams>,
) -> ApiResult<Json<BindingListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let page = params.page.unwrap_or(1).max(1);
    let page_size = params.page_size.unwrap_or(50).min(100);
    let offset = (page - 1) * page_size;

    let filter = BindingFilter {
        connector_id: params.connector_id,
        script_id: params.script_id,
        hook_phase: params
            .hook_phase
            .as_deref()
            .map(|s| parse_binding_enum("hook_phase", s))
            .transpose()?,
        operation_type: params
            .operation_type
            .as_deref()
            .map(|s| parse_binding_enum("operation_type", s))
            .transpose()?,
        enabled: None,
    };

    let (bindings, total) = state
        .script_binding_service
        .list_bindings(tenant_id, &filter, page_size, offset)
        .await?;

    Ok(Json(BindingListResponse {
        bindings: bindings.into_iter().map(Into::into).collect(),
        total,
    }))
}

/// Create a new script hook binding.
#[utoipa::path(
    post,
    path = "/governance/scripts/bindings",
    tag = "Governance - Provisioning Scripts",
    request_body = CreateBindingRequest,
    responses(
        (status = 201, description = "Script hook binding created", body = BindingResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Script or connector not found"),
        (status = 409, description = "Maximum bindings exceeded for hook point"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_binding(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(body): Json<CreateBindingRequest>,
) -> ApiResult<(StatusCode, Json<BindingResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let hook_phase: GovHookPhase =
        serde_json::from_value(serde_json::Value::String(body.hook_phase.clone())).map_err(
            |_| ApiGovernanceError::Validation(format!("Invalid hook_phase: {}", body.hook_phase)),
        )?;

    let operation_type: ScriptOperationType = serde_json::from_value(serde_json::Value::String(
        body.operation_type.clone(),
    ))
    .map_err(|_| {
        ApiGovernanceError::Validation(format!("Invalid operation_type: {}", body.operation_type))
    })?;

    let failure_policy: FailurePolicy = body
        .failure_policy
        .as_deref()
        .map(|fp| {
            serde_json::from_value(serde_json::Value::String(fp.to_string())).map_err(|_| {
                ApiGovernanceError::Validation(format!("Invalid failure_policy: {fp}"))
            })
        })
        .transpose()?
        .unwrap_or(FailurePolicy::Abort);

    let max_retries = body.max_retries.unwrap_or(0);
    let timeout_seconds = body.timeout_seconds.unwrap_or(30);

    let binding = state
        .script_binding_service
        .create_binding(
            tenant_id,
            body.script_id,
            body.connector_id,
            hook_phase,
            operation_type,
            body.execution_order,
            failure_policy,
            max_retries,
            timeout_seconds,
        )
        .await?;

    // Record audit event for binding creation.
    state
        .script_audit_service
        .record_bound(
            tenant_id,
            body.script_id,
            actor_id,
            binding.id,
            body.connector_id,
        )
        .await?;

    Ok((StatusCode::CREATED, Json(binding.into())))
}

/// Get a script hook binding by ID.
#[utoipa::path(
    get,
    path = "/governance/scripts/bindings/{id}",
    tag = "Governance - Provisioning Scripts",
    params(
        ("id" = Uuid, Path, description = "Binding ID")
    ),
    responses(
        (status = 200, description = "Script hook binding details", body = BindingResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Binding not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_binding(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<BindingResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let binding = state
        .script_binding_service
        .get_binding(tenant_id, id)
        .await?;

    Ok(Json(binding.into()))
}

/// Update a script hook binding.
#[utoipa::path(
    put,
    path = "/governance/scripts/bindings/{id}",
    tag = "Governance - Provisioning Scripts",
    params(
        ("id" = Uuid, Path, description = "Binding ID")
    ),
    request_body = UpdateBindingRequest,
    responses(
        (status = 200, description = "Script hook binding updated", body = BindingResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Binding not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_binding(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateBindingRequest>,
) -> ApiResult<Json<BindingResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let failure_policy: Option<FailurePolicy> = body
        .failure_policy
        .as_deref()
        .map(|fp| {
            serde_json::from_value(serde_json::Value::String(fp.to_string())).map_err(|_| {
                ApiGovernanceError::Validation(format!("Invalid failure_policy: {fp}"))
            })
        })
        .transpose()?;

    let binding = state
        .script_binding_service
        .update_binding(
            tenant_id,
            id,
            body.execution_order,
            failure_policy,
            body.max_retries,
            body.timeout_seconds,
            body.enabled,
        )
        .await?;

    Ok(Json(binding.into()))
}

/// Delete a script hook binding.
#[utoipa::path(
    delete,
    path = "/governance/scripts/bindings/{id}",
    tag = "Governance - Provisioning Scripts",
    params(
        ("id" = Uuid, Path, description = "Binding ID")
    ),
    responses(
        (status = 204, description = "Script hook binding deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Binding not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_binding(
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
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Retrieve binding details before deletion for the audit trail.
    let binding = state
        .script_binding_service
        .get_binding(tenant_id, id)
        .await?;

    state
        .script_binding_service
        .delete_binding(tenant_id, id)
        .await?;

    // Record audit event for binding deletion.
    state
        .script_audit_service
        .record_unbound(
            tenant_id,
            binding.script_id,
            actor_id,
            id,
            binding.connector_id,
        )
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// List all script hook bindings for a specific connector.
#[utoipa::path(
    get,
    path = "/governance/connectors/{connector_id}/script-bindings",
    tag = "Governance - Provisioning Scripts",
    params(
        ("connector_id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 200, description = "Script hook bindings for connector", body = BindingListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_bindings_by_connector(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(connector_id): Path<Uuid>,
) -> ApiResult<Json<BindingListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let bindings = state
        .script_binding_service
        .list_by_connector(tenant_id, connector_id)
        .await?;

    let total = bindings.len() as i64;

    Ok(Json(BindingListResponse {
        bindings: bindings.into_iter().map(Into::into).collect(),
        total,
    }))
}

// ============================================================================
// Conversion helpers
// ============================================================================

impl From<xavyo_db::models::GovScriptHookBinding> for BindingResponse {
    fn from(b: xavyo_db::models::GovScriptHookBinding) -> Self {
        Self {
            id: b.id,
            tenant_id: b.tenant_id,
            script_id: b.script_id,
            connector_id: b.connector_id,
            hook_phase: serde_json::to_value(b.hook_phase)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default(),
            operation_type: serde_json::to_value(b.operation_type)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default(),
            execution_order: b.execution_order,
            failure_policy: serde_json::to_value(b.failure_policy)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default(),
            max_retries: b.max_retries,
            timeout_seconds: b.timeout_seconds,
            enabled: b.enabled,
            // The DB model does not store created_by; use nil UUID as placeholder.
            created_by: Uuid::nil(),
            created_at: b.created_at,
            updated_at: b.updated_at,
        }
    }
}

/// Parse a query enum. Unknown values are 400, not an unfiltered list.
fn parse_binding_enum<T: serde::de::DeserializeOwned>(
    field: &str,
    value: &str,
) -> Result<T, ApiGovernanceError> {
    serde_json::from_value(serde_json::Value::String(value.to_string()))
        .map_err(|_| ApiGovernanceError::Validation(format!("Invalid {field}: {value}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_mutations_do_not_swallow_audit_writes() {
        let src = include_str!("script_hook_bindings.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            !production.contains("let _ = state\n        .script_audit_service"),
            "script binding mutations must not swallow script audit writes"
        );
        assert!(
            production.contains("record_bound")
                && production.contains("record_unbound")
                && production.contains(".await?;"),
            "script binding mutations must fail when script audit rows cannot be written"
        );
    }

    #[test]
    fn binding_list_rejects_unknown_filter_enums() {
        assert!(parse_binding_enum::<GovHookPhase>("hook_phase", "before").is_ok());
        assert!(parse_binding_enum::<GovHookPhase>("hook_phase", "nope").is_err());
        assert!(parse_binding_enum::<ScriptOperationType>("operation_type", "create").is_ok());
        assert!(parse_binding_enum::<ScriptOperationType>("operation_type", "nope").is_err());
        let src = include_str!("script_hook_bindings.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("parse_binding_enum(")
                && !production.contains(".ok()\n            }),"),
            "binding list must not treat invalid enums as unfiltered"
        );
    }
}
