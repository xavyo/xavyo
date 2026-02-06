//! HTTP handlers for script validation and dry-run testing (F066).
//!
//! Provides endpoints for testing provisioning scripts before production use.

use axum::{
    extract::{Path, State},
    Extension, Json,
};
use serde::Deserialize;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;
use xavyo_auth::JwtClaims;

use crate::{
    error::{ApiGovernanceError, ApiResult},
    models::script::{DryRunRequest, DryRunResponse, ValidateScriptRequest, ValidationResponse},
    router::GovernanceState,
};

/// Request body for raw (unsaved) script dry-run, which requires the script body inline.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RawDryRunRequest {
    /// The script body to execute.
    pub script_body: String,

    /// Simulated provisioning context for the dry run.
    pub context: serde_json::Value,
}

impl Validate for RawDryRunRequest {
    fn validate(&self) -> Result<(), validator::ValidationErrors> {
        let mut errors = validator::ValidationErrors::new();
        // Max 1MB script body
        if self.script_body.len() > 1_048_576 {
            let mut err = validator::ValidationError::new("length");
            err.message = Some("script_body must be at most 1MB".into());
            errors.add("script_body", err);
        }
        // Max 100KB context
        if self.context.to_string().len() > 102_400 {
            let mut err = validator::ValidationError::new("length");
            err.message = Some("context must be at most 100KB".into());
            errors.add("context", err);
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Validate a script for syntax errors (without executing it).
#[utoipa::path(
    post,
    path = "/governance/scripts/validate",
    tag = "Governance - Provisioning Scripts",
    request_body = ValidateScriptRequest,
    responses(
        (status = 200, description = "Validation result", body = ValidationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn validate_script(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(body): Json<ValidateScriptRequest>,
) -> ApiResult<Json<ValidationResponse>> {
    let _tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .script_execution_service
        .validate_script(&body.script_body);

    Ok(Json(ValidationResponse {
        valid: result.valid,
        errors: result
            .errors
            .into_iter()
            .map(|e| crate::models::script::ScriptError {
                line: e.line,
                column: e.column,
                message: e.message,
            })
            .collect(),
    }))
}

/// Execute a dry-run of a saved script version with sample context.
#[utoipa::path(
    post,
    path = "/governance/scripts/{script_id}/versions/{version_number}/dry-run",
    tag = "Governance - Provisioning Scripts",
    params(
        ("script_id" = Uuid, Path, description = "Script ID"),
        ("version_number" = i32, Path, description = "Version number")
    ),
    request_body = DryRunRequest,
    responses(
        (status = 200, description = "Dry-run result", body = DryRunResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Script or version not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn dry_run_version(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((script_id, version_number)): Path<(Uuid, i32)>,
    Json(body): Json<DryRunRequest>,
) -> ApiResult<Json<DryRunResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .script_execution_service
        .dry_run(tenant_id, script_id, version_number, body.context, 30)
        .await?;

    Ok(Json(DryRunResponse {
        success: result.success,
        output: result.output,
        error: result.error,
        duration_ms: result.duration_ms,
    }))
}

/// Execute a dry-run of a raw (unsaved) script body with sample context.
#[utoipa::path(
    post,
    path = "/governance/scripts/dry-run",
    tag = "Governance - Provisioning Scripts",
    request_body = RawDryRunRequest,
    responses(
        (status = 200, description = "Dry-run result", body = DryRunResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn dry_run_raw(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(body): Json<RawDryRunRequest>,
) -> ApiResult<Json<DryRunResponse>> {
    body.validate()
        .map_err(|e| ApiGovernanceError::Validation(e.to_string()))?;
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result =
        state
            .script_execution_service
            .dry_run_raw(&body.script_body, body.context, tenant_id, 30);

    Ok(Json(DryRunResponse {
        success: result.success,
        output: result.output,
        error: result.error,
        duration_ms: result.duration_ms,
    }))
}
