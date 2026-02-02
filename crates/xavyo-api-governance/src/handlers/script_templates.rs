//! HTTP handlers for script template operations (F066).
//!
//! Script templates define reusable provisioning script patterns that can be
//! instantiated into concrete scripts with variable substitution.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_db::models::gov_script_template::GovScriptTemplate;
use xavyo_db::models::gov_script_types::TemplateCategory;

use crate::{
    error::{ApiGovernanceError, ApiResult},
    models::script::{
        CreateTemplateRequest, InstantiateTemplateRequest, ScriptResponse, TemplateListParams,
        TemplateListResponse, TemplateResponse, UpdateTemplateRequest,
    },
    router::GovernanceState,
};

/// Convert a DB `GovScriptTemplate` into an API `TemplateResponse`.
fn map_template(t: GovScriptTemplate) -> TemplateResponse {
    // TemplateCategory derives Serialize with rename_all = "snake_case", so
    // serialising via serde_json gives the canonical string representation.
    let category_str = serde_json::to_value(t.category)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| format!("{:?}", t.category));

    TemplateResponse {
        id: t.id,
        tenant_id: t.tenant_id,
        name: t.name,
        description: t.description,
        category: category_str,
        template_body: t.template_body,
        placeholder_annotations: t.placeholder_annotations,
        is_system: t.is_system,
        created_by: t.created_by,
        created_at: t.created_at,
        updated_at: t.updated_at,
    }
}

/// Parse a category string into `TemplateCategory`, returning a validation
/// error on failure.
fn parse_category(s: &str) -> Result<TemplateCategory, ApiGovernanceError> {
    serde_json::from_value::<TemplateCategory>(serde_json::Value::String(s.to_string()))
        .map_err(|_| {
            ApiGovernanceError::Validation(format!(
                "Invalid template category: '{}'. Expected one of: attribute_mapping, value_generation, conditional_logic, data_formatting, custom",
                s
            ))
        })
}

/// List script templates with optional filtering and pagination.
#[utoipa::path(
    get,
    path = "/governance/script-templates",
    tag = "Governance - Provisioning Scripts",
    params(TemplateListParams),
    responses(
        (status = 200, description = "List of script templates", body = TemplateListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_templates(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<TemplateListParams>,
) -> ApiResult<Json<TemplateListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Parse optional category filter
    let category = match &params.category {
        Some(cat) => Some(parse_category(cat)?),
        None => None,
    };

    let page = params.page.unwrap_or(1).max(1);
    let page_size = params.page_size.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * page_size;

    let (templates, total) = state
        .script_template_service
        .list_templates(
            tenant_id,
            category,
            params.search.clone(),
            page_size,
            offset,
        )
        .await?;

    Ok(Json(TemplateListResponse {
        templates: templates.into_iter().map(map_template).collect(),
        total,
    }))
}

/// Create a new script template.
#[utoipa::path(
    post,
    path = "/governance/script-templates",
    tag = "Governance - Provisioning Scripts",
    request_body = CreateTemplateRequest,
    responses(
        (status = 201, description = "Script template created", body = TemplateResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Template name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_template(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(body): Json<CreateTemplateRequest>,
) -> ApiResult<(StatusCode, Json<TemplateResponse>)> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let category = parse_category(&body.category)?;

    let template = state
        .script_template_service
        .create_template(
            tenant_id,
            body.name,
            body.description,
            category,
            body.template_body,
            body.placeholder_annotations,
            false, // not a system template
            actor_id,
        )
        .await?;

    Ok((StatusCode::CREATED, Json(map_template(template))))
}

/// Get a script template by ID.
#[utoipa::path(
    get,
    path = "/governance/script-templates/{id}",
    tag = "Governance - Provisioning Scripts",
    params(
        ("id" = Uuid, Path, description = "Script template ID")
    ),
    responses(
        (status = 200, description = "Script template details", body = TemplateResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Script template not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_template(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<TemplateResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let template = state
        .script_template_service
        .get_template(tenant_id, id)
        .await?;

    Ok(Json(map_template(template)))
}

/// Update a script template.
#[utoipa::path(
    put,
    path = "/governance/script-templates/{id}",
    tag = "Governance - Provisioning Scripts",
    params(
        ("id" = Uuid, Path, description = "Script template ID")
    ),
    request_body = UpdateTemplateRequest,
    responses(
        (status = 200, description = "Script template updated", body = TemplateResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Script template not found"),
        (status = 409, description = "Template name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_template(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateTemplateRequest>,
) -> ApiResult<Json<TemplateResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Parse optional category if provided
    let category = match &body.category {
        Some(cat) => Some(parse_category(cat)?),
        None => None,
    };

    let template = state
        .script_template_service
        .update_template(
            tenant_id,
            id,
            body.name,
            body.description,
            category,
            body.template_body,
            body.placeholder_annotations,
        )
        .await?;

    Ok(Json(map_template(template)))
}

/// Delete a script template.
#[utoipa::path(
    delete,
    path = "/governance/script-templates/{id}",
    tag = "Governance - Provisioning Scripts",
    params(
        ("id" = Uuid, Path, description = "Script template ID")
    ),
    responses(
        (status = 204, description = "Script template deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Script template not found"),
        (status = 409, description = "Template is in use"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_template(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state
        .script_template_service
        .delete_template(tenant_id, id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Instantiate a script template into a concrete provisioning script.
#[utoipa::path(
    post,
    path = "/governance/script-templates/{id}/instantiate",
    tag = "Governance - Provisioning Scripts",
    params(
        ("id" = Uuid, Path, description = "Script template ID")
    ),
    request_body = InstantiateTemplateRequest,
    responses(
        (status = 201, description = "Script instantiated from template", body = ScriptResponse),
        (status = 400, description = "Invalid request or missing template variables"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Script template not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn instantiate_template(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(body): Json<InstantiateTemplateRequest>,
) -> ApiResult<(StatusCode, Json<ScriptResponse>)> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Step 1: Get the template
    let template = state
        .script_template_service
        .instantiate_template(tenant_id, id)
        .await?;

    // Step 2: Create a new script from the template body
    let (script, _version) = state
        .script_service
        .create_script(
            tenant_id,
            body.name,
            body.description,
            template.template_body,
            actor_id,
        )
        .await?;

    // Step 3: Convert DB model to API response
    let status_str = serde_json::to_value(script.status)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_else(|| format!("{:?}", script.status));

    let response = ScriptResponse {
        id: script.id,
        tenant_id: script.tenant_id,
        name: script.name,
        description: script.description,
        current_version: script.current_version,
        status: status_str,
        is_system: script.is_system,
        created_by: script.created_by,
        created_at: script.created_at,
        updated_at: script.updated_at,
    };

    Ok((StatusCode::CREATED, Json(response)))
}
