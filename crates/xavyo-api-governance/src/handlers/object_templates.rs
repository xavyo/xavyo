//! Object template handlers for governance API (F058).
//!
//! Object templates define rules that are automatically applied to objects
//! (users, roles, entitlements) when created or modified. They support
//! default values, computed values, validations, and normalization.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;
use xavyo_db::models::{
    CreateGovObjectTemplate, CreateGovTemplateRule, CreateGovTemplateScope, ObjectTemplateFilter,
    TemplateObjectType, TemplateRuleFilter, TemplateScopeType, UpdateGovObjectTemplate,
    UpdateGovTemplateRule,
};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    ApplicationEventListResponse, ApplicationEventResponse, CreateRuleRequest, CreateScopeRequest,
    CreateTemplateRequest, ListApplicationEventsQuery, ListObjectTemplatesQuery,
    ListTemplateEventsQuery, ListTemplateRulesQuery, ListVersionsQuery, MergePolicyResponse,
    RuleListResponse, RuleResponse, ScopeListResponse, ScopeResponse, TemplateDetailResponse,
    TemplateEventListResponse, TemplateEventResponse, TemplateListResponse, TemplateResponse,
    UpdateRuleRequest, UpdateTemplateRequest, VersionListResponse, VersionResponse,
};
use crate::router::GovernanceState;

// ============================================================================
// Object Template CRUD Operations
// ============================================================================

/// List object templates with filtering.
#[utoipa::path(
    get,
    path = "/governance/object-templates",
    tag = "Governance - Object Templates",
    params(ListObjectTemplatesQuery),
    responses(
        (status = 200, description = "List of object templates", body = TemplateListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_templates(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListObjectTemplatesQuery>,
) -> ApiResult<Json<TemplateListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let filter = ObjectTemplateFilter {
        status: query.status,
        object_type: query.object_type,
        name_contains: query.name,
        priority_min: None,
        priority_max: None,
        parent_template_id: None, // Can be added to query later
        include_orphans: Some(true),
    };

    let (templates, total) = state
        .object_template_service
        .list(tenant_id, &filter, limit, offset)
        .await?;

    let items: Vec<TemplateResponse> = templates.into_iter().map(TemplateResponse::from).collect();

    Ok(Json(TemplateListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Create a new object template.
#[utoipa::path(
    post,
    path = "/governance/object-templates",
    tag = "Governance - Object Templates",
    request_body = CreateTemplateRequest,
    responses(
        (status = 201, description = "Object template created", body = TemplateResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Conflict - name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_template(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateTemplateRequest>,
) -> ApiResult<Json<TemplateResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let created_by = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let input = CreateGovObjectTemplate {
        name: request.name,
        description: request.description,
        object_type: request.object_type,
        priority: Some(request.priority),
        parent_template_id: request.parent_template_id,
    };

    let result = state
        .object_template_service
        .create(tenant_id, created_by, input)
        .await?;

    Ok(Json(TemplateResponse::from(result)))
}

/// Get an object template by ID with full details.
#[utoipa::path(
    get,
    path = "/governance/object-templates/{id}",
    tag = "Governance - Object Templates",
    params(
        ("id" = Uuid, Path, description = "Template ID")
    ),
    responses(
        (status = 200, description = "Template details", body = TemplateDetailResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_template(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<TemplateDetailResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let (template, rules, scopes, merge_policies, parent, current_version) = state
        .object_template_service
        .get_detail(tenant_id, id)
        .await?;

    Ok(Json(TemplateDetailResponse {
        template: TemplateResponse::from(template),
        rules: rules.into_iter().map(RuleResponse::from).collect(),
        scopes: scopes.into_iter().map(ScopeResponse::from).collect(),
        merge_policies: merge_policies
            .into_iter()
            .map(MergePolicyResponse::from)
            .collect(),
        parent: parent.map(|p| Box::new(TemplateResponse::from(p))),
        current_version,
    }))
}

/// Update an object template.
#[utoipa::path(
    put,
    path = "/governance/object-templates/{id}",
    tag = "Governance - Object Templates",
    params(
        ("id" = Uuid, Path, description = "Template ID")
    ),
    request_body = UpdateTemplateRequest,
    responses(
        (status = 200, description = "Template updated", body = TemplateResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template not found"),
        (status = 409, description = "Conflict - name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_template(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateTemplateRequest>,
) -> ApiResult<Json<TemplateResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let input = UpdateGovObjectTemplate {
        name: request.name,
        description: request.description,
        priority: request.priority,
        parent_template_id: request.parent_template_id,
    };

    let result = state
        .object_template_service
        .update(tenant_id, id, actor_id, input)
        .await?;

    Ok(Json(TemplateResponse::from(result)))
}

/// Delete an object template.
#[utoipa::path(
    delete,
    path = "/governance/object-templates/{id}",
    tag = "Governance - Object Templates",
    params(
        ("id" = Uuid, Path, description = "Template ID")
    ),
    responses(
        (status = 204, description = "Template deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template not found"),
        (status = 409, description = "Conflict - template has active children"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_template(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<()> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    state
        .object_template_service
        .delete(tenant_id, id, actor_id)
        .await?;

    Ok(())
}

// ============================================================================
// Template Status Operations
// ============================================================================

/// Activate a draft template.
#[utoipa::path(
    post,
    path = "/governance/object-templates/{id}/activate",
    tag = "Governance - Object Templates",
    params(
        ("id" = Uuid, Path, description = "Template ID")
    ),
    responses(
        (status = 200, description = "Template activated", body = TemplateResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template not found"),
        (status = 409, description = "Conflict - template is not in draft status or has no scopes"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn activate_template(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<TemplateResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .object_template_service
        .activate(tenant_id, id, actor_id)
        .await?;

    Ok(Json(TemplateResponse::from(result)))
}

/// Disable an active template.
#[utoipa::path(
    post,
    path = "/governance/object-templates/{id}/disable",
    tag = "Governance - Object Templates",
    params(
        ("id" = Uuid, Path, description = "Template ID")
    ),
    responses(
        (status = 200, description = "Template disabled", body = TemplateResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template not found"),
        (status = 409, description = "Conflict - template is not in active status"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn disable_template(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<TemplateResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .object_template_service
        .disable(tenant_id, id, actor_id)
        .await?;

    Ok(Json(TemplateResponse::from(result)))
}

// ============================================================================
// Template Rule Operations
// ============================================================================

/// List rules for a template.
#[utoipa::path(
    get,
    path = "/governance/object-templates/{template_id}/rules",
    tag = "Governance - Object Templates",
    params(
        ("template_id" = Uuid, Path, description = "Template ID"),
        ListTemplateRulesQuery
    ),
    responses(
        (status = 200, description = "List of rules", body = RuleListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_rules(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(template_id): Path<Uuid>,
    Query(query): Query<ListTemplateRulesQuery>,
) -> ApiResult<Json<RuleListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(100).min(500);
    let offset = query.offset.unwrap_or(0);

    let filter = TemplateRuleFilter {
        template_id: Some(template_id),
        rule_type: query.rule_type,
        target_attribute: query.target_attribute,
        strength: query.strength,
    };

    let (rules, total) = state
        .template_rule_service
        .list_with_filter(tenant_id, template_id, &filter, limit, offset)
        .await?;

    let items: Vec<RuleResponse> = rules.into_iter().map(RuleResponse::from).collect();

    Ok(Json(RuleListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Add a rule to a template.
#[utoipa::path(
    post,
    path = "/governance/object-templates/{template_id}/rules",
    tag = "Governance - Object Templates",
    params(
        ("template_id" = Uuid, Path, description = "Template ID")
    ),
    request_body = CreateRuleRequest,
    responses(
        (status = 201, description = "Rule created", body = RuleResponse),
        (status = 400, description = "Invalid request or expression"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template not found"),
        (status = 409, description = "Conflict - circular dependency detected"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn add_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(template_id): Path<Uuid>,
    Json(request): Json<CreateRuleRequest>,
) -> ApiResult<Json<RuleResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let input = CreateGovTemplateRule {
        rule_type: request.rule_type,
        target_attribute: request.target_attribute,
        expression: request.expression,
        priority: Some(request.priority),
        strength: Some(request.strength),
        condition: request.condition,
        authoritative: Some(request.authoritative),
        error_message: request.error_message,
        exclusive: Some(request.exclusive),
        time_from: request.time_from,
        time_to: request.time_to,
        time_reference: request.time_reference,
    };

    let result = state
        .template_rule_service
        .add_rule(tenant_id, template_id, actor_id, input)
        .await?;

    Ok(Json(RuleResponse::from(result)))
}

/// Get a specific rule.
#[utoipa::path(
    get,
    path = "/governance/object-templates/{template_id}/rules/{rule_id}",
    tag = "Governance - Object Templates",
    params(
        ("template_id" = Uuid, Path, description = "Template ID"),
        ("rule_id" = Uuid, Path, description = "Rule ID")
    ),
    responses(
        (status = 200, description = "Rule details", body = RuleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template or rule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((template_id, rule_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<RuleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Verify template exists
    state
        .object_template_service
        .get(tenant_id, template_id)
        .await?;

    let rule = state.template_rule_service.get(tenant_id, rule_id).await?;

    // Verify rule belongs to template
    if rule.template_id != template_id {
        return Err(ApiGovernanceError::NotFound("Rule not found".to_string()));
    }

    Ok(Json(RuleResponse::from(rule)))
}

/// Update a rule.
#[utoipa::path(
    put,
    path = "/governance/object-templates/{template_id}/rules/{rule_id}",
    tag = "Governance - Object Templates",
    params(
        ("template_id" = Uuid, Path, description = "Template ID"),
        ("rule_id" = Uuid, Path, description = "Rule ID")
    ),
    request_body = UpdateRuleRequest,
    responses(
        (status = 200, description = "Rule updated", body = RuleResponse),
        (status = 400, description = "Invalid request or expression"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template or rule not found"),
        (status = 409, description = "Conflict - circular dependency detected"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((template_id, rule_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateRuleRequest>,
) -> ApiResult<Json<RuleResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let input = UpdateGovTemplateRule {
        expression: request.expression,
        priority: request.priority,
        strength: request.strength,
        condition: request.condition,
        authoritative: request.authoritative,
        error_message: request.error_message,
        exclusive: request.exclusive,
        time_from: request.time_from,
        time_to: request.time_to,
        time_reference: request.time_reference,
    };

    let result = state
        .template_rule_service
        .update_rule(tenant_id, template_id, rule_id, actor_id, input)
        .await?;

    Ok(Json(RuleResponse::from(result)))
}

/// Remove a rule from a template.
#[utoipa::path(
    delete,
    path = "/governance/object-templates/{template_id}/rules/{rule_id}",
    tag = "Governance - Object Templates",
    params(
        ("template_id" = Uuid, Path, description = "Template ID"),
        ("rule_id" = Uuid, Path, description = "Rule ID")
    ),
    responses(
        (status = 204, description = "Rule removed"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template or rule not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_rule(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((template_id, rule_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<()> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    state
        .template_rule_service
        .remove_rule(tenant_id, template_id, rule_id, actor_id)
        .await?;

    Ok(())
}

// ============================================================================
// Version Operations
// ============================================================================

/// List versions for a template.
#[utoipa::path(
    get,
    path = "/governance/object-templates/{template_id}/versions",
    tag = "Governance - Object Templates",
    params(
        ("template_id" = Uuid, Path, description = "Template ID"),
        ListVersionsQuery
    ),
    responses(
        (status = 200, description = "List of versions", body = VersionListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_versions(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(template_id): Path<Uuid>,
    Query(query): Query<ListVersionsQuery>,
) -> ApiResult<Json<VersionListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let (versions, total) = state
        .object_template_service
        .list_versions(tenant_id, template_id, limit, offset)
        .await?;

    let items: Vec<VersionResponse> = versions.into_iter().map(VersionResponse::from).collect();

    Ok(Json(VersionListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Get a specific version.
#[utoipa::path(
    get,
    path = "/governance/object-templates/{template_id}/versions/{version_id}",
    tag = "Governance - Object Templates",
    params(
        ("template_id" = Uuid, Path, description = "Template ID"),
        ("version_id" = Uuid, Path, description = "Version ID")
    ),
    responses(
        (status = 200, description = "Version details", body = VersionResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template or version not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_version(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((template_id, version_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<VersionResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let version = state
        .object_template_service
        .get_version(tenant_id, template_id, version_id)
        .await?;

    Ok(Json(VersionResponse::from(version)))
}

// ============================================================================
// Event Operations
// ============================================================================

/// List events for a template.
#[utoipa::path(
    get,
    path = "/governance/object-templates/{template_id}/events",
    tag = "Governance - Object Templates",
    params(
        ("template_id" = Uuid, Path, description = "Template ID"),
        ListTemplateEventsQuery
    ),
    responses(
        (status = 200, description = "List of events", body = TemplateEventListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_events(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(template_id): Path<Uuid>,
    Query(query): Query<ListTemplateEventsQuery>,
) -> ApiResult<Json<TemplateEventListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let (events, total) = state
        .object_template_service
        .list_events(tenant_id, template_id, query.event_type, limit, offset)
        .await?;

    let items: Vec<TemplateEventResponse> = events
        .into_iter()
        .map(TemplateEventResponse::from)
        .collect();

    Ok(Json(TemplateEventListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

// ============================================================================
// Scope Operations
// ============================================================================

/// Add a scope to a template.
#[utoipa::path(
    post,
    path = "/governance/object-templates/{template_id}/scopes",
    tag = "Governance - Object Templates",
    params(
        ("template_id" = Uuid, Path, description = "Template ID")
    ),
    request_body = CreateScopeRequest,
    responses(
        (status = 201, description = "Scope added", body = ScopeResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn add_scope(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(template_id): Path<Uuid>,
    Json(request): Json<CreateScopeRequest>,
) -> ApiResult<Json<ScopeResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Verify template exists (get() returns Result, not Option)
    state
        .object_template_service
        .get(tenant_id, template_id)
        .await?;

    // Convert condition scope to proper scope_value
    let (scope_value, condition) = if request.scope_type == TemplateScopeType::Condition {
        (None, request.condition.clone())
    } else {
        (request.scope_value.clone(), None)
    };

    let scope = state
        .template_scope_service
        .add_scope(
            tenant_id,
            template_id,
            actor_id,
            CreateGovTemplateScope {
                scope_type: request.scope_type,
                scope_value,
                condition,
            },
        )
        .await?;

    Ok(Json(ScopeResponse::from(scope)))
}

/// List scopes for a template.
#[utoipa::path(
    get,
    path = "/governance/object-templates/{template_id}/scopes",
    tag = "Governance - Object Templates",
    params(
        ("template_id" = Uuid, Path, description = "Template ID")
    ),
    responses(
        (status = 200, description = "List of scopes", body = ScopeListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_scopes(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(template_id): Path<Uuid>,
) -> ApiResult<Json<ScopeListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Verify template exists (get() returns Result, not Option)
    state
        .object_template_service
        .get(tenant_id, template_id)
        .await?;

    let scopes = state
        .template_scope_service
        .list_by_template(tenant_id, template_id)
        .await?;

    let items: Vec<ScopeResponse> = scopes.into_iter().map(ScopeResponse::from).collect();

    Ok(Json(ScopeListResponse { items }))
}

/// Remove a scope from a template.
#[utoipa::path(
    delete,
    path = "/governance/object-templates/{template_id}/scopes/{scope_id}",
    tag = "Governance - Object Templates",
    params(
        ("template_id" = Uuid, Path, description = "Template ID"),
        ("scope_id" = Uuid, Path, description = "Scope ID")
    ),
    responses(
        (status = 204, description = "Scope removed"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template or scope not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_scope(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((template_id, scope_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<()> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    state
        .template_scope_service
        .remove_scope(tenant_id, template_id, scope_id, actor_id)
        .await?;

    Ok(())
}

// ============================================================================
// Application Event Operations
// ============================================================================

/// List application events for a template.
#[utoipa::path(
    get,
    path = "/governance/object-templates/{template_id}/application-events",
    tag = "Governance - Object Templates",
    params(
        ("template_id" = Uuid, Path, description = "Template ID"),
        ListApplicationEventsQuery
    ),
    responses(
        (status = 200, description = "List of application events", body = ApplicationEventListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Template not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_application_events_by_template(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(template_id): Path<Uuid>,
    Query(_query): Query<ListApplicationEventsQuery>,
) -> ApiResult<Json<ApplicationEventListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Verify template exists (get() returns Result, not Option)
    state
        .object_template_service
        .get(tenant_id, template_id)
        .await?;

    let events = state
        .template_application_service
        .list_events_by_template(tenant_id, template_id)
        .await?;

    let items: Vec<ApplicationEventResponse> = events
        .into_iter()
        .map(ApplicationEventResponse::from)
        .collect();

    Ok(Json(ApplicationEventListResponse {
        items,
        total: 0, // Events don't have pagination yet
        limit: 100,
        offset: 0,
    }))
}

/// List application events by object type and ID.
#[utoipa::path(
    get,
    path = "/governance/object-templates/application-events/{object_type}/{object_id}",
    tag = "Governance - Object Templates",
    params(
        ("object_type" = TemplateObjectType, Path, description = "Object type"),
        ("object_id" = Uuid, Path, description = "Object ID"),
        ListApplicationEventsQuery
    ),
    responses(
        (status = 200, description = "List of application events", body = ApplicationEventListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_application_events_by_object(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((object_type, object_id)): Path<(TemplateObjectType, Uuid)>,
    Query(_query): Query<ListApplicationEventsQuery>,
) -> ApiResult<Json<ApplicationEventListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let events = state
        .template_application_service
        .list_events_by_object(tenant_id, object_type, object_id)
        .await?;

    let items: Vec<ApplicationEventResponse> = events
        .into_iter()
        .map(ApplicationEventResponse::from)
        .collect();

    Ok(Json(ApplicationEventListResponse {
        items,
        total: 0, // Events don't have pagination yet
        limit: 100,
        offset: 0,
    }))
}
