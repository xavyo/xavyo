//! Escalation policy handlers for governance API (F054).

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;
use xavyo_db::models::{
    CreateEscalationLevel, CreateEscalationPolicy, CreateEscalationRule, GovApprovalStep,
    GovEscalationRule, UpdateEscalationPolicy,
};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    ConfigureStepEscalationRequest, CreateEscalationLevelRequest, CreateEscalationPolicyRequest,
    EscalationLevelResponse, EscalationPolicyListResponse, EscalationPolicyResponse,
    EscalationPolicySummary, ListEscalationPoliciesQuery, StepEscalationResponse,
    UpdateEscalationPolicyRequest,
};
use crate::router::GovernanceState;

/// List escalation policies.
#[utoipa::path(
    get,
    path = "/governance/escalation-policies",
    tag = "Governance - Workflow Escalation",
    params(ListEscalationPoliciesQuery),
    responses(
        (status = 200, description = "List of escalation policies", body = EscalationPolicyListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_policies(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListEscalationPoliciesQuery>,
) -> ApiResult<Json<EscalationPolicyListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let (policies, total) = state
        .escalation_policy_service
        .list_policies(tenant_id, query.is_active, limit, offset)
        .await?;

    let items: Vec<EscalationPolicySummary> = policies
        .into_iter()
        .map(|p| {
            let default_timeout_secs = p.timeout_secs();
            EscalationPolicySummary {
                id: p.id,
                name: p.name,
                description: p.description,
                default_timeout_secs,
                final_fallback: p.final_fallback,
                is_active: p.is_active,
                level_count: 0, // Will be populated in a future enhancement
                created_at: p.created_at,
                updated_at: p.updated_at,
            }
        })
        .collect();

    Ok(Json(EscalationPolicyListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Get an escalation policy by ID.
#[utoipa::path(
    get,
    path = "/governance/escalation-policies/{id}",
    tag = "Governance - Workflow Escalation",
    params(
        ("id" = Uuid, Path, description = "Escalation Policy ID")
    ),
    responses(
        (status = 200, description = "Escalation policy details", body = EscalationPolicyResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Policy not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_policy(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<EscalationPolicyResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let (policy, levels) = state
        .escalation_policy_service
        .get_policy_with_levels(tenant_id, id)
        .await?;

    Ok(Json(EscalationPolicyResponse::from_policy_and_levels(
        policy, levels,
    )))
}

/// Create a new escalation policy.
#[utoipa::path(
    post,
    path = "/governance/escalation-policies",
    tag = "Governance - Workflow Escalation",
    request_body = CreateEscalationPolicyRequest,
    responses(
        (status = 201, description = "Policy created", body = EscalationPolicyResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Policy name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_policy(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateEscalationPolicyRequest>,
) -> ApiResult<(StatusCode, Json<EscalationPolicyResponse>)> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = CreateEscalationPolicy {
        name: request.name,
        description: request.description,
        default_timeout_secs: request.default_timeout_secs,
        warning_threshold_secs: request.warning_threshold_secs,
        final_fallback: request.final_fallback,
    };

    let policy = state
        .escalation_policy_service
        .create_policy(tenant_id, input)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(EscalationPolicyResponse::from_policy_and_levels(
            policy,
            vec![],
        )),
    ))
}

/// Update an escalation policy.
#[utoipa::path(
    put,
    path = "/governance/escalation-policies/{id}",
    tag = "Governance - Workflow Escalation",
    params(
        ("id" = Uuid, Path, description = "Escalation Policy ID")
    ),
    request_body = UpdateEscalationPolicyRequest,
    responses(
        (status = 200, description = "Policy updated", body = EscalationPolicyResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Policy not found"),
        (status = 409, description = "Policy name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_policy(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateEscalationPolicyRequest>,
) -> ApiResult<Json<EscalationPolicyResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = UpdateEscalationPolicy {
        name: request.name,
        description: request.description,
        default_timeout_secs: request.default_timeout_secs,
        warning_threshold_secs: request.warning_threshold_secs,
        final_fallback: request.final_fallback,
        is_active: request.is_active,
    };

    let policy = state
        .escalation_policy_service
        .update_policy(tenant_id, id, input)
        .await?;

    let (_, levels) = state
        .escalation_policy_service
        .get_policy_with_levels(tenant_id, id)
        .await?;

    Ok(Json(EscalationPolicyResponse::from_policy_and_levels(
        policy, levels,
    )))
}

/// Delete an escalation policy.
#[utoipa::path(
    delete,
    path = "/governance/escalation-policies/{id}",
    tag = "Governance - Workflow Escalation",
    params(
        ("id" = Uuid, Path, description = "Escalation Policy ID")
    ),
    responses(
        (status = 204, description = "Policy deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Policy not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_policy(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state
        .escalation_policy_service
        .delete_policy(tenant_id, id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Set a policy as the active default.
#[utoipa::path(
    post,
    path = "/governance/escalation-policies/{id}/set-default",
    tag = "Governance - Workflow Escalation",
    params(
        ("id" = Uuid, Path, description = "Escalation Policy ID")
    ),
    responses(
        (status = 200, description = "Policy set as default", body = EscalationPolicyResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Policy not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn set_default_policy(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<EscalationPolicyResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let policy = state
        .escalation_policy_service
        .set_active_default(tenant_id, id)
        .await?;

    let (_, levels) = state
        .escalation_policy_service
        .get_policy_with_levels(tenant_id, id)
        .await?;

    Ok(Json(EscalationPolicyResponse::from_policy_and_levels(
        policy, levels,
    )))
}

/// Add an escalation level to a policy.
#[utoipa::path(
    post,
    path = "/governance/escalation-policies/{policy_id}/levels",
    tag = "Governance - Workflow Escalation",
    params(
        ("policy_id" = Uuid, Path, description = "Escalation Policy ID")
    ),
    request_body = CreateEscalationLevelRequest,
    responses(
        (status = 201, description = "Level added", body = EscalationLevelResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Policy not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn add_level(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(policy_id): Path<Uuid>,
    Json(request): Json<CreateEscalationLevelRequest>,
) -> ApiResult<(StatusCode, Json<EscalationLevelResponse>)> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = CreateEscalationLevel {
        level_order: request.level_order,
        level_name: request.level_name,
        timeout_secs: request.timeout_secs,
        target_type: request.target_type,
        target_id: request.target_id,
        manager_chain_depth: request.manager_chain_depth,
    };

    let level = state
        .escalation_policy_service
        .add_level(tenant_id, policy_id, input)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(EscalationLevelResponse::from(level)),
    ))
}

/// Remove an escalation level.
#[utoipa::path(
    delete,
    path = "/governance/escalation-policies/{policy_id}/levels/{level_id}",
    tag = "Governance - Workflow Escalation",
    params(
        ("policy_id" = Uuid, Path, description = "Escalation Policy ID"),
        ("level_id" = Uuid, Path, description = "Escalation Level ID")
    ),
    responses(
        (status = 204, description = "Level removed"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Level not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_level(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((policy_id, level_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Verify policy exists and belongs to tenant
    let _ = state
        .escalation_policy_service
        .get_policy(tenant_id, policy_id)
        .await?;

    state
        .escalation_policy_service
        .remove_level(tenant_id, level_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Step Escalation Configuration
// ============================================================================

/// Get escalation configuration for an approval step.
#[utoipa::path(
    get,
    path = "/governance/approval-steps/{step_id}/escalation",
    tag = "Governance - Workflow Escalation",
    params(
        ("step_id" = Uuid, Path, description = "Approval Step ID")
    ),
    responses(
        (status = 200, description = "Step escalation configuration", body = StepEscalationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Step not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_step_escalation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(step_id): Path<Uuid>,
) -> ApiResult<Json<StepEscalationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Verify step exists
    let step = xavyo_db::models::GovApprovalStep::find_by_id(
        state.escalation_policy_service.pool(),
        step_id,
    )
    .await?
    .ok_or(ApiGovernanceError::StepNotFound(step_id))?;

    // Get rule if configured
    let rule = xavyo_db::models::GovEscalationRule::find_by_step(
        state.escalation_policy_service.pool(),
        tenant_id,
        step_id,
    )
    .await?;

    Ok(Json(StepEscalationResponse::from_step_and_rule(
        step_id,
        step.escalation_enabled,
        rule,
    )))
}

/// Configure escalation for an approval step.
#[utoipa::path(
    put,
    path = "/governance/approval-steps/{step_id}/escalation",
    tag = "Governance - Workflow Escalation",
    params(
        ("step_id" = Uuid, Path, description = "Approval Step ID")
    ),
    request_body = ConfigureStepEscalationRequest,
    responses(
        (status = 200, description = "Step escalation configured", body = StepEscalationResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Step not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn configure_step_escalation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(step_id): Path<Uuid>,
    Json(request): Json<ConfigureStepEscalationRequest>,
) -> ApiResult<Json<StepEscalationResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Verify step exists
    let step = GovApprovalStep::find_by_id(state.escalation_policy_service.pool(), step_id)
        .await?
        .ok_or(ApiGovernanceError::StepNotFound(step_id))?;

    // Create or update the rule
    let input = CreateEscalationRule {
        timeout_secs: request.timeout_secs,
        warning_threshold_secs: request.warning_threshold_secs,
        final_fallback: request.final_fallback,
    };

    let rule = GovEscalationRule::upsert(
        state.escalation_policy_service.pool(),
        tenant_id,
        step_id,
        input,
    )
    .await?;

    Ok(Json(StepEscalationResponse::from_step_and_rule(
        step_id,
        step.escalation_enabled,
        Some(rule),
    )))
}

/// Remove escalation configuration for an approval step.
#[utoipa::path(
    delete,
    path = "/governance/approval-steps/{step_id}/escalation",
    tag = "Governance - Workflow Escalation",
    params(
        ("step_id" = Uuid, Path, description = "Approval Step ID")
    ),
    responses(
        (status = 204, description = "Step escalation configuration removed"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Step not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_step_escalation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(step_id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Verify step exists
    let _ = GovApprovalStep::find_by_id(state.escalation_policy_service.pool(), step_id)
        .await?
        .ok_or(ApiGovernanceError::StepNotFound(step_id))?;

    // Delete the rule if it exists
    GovEscalationRule::delete_by_step(state.escalation_policy_service.pool(), tenant_id, step_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Enable escalation for an approval step.
#[utoipa::path(
    post,
    path = "/governance/approval-steps/{step_id}/escalation/enable",
    tag = "Governance - Workflow Escalation",
    params(
        ("step_id" = Uuid, Path, description = "Approval Step ID")
    ),
    responses(
        (status = 200, description = "Escalation enabled", body = StepEscalationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Step not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn enable_step_escalation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(step_id): Path<Uuid>,
) -> ApiResult<Json<StepEscalationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Verify step exists
    let _ = GovApprovalStep::find_by_id(state.escalation_policy_service.pool(), step_id)
        .await?
        .ok_or(ApiGovernanceError::StepNotFound(step_id))?;

    // Enable the rule if it exists
    let rule =
        GovEscalationRule::enable(state.escalation_policy_service.pool(), tenant_id, step_id)
            .await?;

    Ok(Json(StepEscalationResponse::from_step_and_rule(
        step_id, true, rule,
    )))
}

/// Disable escalation for an approval step.
#[utoipa::path(
    post,
    path = "/governance/approval-steps/{step_id}/escalation/disable",
    tag = "Governance - Workflow Escalation",
    params(
        ("step_id" = Uuid, Path, description = "Approval Step ID")
    ),
    responses(
        (status = 200, description = "Escalation disabled", body = StepEscalationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Step not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn disable_step_escalation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(step_id): Path<Uuid>,
) -> ApiResult<Json<StepEscalationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Verify step exists
    let _ = GovApprovalStep::find_by_id(state.escalation_policy_service.pool(), step_id)
        .await?
        .ok_or(ApiGovernanceError::StepNotFound(step_id))?;

    // Disable the rule if it exists
    let rule =
        GovEscalationRule::disable(state.escalation_policy_service.pool(), tenant_id, step_id)
            .await?;

    Ok(Json(StepEscalationResponse::from_step_and_rule(
        step_id, false, rule,
    )))
}
