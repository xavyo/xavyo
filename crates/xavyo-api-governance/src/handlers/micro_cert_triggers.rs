//! Micro-certification trigger rule handlers for governance API (F055).

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;
use xavyo_db::models::{CreateMicroCertTrigger, MicroCertTriggerFilter, UpdateMicroCertTrigger};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    CreateTriggerRuleRequest, ListTriggerRulesQuery, TriggerRuleListResponse, TriggerRuleResponse,
    UpdateTriggerRuleRequest,
};
use crate::router::GovernanceState;

/// List micro-certification trigger rules.
#[utoipa::path(
    get,
    path = "/governance/micro-cert-triggers",
    tag = "Governance - Micro-certification",
    params(ListTriggerRulesQuery),
    responses(
        (status = 200, description = "List of trigger rules", body = TriggerRuleListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_triggers(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListTriggerRulesQuery>,
) -> ApiResult<Json<TriggerRuleListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let filter = MicroCertTriggerFilter {
        trigger_type: query.trigger_type,
        scope_type: query.scope_type,
        scope_id: query.scope_id,
        is_active: query.is_active,
        is_default: query.is_default,
    };

    let (triggers, total) = state
        .micro_cert_trigger_service
        .list(tenant_id, &filter, limit, offset)
        .await?;

    let items: Vec<TriggerRuleResponse> = triggers
        .into_iter()
        .map(TriggerRuleResponse::from)
        .collect();

    Ok(Json(TriggerRuleListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Get a trigger rule by ID.
#[utoipa::path(
    get,
    path = "/governance/micro-cert-triggers/{id}",
    tag = "Governance - Micro-certification",
    params(
        ("id" = Uuid, Path, description = "Trigger Rule ID")
    ),
    responses(
        (status = 200, description = "Trigger rule details", body = TriggerRuleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Trigger not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_trigger(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<TriggerRuleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let trigger = state.micro_cert_trigger_service.get(tenant_id, id).await?;

    Ok(Json(TriggerRuleResponse::from(trigger)))
}

/// Create a new trigger rule.
#[utoipa::path(
    post,
    path = "/governance/micro-cert-triggers",
    tag = "Governance - Micro-certification",
    request_body = CreateTriggerRuleRequest,
    responses(
        (status = 201, description = "Trigger created", body = TriggerRuleResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Trigger name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_trigger(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateTriggerRuleRequest>,
) -> ApiResult<(StatusCode, Json<TriggerRuleResponse>)> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = CreateMicroCertTrigger {
        name: request.name,
        trigger_type: request.trigger_type,
        scope_type: request.scope_type,
        scope_id: request.scope_id,
        reviewer_type: request.reviewer_type,
        specific_reviewer_id: request.specific_reviewer_id,
        fallback_reviewer_id: request.fallback_reviewer_id,
        timeout_secs: request.timeout_secs,
        reminder_threshold_percent: request.reminder_threshold_percent,
        auto_revoke: request.auto_revoke,
        revoke_triggering_assignment: request.revoke_triggering_assignment,
        is_default: request.is_default,
        priority: request.priority,
        metadata: request.metadata,
    };

    let trigger = state
        .micro_cert_trigger_service
        .create(tenant_id, input)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(TriggerRuleResponse::from(trigger)),
    ))
}

/// Update a trigger rule.
#[utoipa::path(
    put,
    path = "/governance/micro-cert-triggers/{id}",
    tag = "Governance - Micro-certification",
    params(
        ("id" = Uuid, Path, description = "Trigger Rule ID")
    ),
    request_body = UpdateTriggerRuleRequest,
    responses(
        (status = 200, description = "Trigger updated", body = TriggerRuleResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Trigger not found"),
        (status = 409, description = "Trigger name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_trigger(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateTriggerRuleRequest>,
) -> ApiResult<Json<TriggerRuleResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = UpdateMicroCertTrigger {
        name: request.name,
        scope_type: request.scope_type,
        scope_id: request.scope_id,
        reviewer_type: request.reviewer_type,
        specific_reviewer_id: request.specific_reviewer_id,
        fallback_reviewer_id: request.fallback_reviewer_id,
        timeout_secs: request.timeout_secs,
        reminder_threshold_percent: request.reminder_threshold_percent,
        auto_revoke: request.auto_revoke,
        revoke_triggering_assignment: request.revoke_triggering_assignment,
        is_active: request.is_active,
        is_default: request.is_default,
        priority: request.priority,
        metadata: request.metadata,
    };

    let trigger = state
        .micro_cert_trigger_service
        .update(tenant_id, id, input)
        .await?;

    Ok(Json(TriggerRuleResponse::from(trigger)))
}

/// Delete a trigger rule.
#[utoipa::path(
    delete,
    path = "/governance/micro-cert-triggers/{id}",
    tag = "Governance - Micro-certification",
    params(
        ("id" = Uuid, Path, description = "Trigger Rule ID")
    ),
    responses(
        (status = 204, description = "Trigger deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Trigger not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_trigger(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state
        .micro_cert_trigger_service
        .delete(tenant_id, id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Set a trigger rule as the default for its type.
#[utoipa::path(
    post,
    path = "/governance/micro-cert-triggers/{id}/set-default",
    tag = "Governance - Micro-certification",
    params(
        ("id" = Uuid, Path, description = "Trigger Rule ID")
    ),
    responses(
        (status = 200, description = "Trigger set as default", body = TriggerRuleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Trigger not found"),
        (status = 412, description = "Trigger is not active"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn set_default(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<TriggerRuleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let trigger = state
        .micro_cert_trigger_service
        .set_default(tenant_id, id)
        .await?;

    Ok(Json(TriggerRuleResponse::from(trigger)))
}

/// Enable a trigger rule.
#[utoipa::path(
    post,
    path = "/governance/micro-cert-triggers/{id}/enable",
    tag = "Governance - Micro-certification",
    params(
        ("id" = Uuid, Path, description = "Trigger Rule ID")
    ),
    responses(
        (status = 200, description = "Trigger enabled", body = TriggerRuleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Trigger not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn enable_trigger(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<TriggerRuleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let trigger = state
        .micro_cert_trigger_service
        .enable(tenant_id, id)
        .await?;

    Ok(Json(TriggerRuleResponse::from(trigger)))
}

/// Disable a trigger rule.
#[utoipa::path(
    post,
    path = "/governance/micro-cert-triggers/{id}/disable",
    tag = "Governance - Micro-certification",
    params(
        ("id" = Uuid, Path, description = "Trigger Rule ID")
    ),
    responses(
        (status = 200, description = "Trigger disabled", body = TriggerRuleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Trigger not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn disable_trigger(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<TriggerRuleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let trigger = state
        .micro_cert_trigger_service
        .disable(tenant_id, id)
        .await?;

    Ok(Json(TriggerRuleResponse::from(trigger)))
}
