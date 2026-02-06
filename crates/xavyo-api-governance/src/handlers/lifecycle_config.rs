//! HTTP handlers for lifecycle configuration management (F052).
//!
//! These handlers provide CRUD operations for lifecycle configurations,
//! including states and transitions.
//!
//! Extended in F-193 to support transition conditions and state actions.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;

use crate::{
    error::ApiResult,
    models::{
        CreateLifecycleConfigRequest, CreateLifecycleStateRequest,
        CreateLifecycleTransitionRequest, EvaluateTransitionConditionsRequest,
        GetStateActionsResponse, GetTransitionConditionsResponse, LifecycleAction,
        LifecycleConfigDetailResponse, LifecycleConfigListResponse, LifecycleConfigResponse,
        LifecycleStateResponse, LifecycleTransitionResponse, ListLifecycleConfigsQuery,
        TransitionCondition, TransitionConditionsEvaluationResult, UpdateLifecycleConfigRequest,
        UpdateLifecycleStateRequest, UpdateStateActionsRequest, UpdateTransitionConditionsRequest,
    },
    router::GovernanceState,
    services::condition_evaluator::ConditionEvaluator,
};
use xavyo_auth::JwtClaims;
use xavyo_db::{GovLifecycleState, GovLifecycleTransition};

/// List lifecycle configurations.
///
/// Returns a paginated list of lifecycle configurations with optional filtering.
#[utoipa::path(
    get,
    path = "/governance/lifecycle/configs",
    params(ListLifecycleConfigsQuery),
    responses(
        (status = 200, description = "List of lifecycle configurations", body = LifecycleConfigListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Lifecycle Configuration"
)]
pub async fn list_configs(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<ListLifecycleConfigsQuery>,
) -> ApiResult<Json<LifecycleConfigListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let configs = state
        .lifecycle_config_service
        .list_configs(tenant_id, &params)
        .await?;
    Ok(Json(configs))
}

/// Get a lifecycle configuration by ID.
///
/// Returns detailed information about a lifecycle configuration,
/// including its states and transitions.
#[utoipa::path(
    get,
    path = "/governance/lifecycle/configs/{config_id}",
    params(
        ("config_id" = Uuid, Path, description = "Lifecycle configuration ID")
    ),
    responses(
        (status = 200, description = "Lifecycle configuration details", body = LifecycleConfigDetailResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Configuration not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Lifecycle Configuration"
)]
pub async fn get_config(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(config_id): Path<Uuid>,
) -> ApiResult<Json<LifecycleConfigDetailResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let config = state
        .lifecycle_config_service
        .get_config(tenant_id, config_id)
        .await?;
    Ok(Json(config))
}

/// Create a new lifecycle configuration.
///
/// Creates a configuration for managing the lifecycle of a specific object type.
/// Only one configuration per object type is allowed.
#[utoipa::path(
    post,
    path = "/governance/lifecycle/configs",
    request_body = CreateLifecycleConfigRequest,
    responses(
        (status = 201, description = "Lifecycle configuration created", body = LifecycleConfigResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Configuration already exists for this object type"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Lifecycle Configuration"
)]
pub async fn create_config(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateLifecycleConfigRequest>,
) -> ApiResult<Json<LifecycleConfigResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let config = state
        .lifecycle_config_service
        .create_config(tenant_id, request)
        .await?;
    Ok(Json(config))
}

/// Update a lifecycle configuration.
///
/// Updates the name, description, or active status of a configuration.
#[utoipa::path(
    patch,
    path = "/governance/lifecycle/configs/{config_id}",
    params(
        ("config_id" = Uuid, Path, description = "Lifecycle configuration ID")
    ),
    request_body = UpdateLifecycleConfigRequest,
    responses(
        (status = 200, description = "Lifecycle configuration updated", body = LifecycleConfigResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Configuration not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Lifecycle Configuration"
)]
pub async fn update_config(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(config_id): Path<Uuid>,
    Json(request): Json<UpdateLifecycleConfigRequest>,
) -> ApiResult<Json<LifecycleConfigResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let config = state
        .lifecycle_config_service
        .update_config(tenant_id, config_id, request)
        .await?;
    Ok(Json(config))
}

/// Delete a lifecycle configuration.
///
/// Deletes a lifecycle configuration. This will also delete all associated
/// states and transitions. Fails if any objects are using this configuration.
#[utoipa::path(
    delete,
    path = "/governance/lifecycle/configs/{config_id}",
    params(
        ("config_id" = Uuid, Path, description = "Lifecycle configuration ID")
    ),
    responses(
        (status = 204, description = "Lifecycle configuration deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Configuration not found"),
        (status = 409, description = "Configuration is in use"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Lifecycle Configuration"
)]
pub async fn delete_config(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(config_id): Path<Uuid>,
) -> ApiResult<axum::http::StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    state
        .lifecycle_config_service
        .delete_config(tenant_id, config_id)
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Add a state to a lifecycle configuration.
///
/// Creates a new state that objects can be in within this lifecycle.
#[utoipa::path(
    post,
    path = "/governance/lifecycle/configs/{config_id}/states",
    params(
        ("config_id" = Uuid, Path, description = "Lifecycle configuration ID")
    ),
    request_body = CreateLifecycleStateRequest,
    responses(
        (status = 201, description = "Lifecycle state created", body = LifecycleStateResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Configuration not found"),
        (status = 409, description = "State name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Lifecycle Configuration"
)]
pub async fn add_state(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(config_id): Path<Uuid>,
    Json(request): Json<CreateLifecycleStateRequest>,
) -> ApiResult<Json<LifecycleStateResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let lifecycle_state = state
        .lifecycle_config_service
        .add_state(tenant_id, config_id, request)
        .await?;
    Ok(Json(lifecycle_state))
}

/// Update a lifecycle state.
///
/// Updates properties of an existing state.
#[utoipa::path(
    patch,
    path = "/governance/lifecycle/configs/{config_id}/states/{state_id}",
    params(
        ("config_id" = Uuid, Path, description = "Lifecycle configuration ID"),
        ("state_id" = Uuid, Path, description = "Lifecycle state ID")
    ),
    request_body = UpdateLifecycleStateRequest,
    responses(
        (status = 200, description = "Lifecycle state updated", body = LifecycleStateResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "State not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Lifecycle Configuration"
)]
pub async fn update_state(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((config_id, state_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateLifecycleStateRequest>,
) -> ApiResult<Json<LifecycleStateResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let lifecycle_state = state
        .lifecycle_config_service
        .update_state(tenant_id, config_id, state_id, request)
        .await?;
    Ok(Json(lifecycle_state))
}

/// Delete a lifecycle state.
///
/// Removes a state from the configuration. Fails if any objects are in this state
/// or if transitions reference this state.
#[utoipa::path(
    delete,
    path = "/governance/lifecycle/configs/{config_id}/states/{state_id}",
    params(
        ("config_id" = Uuid, Path, description = "Lifecycle configuration ID"),
        ("state_id" = Uuid, Path, description = "Lifecycle state ID")
    ),
    responses(
        (status = 204, description = "Lifecycle state deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "State not found"),
        (status = 409, description = "State is in use"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Lifecycle Configuration"
)]
pub async fn delete_state(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((config_id, state_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<axum::http::StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    state
        .lifecycle_config_service
        .delete_state(tenant_id, config_id, state_id)
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Add a transition to a lifecycle configuration.
///
/// Creates a new transition defining how objects can move between states.
#[utoipa::path(
    post,
    path = "/governance/lifecycle/configs/{config_id}/transitions",
    params(
        ("config_id" = Uuid, Path, description = "Lifecycle configuration ID")
    ),
    request_body = CreateLifecycleTransitionRequest,
    responses(
        (status = 201, description = "Lifecycle transition created", body = LifecycleTransitionResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Configuration or states not found"),
        (status = 409, description = "Transition already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Lifecycle Configuration"
)]
pub async fn add_transition(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(config_id): Path<Uuid>,
    Json(request): Json<CreateLifecycleTransitionRequest>,
) -> ApiResult<Json<LifecycleTransitionResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let transition = state
        .lifecycle_config_service
        .add_transition(tenant_id, config_id, request)
        .await?;
    Ok(Json(transition))
}

/// Delete a transition from a lifecycle configuration.
///
/// Removes a transition. This does not affect objects that have already
/// used this transition.
#[utoipa::path(
    delete,
    path = "/governance/lifecycle/configs/{config_id}/transitions/{transition_id}",
    params(
        ("config_id" = Uuid, Path, description = "Lifecycle configuration ID"),
        ("transition_id" = Uuid, Path, description = "Lifecycle transition ID")
    ),
    responses(
        (status = 204, description = "Lifecycle transition deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Transition not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Lifecycle Configuration"
)]
pub async fn delete_transition(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((config_id, transition_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<axum::http::StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    state
        .lifecycle_config_service
        .delete_transition(tenant_id, config_id, transition_id)
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

// =========================================================================
// Transition Conditions (F-193)
// =========================================================================

/// Get conditions for a transition.
///
/// Returns the conditions configured for a specific transition.
/// Conditions must be satisfied before the transition can be executed.
#[utoipa::path(
    get,
    path = "/governance/lifecycle/configs/{config_id}/transitions/{transition_id}/conditions",
    params(
        ("config_id" = Uuid, Path, description = "Lifecycle configuration ID"),
        ("transition_id" = Uuid, Path, description = "Lifecycle transition ID")
    ),
    responses(
        (status = 200, description = "Transition conditions", body = GetTransitionConditionsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Transition not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Lifecycle Conditions"
)]
pub async fn get_transition_conditions(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((config_id, transition_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<GetTransitionConditionsResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Get the transition
    let transition = GovLifecycleTransition::find_by_id(state.pool(), tenant_id, transition_id)
        .await?
        .ok_or(crate::error::ApiGovernanceError::NotFound(format!(
            "Transition {} not found",
            transition_id
        )))?;

    // Verify it belongs to the specified config
    if transition.config_id != config_id {
        return Err(crate::error::ApiGovernanceError::NotFound(format!(
            "Transition {} not found in config {}",
            transition_id, config_id
        )));
    }

    // Parse conditions from JSON
    let conditions: Vec<TransitionCondition> = match &transition.conditions {
        Some(serde_json::Value::Array(arr)) if !arr.is_empty() => {
            serde_json::from_value(serde_json::Value::Array(arr.clone())).map_err(|e| {
                crate::error::ApiGovernanceError::Internal(format!(
                    "Failed to parse conditions: {}",
                    e
                ))
            })?
        }
        _ => Vec::new(),
    };

    Ok(Json(GetTransitionConditionsResponse {
        transition_id,
        transition_name: transition.name,
        conditions,
    }))
}

/// Update conditions for a transition.
///
/// Replaces all conditions for a transition with the provided conditions.
/// Conditions are evaluated before a transition can be executed.
#[utoipa::path(
    put,
    path = "/governance/lifecycle/configs/{config_id}/transitions/{transition_id}/conditions",
    params(
        ("config_id" = Uuid, Path, description = "Lifecycle configuration ID"),
        ("transition_id" = Uuid, Path, description = "Lifecycle transition ID")
    ),
    request_body = UpdateTransitionConditionsRequest,
    responses(
        (status = 200, description = "Transition conditions updated", body = GetTransitionConditionsResponse),
        (status = 400, description = "Invalid conditions"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Transition not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Lifecycle Conditions"
)]
pub async fn update_transition_conditions(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((config_id, transition_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateTransitionConditionsRequest>,
) -> ApiResult<Json<GetTransitionConditionsResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Get the transition to verify it exists and belongs to the config
    let transition = GovLifecycleTransition::find_by_id(state.pool(), tenant_id, transition_id)
        .await?
        .ok_or(crate::error::ApiGovernanceError::NotFound(format!(
            "Transition {} not found",
            transition_id
        )))?;

    // Verify it belongs to the specified config
    if transition.config_id != config_id {
        return Err(crate::error::ApiGovernanceError::NotFound(format!(
            "Transition {} not found in config {}",
            transition_id, config_id
        )));
    }

    // Convert conditions to JSON
    let conditions_json = serde_json::to_value(&request.conditions).map_err(|e| {
        crate::error::ApiGovernanceError::Internal(format!("Failed to serialize conditions: {}", e))
    })?;

    // Update the transition conditions
    GovLifecycleTransition::update_conditions(
        state.pool(),
        tenant_id,
        transition_id,
        &conditions_json,
    )
    .await?;

    Ok(Json(GetTransitionConditionsResponse {
        transition_id,
        transition_name: transition.name,
        conditions: request.conditions,
    }))
}

/// Evaluate conditions for a transition.
///
/// Evaluates all conditions for a transition against a specific object.
/// Returns whether all conditions are satisfied and individual condition results.
#[utoipa::path(
    post,
    path = "/governance/lifecycle/configs/{config_id}/transitions/{transition_id}/conditions/evaluate",
    params(
        ("config_id" = Uuid, Path, description = "Lifecycle configuration ID"),
        ("transition_id" = Uuid, Path, description = "Lifecycle transition ID")
    ),
    request_body = EvaluateTransitionConditionsRequest,
    responses(
        (status = 200, description = "Condition evaluation result", body = TransitionConditionsEvaluationResult),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Transition or object not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Lifecycle Conditions"
)]
pub async fn evaluate_transition_conditions(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((config_id, transition_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<EvaluateTransitionConditionsRequest>,
) -> ApiResult<Json<TransitionConditionsEvaluationResult>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Verify the transition exists and belongs to the config
    let transition = GovLifecycleTransition::find_by_id(state.pool(), tenant_id, transition_id)
        .await?
        .ok_or(crate::error::ApiGovernanceError::NotFound(format!(
            "Transition {} not found",
            transition_id
        )))?;

    if transition.config_id != config_id {
        return Err(crate::error::ApiGovernanceError::NotFound(format!(
            "Transition {} not found in config {}",
            transition_id, config_id
        )));
    }

    // Use the ConditionEvaluator service
    let evaluator = ConditionEvaluator::new(state.pool().clone());
    let result = evaluator
        .evaluate(tenant_id, transition_id, request.object_id)
        .await?;

    Ok(Json(result))
}

// ============================================================================
// State Actions Handlers (F-193)
// ============================================================================

/// Get state actions.
///
/// Returns the entry and exit actions configured for a lifecycle state.
#[utoipa::path(
    get,
    path = "/governance/lifecycle/configs/{config_id}/states/{state_id}/actions",
    params(
        ("config_id" = Uuid, Path, description = "Lifecycle configuration ID"),
        ("state_id" = Uuid, Path, description = "Lifecycle state ID")
    ),
    responses(
        (status = 200, description = "State actions", body = GetStateActionsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "State not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Lifecycle Actions"
)]
pub async fn get_state_actions(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((config_id, state_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<GetStateActionsResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Find the state
    let lifecycle_state = GovLifecycleState::find_by_id(state.pool(), tenant_id, state_id)
        .await?
        .ok_or(crate::error::ApiGovernanceError::NotFound(format!(
            "State {} not found",
            state_id
        )))?;

    // Verify state belongs to the config
    if lifecycle_state.config_id != config_id {
        return Err(crate::error::ApiGovernanceError::NotFound(format!(
            "State {} not found in config {}",
            state_id, config_id
        )));
    }

    // Parse entry actions
    let entry_actions: Vec<LifecycleAction> = lifecycle_state
        .entry_actions
        .as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    // Parse exit actions
    let exit_actions: Vec<LifecycleAction> = lifecycle_state
        .exit_actions
        .as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    Ok(Json(GetStateActionsResponse {
        state_id,
        state_name: lifecycle_state.name,
        entry_actions,
        exit_actions,
    }))
}

/// Update state actions.
///
/// Updates the entry and/or exit actions for a lifecycle state.
/// Providing entry_actions or exit_actions replaces all existing actions for that trigger type.
#[utoipa::path(
    put,
    path = "/governance/lifecycle/configs/{config_id}/states/{state_id}/actions",
    params(
        ("config_id" = Uuid, Path, description = "Lifecycle configuration ID"),
        ("state_id" = Uuid, Path, description = "Lifecycle state ID")
    ),
    request_body = UpdateStateActionsRequest,
    responses(
        (status = 200, description = "Updated state actions", body = GetStateActionsResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "State not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Lifecycle Actions"
)]
pub async fn update_state_actions(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((config_id, state_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateStateActionsRequest>,
) -> ApiResult<Json<GetStateActionsResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Find the state
    let lifecycle_state = GovLifecycleState::find_by_id(state.pool(), tenant_id, state_id)
        .await?
        .ok_or(crate::error::ApiGovernanceError::NotFound(format!(
            "State {} not found",
            state_id
        )))?;

    // Verify state belongs to the config
    if lifecycle_state.config_id != config_id {
        return Err(crate::error::ApiGovernanceError::NotFound(format!(
            "State {} not found in config {}",
            state_id, config_id
        )));
    }

    // Prepare the actions as JSON values
    let entry_actions_json = request
        .entry_actions
        .as_ref()
        .and_then(|actions| serde_json::to_value(actions).ok());

    let exit_actions_json = request
        .exit_actions
        .as_ref()
        .and_then(|actions| serde_json::to_value(actions).ok());

    // Update the state with new actions
    let updated_state = GovLifecycleState::update_actions(
        state.pool(),
        tenant_id,
        state_id,
        entry_actions_json.as_ref(),
        exit_actions_json.as_ref(),
    )
    .await?
    .ok_or(crate::error::ApiGovernanceError::NotFound(format!(
        "State {} not found after update",
        state_id
    )))?;

    // Parse the updated actions
    let entry_actions: Vec<LifecycleAction> = updated_state
        .entry_actions
        .as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let exit_actions: Vec<LifecycleAction> = updated_state
        .exit_actions
        .as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    Ok(Json(GetStateActionsResponse {
        state_id,
        state_name: updated_state.name,
        entry_actions,
        exit_actions,
    }))
}

/// Get comprehensive lifecycle status for a user.
///
/// Returns the user's current lifecycle state, available transitions with
/// condition evaluation, pending scheduled transitions, and effective
/// lifecycle model (from archetype or direct assignment).
#[utoipa::path(
    get,
    path = "/governance/users/{user_id}/lifecycle/status",
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User lifecycle status", body = UserLifecycleStatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "User not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Lifecycle Configuration"
)]
pub async fn get_user_lifecycle_status(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(user_id): Path<Uuid>,
) -> ApiResult<Json<crate::models::UserLifecycleStatusResponse>> {
    use crate::models::{
        AvailableTransitionWithConditions, LifecycleModelInfo, LifecycleModelSource,
        LifecycleStateResponse, LifecycleTransitionResponse, RollbackInfo,
        ScheduledTransitionResponse, UserLifecycleStatusResponse,
    };
    use crate::services::ArchetypeLifecycleService;
    use std::sync::Arc;
    use xavyo_db::GovLifecycleConfig;

    let pool = state.pool();
    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or_else(|| crate::error::ApiGovernanceError::Unauthorized)?;

    // Get user information
    let user: Option<(Option<Uuid>, Option<Uuid>, Option<String>)> = sqlx::query_as(
        r"
        SELECT lifecycle_config_id, archetype_id, lifecycle_state FROM users
        WHERE id = $1 AND tenant_id = $2
        ",
    )
    .bind(user_id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(crate::error::ApiGovernanceError::Database)?;

    let Some((lifecycle_config_id, archetype_id, lifecycle_state)) = user else {
        return Err(crate::error::ApiGovernanceError::NotFound(format!(
            "User {} not found",
            user_id
        )));
    };

    // Resolve effective lifecycle model
    let lifecycle_model: Option<LifecycleModelInfo> = if let Some(config_id) = lifecycle_config_id {
        // Direct assignment
        let config = GovLifecycleConfig::find_by_id(pool, tenant_id, config_id)
            .await
            .map_err(crate::error::ApiGovernanceError::Database)?;

        config.map(|c| LifecycleModelInfo {
            id: c.id,
            name: c.name,
            source: LifecycleModelSource::Direct,
        })
    } else if let Some(arch_id) = archetype_id {
        // Try archetype inheritance
        let archetype_service = ArchetypeLifecycleService::new(Arc::new(pool.clone()));
        let effective = archetype_service
            .resolve_effective_lifecycle(tenant_id, arch_id)
            .await
            .map_err(|e| {
                crate::error::ApiGovernanceError::Governance(
                    xavyo_governance::GovernanceError::ActionExecutionFailed(e.to_string()),
                )
            })?;

        effective.map(|e| LifecycleModelInfo {
            id: e.model_id,
            name: e.model_name,
            source: LifecycleModelSource::Archetype, // Simplified - same source regardless
        })
    } else {
        None
    };

    // Get current state info if lifecycle model is assigned
    let current_state: Option<LifecycleStateResponse> = if let Some(ref model) = lifecycle_model {
        if let Some(ref state_name) = lifecycle_state {
            let state_record =
                GovLifecycleState::find_by_name(pool, tenant_id, model.id, state_name)
                    .await
                    .map_err(crate::error::ApiGovernanceError::Database)?;

            state_record.map(|s| LifecycleStateResponse {
                id: s.id,
                name: s.name,
                description: s.description,
                is_initial: s.is_initial,
                is_terminal: s.is_terminal,
                entitlement_action: s.entitlement_action,
                position: s.position,
                object_count: 0,
                created_at: s.created_at,
            })
        } else {
            None
        }
    } else {
        None
    };

    // Get available transitions with condition evaluation
    let mut available_transitions: Vec<AvailableTransitionWithConditions> = Vec::new();

    if let (Some(ref _model), Some(ref current)) = (&lifecycle_model, &current_state) {
        let transitions = GovLifecycleTransition::list_from_state(pool, tenant_id, current.id)
            .await
            .map_err(crate::error::ApiGovernanceError::Database)?;

        let condition_evaluator = ConditionEvaluator::new(pool.clone());

        for transition in transitions {
            let conditions: Vec<TransitionCondition> = transition
                .conditions
                .as_ref()
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default();

            let to_state = GovLifecycleState::find_by_id(pool, tenant_id, transition.to_state_id)
                .await
                .map_err(crate::error::ApiGovernanceError::Database)?;

            // Evaluate conditions using evaluate_conditions method
            let result = condition_evaluator
                .evaluate_conditions(tenant_id, user_id, &conditions)
                .await
                .map_err(|e| {
                    crate::error::ApiGovernanceError::Governance(
                        xavyo_governance::GovernanceError::ActionExecutionFailed(e.to_string()),
                    )
                })?;

            let all_satisfied = result.all_satisfied;
            let condition_results = result.conditions;

            available_transitions.push(AvailableTransitionWithConditions {
                transition: LifecycleTransitionResponse {
                    id: transition.id,
                    name: transition.name,
                    from_state_id: transition.from_state_id,
                    from_state_name: current.name.clone(),
                    to_state_id: transition.to_state_id,
                    to_state_name: to_state.map(|s| s.name).unwrap_or_default(),
                    requires_approval: transition.requires_approval,
                    approval_workflow_id: transition.approval_workflow_id,
                    grace_period_hours: transition.grace_period_hours,
                    created_at: transition.created_at,
                },
                conditions_satisfied: all_satisfied,
                condition_results,
            });
        }
    }

    // Note: Pending schedules and rollback info require additional queries
    // that are not part of the core lifecycle status. For now, return empty values.
    // These can be enhanced in a future iteration.
    let pending_schedules: Vec<ScheduledTransitionResponse> = Vec::new();
    let active_rollback: Option<RollbackInfo> = None;

    Ok(Json(UserLifecycleStatusResponse {
        user_id,
        current_state,
        available_transitions,
        pending_schedules,
        active_rollback,
        lifecycle_model,
    }))
}
