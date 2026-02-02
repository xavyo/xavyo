//! HTTP handlers for lifecycle configuration management (F052).
//!
//! These handlers provide CRUD operations for lifecycle configurations,
//! including states and transitions.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;

use crate::{
    error::ApiResult,
    models::{
        CreateLifecycleConfigRequest, CreateLifecycleStateRequest,
        CreateLifecycleTransitionRequest, LifecycleConfigDetailResponse,
        LifecycleConfigListResponse, LifecycleConfigResponse, LifecycleStateResponse,
        LifecycleTransitionResponse, ListLifecycleConfigsQuery, UpdateLifecycleConfigRequest,
        UpdateLifecycleStateRequest,
    },
    router::GovernanceState,
};
use xavyo_auth::JwtClaims;

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
