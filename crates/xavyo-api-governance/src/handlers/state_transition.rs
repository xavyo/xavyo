//! HTTP handlers for state transitions (F052).
//!
//! These handlers provide endpoints for executing state transitions,
//! querying object states, and viewing transition audit records.

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::Response,
    Extension, Json,
};
use serde::Deserialize;
use uuid::Uuid;
use xavyo_db::OutputFormat;

use crate::{
    error::ApiResult,
    models::{
        ExecuteTransitionRequest, ListTransitionAuditQuery, ListTransitionRequestsQuery,
        ObjectLifecycleStatusResponse, TransitionAuditListResponse, TransitionAuditResponse,
        TransitionRequestListResponse, TransitionRequestResponse,
    },
    router::GovernanceState,
    services::StateAffectedEntitlements,
};
use xavyo_auth::JwtClaims;

/// Request body for rollback operation.
#[derive(Debug, Deserialize)]
pub struct RollbackRequest {
    /// Reason for the rollback.
    pub reason: Option<String>,
}

/// Execute a state transition.
///
/// Initiates a state transition for an object. The transition may be executed
/// immediately or scheduled for later. If the transition requires approval,
/// an approval request is created.
#[utoipa::path(
    post,
    path = "/governance/lifecycle/transitions",
    request_body = ExecuteTransitionRequest,
    responses(
        (status = 200, description = "Transition executed immediately", body = TransitionRequestResponse),
        (status = 202, description = "Transition scheduled or pending approval", body = TransitionRequestResponse),
        (status = 400, description = "Invalid request or transition not allowed"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Object or transition not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Governance - State Transitions"
)]
pub async fn execute_transition(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<ExecuteTransitionRequest>,
) -> ApiResult<(StatusCode, Json<TransitionRequestResponse>)> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id =
        Uuid::parse_str(&claims.sub).map_err(|_| crate::error::ApiGovernanceError::Unauthorized)?;
    let (status, response) = state
        .state_transition_service
        .execute_transition(tenant_id, user_id, request)
        .await?;
    Ok((status, Json(response)))
}

/// Get an object's lifecycle status.
///
/// Returns the current state of an object and available transitions.
#[utoipa::path(
    get,
    path = "/governance/lifecycle/objects/{object_type}/{object_id}",
    params(
        ("object_type" = String, Path, description = "Object type (user, role, entitlement)"),
        ("object_id" = Uuid, Path, description = "Object ID")
    ),
    responses(
        (status = 200, description = "Object lifecycle status", body = ObjectLifecycleStatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Object not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Governance - State Transitions"
)]
pub async fn get_object_state(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((object_type, object_id)): Path<(String, Uuid)>,
) -> ApiResult<Json<ObjectLifecycleStatusResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let status = state
        .state_transition_service
        .get_object_state(tenant_id, &object_type, object_id)
        .await?;
    Ok(Json(status))
}

/// List transition requests.
///
/// Returns a paginated list of transition requests with optional filtering.
#[utoipa::path(
    get,
    path = "/governance/lifecycle/transitions/requests",
    params(ListTransitionRequestsQuery),
    responses(
        (status = 200, description = "List of transition requests", body = TransitionRequestListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Governance - State Transitions"
)]
pub async fn list_transition_requests(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<ListTransitionRequestsQuery>,
) -> ApiResult<Json<TransitionRequestListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let requests = state
        .state_transition_service
        .list_transition_requests(tenant_id, &params)
        .await?;
    Ok(Json(requests))
}

/// Get a transition request by ID.
///
/// Returns details about a specific transition request.
#[utoipa::path(
    get,
    path = "/governance/lifecycle/transitions/requests/{request_id}",
    params(
        ("request_id" = Uuid, Path, description = "Transition request ID")
    ),
    responses(
        (status = 200, description = "Transition request details", body = TransitionRequestResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Request not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Governance - State Transitions"
)]
pub async fn get_transition_request(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(request_id): Path<Uuid>,
) -> ApiResult<Json<TransitionRequestResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let request = state
        .state_transition_service
        .get_transition_request(tenant_id, request_id)
        .await?;
    Ok(Json(request))
}

/// List transition audit records.
///
/// Returns a paginated list of transition audit records with optional filtering.
#[utoipa::path(
    get,
    path = "/governance/lifecycle/transitions/audit",
    params(ListTransitionAuditQuery),
    responses(
        (status = 200, description = "List of audit records", body = TransitionAuditListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Governance - State Transitions"
)]
pub async fn list_transition_audit(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<ListTransitionAuditQuery>,
) -> ApiResult<Json<TransitionAuditListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let audit = state
        .state_transition_service
        .list_transition_audit(tenant_id, &params)
        .await?;
    Ok(Json(audit))
}

/// Get a transition audit record by ID.
///
/// Returns details about a specific audit record including before/after snapshots.
#[utoipa::path(
    get,
    path = "/governance/lifecycle/transitions/audit/{audit_id}",
    params(
        ("audit_id" = Uuid, Path, description = "Audit record ID")
    ),
    responses(
        (status = 200, description = "Audit record details", body = TransitionAuditResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Audit record not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Governance - State Transitions"
)]
pub async fn get_transition_audit(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(audit_id): Path<Uuid>,
) -> ApiResult<Json<TransitionAuditResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let audit = state
        .state_transition_service
        .get_transition_audit(tenant_id, audit_id)
        .await?;
    Ok(Json(audit))
}

/// Rollback a transition within its grace period.
///
/// Reverts an executed transition back to its original state. Only available
/// while the grace period is active.
#[utoipa::path(
    post,
    path = "/governance/lifecycle/transitions/{request_id}/rollback",
    params(
        ("request_id" = Uuid, Path, description = "Transition request ID")
    ),
    request_body = RollbackRequest,
    responses(
        (status = 200, description = "Transition rolled back", body = TransitionRequestResponse),
        (status = 400, description = "Rollback not available or grace period expired"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Transition request not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Governance - State Transitions"
)]
pub async fn rollback_transition(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(request_id): Path<Uuid>,
    Json(request): Json<RollbackRequest>,
) -> ApiResult<Json<TransitionRequestResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id =
        Uuid::parse_str(&claims.sub).map_err(|_| crate::error::ApiGovernanceError::Unauthorized)?;
    let response = state
        .state_transition_service
        .rollback_transition(tenant_id, request_id, user_id, request.reason)
        .await?;
    Ok(Json(response))
}

/// Preview entitlements affected by a transition.
///
/// Returns a list of entitlements that would be affected (paused or revoked)
/// if the specified transition is executed on the object.
#[utoipa::path(
    get,
    path = "/governance/lifecycle/transitions/{transition_id}/affected-entitlements/{object_id}",
    params(
        ("transition_id" = Uuid, Path, description = "Transition ID"),
        ("object_id" = Uuid, Path, description = "Object ID")
    ),
    responses(
        (status = 200, description = "Affected entitlements preview", body = StateAffectedEntitlements),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Transition not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Governance - State Transitions"
)]
pub async fn get_affected_entitlements(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((transition_id, object_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<StateAffectedEntitlements>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let affected = state
        .state_transition_service
        .get_affected_entitlements(tenant_id, transition_id, object_id)
        .await?;
    Ok(Json(affected))
}

/// Query parameters for audit export.
#[derive(Debug, Clone, Deserialize)]
pub struct ExportAuditQuery {
    /// Filter by object ID.
    pub object_id: Option<Uuid>,

    /// Filter by object type.
    pub object_type: Option<xavyo_db::LifecycleObjectType>,

    /// Filter by actor.
    pub actor_id: Option<Uuid>,

    /// Filter by action type.
    pub action_type: Option<xavyo_db::AuditActionType>,

    /// Only records after this date.
    pub from_date: Option<chrono::DateTime<chrono::Utc>>,

    /// Only records before this date.
    pub to_date: Option<chrono::DateTime<chrono::Utc>>,

    /// Export format (json or csv).
    #[serde(default)]
    pub format: ExportFormat,
}

/// Export format options.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    #[default]
    Json,
    Csv,
}

impl From<ExportFormat> for OutputFormat {
    fn from(f: ExportFormat) -> Self {
        match f {
            ExportFormat::Json => OutputFormat::Json,
            ExportFormat::Csv => OutputFormat::Csv,
        }
    }
}

/// Export transition audit records.
///
/// Returns audit records in CSV or JSON format for download.
#[utoipa::path(
    get,
    path = "/governance/lifecycle/transitions/audit/export",
    params(
        ("object_id" = Option<Uuid>, Query, description = "Filter by object ID"),
        ("object_type" = Option<String>, Query, description = "Filter by object type"),
        ("actor_id" = Option<Uuid>, Query, description = "Filter by actor"),
        ("action_type" = Option<String>, Query, description = "Filter by action type"),
        ("from_date" = Option<String>, Query, description = "Only records after this date"),
        ("to_date" = Option<String>, Query, description = "Only records before this date"),
        ("format" = Option<String>, Query, description = "Export format (json or csv)")
    ),
    responses(
        (status = 200, description = "Audit records export", content_type = ["application/json", "text/csv"]),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Governance - State Transitions"
)]
pub async fn export_transition_audit(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<ExportAuditQuery>,
) -> ApiResult<Response> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(crate::error::ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let audit_params = ListTransitionAuditQuery {
        object_id: params.object_id,
        object_type: params.object_type,
        actor_id: params.actor_id,
        action_type: params.action_type,
        from_date: params.from_date,
        to_date: params.to_date,
        limit: None,
        offset: None,
    };

    let result = state
        .state_transition_service
        .export_transition_audit(tenant_id, &audit_params, params.format.into())
        .await?;

    let filename = format!(
        "lifecycle_audit_export_{}.{}",
        chrono::Utc::now().format("%Y%m%d_%H%M%S"),
        result.file_extension
    );

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, result.content_type)
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .body(Body::from(result.content))
        .unwrap();

    Ok(response)
}
