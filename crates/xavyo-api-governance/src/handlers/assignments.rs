//! Assignment handlers for governance API.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;
use xavyo_db::models::{BulkAssignmentRequest, CreateGovAssignment, GovPersona};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    AssignmentListResponse, AssignmentResponse, BulkAssignmentResponse,
    BulkCreateAssignmentsRequest, CreateAssignmentRequest, ListAssignmentsQuery,
};
use crate::router::GovernanceState;
use xavyo_webhooks::{EventPublisher, WebhookEvent};

/// Helper function to check if target is a persona and log audit event if so.
/// This supports F063 persona entitlement audit integration.
async fn maybe_log_persona_entitlement_audit(
    state: &GovernanceState,
    tenant_id: Uuid,
    actor_id: Uuid,
    target_id: Uuid,
    entitlement_id: Uuid,
    entitlement_name: &str,
    is_add: bool,
    reason: Option<&str>,
) {
    // Check if target_id is a persona
    if let Ok(Some(_persona)) = GovPersona::find_by_id(state.pool(), tenant_id, target_id).await {
        // Target is a persona - log persona audit event
        if is_add {
            let _ = state
                .persona_audit_service
                .log_entitlement_added(
                    tenant_id,
                    actor_id,
                    target_id,
                    entitlement_id,
                    entitlement_name,
                )
                .await;
        } else {
            let _ = state
                .persona_audit_service
                .log_entitlement_removed(
                    tenant_id,
                    actor_id,
                    target_id,
                    entitlement_id,
                    entitlement_name,
                    reason.unwrap_or("Entitlement removed"),
                )
                .await;
        }
    }
}

/// List assignments with optional filtering and pagination.
#[utoipa::path(
    get,
    path = "/governance/assignments",
    tag = "Governance - Assignments",
    params(ListAssignmentsQuery),
    responses(
        (status = 200, description = "List of assignments", body = AssignmentListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_assignments(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListAssignmentsQuery>,
) -> ApiResult<Json<AssignmentListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let (assignments, total) = state
        .assignment_service
        .list_assignments(
            tenant_id,
            query.entitlement_id,
            query.target_type,
            query.target_id,
            query.status,
            query.limit,
            query.offset,
        )
        .await?;

    Ok(Json(AssignmentListResponse {
        items: assignments.into_iter().map(Into::into).collect(),
        total,
        limit: query.limit,
        offset: query.offset,
    }))
}

/// Get an assignment by ID.
#[utoipa::path(
    get,
    path = "/governance/assignments/{id}",
    tag = "Governance - Assignments",
    params(
        ("id" = Uuid, Path, description = "Assignment ID")
    ),
    responses(
        (status = 200, description = "Assignment details", body = AssignmentResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Assignment not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_assignment(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<AssignmentResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let assignment = state
        .assignment_service
        .get_assignment(tenant_id, id)
        .await?;

    Ok(Json(assignment.into()))
}

/// Create a new assignment.
#[utoipa::path(
    post,
    path = "/governance/assignments",
    tag = "Governance - Assignments",
    request_body = CreateAssignmentRequest,
    responses(
        (status = 201, description = "Assignment created", body = AssignmentResponse),
        (status = 400, description = "Invalid request or expiration date in past"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Entitlement not found"),
        (status = 409, description = "Assignment already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_assignment(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    publisher: Option<Extension<EventPublisher>>,
    Json(request): Json<CreateAssignmentRequest>,
) -> ApiResult<(StatusCode, Json<AssignmentResponse>)> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let assigned_by = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let input = CreateGovAssignment {
        entitlement_id: request.entitlement_id,
        target_type: request.target_type,
        target_id: request.target_id,
        assigned_by,
        expires_at: request.expires_at,
        justification: request.justification,
        parameter_hash: None,
        valid_from: None,
        valid_to: None,
    };

    let assignment = state
        .assignment_service
        .create_assignment(tenant_id, input)
        .await?;

    let response: AssignmentResponse = assignment.into();

    // F063: Log persona audit event if target is a persona
    // Get entitlement name for audit log
    if let Ok(entitlement) = state
        .entitlement_service
        .get_entitlement(tenant_id, request.entitlement_id)
        .await
    {
        maybe_log_persona_entitlement_audit(
            &state,
            tenant_id,
            assigned_by,
            request.target_id,
            request.entitlement_id,
            &entitlement.name,
            true, // is_add
            None,
        )
        .await;
    }

    // F085: Publish role.assigned webhook event
    if let Some(Extension(publisher)) = publisher {
        publisher.publish(WebhookEvent {
            event_id: Uuid::new_v4(),
            event_type: "role.assigned".to_string(),
            tenant_id,
            actor_id: Some(assigned_by),
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "assignment_id": response.id,
                "entitlement_id": response.entitlement_id,
                "target_type": response.target_type,
                "target_id": response.target_id,
            }),
        });
    }

    Ok((StatusCode::CREATED, Json(response)))
}

/// Create multiple assignments at once.
#[utoipa::path(
    post,
    path = "/governance/assignments/bulk",
    tag = "Governance - Assignments",
    request_body = BulkCreateAssignmentsRequest,
    responses(
        (status = 200, description = "Bulk assignment result", body = BulkAssignmentResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Entitlement not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn bulk_create_assignments(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<BulkCreateAssignmentsRequest>,
) -> ApiResult<Json<BulkAssignmentResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let assigned_by = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let bulk_request = BulkAssignmentRequest {
        entitlement_id: request.entitlement_id,
        target_type: request.target_type,
        target_ids: request.target_ids,
        assigned_by,
        expires_at: request.expires_at,
        justification: request.justification,
    };

    let result = state
        .assignment_service
        .bulk_create_assignments(tenant_id, bulk_request)
        .await?;

    Ok(Json(result.into()))
}

/// Revoke (delete) an assignment.
#[utoipa::path(
    delete,
    path = "/governance/assignments/{id}",
    tag = "Governance - Assignments",
    params(
        ("id" = Uuid, Path, description = "Assignment ID")
    ),
    responses(
        (status = 204, description = "Assignment revoked"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Assignment not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_assignment(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    publisher: Option<Extension<EventPublisher>>,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).ok();

    // F063: Get assignment details before revoking for persona audit
    let assignment = state
        .assignment_service
        .get_assignment(tenant_id, id)
        .await
        .ok();

    state
        .assignment_service
        .revoke_assignment(tenant_id, id)
        .await?;

    // F063: Log persona audit event if target was a persona
    if let (Some(assignment), Some(actor)) = (&assignment, actor_id) {
        if let Ok(entitlement) = state
            .entitlement_service
            .get_entitlement(tenant_id, assignment.entitlement_id)
            .await
        {
            maybe_log_persona_entitlement_audit(
                &state,
                tenant_id,
                actor,
                assignment.target_id,
                assignment.entitlement_id,
                &entitlement.name,
                false, // is_add = false (revoke)
                Some("Assignment revoked"),
            )
            .await;
        }
    }

    // F085: Publish role.unassigned webhook event
    if let Some(Extension(publisher)) = publisher {
        publisher.publish(WebhookEvent {
            event_id: Uuid::new_v4(),
            event_type: "role.unassigned".to_string(),
            tenant_id,
            actor_id,
            timestamp: chrono::Utc::now(),
            data: serde_json::json!({
                "assignment_id": id,
            }),
        });
    }

    Ok(StatusCode::NO_CONTENT)
}
