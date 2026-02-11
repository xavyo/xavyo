//! Approval workflow handlers for governance API.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    ApprovalWorkflowListResponse, ApprovalWorkflowResponse, ApprovalWorkflowSummary,
    CreateApprovalWorkflowRequest, ListWorkflowsQuery, UpdateApprovalWorkflowRequest,
};
use crate::router::GovernanceState;
use crate::services::CreateStepInput;

/// List approval workflows.
#[utoipa::path(
    get,
    path = "/governance/approval-workflows",
    tag = "Governance - Approval Workflows",
    params(ListWorkflowsQuery),
    responses(
        (status = 200, description = "List of approval workflows", body = ApprovalWorkflowListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_workflows(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListWorkflowsQuery>,
) -> ApiResult<Json<ApprovalWorkflowListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let (workflows, total) = state
        .approval_workflow_service
        .list_workflows(tenant_id, query.is_active, query.is_default, limit, offset)
        .await?;

    let items: Vec<ApprovalWorkflowSummary> = workflows
        .into_iter()
        .map(|wws| ApprovalWorkflowSummary {
            id: wws.workflow.id,
            name: wws.workflow.name,
            description: wws.workflow.description,
            is_default: wws.workflow.is_default,
            is_active: wws.workflow.is_active,
            step_count: wws.steps.len() as i32,
            created_at: wws.workflow.created_at,
            updated_at: wws.workflow.updated_at,
        })
        .collect();

    Ok(Json(ApprovalWorkflowListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Get an approval workflow by ID.
#[utoipa::path(
    get,
    path = "/governance/approval-workflows/{id}",
    tag = "Governance - Approval Workflows",
    params(
        ("id" = Uuid, Path, description = "Approval Workflow ID")
    ),
    responses(
        (status = 200, description = "Approval workflow details", body = ApprovalWorkflowResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Workflow not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_workflow(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApprovalWorkflowResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let wws = state
        .approval_workflow_service
        .get_workflow(tenant_id, id)
        .await?;

    Ok(Json(ApprovalWorkflowResponse::from_workflow_and_steps(
        wws.workflow,
        wws.steps,
    )))
}

/// Create a new approval workflow.
#[utoipa::path(
    post,
    path = "/governance/approval-workflows",
    tag = "Governance - Approval Workflows",
    request_body = CreateApprovalWorkflowRequest,
    responses(
        (status = 201, description = "Workflow created", body = ApprovalWorkflowResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Workflow name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_workflow(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateApprovalWorkflowRequest>,
) -> ApiResult<(StatusCode, Json<ApprovalWorkflowResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let steps: Vec<CreateStepInput> = request
        .steps
        .into_iter()
        .map(|s| CreateStepInput {
            approver_type: s.approver_type,
            specific_approvers: s.specific_approvers,
        })
        .collect();

    let wws = state
        .approval_workflow_service
        .create_workflow(
            tenant_id,
            request.name,
            request.description,
            request.is_default,
            steps,
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(ApprovalWorkflowResponse::from_workflow_and_steps(
            wws.workflow,
            wws.steps,
        )),
    ))
}

/// Update an approval workflow.
#[utoipa::path(
    put,
    path = "/governance/approval-workflows/{id}",
    tag = "Governance - Approval Workflows",
    params(
        ("id" = Uuid, Path, description = "Approval Workflow ID")
    ),
    request_body = UpdateApprovalWorkflowRequest,
    responses(
        (status = 200, description = "Workflow updated", body = ApprovalWorkflowResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Workflow not found"),
        (status = 409, description = "Workflow name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_workflow(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateApprovalWorkflowRequest>,
) -> ApiResult<Json<ApprovalWorkflowResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let steps = request.steps.map(|s| {
        s.into_iter()
            .map(|step| CreateStepInput {
                approver_type: step.approver_type,
                specific_approvers: step.specific_approvers,
            })
            .collect()
    });

    let wws = state
        .approval_workflow_service
        .update_workflow(
            tenant_id,
            id,
            request.name,
            request.description,
            request.is_default,
            request.is_active,
            steps,
        )
        .await?;

    Ok(Json(ApprovalWorkflowResponse::from_workflow_and_steps(
        wws.workflow,
        wws.steps,
    )))
}

/// Delete an approval workflow.
#[utoipa::path(
    delete,
    path = "/governance/approval-workflows/{id}",
    tag = "Governance - Approval Workflows",
    params(
        ("id" = Uuid, Path, description = "Approval Workflow ID")
    ),
    responses(
        (status = 204, description = "Workflow deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Workflow not found"),
        (status = 412, description = "Cannot delete workflow with pending requests"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_workflow(
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

    state
        .approval_workflow_service
        .delete_workflow(tenant_id, id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Set a workflow as the default.
#[utoipa::path(
    post,
    path = "/governance/approval-workflows/{id}/set-default",
    tag = "Governance - Approval Workflows",
    params(
        ("id" = Uuid, Path, description = "Approval Workflow ID")
    ),
    responses(
        (status = 200, description = "Workflow set as default", body = ApprovalWorkflowResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Workflow not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn set_default_workflow(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ApprovalWorkflowResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let wws = state
        .approval_workflow_service
        .set_default_workflow(tenant_id, id)
        .await?;

    Ok(Json(ApprovalWorkflowResponse::from_workflow_and_steps(
        wws.workflow,
        wws.steps,
    )))
}
