//! Parametric role handlers for governance API (F057).
//!
//! Parametric roles allow roles to have customizable parameters that can be
//! bound at assignment time. This enables a single role definition to be used
//! with different parameter values.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use std::collections::HashMap;
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;
use xavyo_db::{
    CreateGovRoleParameter, ParameterAuditFilter, RoleParameterFilter, SetGovAssignmentParameter,
    UpdateGovRoleParameter,
};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    AssignmentParameterResponse, CreateRoleParameterRequest, ListParameterAuditQuery,
    ListRoleParametersQuery, ParameterAuditEventResponse, ParameterAuditListResponse,
    RoleParameterListResponse, RoleParameterResponse, UpdateRoleParameterRequest,
    ValidateParametersRequest, ValidateParametersResponse,
};
use crate::router::GovernanceState;
use crate::services::ValidationResult;

// ============================================================================
// Role Parameter CRUD Operations (User Story 1)
// ============================================================================

/// List all parameters defined for a role.
#[utoipa::path(
    get,
    path = "/governance/roles/{role_id}/parameters",
    tag = "Governance - Parametric Roles",
    params(
        ("role_id" = Uuid, Path, description = "Role (entitlement) ID"),
        ListRoleParametersQuery
    ),
    responses(
        (status = 200, description = "List of role parameters", body = RoleParameterListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_role_parameters(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
    Query(query): Query<ListRoleParametersQuery>,
) -> ApiResult<Json<RoleParameterListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let filter = RoleParameterFilter {
        parameter_type: query.parameter_type,
        is_required: query.is_required,
        name_contains: query.name,
    };

    let params = state
        .parameter_service
        .list_parameters_filtered(tenant_id, role_id, &filter)
        .await?;

    let total = params.len() as i64;
    let items: Vec<RoleParameterResponse> = params
        .into_iter()
        .map(RoleParameterResponse::from)
        .collect();

    Ok(Json(RoleParameterListResponse { items, total }))
}

/// Add a new parameter to a role.
#[utoipa::path(
    post,
    path = "/governance/roles/{role_id}/parameters",
    tag = "Governance - Parametric Roles",
    params(
        ("role_id" = Uuid, Path, description = "Role (entitlement) ID")
    ),
    request_body = CreateRoleParameterRequest,
    responses(
        (status = 201, description = "Parameter created", body = RoleParameterResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role not found"),
        (status = 409, description = "Parameter name already exists for this role"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn add_role_parameter(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
    Json(request): Json<CreateRoleParameterRequest>,
) -> ApiResult<(StatusCode, Json<RoleParameterResponse>)> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = CreateGovRoleParameter {
        name: request.name,
        display_name: request.display_name,
        description: request.description,
        parameter_type: request.parameter_type,
        is_required: Some(request.is_required),
        default_value: request.default_value,
        constraints: request.constraints.map(std::convert::Into::into),
        display_order: Some(request.display_order),
    };

    let param = state
        .parameter_service
        .create_parameter(tenant_id, role_id, input)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(RoleParameterResponse::from(param)),
    ))
}

/// Get a specific role parameter by ID.
#[utoipa::path(
    get,
    path = "/governance/roles/{role_id}/parameters/{parameter_id}",
    tag = "Governance - Parametric Roles",
    params(
        ("role_id" = Uuid, Path, description = "Role (entitlement) ID"),
        ("parameter_id" = Uuid, Path, description = "Parameter ID")
    ),
    responses(
        (status = 200, description = "Parameter details", body = RoleParameterResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Parameter or role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_role_parameter(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((role_id, parameter_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<Json<RoleParameterResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let param = state
        .parameter_service
        .get_parameter(tenant_id, parameter_id)
        .await?;

    // Verify the parameter belongs to the specified role
    if param.role_id != role_id {
        return Err(ApiGovernanceError::from(
            xavyo_governance::GovernanceError::RoleParameterNotFound(parameter_id),
        ));
    }

    Ok(Json(RoleParameterResponse::from(param)))
}

/// Update a role parameter.
#[utoipa::path(
    put,
    path = "/governance/roles/{role_id}/parameters/{parameter_id}",
    tag = "Governance - Parametric Roles",
    params(
        ("role_id" = Uuid, Path, description = "Role (entitlement) ID"),
        ("parameter_id" = Uuid, Path, description = "Parameter ID")
    ),
    request_body = UpdateRoleParameterRequest,
    responses(
        (status = 200, description = "Parameter updated", body = RoleParameterResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Parameter or role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_role_parameter(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((role_id, parameter_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateRoleParameterRequest>,
) -> ApiResult<Json<RoleParameterResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Verify the parameter belongs to the specified role
    let existing = state
        .parameter_service
        .get_parameter(tenant_id, parameter_id)
        .await?;

    if existing.role_id != role_id {
        return Err(ApiGovernanceError::from(
            xavyo_governance::GovernanceError::RoleParameterNotFound(parameter_id),
        ));
    }

    let input = UpdateGovRoleParameter {
        display_name: request.display_name,
        description: request.description,
        is_required: request.is_required,
        default_value: request.default_value,
        constraints: request.constraints.map(std::convert::Into::into),
        display_order: request.display_order,
    };

    let param = state
        .parameter_service
        .update_parameter(tenant_id, parameter_id, input)
        .await?;

    Ok(Json(RoleParameterResponse::from(param)))
}

/// Delete a role parameter.
///
/// A parameter can only be deleted if no assignments are using it (FR-012).
#[utoipa::path(
    delete,
    path = "/governance/roles/{role_id}/parameters/{parameter_id}",
    tag = "Governance - Parametric Roles",
    params(
        ("role_id" = Uuid, Path, description = "Role (entitlement) ID"),
        ("parameter_id" = Uuid, Path, description = "Parameter ID")
    ),
    responses(
        (status = 204, description = "Parameter deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Parameter or role not found"),
        (status = 409, description = "Cannot delete - parameter has active assignments"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_role_parameter(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((role_id, parameter_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Verify the parameter belongs to the specified role
    let existing = state
        .parameter_service
        .get_parameter(tenant_id, parameter_id)
        .await?;

    if existing.role_id != role_id {
        return Err(ApiGovernanceError::from(
            xavyo_governance::GovernanceError::RoleParameterNotFound(parameter_id),
        ));
    }

    state
        .parameter_service
        .delete_parameter(tenant_id, parameter_id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

// ============================================================================
// Parameter Validation (User Story 1/2)
// ============================================================================

/// Validate parameter values before creating an assignment.
#[utoipa::path(
    post,
    path = "/governance/roles/{role_id}/parameters/validate",
    tag = "Governance - Parametric Roles",
    params(
        ("role_id" = Uuid, Path, description = "Role (entitlement) ID")
    ),
    request_body = ValidateParametersRequest,
    responses(
        (status = 200, description = "Validation result", body = ValidateParametersResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role not found or not parametric"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn validate_parameters(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
    Json(request): Json<ValidateParametersRequest>,
) -> ApiResult<Json<ValidateParametersResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Convert request values to parameter ID-based map
    let mut values: HashMap<Uuid, serde_json::Value> = HashMap::new();
    let mut values_by_name: HashMap<String, serde_json::Value> = HashMap::new();

    for pv in request.parameters {
        if let Some(id) = pv.parameter_id {
            values.insert(id, pv.value);
        } else if let Some(name) = pv.parameter_name {
            values_by_name.insert(name, pv.value);
        }
    }

    // Validate using the appropriate method
    let result = if values_by_name.is_empty() {
        state
            .parameter_service
            .validate_parameters(tenant_id, role_id, &values)
            .await?
    } else {
        state
            .parameter_service
            .validate_parameters_by_name(tenant_id, role_id, &values_by_name)
            .await?
    };

    Ok(Json(convert_validation_result(result)))
}

// ============================================================================
// Parametric Assignment CRUD (User Story 2)
// ============================================================================

/// Create a parametric assignment (role assignment with parameters).
#[utoipa::path(
    post,
    path = "/governance/roles/{role_id}/assignments",
    tag = "Governance - Parametric Roles",
    params(
        ("role_id" = Uuid, Path, description = "Role (entitlement) ID")
    ),
    request_body = crate::models::CreateParametricAssignmentRequest,
    responses(
        (status = 201, description = "Parametric assignment created", body = crate::models::ParametricAssignmentResponse),
        (status = 400, description = "Invalid request or validation failed"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role not found or not parametric"),
        (status = 409, description = "Assignment with same parameters already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_parametric_assignment(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
    Json(request): Json<crate::models::CreateParametricAssignmentRequest>,
) -> ApiResult<(
    StatusCode,
    Json<crate::models::ParametricAssignmentResponse>,
)> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Parse target type
    let target_type = match request.target_type.as_str() {
        "user" => xavyo_db::GovAssignmentTargetType::User,
        "group" => xavyo_db::GovAssignmentTargetType::Group,
        _ => {
            return Err(ApiGovernanceError::Validation(
                "Invalid target_type, must be 'user' or 'group'".to_string(),
            ))
        }
    };

    // Convert parameter values to ID-based map for validation
    let mut values: HashMap<Uuid, serde_json::Value> = HashMap::new();
    let mut values_by_name: HashMap<String, serde_json::Value> = HashMap::new();

    for pv in &request.parameters {
        if let Some(id) = pv.parameter_id {
            values.insert(id, pv.value.clone());
        } else if let Some(ref name) = pv.parameter_name {
            values_by_name.insert(name.clone(), pv.value.clone());
        }
    }

    // If we have name-based parameters, resolve them to IDs
    if !values_by_name.is_empty() {
        let params = state
            .parameter_service
            .list_parameters(tenant_id, role_id)
            .await?;
        for param in params {
            if let Some(value) = values_by_name.remove(&param.name) {
                values.insert(param.id, value);
            }
        }
    }

    // Validate parameter values
    let validation_result = state
        .parameter_service
        .validate_parameters(tenant_id, role_id, &values)
        .await?;

    if !validation_result.is_valid {
        return Err(ApiGovernanceError::Validation(format!(
            "Parameter validation failed: {}",
            validation_result.errors.join(", ")
        )));
    }

    // Compute parameter hash
    let parameter_hash = state
        .parameter_service
        .compute_parameter_hash(tenant_id, role_id, &values)
        .await?;

    // Check for duplicate parametric assignment
    if state
        .parameter_service
        .check_parametric_assignment_exists(
            tenant_id,
            role_id,
            target_type,
            request.target_id,
            &parameter_hash,
        )
        .await?
    {
        return Err(ApiGovernanceError::Conflict(
            "Assignment with same parameters already exists".to_string(),
        ));
    }

    // Create the assignment
    let assignment_input = xavyo_db::CreateGovAssignment {
        entitlement_id: role_id,
        target_type,
        target_id: request.target_id,
        assigned_by: actor_id,
        expires_at: request.expires_at,
        justification: request.justification,
        parameter_hash: Some(parameter_hash.clone()),
        valid_from: request.valid_from,
        valid_to: request.valid_to,
    };

    let assignment = state
        .parameter_service
        .create_parametric_assignment(tenant_id, assignment_input)
        .await?;

    // Set parameter values
    let param_values: Vec<SetGovAssignmentParameter> = values
        .into_iter()
        .map(|(parameter_id, value)| SetGovAssignmentParameter {
            parameter_id,
            value,
        })
        .collect();

    let assignment_params = state
        .parameter_service
        .set_assignment_parameters(tenant_id, assignment.id, actor_id, param_values)
        .await?;

    // Build response
    let now = chrono::Utc::now();
    let is_temporally_active = assignment.valid_from.is_none_or(|vf| vf <= now)
        && assignment.valid_to.is_none_or(|vt| vt > now);

    let params_response: Vec<crate::models::AssignmentParameterResponse> = assignment_params
        .into_iter()
        .map(crate::models::AssignmentParameterResponse::from)
        .collect();

    let response = crate::models::ParametricAssignmentResponse {
        id: assignment.id,
        tenant_id: assignment.tenant_id,
        role_id: assignment.entitlement_id,
        role_name: None, // Would need to fetch
        target_type: request.target_type,
        target_id: assignment.target_id,
        assigned_by: assignment.assigned_by,
        assigned_at: assignment.assigned_at,
        status: format!("{:?}", assignment.status).to_lowercase(),
        justification: assignment.justification,
        expires_at: assignment.expires_at,
        parameter_hash: assignment.parameter_hash,
        valid_from: assignment.valid_from,
        valid_to: assignment.valid_to,
        is_temporally_active,
        parameters: params_response,
    };

    Ok((StatusCode::CREATED, Json(response)))
}

/// Get a parametric assignment by ID.
#[utoipa::path(
    get,
    path = "/governance/assignments/{assignment_id}",
    tag = "Governance - Parametric Roles",
    params(
        ("assignment_id" = Uuid, Path, description = "Assignment ID")
    ),
    responses(
        (status = 200, description = "Parametric assignment details", body = crate::models::ParametricAssignmentResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Assignment not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_parametric_assignment(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(assignment_id): Path<Uuid>,
) -> ApiResult<Json<crate::models::ParametricAssignmentResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let assignment = state
        .parameter_service
        .get_assignment(tenant_id, assignment_id)
        .await?
        .ok_or_else(|| ApiGovernanceError::NotFound("Assignment not found".to_string()))?;

    // Get parameters
    let params = state
        .parameter_service
        .get_assignment_parameters(tenant_id, assignment_id)
        .await?;

    let now = chrono::Utc::now();
    let is_temporally_active = assignment.valid_from.is_none_or(|vf| vf <= now)
        && assignment.valid_to.is_none_or(|vt| vt > now);

    let params_response: Vec<crate::models::AssignmentParameterResponse> = params
        .into_iter()
        .map(crate::models::AssignmentParameterResponse::from)
        .collect();

    let response = crate::models::ParametricAssignmentResponse {
        id: assignment.id,
        tenant_id: assignment.tenant_id,
        role_id: assignment.entitlement_id,
        role_name: None,
        target_type: format!("{:?}", assignment.target_type).to_lowercase(),
        target_id: assignment.target_id,
        assigned_by: assignment.assigned_by,
        assigned_at: assignment.assigned_at,
        status: format!("{:?}", assignment.status).to_lowercase(),
        justification: assignment.justification,
        expires_at: assignment.expires_at,
        parameter_hash: assignment.parameter_hash,
        valid_from: assignment.valid_from,
        valid_to: assignment.valid_to,
        is_temporally_active,
        parameters: params_response,
    };

    Ok(Json(response))
}

/// List parametric assignments for a user.
#[utoipa::path(
    get,
    path = "/governance/users/{user_id}/parametric-assignments",
    tag = "Governance - Parametric Roles",
    params(
        ("user_id" = Uuid, Path, description = "User ID"),
        crate::models::ListParametricAssignmentsQuery
    ),
    responses(
        (status = 200, description = "List of parametric assignments", body = crate::models::ParametricAssignmentListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_user_parametric_assignments(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(user_id): Path<Uuid>,
    Query(query): Query<crate::models::ListParametricAssignmentsQuery>,
) -> ApiResult<Json<crate::models::ParametricAssignmentListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);
    let include_inactive = query.include_inactive.unwrap_or(false);

    // Get parametric assignments for the user
    let assignments = if let Some(role_id) = query.role_id {
        state
            .parameter_service
            .list_parametric_assignments_by_user_and_role(tenant_id, user_id, role_id)
            .await?
    } else {
        state
            .parameter_service
            .list_parametric_assignments_by_user(tenant_id, user_id, include_inactive)
            .await?
    };

    let now = chrono::Utc::now();
    let mut items = Vec::new();

    for assignment in assignments {
        let is_temporally_active = assignment.valid_from.is_none_or(|vf| vf <= now)
            && assignment.valid_to.is_none_or(|vt| vt > now);

        // Skip inactive if not requested
        if !include_inactive && !is_temporally_active {
            continue;
        }

        // Get parameters for this assignment
        let params = state
            .parameter_service
            .get_assignment_parameters(tenant_id, assignment.id)
            .await
            .unwrap_or_default();

        let params_response: Vec<crate::models::AssignmentParameterResponse> = params
            .into_iter()
            .map(crate::models::AssignmentParameterResponse::from)
            .collect();

        items.push(crate::models::ParametricAssignmentResponse {
            id: assignment.id,
            tenant_id: assignment.tenant_id,
            role_id: assignment.entitlement_id,
            role_name: None,
            target_type: format!("{:?}", assignment.target_type).to_lowercase(),
            target_id: assignment.target_id,
            assigned_by: assignment.assigned_by,
            assigned_at: assignment.assigned_at,
            status: format!("{:?}", assignment.status).to_lowercase(),
            justification: assignment.justification,
            expires_at: assignment.expires_at,
            parameter_hash: assignment.parameter_hash,
            valid_from: assignment.valid_from,
            valid_to: assignment.valid_to,
            is_temporally_active,
            parameters: params_response,
        });
    }

    let total = items.len() as i64;

    // Apply pagination
    let paginated_items: Vec<_> = items
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();

    Ok(Json(crate::models::ParametricAssignmentListResponse {
        items: paginated_items,
        total,
        limit,
        offset,
    }))
}

// ============================================================================
// Assignment Parameter Operations (User Story 2)
// ============================================================================

/// Get parameters for an assignment.
#[utoipa::path(
    get,
    path = "/governance/assignments/{assignment_id}/parameters",
    tag = "Governance - Parametric Roles",
    params(
        ("assignment_id" = Uuid, Path, description = "Assignment ID")
    ),
    responses(
        (status = 200, description = "Assignment parameters", body = Vec<AssignmentParameterResponse>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Assignment not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_assignment_parameters(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(assignment_id): Path<Uuid>,
) -> ApiResult<Json<Vec<AssignmentParameterResponse>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let params = state
        .parameter_service
        .get_assignment_parameters(tenant_id, assignment_id)
        .await?;

    let items: Vec<AssignmentParameterResponse> = params
        .into_iter()
        .map(AssignmentParameterResponse::from)
        .collect();

    Ok(Json(items))
}

/// Update parameters for an existing assignment.
#[utoipa::path(
    put,
    path = "/governance/assignments/{assignment_id}/parameters",
    tag = "Governance - Parametric Roles",
    params(
        ("assignment_id" = Uuid, Path, description = "Assignment ID")
    ),
    request_body = ValidateParametersRequest,
    responses(
        (status = 200, description = "Parameters updated", body = Vec<AssignmentParameterResponse>),
        (status = 400, description = "Invalid request or validation failed"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Assignment not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_assignment_parameters(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(assignment_id): Path<Uuid>,
    Json(request): Json<ValidateParametersRequest>,
) -> ApiResult<Json<Vec<AssignmentParameterResponse>>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Convert request values to SetGovAssignmentParameter
    let values: Vec<SetGovAssignmentParameter> = request
        .parameters
        .into_iter()
        .filter_map(|pv| {
            pv.parameter_id.map(|id| SetGovAssignmentParameter {
                parameter_id: id,
                value: pv.value,
            })
        })
        .collect();

    let params = state
        .parameter_service
        .update_assignment_parameters(tenant_id, assignment_id, actor_id, values)
        .await?;

    let items: Vec<AssignmentParameterResponse> = params
        .into_iter()
        .map(AssignmentParameterResponse::from)
        .collect();

    Ok(Json(items))
}

// ============================================================================
// Audit Trail (User Story 6)
// ============================================================================

/// List parameter audit events.
#[utoipa::path(
    get,
    path = "/governance/parameters/audit",
    tag = "Governance - Parametric Roles",
    params(ListParameterAuditQuery),
    responses(
        (status = 200, description = "Audit events list", body = ParameterAuditListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_parameter_audit(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListParameterAuditQuery>,
) -> ApiResult<Json<ParameterAuditListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let filter = ParameterAuditFilter {
        assignment_id: query.assignment_id,
        event_type: query.event_type,
        actor_id: query.actor_id,
        from_date: query.from_date,
        to_date: query.to_date,
    };

    let (events, total) = state
        .parameter_service
        .query_audit_events(tenant_id, &filter, limit, offset)
        .await?;

    let items: Vec<ParameterAuditEventResponse> = events
        .into_iter()
        .map(ParameterAuditEventResponse::from)
        .collect();

    Ok(Json(ParameterAuditListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Get audit events for a specific assignment.
#[utoipa::path(
    get,
    path = "/governance/assignments/{assignment_id}/parameters/audit",
    tag = "Governance - Parametric Roles",
    params(
        ("assignment_id" = Uuid, Path, description = "Assignment ID")
    ),
    responses(
        (status = 200, description = "Assignment audit events", body = Vec<ParameterAuditEventResponse>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Assignment not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_assignment_parameter_audit(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(assignment_id): Path<Uuid>,
) -> ApiResult<Json<Vec<ParameterAuditEventResponse>>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let events = state
        .parameter_service
        .list_assignment_audit(tenant_id, assignment_id)
        .await?;

    let items: Vec<ParameterAuditEventResponse> = events
        .into_iter()
        .map(ParameterAuditEventResponse::from)
        .collect();

    Ok(Json(items))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert service validation result to API response.
fn convert_validation_result(result: ValidationResult) -> ValidateParametersResponse {
    ValidateParametersResponse {
        is_valid: result.is_valid,
        results: result
            .results
            .into_iter()
            .map(|r| crate::models::ParameterValidationResult {
                parameter_id: r.parameter_id,
                parameter_name: r.parameter_name,
                is_valid: r.is_valid,
                errors: r.errors,
                normalized_value: r.normalized_value,
            })
            .collect(),
        errors: result.errors,
    }
}
