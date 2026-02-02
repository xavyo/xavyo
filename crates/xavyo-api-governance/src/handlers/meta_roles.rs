//! Meta-role handlers for governance API (F056).
//!
//! Meta-roles enable hierarchical role inheritance where a meta-role can define
//! entitlements, constraints, and policies that are automatically inherited by
//! all roles matching specific criteria.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;
use xavyo_db::{
    CreateGovMetaRole, CreateGovMetaRoleConstraint, CreateGovMetaRoleCriteria,
    CreateGovMetaRoleEntitlement, MetaRoleFilter, UpdateGovMetaRole,
};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    AddMetaRoleConstraintRequest, AddMetaRoleEntitlementRequest, CascadeFailure,
    CascadeStatusResponse, ConflictListResponse, ConflictResponse, CreateMetaRoleRequest,
    EventListResponse, EventResponse, EventStatsResponse, InheritanceListResponse,
    InheritanceResponse, ListConflictsQuery, ListEventsQuery, ListInheritancesQuery,
    ListMetaRolesQuery, MetaRoleConstraintResponse, MetaRoleCriteriaResponse,
    MetaRoleEntitlementResponse, MetaRoleListResponse, MetaRoleResponse, MetaRoleStatsResponse,
    MetaRoleWithDetailsResponse, ResolveConflictRequest, RoleMatchResponse,
    SimulateMetaRoleRequest, SimulationResultResponse, TriggerCascadeRequest,
    UpdateMetaRoleRequest,
};
use crate::router::GovernanceState;

// ============================================================================
// Meta-Role CRUD Operations
// ============================================================================

/// List meta-roles with filtering.
#[utoipa::path(
    get,
    path = "/governance/meta-roles",
    tag = "Governance - Meta-roles",
    params(ListMetaRolesQuery),
    responses(
        (status = 200, description = "List of meta-roles", body = MetaRoleListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_meta_roles(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListMetaRolesQuery>,
) -> ApiResult<Json<MetaRoleListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let filter = MetaRoleFilter {
        status: query.status,
        name_contains: query.name,
        priority_min: None,
        priority_max: None,
    };

    let (meta_roles, total) = state
        .meta_role_service
        .list(tenant_id, &filter, limit, offset)
        .await?;

    let items: Vec<MetaRoleResponse> = meta_roles.into_iter().map(MetaRoleResponse::from).collect();

    Ok(Json(MetaRoleListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Create a new meta-role.
#[utoipa::path(
    post,
    path = "/governance/meta-roles",
    tag = "Governance - Meta-roles",
    request_body = CreateMetaRoleRequest,
    responses(
        (status = 201, description = "Meta-role created", body = MetaRoleResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Conflict - name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_meta_role(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateMetaRoleRequest>,
) -> ApiResult<Json<MetaRoleResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let created_by = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Convert API request to DB model
    let input = CreateGovMetaRole {
        name: request.name,
        description: request.description,
        priority: Some(request.priority),
        criteria_logic: Some(request.criteria_logic),
    };

    let criteria: Vec<CreateGovMetaRoleCriteria> = request
        .criteria
        .into_iter()
        .map(|c| CreateGovMetaRoleCriteria {
            field: c.field,
            operator: c.operator,
            value: c.value,
        })
        .collect();

    let result = state
        .meta_role_service
        .create(tenant_id, created_by, input, criteria)
        .await?;

    Ok(Json(MetaRoleResponse::from(result)))
}

/// Get a meta-role by ID.
#[utoipa::path(
    get,
    path = "/governance/meta-roles/{id}",
    tag = "Governance - Meta-roles",
    params(
        ("id" = Uuid, Path, description = "Meta-role ID")
    ),
    responses(
        (status = 200, description = "Meta-role details", body = MetaRoleWithDetailsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Meta-role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_meta_role(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<MetaRoleWithDetailsResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Get meta-role
    let meta_role = state.meta_role_service.get(tenant_id, id).await?;

    // Get related data
    let criteria = state.meta_role_service.list_criteria(tenant_id, id).await?;
    let entitlements = state
        .meta_role_service
        .list_entitlements(tenant_id, id)
        .await?;
    let constraints = state
        .meta_role_service
        .list_constraints(tenant_id, id)
        .await?;

    Ok(Json(MetaRoleWithDetailsResponse {
        meta_role: MetaRoleResponse::from(meta_role),
        criteria: criteria
            .into_iter()
            .map(MetaRoleCriteriaResponse::from)
            .collect(),
        entitlements: entitlements
            .into_iter()
            .map(|e| MetaRoleEntitlementResponse {
                id: e.id,
                meta_role_id: e.meta_role_id,
                entitlement_id: e.entitlement_id,
                permission_type: e.permission_type,
                created_at: e.created_at,
                entitlement: None,
            })
            .collect(),
        constraints: constraints
            .into_iter()
            .map(|c| MetaRoleConstraintResponse {
                id: c.id,
                meta_role_id: c.meta_role_id,
                constraint_type: c.constraint_type,
                constraint_value: c.constraint_value,
                created_at: c.created_at,
            })
            .collect(),
        stats: None,
    }))
}

/// Update a meta-role.
#[utoipa::path(
    put,
    path = "/governance/meta-roles/{id}",
    tag = "Governance - Meta-roles",
    params(
        ("id" = Uuid, Path, description = "Meta-role ID")
    ),
    request_body = UpdateMetaRoleRequest,
    responses(
        (status = 200, description = "Meta-role updated", body = MetaRoleResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Meta-role not found"),
        (status = 409, description = "Conflict - name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_meta_role(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateMetaRoleRequest>,
) -> ApiResult<Json<MetaRoleResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let updated_by = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let input = UpdateGovMetaRole {
        name: request.name,
        description: request.description,
        priority: request.priority,
        criteria_logic: request.criteria_logic,
    };

    let result = state
        .meta_role_service
        .update(tenant_id, id, updated_by, input)
        .await?;

    Ok(Json(MetaRoleResponse::from(result)))
}

/// Delete a meta-role.
#[utoipa::path(
    delete,
    path = "/governance/meta-roles/{id}",
    tag = "Governance - Meta-roles",
    params(
        ("id" = Uuid, Path, description = "Meta-role ID")
    ),
    responses(
        (status = 204, description = "Meta-role deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Meta-role not found"),
        (status = 409, description = "Cannot delete - has active inheritances"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_meta_role(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<()> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let deleted_by = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    state
        .meta_role_service
        .delete(tenant_id, id, deleted_by)
        .await?;

    Ok(())
}

/// Enable a meta-role.
#[utoipa::path(
    post,
    path = "/governance/meta-roles/{id}/enable",
    tag = "Governance - Meta-roles",
    params(
        ("id" = Uuid, Path, description = "Meta-role ID")
    ),
    responses(
        (status = 200, description = "Meta-role enabled", body = MetaRoleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Meta-role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn enable_meta_role(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<MetaRoleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let enabled_by = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .meta_role_service
        .enable(tenant_id, id, enabled_by)
        .await?;

    Ok(Json(MetaRoleResponse::from(result)))
}

/// Disable a meta-role.
#[utoipa::path(
    post,
    path = "/governance/meta-roles/{id}/disable",
    tag = "Governance - Meta-roles",
    params(
        ("id" = Uuid, Path, description = "Meta-role ID")
    ),
    responses(
        (status = 200, description = "Meta-role disabled", body = MetaRoleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Meta-role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn disable_meta_role(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<MetaRoleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let disabled_by = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .meta_role_service
        .disable(tenant_id, id, disabled_by)
        .await?;

    Ok(Json(MetaRoleResponse::from(result)))
}

// ============================================================================
// Meta-Role Criteria Management
// ============================================================================

/// Add a criterion to a meta-role.
#[utoipa::path(
    post,
    path = "/governance/meta-roles/{id}/criteria",
    tag = "Governance - Meta-roles",
    params(
        ("id" = Uuid, Path, description = "Meta-role ID")
    ),
    request_body = CreateMetaRoleCriteriaRequest,
    responses(
        (status = 201, description = "Criterion added", body = MetaRoleCriteriaResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Meta-role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn add_criteria(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<crate::models::CreateMetaRoleCriteriaRequest>,
) -> ApiResult<Json<MetaRoleCriteriaResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = CreateGovMetaRoleCriteria {
        field: request.field,
        operator: request.operator,
        value: request.value,
    };

    let result = state
        .meta_role_service
        .add_criterion(tenant_id, id, input)
        .await?;

    Ok(Json(MetaRoleCriteriaResponse::from(result)))
}

/// Remove a criterion from a meta-role.
#[utoipa::path(
    delete,
    path = "/governance/meta-roles/{id}/criteria/{criteria_id}",
    tag = "Governance - Meta-roles",
    params(
        ("id" = Uuid, Path, description = "Meta-role ID"),
        ("criteria_id" = Uuid, Path, description = "Criteria ID")
    ),
    responses(
        (status = 204, description = "Criterion removed"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Meta-role or criterion not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_criteria(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((id, criteria_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<()> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state
        .meta_role_service
        .remove_criterion(tenant_id, id, criteria_id)
        .await?;

    Ok(())
}

// ============================================================================
// Meta-Role Entitlement Management
// ============================================================================

/// Add an entitlement to a meta-role.
#[utoipa::path(
    post,
    path = "/governance/meta-roles/{id}/entitlements",
    tag = "Governance - Meta-roles",
    params(
        ("id" = Uuid, Path, description = "Meta-role ID")
    ),
    request_body = AddMetaRoleEntitlementRequest,
    responses(
        (status = 201, description = "Entitlement added", body = MetaRoleEntitlementResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Meta-role or entitlement not found"),
        (status = 409, description = "Entitlement already exists on meta-role"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn add_entitlement(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<AddMetaRoleEntitlementRequest>,
) -> ApiResult<Json<MetaRoleEntitlementResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = CreateGovMetaRoleEntitlement {
        entitlement_id: request.entitlement_id,
        permission_type: request.permission_type,
    };

    let result = state
        .meta_role_service
        .add_entitlement(tenant_id, id, input)
        .await?;

    Ok(Json(MetaRoleEntitlementResponse {
        id: result.id,
        meta_role_id: result.meta_role_id,
        entitlement_id: result.entitlement_id,
        permission_type: result.permission_type,
        created_at: result.created_at,
        entitlement: None,
    }))
}

/// Remove an entitlement from a meta-role.
#[utoipa::path(
    delete,
    path = "/governance/meta-roles/{id}/entitlements/{entitlement_id}",
    tag = "Governance - Meta-roles",
    params(
        ("id" = Uuid, Path, description = "Meta-role ID"),
        ("entitlement_id" = Uuid, Path, description = "Entitlement mapping ID")
    ),
    responses(
        (status = 204, description = "Entitlement removed"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Meta-role or entitlement not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_entitlement(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((id, entitlement_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<()> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state
        .meta_role_service
        .remove_entitlement(tenant_id, id, entitlement_id)
        .await?;

    Ok(())
}

// ============================================================================
// Meta-Role Constraint Management
// ============================================================================

/// Add a constraint to a meta-role.
#[utoipa::path(
    post,
    path = "/governance/meta-roles/{id}/constraints",
    tag = "Governance - Meta-roles",
    params(
        ("id" = Uuid, Path, description = "Meta-role ID")
    ),
    request_body = AddMetaRoleConstraintRequest,
    responses(
        (status = 201, description = "Constraint added", body = MetaRoleConstraintResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Meta-role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn add_constraint(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<AddMetaRoleConstraintRequest>,
) -> ApiResult<Json<MetaRoleConstraintResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let input = CreateGovMetaRoleConstraint {
        constraint_type: request.constraint_type,
        constraint_value: request.constraint_value,
    };

    let result = state
        .meta_role_service
        .add_constraint(tenant_id, id, input)
        .await?;

    Ok(Json(MetaRoleConstraintResponse {
        id: result.id,
        meta_role_id: result.meta_role_id,
        constraint_type: result.constraint_type,
        constraint_value: result.constraint_value,
        created_at: result.created_at,
    }))
}

/// Remove a constraint from a meta-role.
#[utoipa::path(
    delete,
    path = "/governance/meta-roles/{id}/constraints/{constraint_id}",
    tag = "Governance - Meta-roles",
    params(
        ("id" = Uuid, Path, description = "Meta-role ID"),
        ("constraint_id" = Uuid, Path, description = "Constraint ID")
    ),
    responses(
        (status = 204, description = "Constraint removed"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Meta-role or constraint not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_constraint(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path((id, constraint_id)): Path<(Uuid, Uuid)>,
) -> ApiResult<()> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    state
        .meta_role_service
        .remove_constraint(tenant_id, id, constraint_id)
        .await?;

    Ok(())
}

// ============================================================================
// Meta-Role Matching and Inheritance
// ============================================================================

/// Get meta-roles that apply to a specific role.
#[utoipa::path(
    get,
    path = "/governance/roles/{role_id}/meta-roles",
    tag = "Governance - Meta-roles",
    params(
        ("role_id" = Uuid, Path, description = "Role (entitlement) ID")
    ),
    responses(
        (status = 200, description = "Meta-roles for role", body = RoleMatchResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_role_meta_roles(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(role_id): Path<Uuid>,
) -> ApiResult<Json<RoleMatchResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let result = state
        .meta_role_matching_service
        .evaluate_role_matches(tenant_id, role_id)
        .await?;

    let total_matches = result.matching_meta_roles.len() as i64;

    // Check for unresolved conflicts
    let has_conflicts = state
        .meta_role_conflict_service
        .role_has_conflicts(tenant_id, role_id)
        .await?;

    Ok(Json(RoleMatchResponse {
        role_id,
        matching_meta_roles: result
            .matching_meta_roles
            .into_iter()
            .map(|m| crate::models::MatchingMetaRole {
                meta_role_id: m.meta_role_id,
                name: m.name,
                priority: m.priority,
                match_reason: m.match_reason,
                already_applied: m.already_applied,
                inheritance_id: m.inheritance_id,
            })
            .collect(),
        total_matches,
        has_conflicts,
    }))
}

/// List inheritance relationships for a meta-role.
#[utoipa::path(
    get,
    path = "/governance/meta-roles/{id}/inheritances",
    tag = "Governance - Meta-roles",
    params(
        ("id" = Uuid, Path, description = "Meta-role ID"),
        ListInheritancesQuery
    ),
    responses(
        (status = 200, description = "Inheritance relationships", body = InheritanceListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Meta-role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_inheritances(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Query(query): Query<ListInheritancesQuery>,
) -> ApiResult<Json<InheritanceListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let inheritances = state
        .meta_role_matching_service
        .list_inheritances_by_meta_role(tenant_id, id, query.status, limit, offset)
        .await?;

    let total = inheritances.len() as i64;
    let items: Vec<InheritanceResponse> = inheritances
        .into_iter()
        .map(InheritanceResponse::from)
        .collect();

    Ok(Json(InheritanceListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Manually trigger re-evaluation of all roles against a meta-role.
#[utoipa::path(
    post,
    path = "/governance/meta-roles/{id}/reevaluate",
    tag = "Governance - Meta-roles",
    params(
        ("id" = Uuid, Path, description = "Meta-role ID")
    ),
    responses(
        (status = 200, description = "Re-evaluation triggered", body = MetaRoleStatsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Meta-role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn reevaluate_meta_role(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<MetaRoleStatsResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let (added, removed) = state
        .meta_role_matching_service
        .reevaluate_meta_role(tenant_id, id)
        .await?;

    Ok(Json(MetaRoleStatsResponse {
        active_inheritances: added,
        unresolved_conflicts: 0,
        criteria_count: 0,
        entitlements_count: 0,
        constraints_count: removed,
    }))
}

// ============================================================================
// Conflict Detection and Resolution
// ============================================================================

/// List conflicts for a meta-role or across all meta-roles.
#[utoipa::path(
    get,
    path = "/governance/meta-roles/conflicts",
    tag = "Governance - Meta-roles",
    params(ListConflictsQuery),
    responses(
        (status = 200, description = "List of conflicts", body = ConflictListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_conflicts(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListConflictsQuery>,
) -> ApiResult<Json<ConflictListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let (conflicts, total) = state
        .meta_role_conflict_service
        .list_conflicts(tenant_id, query.resolution_status, limit, offset)
        .await?;

    let items: Vec<ConflictResponse> = conflicts.into_iter().map(ConflictResponse::from).collect();

    Ok(Json(ConflictListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Resolve a conflict.
#[utoipa::path(
    post,
    path = "/governance/meta-roles/conflicts/{conflict_id}/resolve",
    tag = "Governance - Meta-roles",
    params(
        ("conflict_id" = Uuid, Path, description = "Conflict ID")
    ),
    request_body = ResolveConflictRequest,
    responses(
        (status = 200, description = "Conflict resolved", body = ConflictResponse),
        (status = 400, description = "Invalid resolution"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Conflict not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn resolve_conflict(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(conflict_id): Path<Uuid>,
    Json(request): Json<ResolveConflictRequest>,
) -> ApiResult<Json<ConflictResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let resolved_by = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    use xavyo_db::ResolutionStatus;

    let resolved_conflict = match request.resolution_status {
        ResolutionStatus::ResolvedPriority => {
            state
                .meta_role_conflict_service
                .resolve_conflict_by_priority(tenant_id, conflict_id, resolved_by)
                .await?
        }
        ResolutionStatus::ResolvedManual => {
            // Extract winning_meta_role_id from resolution_choice
            let winning_meta_role_id = request
                .resolution_choice
                .as_ref()
                .and_then(|c| c.get("winning_meta_role_id"))
                .and_then(|v| v.as_str())
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(|| {
                    ApiGovernanceError::Validation(
                        "resolution_choice.winning_meta_role_id is required for manual resolution"
                            .to_string(),
                    )
                })?;
            state
                .meta_role_conflict_service
                .resolve_conflict_manually(
                    tenant_id,
                    conflict_id,
                    resolved_by,
                    winning_meta_role_id,
                    request.comment.clone(),
                )
                .await?
        }
        ResolutionStatus::Ignored => {
            let reason = request
                .comment
                .clone()
                .unwrap_or_else(|| "Acknowledged".to_string());
            state
                .meta_role_conflict_service
                .ignore_conflict(tenant_id, conflict_id, resolved_by, reason)
                .await?
        }
        ResolutionStatus::Unresolved => {
            return Err(ApiGovernanceError::Validation(
                "Cannot set resolution_status to 'unresolved'".to_string(),
            ));
        }
    };

    Ok(Json(ConflictResponse::from(resolved_conflict)))
}

// ============================================================================
// Simulation
// ============================================================================

/// Simulate meta-role changes before applying.
#[utoipa::path(
    post,
    path = "/governance/meta-roles/{id}/simulate",
    tag = "Governance - Meta-roles",
    params(
        ("id" = Uuid, Path, description = "Meta-role ID")
    ),
    request_body = SimulateMetaRoleRequest,
    responses(
        (status = 200, description = "Simulation results", body = SimulationResultResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Meta-role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn simulate_changes(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<SimulateMetaRoleRequest>,
) -> ApiResult<Json<SimulationResultResponse>> {
    use crate::models::MetaRoleSimulationType;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = request.limit.clamp(1, 1000);

    let result = match request.simulation_type {
        MetaRoleSimulationType::CriteriaChange => {
            let criteria = request.criteria_changes.ok_or_else(|| {
                ApiGovernanceError::Validation(
                    "criteria_changes required for CriteriaChange simulation".to_string(),
                )
            })?;
            state
                .meta_role_simulation_service
                .simulate_criteria_change(tenant_id, id, criteria, limit)
                .await?
        }
        MetaRoleSimulationType::Enable => {
            state
                .meta_role_simulation_service
                .simulate_enable(tenant_id, id, limit)
                .await?
        }
        MetaRoleSimulationType::Disable => {
            state
                .meta_role_simulation_service
                .simulate_disable(tenant_id, id, limit)
                .await?
        }
        MetaRoleSimulationType::Delete => {
            state
                .meta_role_simulation_service
                .simulate_delete(tenant_id, id, limit)
                .await?
        }
        MetaRoleSimulationType::Create | MetaRoleSimulationType::Update => {
            // For create/update, we'd need more complex logic
            // For now, simulate as criteria change with empty criteria to show current state
            state
                .meta_role_simulation_service
                .simulate_criteria_change(tenant_id, id, vec![], limit)
                .await?
        }
    };

    Ok(Json(SimulationResultResponse {
        simulation_type: result.simulation_type,
        roles_to_add: result.roles_to_add,
        roles_to_remove: result.roles_to_remove,
        potential_conflicts: result.potential_conflicts,
        conflicts_to_resolve: result.conflicts_to_resolve,
        summary: result.summary,
    }))
}

// ============================================================================
// Cascade Operations
// ============================================================================

/// Trigger a cascade update for a meta-role.
#[utoipa::path(
    post,
    path = "/governance/meta-roles/{id}/cascade",
    tag = "Governance - Meta-roles",
    params(
        ("id" = Uuid, Path, description = "Meta-role ID")
    ),
    request_body = TriggerCascadeRequest,
    responses(
        (status = 202, description = "Cascade triggered", body = CascadeStatusResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Meta-role not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn trigger_cascade(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(_request): Json<TriggerCascadeRequest>,
) -> ApiResult<Json<CascadeStatusResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let status = state
        .meta_role_cascade_service
        .cascade_meta_role_changes(tenant_id, id, actor_id)
        .await?;

    let failures = status.error.map(|e| {
        vec![CascadeFailure {
            role_id: Uuid::nil(),
            error: e,
            failed_at: chrono::Utc::now(),
        }]
    });

    Ok(Json(CascadeStatusResponse {
        meta_role_id: status.meta_role_id,
        in_progress: !status.is_complete,
        processed_count: status.processed,
        remaining_count: status.total_affected - status.processed,
        success_count: status.succeeded,
        failure_count: status.failed,
        started_at: None,
        completed_at: if status.is_complete {
            Some(chrono::Utc::now())
        } else {
            None
        },
        failures,
    }))
}

// ============================================================================
// Audit Trail / Events
// ============================================================================

/// List meta-role events (audit trail).
#[utoipa::path(
    get,
    path = "/governance/meta-roles/events",
    tag = "Governance - Meta-roles",
    params(ListEventsQuery),
    responses(
        (status = 200, description = "List of events", body = EventListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_events(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListEventsQuery>,
) -> ApiResult<Json<EventListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    // Events are scoped to a specific meta-role
    let meta_role_id = query.meta_role_id.ok_or_else(|| {
        ApiGovernanceError::Validation("meta_role_id is required for event listing".to_string())
    })?;

    let events = state
        .meta_role_service
        .list_events(tenant_id, meta_role_id, limit, offset)
        .await?;

    let total = events.len() as i64;
    let items: Vec<EventResponse> = events.into_iter().map(EventResponse::from).collect();

    Ok(Json(EventListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Get event statistics.
#[utoipa::path(
    get,
    path = "/governance/meta-roles/events/stats",
    tag = "Governance - Meta-roles",
    responses(
        (status = 200, description = "Event statistics", body = EventStatsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_event_stats(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<EventStatsResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let stats = state.meta_role_service.get_event_stats(tenant_id).await?;

    Ok(Json(EventStatsResponse::from(stats)))
}
