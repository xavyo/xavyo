//! Delegation handlers for governance API.
//!
//! Enhanced in F053 to support scoped delegations and lifecycle management.

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
    CreateDelegationRequest, DelegatedWorkItemListResponse, DelegationAuditListResponse,
    DelegationLifecycleResponse, DelegationListResponse, DelegationResponse,
    DelegationScopeResponse, ExtendDelegationRequest, ListDelegatedWorkItemsQuery,
    ListDelegationAuditQuery, ListDelegationsQuery,
};
use crate::router::GovernanceState;
use crate::services::ListAuditParams;

/// List the current user's delegations.
#[utoipa::path(
    get,
    path = "/governance/delegations",
    tag = "Governance - Delegations",
    params(ListDelegationsQuery),
    responses(
        (status = 200, description = "List of delegations", body = DelegationListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_my_delegations(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListDelegationsQuery>,
) -> ApiResult<Json<DelegationListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let (delegations, total) = state
        .delegation_service
        .list_my_delegations(
            tenant_id,
            user_id,
            query.is_active,
            query.active_now,
            limit,
            offset,
        )
        .await?;

    Ok(Json(DelegationListResponse {
        items: delegations.into_iter().map(Into::into).collect(),
        total,
        limit,
        offset,
    }))
}

/// Get a delegation by ID.
#[utoipa::path(
    get,
    path = "/governance/delegations/{id}",
    tag = "Governance - Delegations",
    params(
        ("id" = Uuid, Path, description = "Delegation ID")
    ),
    responses(
        (status = 200, description = "Delegation details", body = DelegationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Delegation not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_delegation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<DelegationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let delegation = state
        .delegation_service
        .get_delegation(tenant_id, id)
        .await?;

    Ok(Json(delegation.into()))
}

/// Create a new delegation.
#[utoipa::path(
    post,
    path = "/governance/delegations",
    tag = "Governance - Delegations",
    request_body = CreateDelegationRequest,
    responses(
        (status = 201, description = "Delegation created", body = DelegationResponse),
        (status = 400, description = "Invalid request or invalid scope references"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Cannot delegate to yourself"),
        (status = 409, description = "Active delegation already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_delegation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateDelegationRequest>,
) -> ApiResult<(StatusCode, Json<DelegationResponse>)> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let delegation = state
        .delegation_service
        .create_delegation_with_scope(
            tenant_id,
            user_id,
            request.delegate_id,
            request.starts_at,
            request.ends_at,
            request.scope,
        )
        .await?;

    Ok((StatusCode::CREATED, Json(delegation.into())))
}

/// Revoke a delegation.
#[utoipa::path(
    post,
    path = "/governance/delegations/{id}/revoke",
    tag = "Governance - Delegations",
    params(
        ("id" = Uuid, Path, description = "Delegation ID")
    ),
    responses(
        (status = 200, description = "Delegation revoked", body = DelegationResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not authorized to revoke this delegation"),
        (status = 404, description = "Delegation not found"),
        (status = 412, description = "Delegation is not active"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_delegation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<DelegationResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let delegation = state
        .delegation_service
        .revoke_delegation(tenant_id, id, user_id)
        .await?;

    Ok(Json(delegation.into()))
}

/// Extend a delegation's end date (F053).
#[utoipa::path(
    patch,
    path = "/governance/delegations/{id}/extend",
    tag = "Governance - Delegations",
    params(
        ("id" = Uuid, Path, description = "Delegation ID")
    ),
    request_body = ExtendDelegationRequest,
    responses(
        (status = 200, description = "Delegation extended", body = DelegationResponse),
        (status = 400, description = "Invalid extension date"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not authorized to extend this delegation"),
        (status = 404, description = "Delegation not found"),
        (status = 412, description = "Cannot extend expired or revoked delegation"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn extend_delegation(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<ExtendDelegationRequest>,
) -> ApiResult<Json<DelegationResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let delegation = state
        .delegation_service
        .extend_delegation(tenant_id, id, user_id, request.new_ends_at)
        .await?;

    Ok(Json(delegation.into()))
}

/// Get delegation scope details (F053).
#[utoipa::path(
    get,
    path = "/governance/delegations/{id}/scope",
    tag = "Governance - Delegations",
    params(
        ("id" = Uuid, Path, description = "Delegation ID")
    ),
    responses(
        (status = 200, description = "Scope details", body = DelegationScopeResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Delegation not found or has no scope"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_delegation_scope(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<DelegationScopeResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Get the delegation first
    let delegation = state
        .delegation_service
        .get_delegation(tenant_id, id)
        .await?;

    // Check if it has a scope
    let scope_id = delegation.scope_id.ok_or_else(|| {
        ApiGovernanceError::NotFound("Delegation has no scope (full authority)".to_string())
    })?;

    // Get the scope
    let scope = state
        .delegation_service
        .get_delegation_scope(tenant_id, scope_id)
        .await?;

    Ok(Json(DelegationScopeResponse {
        id: scope.id,
        application_ids: scope.application_ids,
        entitlement_ids: scope.entitlement_ids,
        role_ids: scope.role_ids,
        workflow_types: scope.workflow_types,
        created_at: scope.created_at,
    }))
}

/// List delegations where the current user is the deputy (F053).
#[utoipa::path(
    get,
    path = "/governance/delegations/as-deputy",
    tag = "Governance - Delegations",
    params(ListDelegationsQuery),
    responses(
        (status = 200, description = "List of delegations where user is deputy", body = DelegationListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_delegations_as_deputy(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListDelegationsQuery>,
) -> ApiResult<Json<DelegationListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let (delegations, total) = state
        .delegation_service
        .list_delegations_to_me(
            tenant_id,
            user_id,
            query.is_active,
            query.active_now,
            limit,
            offset,
        )
        .await?;

    Ok(Json(DelegationListResponse {
        items: delegations.into_iter().map(Into::into).collect(),
        total,
        limit,
        offset,
    }))
}

/// List work items delegated to the current user (F053).
#[utoipa::path(
    get,
    path = "/governance/work-items/delegated",
    tag = "Governance - Delegations",
    params(ListDelegatedWorkItemsQuery),
    responses(
        (status = 200, description = "List of delegated work items", body = DelegatedWorkItemListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_delegated_work_items(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListDelegatedWorkItemsQuery>,
) -> ApiResult<Json<DelegatedWorkItemListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let (items, total) = state
        .delegation_service
        .get_delegated_work_items(
            tenant_id,
            user_id,
            query.delegator_id,
            query.work_item_type.as_deref(),
            query.application_id,
            limit,
            offset,
        )
        .await?;

    Ok(Json(DelegatedWorkItemListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Process delegation lifecycle (activate pending, expire ended) (F053).
///
/// This endpoint is typically called by a scheduler or admin to process
/// pending activations and expirations.
#[utoipa::path(
    post,
    path = "/governance/delegations/process-lifecycle",
    tag = "Governance - Delegations",
    responses(
        (status = 200, description = "Lifecycle processing result", body = DelegationLifecycleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - requires admin privileges"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn process_delegation_lifecycle(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<DelegationLifecycleResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Note: In production, this would check for admin privileges
    // For now we allow any authenticated user with a tenant

    let result = state
        .delegation_lifecycle_service
        .process_delegation_lifecycle(tenant_id)
        .await?;

    Ok(Json(DelegationLifecycleResponse {
        activated_count: result.activated_count,
        expired_count: result.expired_count,
        warnings_sent: result.warnings_sent,
        activated_ids: result.activated_ids,
        expired_ids: result.expired_ids,
        warned_ids: result.warned_ids,
    }))
}

/// List delegation audit records (F053).
///
/// Provides a complete audit trail of actions taken by deputies on behalf of delegators.
/// Supports filtering by delegation, deputy, delegator, action type, work item type, and date range.
#[utoipa::path(
    get,
    path = "/governance/delegations/audit",
    tag = "Governance - Delegations",
    params(ListDelegationAuditQuery),
    responses(
        (status = 200, description = "List of delegation audit records", body = DelegationAuditListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_delegation_audit(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListDelegationAuditQuery>,
) -> ApiResult<Json<DelegationAuditListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    let params = ListAuditParams {
        delegation_id: query.delegation_id,
        deputy_id: query.deputy_id,
        delegator_id: query.delegator_id,
        action_type: query.action_type,
        work_item_type: query.work_item_type,
        from_date: query.from_date,
        to_date: query.to_date,
        limit,
        offset,
    };

    let (entries, total) = state
        .delegation_audit_service
        .list_delegation_audit(tenant_id, params)
        .await?;

    Ok(Json(DelegationAuditListResponse {
        items: entries,
        total,
        limit,
        offset,
    }))
}
