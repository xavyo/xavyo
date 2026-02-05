//! HTTP request handlers for identity archetypes (F-058).
//!
//! These handlers manage identity archetypes - sub-types of identities with
//! custom schemas, policies, and inheritance.

use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;
use xavyo_auth::JwtClaims;
use xavyo_db::models::{
    ArchetypePolicyBinding, CreateIdentityArchetype, CreatePolicyBinding, IdentityArchetype,
    PolicyType, UpdateIdentityArchetype,
};

use crate::{
    error::{ApiGovernanceError, ApiResult},
    models::{
        archetype::{validate_schema_extensions, validate_user_attributes},
        identity_archetype::{
            AssignIdentityArchetypeRequest, BindPolicyRequest, CreateIdentityArchetypeRequest,
            EffectivePoliciesResponse, EffectivePolicyResponse, IdentityAncestryNodeResponse,
            IdentityArchetypeListResponse, IdentityArchetypeResponse,
            IdentityArchetypeWithAncestryResponse, ListIdentityArchetypesQuery,
            PolicyBindingResponse, UpdateIdentityArchetypeRequest, UserIdentityArchetypeResponse,
        },
    },
    router::GovernanceState,
};

/// List identity archetypes for a tenant.
///
/// GET /governance/archetypes
#[utoipa::path(
    get,
    path = "/governance/archetypes",
    params(ListIdentityArchetypesQuery),
    responses(
        (status = 200, description = "List of archetypes", body = IdentityArchetypeListResponse),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "Identity Archetypes"
)]
pub async fn list_archetypes(
    Extension(claims): Extension<JwtClaims>,
    State(state): State<GovernanceState>,
    Query(query): Query<ListIdentityArchetypesQuery>,
) -> ApiResult<Json<IdentityArchetypeListResponse>> {
    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiGovernanceError::Unauthorized)?;

    let archetypes = IdentityArchetype::list_by_tenant(
        state.pool(),
        tenant_id,
        query.active_only,
        query.limit,
        query.offset,
    )
    .await?;

    let total =
        IdentityArchetype::count_by_tenant(state.pool(), tenant_id, query.active_only).await?;

    Ok(Json(IdentityArchetypeListResponse {
        items: archetypes
            .into_iter()
            .map(IdentityArchetypeResponse::from)
            .collect(),
        total,
        limit: query.limit,
        offset: query.offset,
    }))
}

/// Get a single identity archetype by ID.
///
/// GET /governance/archetypes/:id
#[utoipa::path(
    get,
    path = "/governance/archetypes/{id}",
    params(
        ("id" = Uuid, Path, description = "Archetype ID")
    ),
    responses(
        (status = 200, description = "Archetype details", body = IdentityArchetypeResponse),
        (status = 404, description = "Archetype not found"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "Identity Archetypes"
)]
pub async fn get_archetype(
    Extension(claims): Extension<JwtClaims>,
    State(state): State<GovernanceState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<IdentityArchetypeResponse>> {
    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiGovernanceError::Unauthorized)?;

    let archetype = IdentityArchetype::find_by_id(state.pool(), tenant_id, id)
        .await?
        .ok_or(ApiGovernanceError::ArchetypeNotFound(id))?;

    Ok(Json(IdentityArchetypeResponse::from(archetype)))
}

/// Get an archetype with its ancestry chain.
///
/// GET /governance/archetypes/:id/ancestry
#[utoipa::path(
    get,
    path = "/governance/archetypes/{id}/ancestry",
    params(
        ("id" = Uuid, Path, description = "Archetype ID")
    ),
    responses(
        (status = 200, description = "Archetype with ancestry chain", body = IdentityArchetypeWithAncestryResponse),
        (status = 404, description = "Archetype not found"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "Identity Archetypes"
)]
pub async fn get_archetype_ancestry(
    Extension(claims): Extension<JwtClaims>,
    State(state): State<GovernanceState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<IdentityArchetypeWithAncestryResponse>> {
    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiGovernanceError::Unauthorized)?;

    let archetype = IdentityArchetype::find_by_id(state.pool(), tenant_id, id)
        .await?
        .ok_or(ApiGovernanceError::ArchetypeNotFound(id))?;

    let ancestry_chain = IdentityArchetype::get_ancestry_chain(state.pool(), tenant_id, id).await?;

    Ok(Json(IdentityArchetypeWithAncestryResponse {
        archetype: IdentityArchetypeResponse::from(archetype),
        ancestry_chain: ancestry_chain
            .into_iter()
            .map(IdentityAncestryNodeResponse::from)
            .collect(),
    }))
}

/// Create a new identity archetype.
///
/// POST /governance/archetypes
#[utoipa::path(
    post,
    path = "/governance/archetypes",
    request_body = CreateIdentityArchetypeRequest,
    responses(
        (status = 201, description = "Archetype created", body = IdentityArchetypeResponse),
        (status = 400, description = "Validation error"),
        (status = 409, description = "Name already exists"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "Identity Archetypes"
)]
pub async fn create_archetype(
    Extension(claims): Extension<JwtClaims>,
    State(state): State<GovernanceState>,
    Json(request): Json<CreateIdentityArchetypeRequest>,
) -> ApiResult<Json<IdentityArchetypeResponse>> {
    request.validate()?;

    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiGovernanceError::Unauthorized)?;

    // Check for name uniqueness
    if let Some(_existing) =
        IdentityArchetype::find_by_name(state.pool(), tenant_id, &request.name).await?
    {
        return Err(ApiGovernanceError::ArchetypeNameExists(request.name));
    }

    // Check for circular inheritance if parent is specified
    if let Some(parent_id) = request.parent_archetype_id {
        // Verify parent exists
        IdentityArchetype::find_by_id(state.pool(), tenant_id, parent_id)
            .await?
            .ok_or(ApiGovernanceError::ArchetypeNotFound(parent_id))?;
    }

    // Validate schema extensions structure if provided
    if let Some(ref schema_json) = request.schema_extensions {
        validate_schema_extensions(schema_json).map_err(|e| {
            ApiGovernanceError::Validation(format!("Invalid schema extensions: {}", e))
        })?;
    }

    let input = CreateIdentityArchetype {
        name: request.name,
        description: request.description,
        parent_archetype_id: request.parent_archetype_id,
        schema_extensions: request.schema_extensions,
        lifecycle_model_id: request.lifecycle_model_id,
    };

    let archetype = IdentityArchetype::create(state.pool(), tenant_id, input).await?;

    Ok(Json(IdentityArchetypeResponse::from(archetype)))
}

/// Update an existing identity archetype.
///
/// PUT /governance/archetypes/:id
#[utoipa::path(
    put,
    path = "/governance/archetypes/{id}",
    params(
        ("id" = Uuid, Path, description = "Archetype ID")
    ),
    request_body = UpdateIdentityArchetypeRequest,
    responses(
        (status = 200, description = "Archetype updated", body = IdentityArchetypeResponse),
        (status = 400, description = "Validation error or circular inheritance"),
        (status = 404, description = "Archetype not found"),
        (status = 409, description = "Name already exists"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "Identity Archetypes"
)]
pub async fn update_archetype(
    Extension(claims): Extension<JwtClaims>,
    State(state): State<GovernanceState>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateIdentityArchetypeRequest>,
) -> ApiResult<Json<IdentityArchetypeResponse>> {
    request.validate()?;

    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiGovernanceError::Unauthorized)?;

    // Verify archetype exists
    let _existing = IdentityArchetype::find_by_id(state.pool(), tenant_id, id)
        .await?
        .ok_or(ApiGovernanceError::ArchetypeNotFound(id))?;

    // Check for name uniqueness if name is being changed
    if let Some(ref new_name) = request.name {
        if let Some(existing) =
            IdentityArchetype::find_by_name(state.pool(), tenant_id, new_name).await?
        {
            if existing.id != id {
                return Err(ApiGovernanceError::ArchetypeNameExists(new_name.clone()));
            }
        }
    }

    // Check for circular inheritance if parent is being changed
    if let Some(Some(new_parent_id)) = request.parent_archetype_id {
        // Verify parent exists
        IdentityArchetype::find_by_id(state.pool(), tenant_id, new_parent_id)
            .await?
            .ok_or(ApiGovernanceError::ArchetypeNotFound(new_parent_id))?;

        // Check for circular inheritance
        if IdentityArchetype::check_circular_inheritance(state.pool(), tenant_id, id, new_parent_id)
            .await?
        {
            return Err(ApiGovernanceError::CircularInheritance);
        }
    }

    // Validate schema extensions structure if provided
    if let Some(ref schema_json) = request.schema_extensions {
        validate_schema_extensions(schema_json).map_err(|e| {
            ApiGovernanceError::Validation(format!("Invalid schema extensions: {}", e))
        })?;
    }

    let input = UpdateIdentityArchetype {
        name: request.name,
        description: request.description,
        parent_archetype_id: request.parent_archetype_id,
        schema_extensions: request.schema_extensions,
        lifecycle_model_id: request.lifecycle_model_id,
        is_active: request.is_active,
    };

    let archetype = IdentityArchetype::update(state.pool(), tenant_id, id, input)
        .await?
        .ok_or(ApiGovernanceError::ArchetypeNotFound(id))?;

    Ok(Json(IdentityArchetypeResponse::from(archetype)))
}

/// Delete an identity archetype.
///
/// DELETE /governance/archetypes/:id
#[utoipa::path(
    delete,
    path = "/governance/archetypes/{id}",
    params(
        ("id" = Uuid, Path, description = "Archetype ID")
    ),
    responses(
        (status = 204, description = "Archetype deleted"),
        (status = 404, description = "Archetype not found"),
        (status = 409, description = "Cannot delete archetype with assigned users"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "Identity Archetypes"
)]
pub async fn delete_archetype(
    Extension(claims): Extension<JwtClaims>,
    State(state): State<GovernanceState>,
    Path(id): Path<Uuid>,
) -> ApiResult<()> {
    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiGovernanceError::Unauthorized)?;

    // Verify archetype exists
    IdentityArchetype::find_by_id(state.pool(), tenant_id, id)
        .await?
        .ok_or(ApiGovernanceError::ArchetypeNotFound(id))?;

    // Check if any users are assigned to this archetype
    let assigned_count =
        IdentityArchetype::count_assigned_users(state.pool(), tenant_id, id).await?;
    if assigned_count > 0 {
        return Err(ApiGovernanceError::ArchetypeHasAssignedUsers {
            id,
            count: assigned_count,
        });
    }

    IdentityArchetype::delete(state.pool(), tenant_id, id).await?;

    Ok(())
}

/// List policy bindings for an archetype.
///
/// GET /governance/archetypes/:id/policies
#[utoipa::path(
    get,
    path = "/governance/archetypes/{id}/policies",
    params(
        ("id" = Uuid, Path, description = "Archetype ID")
    ),
    responses(
        (status = 200, description = "List of policy bindings", body = Vec<PolicyBindingResponse>),
        (status = 404, description = "Archetype not found"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "Identity Archetypes"
)]
pub async fn list_archetype_policies(
    Extension(claims): Extension<JwtClaims>,
    State(state): State<GovernanceState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Vec<PolicyBindingResponse>>> {
    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiGovernanceError::Unauthorized)?;

    // Verify archetype exists
    IdentityArchetype::find_by_id(state.pool(), tenant_id, id)
        .await?
        .ok_or(ApiGovernanceError::ArchetypeNotFound(id))?;

    let bindings = ArchetypePolicyBinding::list_by_archetype(state.pool(), tenant_id, id).await?;

    Ok(Json(
        bindings
            .into_iter()
            .map(PolicyBindingResponse::from)
            .collect(),
    ))
}

/// Bind a policy to an archetype.
///
/// POST /governance/archetypes/:id/policies
#[utoipa::path(
    post,
    path = "/governance/archetypes/{id}/policies",
    params(
        ("id" = Uuid, Path, description = "Archetype ID")
    ),
    request_body = BindPolicyRequest,
    responses(
        (status = 200, description = "Policy bound (upsert)", body = PolicyBindingResponse),
        (status = 404, description = "Archetype not found"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "Identity Archetypes"
)]
pub async fn bind_archetype_policy(
    Extension(claims): Extension<JwtClaims>,
    State(state): State<GovernanceState>,
    Path(id): Path<Uuid>,
    Json(request): Json<BindPolicyRequest>,
) -> ApiResult<Json<PolicyBindingResponse>> {
    request.validate()?;

    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiGovernanceError::Unauthorized)?;

    // Verify archetype exists
    IdentityArchetype::find_by_id(state.pool(), tenant_id, id)
        .await?
        .ok_or(ApiGovernanceError::ArchetypeNotFound(id))?;

    let input = CreatePolicyBinding {
        policy_type: PolicyType::from(request.policy_type),
        policy_id: request.policy_id,
    };

    let binding = ArchetypePolicyBinding::bind_policy(state.pool(), tenant_id, id, input).await?;

    Ok(Json(PolicyBindingResponse::from(binding)))
}

/// Unbind a policy from an archetype.
///
/// DELETE /governance/archetypes/:id/policies/:policy_type
#[utoipa::path(
    delete,
    path = "/governance/archetypes/{id}/policies/{policy_type}",
    params(
        ("id" = Uuid, Path, description = "Archetype ID"),
        ("policy_type" = String, Path, description = "Policy type (password, mfa, session)")
    ),
    responses(
        (status = 204, description = "Policy unbound"),
        (status = 404, description = "Archetype or policy binding not found"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "Identity Archetypes"
)]
pub async fn unbind_archetype_policy(
    Extension(claims): Extension<JwtClaims>,
    State(state): State<GovernanceState>,
    Path((id, policy_type_str)): Path<(Uuid, String)>,
) -> ApiResult<()> {
    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiGovernanceError::Unauthorized)?;

    // Verify archetype exists
    IdentityArchetype::find_by_id(state.pool(), tenant_id, id)
        .await?
        .ok_or(ApiGovernanceError::ArchetypeNotFound(id))?;

    let policy_type = PolicyType::parse(&policy_type_str).ok_or_else(|| {
        ApiGovernanceError::Validation(format!("Invalid policy type: {}", policy_type_str))
    })?;

    let deleted =
        ArchetypePolicyBinding::unbind_policy(state.pool(), tenant_id, id, policy_type).await?;

    if !deleted {
        return Err(ApiGovernanceError::NotFound(format!(
            "Policy binding not found for archetype {} and type {}",
            id, policy_type_str
        )));
    }

    Ok(())
}

/// Get effective policies for an archetype (resolved through inheritance).
///
/// GET /governance/archetypes/:id/effective-policies
#[utoipa::path(
    get,
    path = "/governance/archetypes/{id}/effective-policies",
    params(
        ("id" = Uuid, Path, description = "Archetype ID")
    ),
    responses(
        (status = 200, description = "Effective policies", body = EffectivePoliciesResponse),
        (status = 404, description = "Archetype not found"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "Identity Archetypes"
)]
pub async fn get_effective_policies(
    Extension(claims): Extension<JwtClaims>,
    State(state): State<GovernanceState>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<EffectivePoliciesResponse>> {
    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiGovernanceError::Unauthorized)?;

    // Verify archetype exists
    IdentityArchetype::find_by_id(state.pool(), tenant_id, id)
        .await?
        .ok_or(ApiGovernanceError::ArchetypeNotFound(id))?;

    let policies =
        ArchetypePolicyBinding::resolve_effective_policies(state.pool(), tenant_id, id).await?;

    // Resolve effective lifecycle model through inheritance chain
    let ancestry_chain = IdentityArchetype::get_ancestry_chain(state.pool(), tenant_id, id).await?;
    let mut effective_lifecycle_model_id = None;
    let mut lifecycle_model_source_archetype_id = None;

    for node in &ancestry_chain {
        if let Some(archetype) =
            IdentityArchetype::find_by_id(state.pool(), tenant_id, node.id).await?
        {
            if archetype.lifecycle_model_id.is_some() {
                effective_lifecycle_model_id = archetype.lifecycle_model_id;
                lifecycle_model_source_archetype_id = Some(archetype.id);
                break;
            }
        }
    }

    Ok(Json(EffectivePoliciesResponse {
        archetype_id: id,
        policies: policies
            .into_iter()
            .map(EffectivePolicyResponse::from)
            .collect(),
        effective_lifecycle_model_id,
        lifecycle_model_source_archetype_id,
    }))
}

/// Get a user's archetype assignment.
///
/// GET /governance/users/:user_id/archetype
#[utoipa::path(
    get,
    path = "/governance/users/{user_id}/archetype",
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User archetype assignment", body = UserIdentityArchetypeResponse),
        (status = 404, description = "User not found"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "Identity Archetypes"
)]
pub async fn get_user_archetype(
    Extension(claims): Extension<JwtClaims>,
    State(state): State<GovernanceState>,
    Path(user_id): Path<Uuid>,
) -> ApiResult<Json<UserIdentityArchetypeResponse>> {
    use xavyo_db::models::User;

    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiGovernanceError::Unauthorized)?;

    let user = User::find_by_id_in_tenant(state.pool(), tenant_id, user_id)
        .await?
        .ok_or_else(|| ApiGovernanceError::NotFound(format!("User not found: {}", user_id)))?;

    let archetype = if let Some(archetype_id) = user.archetype_id {
        IdentityArchetype::find_by_id(state.pool(), tenant_id, archetype_id)
            .await?
            .map(IdentityArchetypeResponse::from)
    } else {
        None
    };

    Ok(Json(UserIdentityArchetypeResponse {
        user_id,
        archetype,
        custom_attrs: user.archetype_custom_attrs,
    }))
}

/// Assign an archetype to a user.
///
/// PUT /governance/users/:user_id/archetype
#[utoipa::path(
    put,
    path = "/governance/users/{user_id}/archetype",
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    request_body = AssignIdentityArchetypeRequest,
    responses(
        (status = 200, description = "Archetype assigned", body = UserIdentityArchetypeResponse),
        (status = 404, description = "User or archetype not found"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "Identity Archetypes"
)]
pub async fn assign_user_archetype(
    Extension(claims): Extension<JwtClaims>,
    State(state): State<GovernanceState>,
    Path(user_id): Path<Uuid>,
    Json(request): Json<AssignIdentityArchetypeRequest>,
) -> ApiResult<Json<UserIdentityArchetypeResponse>> {
    use xavyo_db::models::User;

    request.validate()?;

    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiGovernanceError::Unauthorized)?;

    // Verify user exists
    User::find_by_id_in_tenant(state.pool(), tenant_id, user_id)
        .await?
        .ok_or_else(|| ApiGovernanceError::NotFound(format!("User not found: {}", user_id)))?;

    // Verify archetype exists
    let archetype = IdentityArchetype::find_by_id(state.pool(), tenant_id, request.archetype_id)
        .await?
        .ok_or(ApiGovernanceError::ArchetypeNotFound(request.archetype_id))?;

    // Validate custom_attrs against archetype schema if provided
    if let Some(ref custom_attrs) = request.custom_attrs {
        // Parse archetype schema
        let schema = validate_schema_extensions(&archetype.schema_extensions).map_err(|e| {
            ApiGovernanceError::Validation(format!("Invalid archetype schema: {}", e))
        })?;

        // Validate user attributes against schema
        validate_user_attributes(custom_attrs, &schema).map_err(|errors| {
            let error_msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
            ApiGovernanceError::Validation(format!(
                "Invalid custom attributes: {}",
                error_msgs.join("; ")
            ))
        })?;
    } else {
        // If no custom_attrs provided, validate against schema to check required fields
        let schema = validate_schema_extensions(&archetype.schema_extensions).map_err(|e| {
            ApiGovernanceError::Validation(format!("Invalid archetype schema: {}", e))
        })?;
        validate_user_attributes(&serde_json::json!({}), &schema).map_err(|errors| {
            let error_msgs: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
            ApiGovernanceError::Validation(format!(
                "Missing required attributes: {}",
                error_msgs.join("; ")
            ))
        })?;
    }

    // Assign archetype to user
    let user = User::assign_archetype(
        state.pool(),
        tenant_id,
        user_id,
        request.archetype_id,
        request.custom_attrs,
    )
    .await?
    .ok_or_else(|| ApiGovernanceError::NotFound(format!("User not found: {}", user_id)))?;

    Ok(Json(UserIdentityArchetypeResponse {
        user_id,
        archetype: Some(IdentityArchetypeResponse::from(archetype)),
        custom_attrs: user.archetype_custom_attrs,
    }))
}

/// Remove an archetype from a user.
///
/// DELETE /governance/users/:user_id/archetype
#[utoipa::path(
    delete,
    path = "/governance/users/{user_id}/archetype",
    params(
        ("user_id" = Uuid, Path, description = "User ID")
    ),
    responses(
        (status = 204, description = "Archetype removed"),
        (status = 404, description = "User not found"),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "Identity Archetypes"
)]
pub async fn remove_user_archetype(
    Extension(claims): Extension<JwtClaims>,
    State(state): State<GovernanceState>,
    Path(user_id): Path<Uuid>,
) -> ApiResult<()> {
    use xavyo_db::models::User;

    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiGovernanceError::Unauthorized)?;

    // Verify user exists
    User::find_by_id_in_tenant(state.pool(), tenant_id, user_id)
        .await?
        .ok_or_else(|| ApiGovernanceError::NotFound(format!("User not found: {}", user_id)))?;

    User::remove_archetype(state.pool(), tenant_id, user_id).await?;

    Ok(())
}

// ============================================================================
// Archetype Lifecycle Handlers (F-193)
// ============================================================================

/// Response for archetype lifecycle model.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ArchetypeLifecycleResponse {
    /// Archetype ID.
    pub archetype_id: Uuid,
    /// Archetype name.
    pub archetype_name: String,
    /// Lifecycle model ID (if assigned).
    pub lifecycle_model_id: Option<Uuid>,
    /// Lifecycle model name (if assigned).
    pub lifecycle_model_name: Option<String>,
    /// Effective lifecycle model (considering inheritance).
    pub effective_lifecycle: Option<EffectiveLifecycleInfo>,
}

/// Information about effective lifecycle model.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct EffectiveLifecycleInfo {
    /// Model ID.
    pub model_id: Uuid,
    /// Model name.
    pub model_name: String,
    /// Whether inherited from parent archetype.
    pub is_inherited: bool,
    /// Source archetype if inherited.
    pub source_archetype: Option<String>,
}

/// Request to assign lifecycle model to archetype.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct AssignArchetypeLifecycleRequest {
    /// Lifecycle model ID to assign.
    pub lifecycle_model_id: Uuid,
}

/// Get archetype lifecycle model.
///
/// Returns the lifecycle model assigned to an archetype, including effective
/// lifecycle considering inheritance.
#[utoipa::path(
    get,
    path = "/governance/archetypes/{archetype_id}/lifecycle",
    params(
        ("archetype_id" = Uuid, Path, description = "Identity archetype ID")
    ),
    responses(
        (status = 200, description = "Archetype lifecycle model", body = ArchetypeLifecycleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Archetype not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Identity Archetypes"
)]
pub async fn get_archetype_lifecycle(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(archetype_id): Path<Uuid>,
) -> ApiResult<Json<ArchetypeLifecycleResponse>> {
    use crate::services::archetype_lifecycle_service::ArchetypeLifecycleService;
    use std::sync::Arc;
    use xavyo_db::IdentityArchetype;

    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiGovernanceError::Unauthorized)?;

    // Get archetype
    let archetype = IdentityArchetype::find_by_id(state.pool(), tenant_id, archetype_id)
        .await?
        .ok_or_else(|| {
            ApiGovernanceError::NotFound(format!("Archetype not found: {}", archetype_id))
        })?;

    // Get directly assigned lifecycle model
    let service = ArchetypeLifecycleService::new(Arc::new(state.pool().clone()));
    let direct_lifecycle = service
        .get_archetype_lifecycle(tenant_id, archetype_id)
        .await?;

    // Get effective lifecycle (considering inheritance)
    let effective = service
        .resolve_effective_lifecycle(tenant_id, archetype_id)
        .await?;

    let effective_info = effective.map(|e| EffectiveLifecycleInfo {
        model_id: e.model_id,
        model_name: e.model_name,
        is_inherited: e.is_inherited,
        source_archetype: e.source_archetype_name,
    });

    Ok(Json(ArchetypeLifecycleResponse {
        archetype_id,
        archetype_name: archetype.name,
        lifecycle_model_id: direct_lifecycle.as_ref().map(|l| l.id),
        lifecycle_model_name: direct_lifecycle.map(|l| l.name),
        effective_lifecycle: effective_info,
    }))
}

/// Assign lifecycle model to archetype.
///
/// Assigns a lifecycle model to an archetype. All identities with this archetype
/// (that don't have a direct lifecycle assignment) will use this lifecycle model.
#[utoipa::path(
    put,
    path = "/governance/archetypes/{archetype_id}/lifecycle",
    params(
        ("archetype_id" = Uuid, Path, description = "Identity archetype ID")
    ),
    request_body = AssignArchetypeLifecycleRequest,
    responses(
        (status = 200, description = "Lifecycle model assigned", body = ArchetypeLifecycleResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Archetype or lifecycle model not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Identity Archetypes"
)]
pub async fn assign_archetype_lifecycle(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(archetype_id): Path<Uuid>,
    Json(request): Json<AssignArchetypeLifecycleRequest>,
) -> ApiResult<Json<ArchetypeLifecycleResponse>> {
    use crate::services::archetype_lifecycle_service::ArchetypeLifecycleService;
    use std::sync::Arc;

    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiGovernanceError::Unauthorized)?;

    let service = ArchetypeLifecycleService::new(Arc::new(state.pool().clone()));

    // Assign lifecycle model
    let archetype = service
        .assign_archetype_lifecycle(tenant_id, archetype_id, request.lifecycle_model_id)
        .await?;

    // Get the lifecycle model details
    let lifecycle = service
        .get_archetype_lifecycle(tenant_id, archetype_id)
        .await?;

    // Get effective lifecycle
    let effective = service
        .resolve_effective_lifecycle(tenant_id, archetype_id)
        .await?;

    let effective_info = effective.map(|e| EffectiveLifecycleInfo {
        model_id: e.model_id,
        model_name: e.model_name,
        is_inherited: e.is_inherited,
        source_archetype: e.source_archetype_name,
    });

    Ok(Json(ArchetypeLifecycleResponse {
        archetype_id,
        archetype_name: archetype.name,
        lifecycle_model_id: lifecycle.as_ref().map(|l| l.id),
        lifecycle_model_name: lifecycle.map(|l| l.name),
        effective_lifecycle: effective_info,
    }))
}

/// Remove lifecycle model from archetype.
///
/// Removes the lifecycle model assignment from an archetype. Identities with this
/// archetype will fall back to inherited lifecycle models (if any).
#[utoipa::path(
    delete,
    path = "/governance/archetypes/{archetype_id}/lifecycle",
    params(
        ("archetype_id" = Uuid, Path, description = "Identity archetype ID")
    ),
    responses(
        (status = 200, description = "Lifecycle model removed", body = ArchetypeLifecycleResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Archetype not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = [])),
    tag = "Identity Archetypes"
)]
pub async fn remove_archetype_lifecycle(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(archetype_id): Path<Uuid>,
) -> ApiResult<Json<ArchetypeLifecycleResponse>> {
    use crate::services::archetype_lifecycle_service::ArchetypeLifecycleService;
    use std::sync::Arc;

    let tenant_id = claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiGovernanceError::Unauthorized)?;

    let service = ArchetypeLifecycleService::new(Arc::new(state.pool().clone()));

    // Remove lifecycle model
    let archetype = service
        .remove_archetype_lifecycle(tenant_id, archetype_id)
        .await?;

    // Get effective lifecycle (from inheritance)
    let effective = service
        .resolve_effective_lifecycle(tenant_id, archetype_id)
        .await?;

    let effective_info = effective.map(|e| EffectiveLifecycleInfo {
        model_id: e.model_id,
        model_name: e.model_name,
        is_inherited: e.is_inherited,
        source_archetype: e.source_archetype_name,
    });

    Ok(Json(ArchetypeLifecycleResponse {
        archetype_id,
        archetype_name: archetype.name,
        lifecycle_model_id: None,
        lifecycle_model_name: None,
        effective_lifecycle: effective_info,
    }))
}
