//! Persona management handlers for governance API (F063).
//!
//! Handles persona archetypes, personas, and related operations.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Extension, Json,
};
use uuid::Uuid;
use validator::Validate;

use xavyo_auth::JwtClaims;
use xavyo_db::models::{
    CreatePersonaArchetype, GovPersona, GovPersonaSession, PersonaArchetypeFilter, PersonaFilter,
    UpdatePersona, UpdatePersonaArchetype, User,
};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    ArchetypeListResponse, ArchetypeResponse, ArchivePersonaRequest, ContextSessionListResponse,
    ContextSessionSummary, CreateArchetypeRequest, CreatePersonaRequest, CurrentContextResponse,
    DeactivatePersonaRequest, ExpiringPersonaSummary, ExpiringPersonasResponse,
    ExtendPersonaRequest, ExtendPersonaResponse, ExtensionStatus, ListArchetypesQuery,
    ListExpiringPersonasQuery, ListPersonasQuery, PersonaAttributesResponse,
    PersonaAuditEventResponse, PersonaAuditListResponse, PersonaDetailResponse,
    PersonaListResponse, PersonaResponse, PropagateAttributesResponse, SearchAuditQuery,
    SwitchBackRequest, SwitchContextRequest, SwitchContextResponse, UpdateArchetypeRequest,
    UpdatePersonaRequest, UserPersonasResponse,
};
use crate::router::GovernanceState;

/// Prefer a non-empty display name, otherwise the user's email.
fn user_display_name(display_name: Option<&str>, email: &str) -> String {
    display_name
        .filter(|name| !name.is_empty())
        .unwrap_or(email)
        .to_string()
}

async fn load_user_display_name(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    user_id: Uuid,
) -> ApiResult<Option<String>> {
    Ok(User::find_by_id_in_tenant(pool, tenant_id, user_id)
        .await?
        .map(|user| user_display_name(user.display_name.as_deref(), &user.email)))
}

// ============================================================================
// Archetype Handlers
// ============================================================================

/// List persona archetypes.
#[utoipa::path(
    get,
    path = "/governance/persona-archetypes",
    tag = "Governance - Persona Management",
    params(ListArchetypesQuery),
    responses(
        (status = 200, description = "List of archetypes", body = ArchetypeListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_archetypes(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListArchetypesQuery>,
) -> ApiResult<Json<ArchetypeListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let filter = PersonaArchetypeFilter {
        is_active: query.is_active,
        name_contains: query.name_contains,
    };

    let (archetypes, total) = state
        .persona_archetype_service
        .list(tenant_id, &filter, limit, offset)
        .await?;

    let items = archetypes
        .into_iter()
        .map(ArchetypeResponse::from)
        .collect();

    Ok(Json(ArchetypeListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Create a persona archetype.
#[utoipa::path(
    post,
    path = "/governance/persona-archetypes",
    tag = "Governance - Persona Management",
    request_body = CreateArchetypeRequest,
    responses(
        (status = 201, description = "Archetype created", body = ArchetypeResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_archetype(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateArchetypeRequest>,
) -> ApiResult<(StatusCode, Json<ArchetypeResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let attribute_mappings = if let Some(mappings) = request.attribute_mappings {
        serde_json::to_value(&mappings).map_err(|e| {
            ApiGovernanceError::Validation(format!("Invalid attribute mappings: {e}"))
        })?
    } else {
        serde_json::json!({
            "propagate": [],
            "computed": [],
            "persona_only": []
        })
    };

    let lifecycle_policy = if let Some(policy) = request.lifecycle_policy {
        policy.validate()?;
        serde_json::to_value(&policy)
            .map_err(|e| ApiGovernanceError::Validation(format!("Invalid lifecycle policy: {e}")))?
    } else {
        serde_json::json!({
            "default_validity_days": 365,
            "max_validity_days": 730,
            "notification_before_expiry_days": 7,
            "auto_extension_allowed": false,
            "extension_requires_approval": true,
            "on_physical_user_deactivation": "cascade_deactivate"
        })
    };

    let default_entitlements = request
        .default_entitlements
        .map(serde_json::to_value)
        .transpose()
        .map_err(|e| {
            ApiGovernanceError::Validation(format!("Invalid default entitlements: {e}"))
        })?;

    let input = CreatePersonaArchetype {
        name: request.name,
        description: request.description,
        naming_pattern: request.naming_pattern,
        attribute_mappings,
        default_entitlements,
        lifecycle_policy,
    };

    let archetype = state
        .persona_archetype_service
        .create(tenant_id, input)
        .await?;

    // Log audit event
    state
        .persona_audit_service
        .log_archetype_created(tenant_id, actor_id, archetype.id, &archetype.name)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(ArchetypeResponse::from(archetype)),
    ))
}

/// Get a persona archetype by ID.
#[utoipa::path(
    get,
    path = "/governance/persona-archetypes/{id}",
    tag = "Governance - Persona Management",
    params(
        ("id" = Uuid, Path, description = "Archetype ID")
    ),
    responses(
        (status = 200, description = "Archetype details", body = ArchetypeResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Archetype not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_archetype(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ArchetypeResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let archetype = state.persona_archetype_service.get(tenant_id, id).await?;

    // Get personas count
    let count = state
        .persona_archetype_service
        .count_active_personas(tenant_id, id)
        .await?;

    let mut response = ArchetypeResponse::from(archetype);
    response.personas_count = Some(count);

    Ok(Json(response))
}

/// Update a persona archetype.
#[utoipa::path(
    put,
    path = "/governance/persona-archetypes/{id}",
    tag = "Governance - Persona Management",
    params(
        ("id" = Uuid, Path, description = "Archetype ID")
    ),
    request_body = UpdateArchetypeRequest,
    responses(
        (status = 200, description = "Archetype updated", body = ArchetypeResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Archetype not found"),
        (status = 409, description = "Name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_archetype(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateArchetypeRequest>,
) -> ApiResult<Json<ArchetypeResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let attribute_mappings = request
        .attribute_mappings
        .map(serde_json::to_value)
        .transpose()
        .map_err(|e| ApiGovernanceError::Validation(format!("Invalid attribute mappings: {e}")))?;
    let lifecycle_policy = if let Some(policy) = request.lifecycle_policy {
        policy.validate()?;
        Some(serde_json::to_value(&policy).map_err(|e| {
            ApiGovernanceError::Validation(format!("Invalid lifecycle policy: {e}"))
        })?)
    } else {
        None
    };
    let default_entitlements = request
        .default_entitlements
        .map(serde_json::to_value)
        .transpose()
        .map_err(|e| {
            ApiGovernanceError::Validation(format!("Invalid default entitlements: {e}"))
        })?;

    let changes = archetype_update_changes(
        request.name.as_deref(),
        request.description.as_deref(),
        request.naming_pattern.as_deref(),
        attribute_mappings.as_ref(),
        default_entitlements.as_ref(),
        lifecycle_policy.as_ref(),
        request.is_active,
    );

    let input = UpdatePersonaArchetype {
        name: request.name,
        description: request.description,
        naming_pattern: request.naming_pattern,
        attribute_mappings,
        default_entitlements,
        lifecycle_policy,
        is_active: request.is_active,
    };

    let archetype = state
        .persona_archetype_service
        .update(tenant_id, id, input)
        .await?;

    state
        .persona_audit_service
        .log_archetype_updated(tenant_id, actor_id, archetype.id, &archetype.name, changes)
        .await?;

    Ok(Json(ArchetypeResponse::from(archetype)))
}

/// Delete a persona archetype.
#[utoipa::path(
    delete,
    path = "/governance/persona-archetypes/{id}",
    tag = "Governance - Persona Management",
    params(
        ("id" = Uuid, Path, description = "Archetype ID")
    ),
    responses(
        (status = 204, description = "Archetype deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Archetype not found"),
        (status = 409, description = "Cannot delete - active personas exist"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_archetype(
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
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Get archetype name before deletion for audit
    let archetype = state.persona_archetype_service.get(tenant_id, id).await?;
    let name = archetype.name.clone();

    // Log audit event BEFORE deletion so the FK reference is still valid
    state
        .persona_audit_service
        .log_archetype_deleted(tenant_id, actor_id, id, &name)
        .await?;

    state
        .persona_archetype_service
        .delete(tenant_id, id)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Activate a persona archetype.
#[utoipa::path(
    post,
    path = "/governance/persona-archetypes/{id}/activate",
    tag = "Governance - Persona Management",
    params(
        ("id" = Uuid, Path, description = "Archetype ID")
    ),
    responses(
        (status = 200, description = "Archetype activated", body = ArchetypeResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Archetype not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn activate_archetype(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ArchetypeResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let archetype = state
        .persona_archetype_service
        .activate(tenant_id, id)
        .await?;

    Ok(Json(ArchetypeResponse::from(archetype)))
}

/// Deactivate a persona archetype.
#[utoipa::path(
    post,
    path = "/governance/persona-archetypes/{id}/deactivate",
    tag = "Governance - Persona Management",
    params(
        ("id" = Uuid, Path, description = "Archetype ID")
    ),
    responses(
        (status = 200, description = "Archetype deactivated", body = ArchetypeResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Archetype not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn deactivate_archetype(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<ArchetypeResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let archetype = state
        .persona_archetype_service
        .deactivate(tenant_id, id)
        .await?;

    Ok(Json(ArchetypeResponse::from(archetype)))
}

// ============================================================================
// Persona Handlers
// ============================================================================

/// List personas with filtering.
#[utoipa::path(
    get,
    path = "/governance/personas",
    tag = "Governance - Persona Management",
    params(ListPersonasQuery),
    responses(
        (status = 200, description = "List of personas", body = PersonaListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_personas(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListPersonasQuery>,
) -> ApiResult<Json<PersonaListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let filter = PersonaFilter {
        status: query.status,
        archetype_id: query.archetype_id,
        physical_user_id: query.physical_user_id,
        expiring_within_days: None,
    };

    let (personas, total) = state
        .persona_service
        .list(tenant_id, &filter, limit, offset)
        .await?;

    let items = personas.into_iter().map(PersonaResponse::from).collect();

    Ok(Json(PersonaListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Create a persona.
#[utoipa::path(
    post,
    path = "/governance/personas",
    tag = "Governance - Persona Management",
    request_body = CreatePersonaRequest,
    responses(
        (status = 201, description = "Persona created", body = PersonaResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Archetype or user not found"),
        (status = 409, description = "Duplicate persona for archetype/user"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_persona(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreatePersonaRequest>,
) -> ApiResult<(StatusCode, Json<PersonaResponse>)> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let persona = state
        .persona_service
        .create(
            tenant_id,
            request.archetype_id,
            request.physical_user_id,
            request.attribute_overrides,
        )
        .await?;

    // Log audit event
    let attrs = persona
        .parse_attributes()
        .map_err(|e| ApiGovernanceError::Validation(e.to_string()))?;
    state
        .persona_audit_service
        .log_persona_created(
            tenant_id,
            actor_id,
            persona.id,
            persona.archetype_id,
            persona.physical_user_id,
            &persona.persona_name,
            persona_handler_json(&attrs)?,
            persona.valid_from,
            persona.valid_until,
        )
        .await?;

    Ok((StatusCode::CREATED, Json(PersonaResponse::from(persona))))
}

/// Get a persona by ID.
#[utoipa::path(
    get,
    path = "/governance/personas/{id}",
    tag = "Governance - Persona Management",
    params(
        ("id" = Uuid, Path, description = "Persona ID")
    ),
    responses(
        (status = 200, description = "Persona details", body = PersonaDetailResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Persona not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_persona(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<PersonaDetailResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let persona = state.persona_service.get(tenant_id, id).await?;

    // Parse attributes
    let attrs = persona
        .parse_attributes()
        .map_err(|e| ApiGovernanceError::Validation(e.to_string()))?;

    let response = PersonaDetailResponse {
        base: PersonaResponse::from(persona),
        attributes: PersonaAttributesResponse::from(attrs),
        entitlements: None,
        physical_user: None,
    };

    Ok(Json(response))
}

/// Update a persona.
#[utoipa::path(
    put,
    path = "/governance/personas/{id}",
    tag = "Governance - Persona Management",
    params(
        ("id" = Uuid, Path, description = "Persona ID")
    ),
    request_body = UpdatePersonaRequest,
    responses(
        (status = 200, description = "Persona updated", body = PersonaResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Persona not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_persona(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdatePersonaRequest>,
) -> ApiResult<Json<PersonaResponse>> {
    if !claims.has_role("admin") {
        return Err(ApiGovernanceError::Forbidden);
    }

    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    // Convert attribute_overrides to the full attributes JSON format
    let attributes = request.attribute_overrides.map(|overrides| {
        serde_json::json!({
            "inherited": {},
            "overrides": overrides,
            "persona_specific": {}
        })
    });

    let input = UpdatePersona {
        display_name: request.display_name,
        attributes,
        valid_until: request.valid_until,
    };

    let persona = state.persona_service.update(tenant_id, id, input).await?;

    Ok(Json(PersonaResponse::from(persona)))
}

/// Activate a persona.
#[utoipa::path(
    post,
    path = "/governance/personas/{id}/activate",
    tag = "Governance - Persona Management",
    params(
        ("id" = Uuid, Path, description = "Persona ID")
    ),
    responses(
        (status = 200, description = "Persona activated", body = PersonaResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Persona not found"),
        (status = 409, description = "Cannot activate - invalid status"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn activate_persona(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<PersonaResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let persona = state.persona_service.activate(tenant_id, id).await?;

    // Log audit event
    state
        .persona_audit_service
        .log_persona_activated(tenant_id, actor_id, id, None)
        .await?;

    Ok(Json(PersonaResponse::from(persona)))
}

/// Deactivate a persona.
#[utoipa::path(
    post,
    path = "/governance/personas/{id}/deactivate",
    tag = "Governance - Persona Management",
    params(
        ("id" = Uuid, Path, description = "Persona ID")
    ),
    request_body = DeactivatePersonaRequest,
    responses(
        (status = 200, description = "Persona deactivated", body = PersonaResponse),
        (status = 400, description = "Invalid request - reason required"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Persona not found"),
        (status = 409, description = "Cannot deactivate - invalid status"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn deactivate_persona(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<DeactivatePersonaRequest>,
) -> ApiResult<Json<PersonaResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let persona = state
        .persona_service
        .deactivate(tenant_id, id, actor_id, &request.reason)
        .await?;

    // Log audit event
    state
        .persona_audit_service
        .log_persona_deactivated(tenant_id, actor_id, id, &request.reason)
        .await?;

    Ok(Json(PersonaResponse::from(persona)))
}

/// Archive a persona.
#[utoipa::path(
    post,
    path = "/governance/personas/{id}/archive",
    tag = "Governance - Persona Management",
    params(
        ("id" = Uuid, Path, description = "Persona ID")
    ),
    request_body = ArchivePersonaRequest,
    responses(
        (status = 200, description = "Persona archived", body = PersonaResponse),
        (status = 400, description = "Invalid request - reason required"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Persona not found"),
        (status = 409, description = "Already archived"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn archive_persona(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<ArchivePersonaRequest>,
) -> ApiResult<Json<PersonaResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let persona = state
        .persona_service
        .archive(tenant_id, id, actor_id, &request.reason)
        .await?;

    // Log audit event
    state
        .persona_audit_service
        .log_persona_archived(tenant_id, actor_id, id, &request.reason)
        .await?;

    Ok(Json(PersonaResponse::from(persona)))
}

/// Propagate attributes from physical user to persona.
#[utoipa::path(
    post,
    path = "/governance/personas/{id}/propagate-attributes",
    tag = "Governance - Persona Management",
    params(
        ("id" = Uuid, Path, description = "Persona ID")
    ),
    responses(
        (status = 200, description = "Attributes propagated", body = PropagateAttributesResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Persona not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn propagate_attributes(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<PropagateAttributesResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let (persona, changed_attributes) = state
        .persona_service
        .propagate_attributes(tenant_id, id)
        .await?;

    let attributes_updated = i32::try_from(changed_attributes.len()).unwrap_or(i32::MAX);

    state
        .persona_audit_service
        .log_attributes_propagated(
            tenant_id,
            actor_id,
            id,
            persona.physical_user_id,
            changed_attributes,
            "manual_propagation",
        )
        .await?;

    Ok(Json(PropagateAttributesResponse {
        persona_id: persona.id,
        attributes_updated,
    }))
}

/// Get personas for a specific user.
#[utoipa::path(
    get,
    path = "/governance/users/{user_id}/personas",
    tag = "Governance - Persona Management",
    params(
        ("user_id" = Uuid, Path, description = "Physical user ID"),
        ("include_archived" = Option<bool>, Query, description = "Include archived personas")
    ),
    responses(
        (status = 200, description = "User's personas", body = UserPersonasResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_user_personas(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(user_id): Path<Uuid>,
    Query(params): Query<IncludeArchivedQuery>,
) -> ApiResult<Json<UserPersonasResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let include_archived = params.include_archived.unwrap_or(false);

    let personas = state
        .persona_service
        .list_for_user(tenant_id, user_id, include_archived)
        .await?;

    let physical_user_name = load_user_display_name(state.pool(), tenant_id, user_id).await?;
    let active_persona_id =
        GovPersonaSession::find_active_for_user(state.pool(), tenant_id, user_id)
            .await?
            .and_then(|session| session.active_persona_id);

    let response = UserPersonasResponse {
        physical_user_id: user_id,
        physical_user_name,
        personas: personas.into_iter().map(PersonaResponse::from).collect(),
        active_persona_id,
    };

    Ok(Json(response))
}

/// Query parameters for `include_archived`.
#[derive(Debug, Clone, serde::Deserialize, utoipa::IntoParams)]
pub struct IncludeArchivedQuery {
    pub include_archived: Option<bool>,
}

// ============================================================================
// Audit Handlers
// ============================================================================

/// List persona audit events.
#[utoipa::path(
    get,
    path = "/governance/persona-audit",
    tag = "Governance - Persona Management",
    params(SearchAuditQuery),
    responses(
        (status = 200, description = "Audit events", body = PersonaAuditListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_audit_events(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<SearchAuditQuery>,
) -> ApiResult<Json<PersonaAuditListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let filter = xavyo_db::models::PersonaAuditEventFilter {
        persona_id: query.persona_id,
        archetype_id: query.archetype_id,
        actor_id: query.actor_id,
        event_type: query.event_type,
        from_date: query.from_date,
        to_date: query.to_date,
    };

    let (events, total) = state
        .persona_audit_service
        .list(tenant_id, &filter, limit, offset)
        .await?;

    let items = events
        .into_iter()
        .map(PersonaAuditEventResponse::from)
        .collect();

    Ok(Json(PersonaAuditListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

/// Get audit events for a specific persona.
#[utoipa::path(
    get,
    path = "/governance/personas/{id}/audit",
    tag = "Governance - Persona Management",
    params(
        ("id" = Uuid, Path, description = "Persona ID"),
        ("limit" = Option<i64>, Query, description = "Maximum results"),
        ("offset" = Option<i64>, Query, description = "Skip results")
    ),
    responses(
        (status = 200, description = "Audit events for persona", body = PersonaAuditListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Persona not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_persona_audit(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Query(query): Query<PaginationQuery>,
) -> ApiResult<Json<PersonaAuditListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    // Verify persona exists
    let _ = state.persona_service.get(tenant_id, id).await?;

    let (events, total) = state
        .persona_audit_service
        .list_for_persona(tenant_id, id, limit, offset)
        .await?;

    Ok(Json(PersonaAuditListResponse {
        items: events
            .into_iter()
            .map(PersonaAuditEventResponse::from)
            .collect(),
        total,
        limit,
        offset,
    }))
}

/// Pagination query parameters.
#[derive(Debug, Clone, serde::Deserialize, utoipa::IntoParams)]
pub struct PaginationQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// ============================================================================
// Context Switching Handlers (T044-T047)
// ============================================================================

/// Switch to a persona context.
#[utoipa::path(
    post,
    path = "/governance/context/switch",
    tag = "Governance - Persona Management",
    request_body = SwitchContextRequest,
    responses(
        (status = 501, description = "Identity-switch JWT re-issuance is not implemented"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Persona does not belong to user"),
        (status = 404, description = "Persona not found"),
        (status = 409, description = "Cannot switch - persona not active or expired"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn switch_context(
    State(_state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<SwitchContextRequest>,
) -> ApiResult<Json<SwitchContextResponse>> {
    request.validate()?;

    let _tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let _user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    // Fail closed: do not persist a persona session or return a placeholder
    // access_token. The BFF stores `access_token` as the session cookie.
    Err(crate::identity_switch::unimplemented_identity_switch_jwt())
}

/// Switch back to physical user context.
#[utoipa::path(
    post,
    path = "/governance/context/switch-back",
    tag = "Governance - Persona Management",
    request_body = SwitchBackRequest,
    responses(
        (status = 501, description = "Identity-switch JWT re-issuance is not implemented"),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn switch_back(
    State(_state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<SwitchBackRequest>,
) -> ApiResult<Json<SwitchContextResponse>> {
    request.validate()?;

    let _tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let _user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    Err(crate::identity_switch::unimplemented_identity_switch_jwt())
}

/// Get current context for the authenticated user.
#[utoipa::path(
    get,
    path = "/governance/context/current",
    tag = "Governance - Persona Management",
    responses(
        (status = 200, description = "Current context", body = CurrentContextResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_current_context(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
) -> ApiResult<Json<CurrentContextResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let context_info = state
        .persona_session_service
        .get_current_context(tenant_id, user_id)
        .await?;
    let physical_user_name = load_user_display_name(state.pool(), tenant_id, user_id).await?;

    let response = if let Some(info) = context_info {
        let active_persona = if let Some(persona_id) = info.persona_id {
            let persona = state.persona_service.get(tenant_id, persona_id).await?;
            Some(PersonaResponse::from(persona))
        } else {
            None
        };

        CurrentContextResponse {
            physical_user_id: user_id,
            physical_user_name,
            is_persona_active: info.persona_id.is_some(),
            active_persona,
            session_started_at: info.session_expires_at - chrono::Duration::hours(8), // Approximate
            session_expires_at: info.session_expires_at,
        }
    } else {
        // No active session - user is operating as physical identity
        CurrentContextResponse {
            physical_user_id: user_id,
            physical_user_name,
            is_persona_active: false,
            active_persona: None,
            session_started_at: chrono::Utc::now(),
            session_expires_at: chrono::Utc::now() + chrono::Duration::hours(8),
        }
    };

    Ok(Json(response))
}

/// Get context session history.
#[utoipa::path(
    get,
    path = "/governance/context/sessions",
    tag = "Governance - Persona Management",
    params(PaginationQuery),
    responses(
        (status = 200, description = "Session history", body = ContextSessionListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_context_sessions(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<PaginationQuery>,
) -> ApiResult<Json<ContextSessionListResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0).max(0);

    let (sessions, total) = state
        .persona_session_service
        .get_session_history(tenant_id, user_id, limit, offset)
        .await?;
    let mut items = Vec::with_capacity(sessions.len());
    for session in sessions {
        items.push(context_session_summary(state.pool(), tenant_id, session).await?);
    }

    Ok(Json(ContextSessionListResponse {
        items,
        total,
        limit,
        offset,
    }))
}

// ============================================================================
// Expiration Handlers (US5)
// ============================================================================

fn expiring_query_days(query: &ListExpiringPersonasQuery) -> i32 {
    query
        .days_ahead
        .or(query.within_days)
        .unwrap_or(7)
        .clamp(1, 90)
}

fn map_expiring_persona(
    p: crate::services::ExpiringPersonaSummary,
) -> Option<ExpiringPersonaSummary> {
    Some(ExpiringPersonaSummary {
        id: p.persona_id,
        persona_name: p.persona_name,
        physical_user_id: p.physical_user_id,
        physical_user_name: None,
        archetype_name: p.archetype_name,
        valid_until: p.valid_until?,
        days_remaining: i32::try_from(p.days_remaining).unwrap_or(i32::MAX),
        notification_sent: false,
    })
}

async fn context_session_summary(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    session: GovPersonaSession,
) -> ApiResult<ContextSessionSummary> {
    Ok(ContextSessionSummary {
        id: session.id,
        switched_at: session.switched_at,
        from_context: persona_context_label(pool, tenant_id, session.previous_persona_id).await?,
        to_context: persona_context_label(pool, tenant_id, session.active_persona_id).await?,
        reason: session.switch_reason,
    })
}

async fn persona_context_label(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    persona_id: Option<Uuid>,
) -> ApiResult<String> {
    let Some(persona_id) = persona_id else {
        return Ok("Physical User".to_string());
    };
    Ok(GovPersona::find_by_id(pool, tenant_id, persona_id)
        .await?
        .map(|persona| persona.persona_name)
        .unwrap_or_else(|| format!("Unknown ({persona_id})")))
}

/// Extend persona validity (T073).
#[utoipa::path(
    post,
    path = "/governance/personas/{id}/extend",
    tag = "Governance - Persona Management",
    params(
        ("id" = Uuid, Path, description = "Persona ID")
    ),
    request_body = ExtendPersonaRequest,
    responses(
        (status = 200, description = "Persona validity extended", body = ExtendPersonaResponse),
        (status = 400, description = "Invalid extension request"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Persona not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn extend_persona(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<ExtendPersonaRequest>,
) -> ApiResult<Json<ExtendPersonaResponse>> {
    request.validate()?;
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let result = state
        .persona_expiration_service
        .extend_validity(
            tenant_id,
            id,
            request.new_valid_until,
            actor_id,
            request.reason.as_deref(),
        )
        .await?;

    let persona = state.persona_service.get(tenant_id, id).await?;

    Ok(Json(ExtendPersonaResponse {
        status: if result.required_approval {
            ExtensionStatus::PendingApproval
        } else {
            ExtensionStatus::Approved
        },
        persona: Some(persona.into()),
        approval_request_id: None,
    }))
}

/// Get expiring personas report (T075).
#[utoipa::path(
    get,
    path = "/governance/personas/expiring",
    tag = "Governance - Persona Management",
    params(ListExpiringPersonasQuery),
    responses(
        (status = 200, description = "Expiring personas report", body = ExpiringPersonasResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_expiring_personas(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListExpiringPersonasQuery>,
) -> ApiResult<Json<ExpiringPersonasResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let days_ahead = i64::from(expiring_query_days(&query));
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let offset = query.offset.unwrap_or(0).max(0);

    let report = state
        .persona_expiration_service
        .get_expiring_report(tenant_id, days_ahead)
        .await?;

    let all: Vec<ExpiringPersonaSummary> = report
        .personas
        .into_iter()
        .filter_map(map_expiring_persona)
        .collect();
    let total = i64::try_from(all.len()).unwrap_or(i64::MAX);
    let mut items: Vec<ExpiringPersonaSummary> = all
        .into_iter()
        .skip(usize::try_from(offset).unwrap_or(0))
        .take(usize::try_from(limit).unwrap_or(50))
        .collect();
    for item in &mut items {
        item.physical_user_name =
            load_user_display_name(state.pool(), tenant_id, item.physical_user_id).await?;
    }

    Ok(Json(ExpiringPersonasResponse {
        items,
        total,
        within_days: expiring_query_days(&query),
        limit,
        offset,
    }))
}

/// Fields actually submitted on an archetype update. Empty `{}` must not be
/// stored as if nothing changed.
fn archetype_update_changes(
    name: Option<&str>,
    description: Option<&str>,
    naming_pattern: Option<&str>,
    attribute_mappings: Option<&serde_json::Value>,
    default_entitlements: Option<&serde_json::Value>,
    lifecycle_policy: Option<&serde_json::Value>,
    is_active: Option<bool>,
) -> serde_json::Value {
    let mut changes = serde_json::Map::new();
    if let Some(v) = name {
        changes.insert("name".into(), serde_json::json!(v));
    }
    if let Some(v) = description {
        changes.insert("description".into(), serde_json::json!(v));
    }
    if let Some(v) = naming_pattern {
        changes.insert("naming_pattern".into(), serde_json::json!(v));
    }
    if let Some(v) = attribute_mappings {
        changes.insert("attribute_mappings".into(), v.clone());
    }
    if let Some(v) = default_entitlements {
        changes.insert("default_entitlements".into(), v.clone());
    }
    if let Some(v) = lifecycle_policy {
        changes.insert("lifecycle_policy".into(), v.clone());
    }
    if let Some(v) = is_active {
        changes.insert("is_active".into(), serde_json::json!(v));
    }
    serde_json::Value::Object(changes)
}

/// Persona handler persist. Serialization errors must not store empty attributes.
pub(crate) fn persona_handler_json<T: serde::Serialize>(value: &T) -> ApiResult<serde_json::Value> {
    serde_json::to_value(value).map_err(|e| ApiGovernanceError::Validation(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archetype_update_and_propagate_audit_real_changes() {
        let src = include_str!("personas.rs");
        let production = src.split("mod tests").next().expect("production source");
        let update = production
            .split("pub async fn update_archetype")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("update_archetype");
        assert!(
            update.contains("archetype_update_changes(")
                && !update.contains("serde_json::json!({})"),
            "archetype update audit must record the submitted changes"
        );
        let propagate = production
            .split("pub async fn propagate_attributes")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("propagate_attributes");
        assert!(
            propagate.contains("changed_attributes")
                && !propagate.contains("serde_json::Map::new()"),
            "attribute propagation audit must record the propagated attributes"
        );
        let changes = archetype_update_changes(Some("n"), None, None, None, None, None, Some(true));
        assert_eq!(changes["name"], "n");
        assert_eq!(changes["is_active"], true);
        assert!(changes.get("description").is_none());
    }

    #[test]
    fn persona_handler_json_does_not_store_empty_on_serialize() {
        let v = persona_handler_json(&serde_json::json!({"inherited": {"a": 1}})).unwrap();
        assert_eq!(v["inherited"]["a"], 1);
        let src = include_str!("personas.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("persona_handler_json(")
                && !production.contains("to_value(&attrs).unwrap_or_default()")
                && !production.contains("parse_attributes().unwrap_or_default()"),
            "persona create/get must fail closed on attribute JSON"
        );
    }

    #[test]
    fn current_context_does_not_hide_persona_lookup_errors() {
        let src = include_str!("personas.rs");
        let production = src.split("mod tests").next().expect("production source");
        let ctx = production
            .split("pub async fn get_current_context")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("get_current_context");
        assert!(
            !ctx.contains(".await.ok()") && ctx.contains("persona_service.get("),
            "persona current-context must not treat lookup errors as no active persona"
        );
        assert!(
            ctx.contains("load_user_display_name(") && !ctx.contains("physical_user_name: None"),
            "GET /governance/context/current must look up the physical user display name"
        );
    }

    #[test]
    fn get_user_personas_fills_display_name_and_active_persona() {
        let src = include_str!("personas.rs");
        let production = src.split("mod tests").next().expect("production source");
        let list = production
            .split("pub async fn get_user_personas")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("get_user_personas");
        assert!(
            list.contains("load_user_display_name(")
                && list.contains("find_active_for_user(")
                && !list.contains("physical_user_name: None")
                && !list.contains("active_persona_id: None"),
            "GET /governance/users/{{id}}/personas must look up the user name and active persona"
        );
    }

    #[test]
    fn persona_audit_list_uses_count_not_page_length() {
        let src = include_str!("personas.rs");
        let production = src.split("mod tests").next().expect("production source");
        let audit = production
            .split("pub async fn get_persona_audit")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("get_persona_audit");
        assert!(
            audit.contains("list_for_persona(")
                && audit.contains("let (events, total)")
                && !audit.contains("events.len() as i64"),
            "GET /governance/personas/{{id}}/audit must report the filtered total, not the page length"
        );
    }

    #[test]
    fn context_sessions_list_uses_count_not_page_length() {
        let src = include_str!("personas.rs");
        let production = src.split("mod tests").next().expect("production source");
        let sessions = production
            .split("pub async fn list_context_sessions")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("list_context_sessions");
        assert!(
            sessions.contains("get_session_history(")
                && sessions.contains("let (sessions, total)")
                && !sessions.contains("sessions.len() as i64"),
            "GET /governance/context/sessions must report the filtered total, not the page length"
        );
        assert!(
            sessions.contains("context_session_summary(") && !sessions.contains("Into::into"),
            "GET /governance/context/sessions must look up persona names"
        );
    }

    #[test]
    fn get_expiring_personas_looks_up_physical_user_name() {
        let src = include_str!("personas.rs");
        let production = src.split("mod tests").next().expect("production source");
        let expiring = production
            .split("pub async fn get_expiring_personas")
            .nth(1)
            .expect("get_expiring_personas");
        assert!(
            expiring.contains("load_user_display_name(") && expiring.contains("physical_user_name"),
            "GET /governance/personas/expiring must look up physical user display names"
        );
    }

    #[test]
    fn extend_persona_uses_advertised_new_valid_until_and_extend_response() {
        let src = include_str!("personas.rs");
        let production = src.split("mod tests").next().expect("production source");
        let extend = production
            .split("pub async fn extend_persona")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("extend_persona");
        assert!(
            extend.contains("request.new_valid_until")
                && extend.contains("ExtendPersonaResponse")
                && extend.contains("ExtensionStatus::Approved")
                && !extend.contains("extension_days")
                && !extend.contains("Json(persona.into())"),
            "POST /governance/personas/{{id}}/extend must accept new_valid_until and return ExtendPersonaResponse"
        );
    }

    #[test]
    fn get_expiring_personas_uses_advertised_page_shape() {
        let src = include_str!("personas.rs");
        let production = src.split("mod tests").next().expect("production source");
        let expiring = production
            .split("pub async fn get_expiring_personas")
            .nth(1)
            .expect("get_expiring_personas");
        assert!(
            expiring.contains("ListExpiringPersonasQuery")
                && expiring.contains("items")
                && expiring.contains("total")
                && expiring.contains("limit")
                && expiring.contains("offset")
                && expiring.contains("days_ahead")
                && expiring.contains("within_days")
                && !expiring.contains("expiring_count")
                && !expiring.contains("personas:"),
            "GET /governance/personas/expiring must return items/total/limit/offset and honor pagination"
        );
    }

    #[test]
    fn propagate_attributes_returns_count_not_persona_body() {
        let src = include_str!("personas.rs");
        let production = src.split("mod tests").next().expect("production source");
        let propagate = production
            .split("pub async fn propagate_attributes")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("propagate_attributes");
        assert!(
            propagate.contains("PropagateAttributesResponse")
                && propagate.contains("attributes_updated")
                && propagate.contains("persona_id: persona.id")
                && !propagate.contains("Json(PersonaResponse::from(persona))"),
            "POST /governance/personas/{{id}}/propagate-attributes must return persona_id and attributes_updated"
        );
    }

    #[test]
    fn map_expiring_persona_uses_advertised_id_and_drops_missing_dates() {
        use chrono::{Duration, Utc};
        use xavyo_db::models::PersonaStatus;

        let until = Utc::now() + Duration::days(3);
        let mapped = map_expiring_persona(crate::services::ExpiringPersonaSummary {
            persona_id: Uuid::new_v4(),
            persona_name: "ops".into(),
            physical_user_id: Uuid::new_v4(),
            valid_until: Some(until),
            days_remaining: 3,
            status: PersonaStatus::Expiring,
            archetype_name: Some("Operator".into()),
        })
        .expect("valid_until present");
        assert_eq!(mapped.persona_name, "ops");
        assert_eq!(mapped.days_remaining, 3);
        assert_eq!(mapped.archetype_name.as_deref(), Some("Operator"));
        assert!(!mapped.notification_sent);

        assert!(
            map_expiring_persona(crate::services::ExpiringPersonaSummary {
                persona_id: Uuid::new_v4(),
                persona_name: "gone".into(),
                physical_user_id: Uuid::new_v4(),
                valid_until: None,
                days_remaining: 0,
                status: PersonaStatus::Expired,
                archetype_name: None,
            })
            .is_none()
        );
    }
}
