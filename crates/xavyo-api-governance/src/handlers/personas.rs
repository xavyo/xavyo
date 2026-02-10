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
    CreatePersonaArchetype, PersonaArchetypeFilter, PersonaFilter, UpdatePersona,
    UpdatePersonaArchetype,
};

use crate::error::{ApiGovernanceError, ApiResult};
use crate::models::{
    ArchetypeListResponse, ArchetypeResponse, ArchivePersonaRequest, ContextSessionListResponse,
    ContextSessionSummary, CreateArchetypeRequest, CreatePersonaRequest, CurrentContextResponse,
    DeactivatePersonaRequest, ListArchetypesQuery, ListPersonasQuery, PersonaAttributesResponse,
    PersonaAuditEventResponse, PersonaAuditListResponse, PersonaDetailResponse,
    PersonaListResponse, PersonaResponse, SearchAuditQuery, SwitchBackRequest,
    SwitchContextRequest, SwitchContextResponse, UpdateArchetypeRequest, UpdatePersonaRequest,
    UserPersonasResponse,
};
use crate::router::GovernanceState;

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

    // Log audit event
    state
        .persona_audit_service
        .log_archetype_updated(
            tenant_id,
            actor_id,
            archetype.id,
            &archetype.name,
            serde_json::json!({}),
        )
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
    let attrs = persona.parse_attributes().unwrap_or_default();
    state
        .persona_audit_service
        .log_persona_created(
            tenant_id,
            actor_id,
            persona.id,
            persona.archetype_id,
            persona.physical_user_id,
            &persona.persona_name,
            serde_json::to_value(&attrs).unwrap_or_default(),
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
    let attrs = persona.parse_attributes().unwrap_or_default();

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
        (status = 200, description = "Attributes propagated", body = PersonaResponse),
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
) -> ApiResult<Json<PersonaResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let persona = state
        .persona_service
        .propagate_attributes(tenant_id, id)
        .await?;

    // Log audit event (with empty changed_attributes for now)
    state
        .persona_audit_service
        .log_attributes_propagated(
            tenant_id,
            actor_id,
            id,
            persona.physical_user_id,
            serde_json::Map::new(),
            "manual_propagation",
        )
        .await?;

    Ok(Json(PersonaResponse::from(persona)))
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

    let response = UserPersonasResponse {
        physical_user_id: user_id,
        physical_user_name: None, // Would be filled with user lookup
        personas: personas.into_iter().map(PersonaResponse::from).collect(),
        active_persona_id: None, // Would be filled with session lookup
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

    let events = state
        .persona_audit_service
        .list_for_persona(tenant_id, id, limit, offset)
        .await?;

    let total = events.len() as i64;

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
        (status = 200, description = "Switched to persona", body = SwitchContextResponse),
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
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<SwitchContextRequest>,
) -> ApiResult<Json<SwitchContextResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let context_info = state
        .persona_session_service
        .switch_to_persona(
            tenant_id,
            user_id,
            request.persona_id,
            request.reason,
            None, // Use default session duration
        )
        .await?;

    // Generate new JWT with persona claims
    // For now, return a placeholder token - in production this would call the auth service
    let access_token = format!("persona_token_{}", context_info.session_id);

    Ok(Json(SwitchContextResponse {
        session_id: context_info.session_id,
        access_token,
        active_persona_id: context_info.persona_id,
        active_persona_name: context_info.persona_name,
        switched_at: chrono::Utc::now(),
    }))
}

/// Switch back to physical user context.
#[utoipa::path(
    post,
    path = "/governance/context/switch-back",
    tag = "Governance - Persona Management",
    request_body = SwitchBackRequest,
    responses(
        (status = 200, description = "Switched back to physical user", body = SwitchContextResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn switch_back(
    State(state): State<GovernanceState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<SwitchBackRequest>,
) -> ApiResult<Json<SwitchContextResponse>> {
    request.validate()?;

    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    let context_info = state
        .persona_session_service
        .switch_back_to_physical(tenant_id, user_id, request.reason)
        .await?;

    // Generate new JWT without persona claims
    let access_token = format!("physical_token_{}", context_info.session_id);

    Ok(Json(SwitchContextResponse {
        session_id: context_info.session_id,
        access_token,
        active_persona_id: None,
        active_persona_name: None,
        switched_at: chrono::Utc::now(),
    }))
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

    let response = if let Some(info) = context_info {
        let active_persona = if let Some(persona_id) = info.persona_id {
            let persona = state.persona_service.get(tenant_id, persona_id).await.ok();
            persona.map(PersonaResponse::from)
        } else {
            None
        };

        CurrentContextResponse {
            physical_user_id: user_id,
            physical_user_name: None, // Would be filled with user lookup
            is_persona_active: info.persona_id.is_some(),
            active_persona,
            session_started_at: info.session_expires_at - chrono::Duration::hours(8), // Approximate
            session_expires_at: info.session_expires_at,
        }
    } else {
        // No active session - user is operating as physical identity
        CurrentContextResponse {
            physical_user_id: user_id,
            physical_user_name: None,
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

    let sessions = state
        .persona_session_service
        .get_session_history(tenant_id, user_id, limit, offset)
        .await?;

    let total = sessions.len() as i64;
    let items: Vec<ContextSessionSummary> =
        sessions.into_iter().map(std::convert::Into::into).collect();

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

/// Request body for extending persona validity.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ExtendPersonaRequest {
    /// Number of days to extend validity.
    pub extension_days: i32,
    /// Reason for extension.
    pub reason: Option<String>,
}

/// Response for expiring personas report.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ExpiringPersonasResponse {
    /// Count of personas in expiring status.
    pub expiring_count: i64,
    /// Count of personas that expire today.
    pub expires_today_count: i64,
    /// Count of personas that expired recently.
    pub recently_expired_count: i64,
    /// List of expiring personas.
    pub personas: Vec<ExpiringPersonaItem>,
    /// Report generation timestamp.
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

/// Expiring persona item in report.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ExpiringPersonaItem {
    /// Persona ID.
    pub persona_id: Uuid,
    /// Persona name.
    pub persona_name: String,
    /// Physical user ID.
    pub physical_user_id: Uuid,
    /// Valid until date.
    pub valid_until: Option<chrono::DateTime<chrono::Utc>>,
    /// Days until expiration.
    pub days_remaining: i64,
    /// Current status.
    pub status: String,
}

/// Query parameters for expiring report.
#[derive(Debug, Clone, serde::Deserialize, utoipa::IntoParams)]
pub struct ExpiringReportQuery {
    /// Number of days ahead to check (default 7).
    pub days_ahead: Option<i64>,
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
        (status = 200, description = "Persona validity extended", body = PersonaResponse),
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
) -> ApiResult<Json<PersonaResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();
    let actor_id = Uuid::parse_str(&claims.sub).map_err(|_| ApiGovernanceError::Unauthorized)?;

    if request.extension_days <= 0 {
        return Err(ApiGovernanceError::Validation(
            "Extension days must be positive".to_string(),
        ));
    }

    let _result = state
        .persona_expiration_service
        .extend_validity(
            tenant_id,
            id,
            request.extension_days,
            actor_id,
            request.reason.as_deref(),
        )
        .await?;

    // Get the updated persona
    let persona = state.persona_service.get(tenant_id, id).await?;

    Ok(Json(persona.into()))
}

/// Get expiring personas report (T075).
#[utoipa::path(
    get,
    path = "/governance/personas/expiring",
    tag = "Governance - Persona Management",
    params(ExpiringReportQuery),
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
    Query(query): Query<ExpiringReportQuery>,
) -> ApiResult<Json<ExpiringPersonasResponse>> {
    let tenant_id = *claims
        .tenant_id()
        .ok_or(ApiGovernanceError::Unauthorized)?
        .as_uuid();

    let days_ahead = query.days_ahead.unwrap_or(7);

    let report = state
        .persona_expiration_service
        .get_expiring_report(tenant_id, days_ahead)
        .await?;

    Ok(Json(ExpiringPersonasResponse {
        expiring_count: report.expiring_count,
        expires_today_count: report.expires_today_count,
        recently_expired_count: report.recently_expired_count,
        personas: report
            .personas
            .into_iter()
            .map(|p| ExpiringPersonaItem {
                persona_id: p.persona_id,
                persona_name: p.persona_name,
                physical_user_id: p.physical_user_id,
                valid_until: p.valid_until,
                days_remaining: p.days_remaining,
                status: format!("{:?}", p.status).to_lowercase(),
            })
            .collect(),
        generated_at: report.generated_at,
    }))
}
