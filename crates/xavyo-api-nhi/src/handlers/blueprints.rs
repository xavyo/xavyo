//! Agent Blueprint CRUD handlers.
//!
//! Provides endpoints for managing reusable agent configuration templates:
//! - `POST /nhi/blueprints` — Create a new blueprint
//! - `GET /nhi/blueprints` — List blueprints
//! - `GET /nhi/blueprints/{id}` — Get a specific blueprint
//! - `PATCH /nhi/blueprints/{id}` — Update a blueprint
//! - `DELETE /nhi/blueprints/{id}` — Delete a blueprint

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;
use xavyo_db::models::nhi_agent_blueprint::{
    CreateNhiAgentBlueprint, NhiAgentBlueprint, NhiAgentBlueprintFilter, UpdateNhiAgentBlueprint,
};

use crate::error::NhiApiError;
use crate::state::NhiState;

// --- Request / Response DTOs ---

#[derive(Debug, Deserialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateBlueprintRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    pub description: Option<String>,
    #[validate(length(min = 1, max = 50))]
    #[serde(default = "default_agent_type")]
    pub agent_type: String,
    pub model_provider: Option<String>,
    pub model_name: Option<String>,
    pub model_version: Option<String>,
    #[serde(default = "default_max_token_lifetime")]
    pub max_token_lifetime_secs: i32,
    #[serde(default)]
    pub requires_human_approval: bool,
    #[serde(default)]
    pub default_entitlements: Vec<String>,
    pub default_delegation: Option<serde_json::Value>,
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_agent_type() -> String {
    "autonomous".into()
}

fn default_max_token_lifetime() -> i32 {
    900
}

#[derive(Debug, Deserialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateBlueprintRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,
    pub description: Option<String>,
    #[validate(length(min = 1, max = 50))]
    pub agent_type: Option<String>,
    pub model_provider: Option<String>,
    pub model_name: Option<String>,
    pub model_version: Option<String>,
    pub max_token_lifetime_secs: Option<i32>,
    pub requires_human_approval: Option<bool>,
    pub default_entitlements: Option<Vec<String>>,
    pub default_delegation: Option<serde_json::Value>,
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct ListBlueprintsQuery {
    pub agent_type: Option<String>,
    pub created_by: Option<Uuid>,
    pub tag: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PaginatedResponse<T: Serialize> {
    pub data: Vec<T>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

// --- Handlers ---

pub async fn create_blueprint(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateBlueprintRequest>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }
    request.validate()?;

    let tenant_uuid = *tenant_id.as_uuid();
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| NhiApiError::BadRequest("Invalid user ID".into()))?;

    let agent_name = request.name.clone();
    let input = CreateNhiAgentBlueprint {
        tenant_id: tenant_uuid,
        name: request.name,
        description: request.description,
        agent_type: request.agent_type,
        model_provider: request.model_provider,
        model_name: request.model_name,
        model_version: request.model_version,
        max_token_lifetime_secs: request.max_token_lifetime_secs,
        requires_human_approval: request.requires_human_approval,
        default_entitlements: request.default_entitlements,
        default_delegation: request.default_delegation,
        tags: request.tags,
        created_by: Some(user_id),
    };

    let blueprint = NhiAgentBlueprint::create(&state.pool, input)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint() == Some("nhi_agent_blueprints_tenant_name_unique") {
                    return NhiApiError::Conflict(format!(
                        "A blueprint with name '{}' already exists",
                        agent_name
                    ));
                }
            }
            NhiApiError::Database(e)
        })?;

    Ok((StatusCode::CREATED, Json(blueprint)))
}

pub async fn list_blueprints(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(_claims): Extension<JwtClaims>,
    Query(query): Query<ListBlueprintsQuery>,
) -> Result<Json<PaginatedResponse<NhiAgentBlueprint>>, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    let offset = query.offset.unwrap_or(0).max(0);

    let filter = NhiAgentBlueprintFilter {
        agent_type: query.agent_type,
        created_by: query.created_by,
        tag: query.tag,
    };

    let data = NhiAgentBlueprint::list(&state.pool, tenant_uuid, &filter, limit, offset).await?;
    let total = NhiAgentBlueprint::count(&state.pool, tenant_uuid, &filter).await?;

    Ok(Json(PaginatedResponse {
        data,
        total,
        limit,
        offset,
    }))
}

pub async fn get_blueprint(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(_claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<NhiAgentBlueprint>, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let blueprint = NhiAgentBlueprint::find_by_id(&state.pool, tenant_uuid, id)
        .await?
        .ok_or(NhiApiError::NotFound)?;
    Ok(Json(blueprint))
}

pub async fn update_blueprint(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateBlueprintRequest>,
) -> Result<Json<NhiAgentBlueprint>, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }
    request.validate()?;

    let tenant_uuid = *tenant_id.as_uuid();

    let update = UpdateNhiAgentBlueprint {
        name: request.name,
        description: request.description,
        agent_type: request.agent_type,
        model_provider: request.model_provider,
        model_name: request.model_name,
        model_version: request.model_version,
        max_token_lifetime_secs: request.max_token_lifetime_secs,
        requires_human_approval: request.requires_human_approval,
        default_entitlements: request.default_entitlements,
        default_delegation: request.default_delegation,
        tags: request.tags,
    };

    let blueprint = NhiAgentBlueprint::update(&state.pool, tenant_uuid, id, update)
        .await?
        .ok_or(NhiApiError::NotFound)?;

    Ok(Json(blueprint))
}

pub async fn delete_blueprint(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }
    let tenant_uuid = *tenant_id.as_uuid();

    let deleted = NhiAgentBlueprint::delete(&state.pool, tenant_uuid, id).await?;
    if !deleted {
        return Err(NhiApiError::NotFound);
    }

    Ok(StatusCode::NO_CONTENT)
}

// --- Router ---

pub fn blueprint_routes(state: NhiState) -> Router {
    Router::new()
        .route("/blueprints", post(create_blueprint).get(list_blueprints))
        .route(
            "/blueprints/:id",
            get(get_blueprint)
                .patch(update_blueprint)
                .delete(delete_blueprint),
        )
        .with_state(state)
}
