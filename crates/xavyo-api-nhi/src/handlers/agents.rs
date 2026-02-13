//! Agent-specific CRUD handlers.
//!
//! Provides endpoints for AI agent management:
//! - `POST /nhi/agents` — Create a new agent
//! - `GET /nhi/agents` — List agents
//! - `GET /nhi/agents/{id}` — Get a specific agent
//! - `PATCH /nhi/agents/{id}` — Update an agent
//! - `DELETE /nhi/agents/{id}` — Delete an agent

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
use xavyo_db::models::{
    nhi_agent::{NhiAgent, NhiAgentFilter, NhiAgentWithIdentity, UpdateNhiAgent},
    nhi_identity::{NhiIdentity, UpdateNhiIdentity},
};
use xavyo_nhi::{NhiLifecycleState, NhiType};

use crate::error::NhiApiError;
use crate::services::nhi_user_permission_service::NhiUserPermissionService;
use crate::state::NhiState;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateAgentRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    pub description: Option<String>,
    pub owner_id: Option<Uuid>,
    pub backup_owner_id: Option<Uuid>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub inactivity_threshold_days: Option<i32>,
    pub rotation_interval_days: Option<i32>,
    // Agent-specific fields
    #[validate(length(min = 1, max = 100))]
    pub agent_type: String,
    pub model_provider: Option<String>,
    pub model_name: Option<String>,
    pub model_version: Option<String>,
    pub agent_card_url: Option<String>,
    pub agent_card_signature: Option<String>,
    #[serde(default = "default_max_token_lifetime")]
    pub max_token_lifetime_secs: i32,
    #[serde(default)]
    pub requires_human_approval: bool,
    pub team_id: Option<Uuid>,
}

fn default_max_token_lifetime() -> i32 {
    900
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateAgentRequest {
    // Base fields
    pub name: Option<String>,
    pub description: Option<String>,
    pub owner_id: Option<Option<Uuid>>,
    pub backup_owner_id: Option<Option<Uuid>>,
    pub expires_at: Option<Option<chrono::DateTime<chrono::Utc>>>,
    pub inactivity_threshold_days: Option<Option<i32>>,
    pub rotation_interval_days: Option<Option<i32>>,
    // Agent-specific fields
    pub agent_type: Option<String>,
    pub model_provider: Option<String>,
    pub model_name: Option<String>,
    pub model_version: Option<String>,
    pub agent_card_url: Option<String>,
    pub agent_card_signature: Option<String>,
    pub max_token_lifetime_secs: Option<i32>,
    pub requires_human_approval: Option<bool>,
    pub team_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct ListAgentsQuery {
    pub agent_type: Option<String>,
    pub lifecycle_state: Option<NhiLifecycleState>,
    pub owner_id: Option<Uuid>,
    pub requires_human_approval: Option<bool>,
    pub team_id: Option<Uuid>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", aliases(
    PaginatedNhiAgentWithIdentityResponse = PaginatedResponse<NhiAgentWithIdentity>,
))]
pub struct PaginatedResponse<T: Serialize> {
    pub data: Vec<T>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /nhi/agents — Create a new agent.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/agents",
    tag = "NHI Agents",
    operation_id = "createNhiAgent",
    request_body = CreateAgentRequest,
    responses(
        (status = 201, description = "Agent created successfully", body = NhiAgentWithIdentity),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden")
    ),
    security(("bearerAuth" = []))
))]
pub async fn create_agent(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateAgentRequest>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }
    request.validate()?;

    let tenant_uuid = *tenant_id.as_uuid();
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| NhiApiError::BadRequest("Invalid user ID".into()))?;

    let mut tx = state.pool.begin().await.map_err(|e| {
        tracing::error!("Failed to begin transaction: {e}");
        NhiApiError::Internal("Failed to begin transaction".into())
    })?;

    // 1. Insert base identity
    let identity: NhiIdentity = sqlx::query_as(
        r"
        INSERT INTO nhi_identities (
            tenant_id, nhi_type, name, description, owner_id, backup_owner_id,
            expires_at, inactivity_threshold_days, rotation_interval_days, created_by
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING *
        ",
    )
    .bind(tenant_uuid)
    .bind(NhiType::Agent)
    .bind(&request.name)
    .bind(&request.description)
    .bind(request.owner_id)
    .bind(request.backup_owner_id)
    .bind(request.expires_at)
    .bind(request.inactivity_threshold_days)
    .bind(request.rotation_interval_days)
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(ref db_err) = e {
            if db_err.constraint() == Some("nhi_identities_tenant_type_name_unique") {
                return NhiApiError::Conflict(format!(
                    "An agent with the name '{}' already exists",
                    request.name
                ));
            }
        }
        NhiApiError::Database(e)
    })?;

    // 2. Insert agent extension
    sqlx::query(
        r"
        INSERT INTO nhi_agents (
            nhi_id, agent_type, model_provider, model_name, model_version,
            agent_card_url, agent_card_signature,
            max_token_lifetime_secs, requires_human_approval, team_id
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ",
    )
    .bind(identity.id)
    .bind(&request.agent_type)
    .bind(&request.model_provider)
    .bind(&request.model_name)
    .bind(&request.model_version)
    .bind(&request.agent_card_url)
    .bind(&request.agent_card_signature)
    .bind(request.max_token_lifetime_secs)
    .bind(request.requires_human_approval)
    .bind(request.team_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await.map_err(|e| {
        tracing::error!("Failed to commit transaction: {e}");
        NhiApiError::Internal("Failed to commit transaction".into())
    })?;

    let result = NhiAgent::find_by_nhi_id(&state.pool, tenant_uuid, identity.id)
        .await?
        .ok_or(NhiApiError::Internal(
            "Failed to fetch created agent".into(),
        ))?;

    Ok((StatusCode::CREATED, Json(result)))
}

/// GET /nhi/agents — List agents with filters.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/agents",
    tag = "NHI Agents",
    operation_id = "listNhiAgents",
    params(ListAgentsQuery),
    responses(
        (status = 200, description = "Paginated list of agents", body = PaginatedNhiAgentWithIdentityResponse),
        (status = 401, description = "Authentication required")
    ),
    security(("bearerAuth" = []))
))]
pub async fn list_agents(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListAgentsQuery>,
) -> Result<Json<PaginatedResponse<NhiAgentWithIdentity>>, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    let offset = query.offset.unwrap_or(0).max(0);

    let filter = NhiAgentFilter {
        agent_type: query.agent_type,
        lifecycle_state: query.lifecycle_state,
        owner_id: query.owner_id,
        requires_human_approval: query.requires_human_approval,
        team_id: query.team_id,
    };

    // Admin/super_admin see all agents; non-admin users only see permitted ones
    if claims.has_role("admin") || claims.has_role("super_admin") {
        let data = NhiAgent::list(&state.pool, tenant_uuid, &filter, limit, offset).await?;
        let total = count_agents(&state.pool, tenant_uuid, &filter).await?;
        Ok(Json(PaginatedResponse {
            data,
            total,
            limit,
            offset,
        }))
    } else {
        use xavyo_db::models::nhi_user_permission::NhiUserPermission;
        let user_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| NhiApiError::BadRequest("Invalid user ID".into()))?;
        let user_perms =
            NhiUserPermission::list_by_user(&state.pool, tenant_uuid, user_id, 10000, 0).await?;
        let mut permitted_nhi_ids: Vec<Uuid> = user_perms.iter().map(|p| p.nhi_id).collect();
        permitted_nhi_ids.sort();
        permitted_nhi_ids.dedup();

        if permitted_nhi_ids.is_empty() {
            return Ok(Json(PaginatedResponse {
                data: vec![],
                total: 0,
                limit,
                offset,
            }));
        }

        let fetch_limit = (limit + offset) * 10;
        let all_data =
            NhiAgent::list(&state.pool, tenant_uuid, &filter, fetch_limit.min(10000), 0).await?;
        let filtered: Vec<NhiAgentWithIdentity> = all_data
            .into_iter()
            .filter(|a| permitted_nhi_ids.binary_search(&a.id).is_ok())
            .collect();
        let total = filtered.len() as i64;
        let data: Vec<NhiAgentWithIdentity> = filtered
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();
        Ok(Json(PaginatedResponse {
            data,
            total,
            limit,
            offset,
        }))
    }
}

/// Count agents matching a filter.
async fn count_agents(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    filter: &NhiAgentFilter,
) -> Result<i64, sqlx::Error> {
    let mut query = String::from(
        r"
        SELECT COUNT(*)
        FROM nhi_identities i
        INNER JOIN nhi_agents a ON a.nhi_id = i.id
        WHERE i.tenant_id = $1
        ",
    );
    let mut param_idx = 2;

    if filter.agent_type.is_some() {
        query.push_str(&format!(" AND a.agent_type = ${param_idx}"));
        param_idx += 1;
    }
    if filter.lifecycle_state.is_some() {
        query.push_str(&format!(" AND i.lifecycle_state = ${param_idx}"));
        param_idx += 1;
    }
    if filter.owner_id.is_some() {
        query.push_str(&format!(" AND i.owner_id = ${param_idx}"));
        param_idx += 1;
    }
    if filter.requires_human_approval.is_some() {
        query.push_str(&format!(" AND a.requires_human_approval = ${param_idx}"));
        param_idx += 1;
    }
    if filter.team_id.is_some() {
        query.push_str(&format!(" AND a.team_id = ${param_idx}"));
        param_idx += 1;
    }
    let _ = param_idx; // suppress unused warning

    let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

    if let Some(ref agent_type) = filter.agent_type {
        q = q.bind(agent_type);
    }
    if let Some(lifecycle_state) = filter.lifecycle_state {
        q = q.bind(lifecycle_state);
    }
    if let Some(owner_id) = filter.owner_id {
        q = q.bind(owner_id);
    }
    if let Some(requires_human_approval) = filter.requires_human_approval {
        q = q.bind(requires_human_approval);
    }
    if let Some(team_id) = filter.team_id {
        q = q.bind(team_id);
    }

    q.fetch_one(pool).await
}

/// GET /nhi/agents/{id} — Get a specific agent.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/agents/{id}",
    tag = "NHI Agents",
    operation_id = "getNhiAgent",
    params(
        ("id" = Uuid, Path, description = "NHI agent ID")
    ),
    responses(
        (status = 200, description = "Agent details", body = NhiAgentWithIdentity),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Agent not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn get_agent(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<NhiAgentWithIdentity>, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();

    // Enforce user→NHI permission (admin/super_admin bypass)
    NhiUserPermissionService::enforce_access(&state.pool, tenant_uuid, &claims, id, "use").await?;

    let agent = NhiAgent::find_by_nhi_id(&state.pool, tenant_uuid, id)
        .await?
        .ok_or(NhiApiError::NotFound)?;

    Ok(Json(agent))
}

/// PATCH /nhi/agents/{id} — Update an agent.
#[cfg_attr(feature = "openapi", utoipa::path(
    patch,
    path = "/nhi/agents/{id}",
    tag = "NHI Agents",
    operation_id = "updateNhiAgent",
    params(
        ("id" = Uuid, Path, description = "NHI agent ID")
    ),
    request_body = UpdateAgentRequest,
    responses(
        (status = 200, description = "Agent updated successfully", body = NhiAgentWithIdentity),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Agent not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn update_agent(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateAgentRequest>,
) -> Result<Json<NhiAgentWithIdentity>, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }
    let tenant_uuid = *tenant_id.as_uuid();

    NhiIdentity::find_by_id(&state.pool, tenant_uuid, id)
        .await?
        .ok_or(NhiApiError::NotFound)?;

    let mut tx = state.pool.begin().await.map_err(|e| {
        tracing::error!("Failed to begin transaction: {e}");
        NhiApiError::Internal("Failed to begin transaction".into())
    })?;

    // Update base identity fields if any are set
    let has_base_update = request.name.is_some()
        || request.description.is_some()
        || request.owner_id.is_some()
        || request.backup_owner_id.is_some()
        || request.expires_at.is_some()
        || request.inactivity_threshold_days.is_some()
        || request.rotation_interval_days.is_some();

    if has_base_update {
        let base_update = UpdateNhiIdentity {
            name: request.name,
            description: request.description,
            owner_id: request.owner_id,
            backup_owner_id: request.backup_owner_id,
            expires_at: request.expires_at,
            inactivity_threshold_days: request.inactivity_threshold_days,
            rotation_interval_days: request.rotation_interval_days,
        };
        update_identity_in_tx(&mut tx, tenant_uuid, id, base_update).await?;
    }

    // Update agent extension fields if any are set
    let has_agent_update = request.agent_type.is_some()
        || request.model_provider.is_some()
        || request.model_name.is_some()
        || request.model_version.is_some()
        || request.agent_card_url.is_some()
        || request.agent_card_signature.is_some()
        || request.max_token_lifetime_secs.is_some()
        || request.requires_human_approval.is_some()
        || request.team_id.is_some();

    if has_agent_update {
        let agent_update = UpdateNhiAgent {
            agent_type: request.agent_type,
            model_provider: request.model_provider,
            model_name: request.model_name,
            model_version: request.model_version,
            agent_card_url: request.agent_card_url,
            agent_card_signature: request.agent_card_signature,
            max_token_lifetime_secs: request.max_token_lifetime_secs,
            requires_human_approval: request.requires_human_approval,
            team_id: request.team_id,
        };
        sqlx::query(
            r"
            UPDATE nhi_agents
            SET agent_type = COALESCE($3, agent_type),
                model_provider = COALESCE($4, model_provider),
                model_name = COALESCE($5, model_name),
                model_version = COALESCE($6, model_version),
                agent_card_url = COALESCE($7, agent_card_url),
                agent_card_signature = COALESCE($8, agent_card_signature),
                max_token_lifetime_secs = COALESCE($9, max_token_lifetime_secs),
                requires_human_approval = COALESCE($10, requires_human_approval),
                team_id = COALESCE($11, team_id)
            WHERE nhi_id = $2
              AND EXISTS (SELECT 1 FROM nhi_identities WHERE id = $2 AND tenant_id = $1)
            ",
        )
        .bind(tenant_uuid)
        .bind(id)
        .bind(&agent_update.agent_type)
        .bind(&agent_update.model_provider)
        .bind(&agent_update.model_name)
        .bind(&agent_update.model_version)
        .bind(&agent_update.agent_card_url)
        .bind(&agent_update.agent_card_signature)
        .bind(agent_update.max_token_lifetime_secs)
        .bind(agent_update.requires_human_approval)
        .bind(agent_update.team_id)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await.map_err(|e| {
        tracing::error!("Failed to commit transaction: {e}");
        NhiApiError::Internal("Failed to commit transaction".into())
    })?;

    let result = NhiAgent::find_by_nhi_id(&state.pool, tenant_uuid, id)
        .await?
        .ok_or(NhiApiError::NotFound)?;

    Ok(Json(result))
}

/// DELETE /nhi/agents/{id} — Delete an agent.
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/nhi/agents/{id}",
    tag = "NHI Agents",
    operation_id = "deleteNhiAgent",
    params(
        ("id" = Uuid, Path, description = "NHI agent ID")
    ),
    responses(
        (status = 204, description = "Agent deleted"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Agent not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn delete_agent(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }
    let tenant_uuid = *tenant_id.as_uuid();

    let deleted = NhiIdentity::delete(&state.pool, tenant_uuid, id).await?;
    if !deleted {
        return Err(NhiApiError::NotFound);
    }

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Helper: update identity within a transaction
// ---------------------------------------------------------------------------

async fn update_identity_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    id: Uuid,
    input: UpdateNhiIdentity,
) -> Result<(), NhiApiError> {
    let mut updates = vec!["updated_at = NOW()".to_string()];
    let mut param_idx: u32 = 3;

    if input.name.is_some() {
        updates.push(format!("name = ${param_idx}"));
        param_idx += 1;
    }
    if input.description.is_some() {
        updates.push(format!("description = ${param_idx}"));
        param_idx += 1;
    }
    if input.owner_id.is_some() {
        updates.push(format!("owner_id = ${param_idx}"));
        param_idx += 1;
    }
    if input.backup_owner_id.is_some() {
        updates.push(format!("backup_owner_id = ${param_idx}"));
        param_idx += 1;
    }
    if input.expires_at.is_some() {
        updates.push(format!("expires_at = ${param_idx}"));
        param_idx += 1;
    }
    if input.inactivity_threshold_days.is_some() {
        updates.push(format!("inactivity_threshold_days = ${param_idx}"));
        param_idx += 1;
    }
    if input.rotation_interval_days.is_some() {
        updates.push(format!("rotation_interval_days = ${param_idx}"));
    }

    let query = format!(
        "UPDATE nhi_identities SET {} WHERE tenant_id = $1 AND id = $2",
        updates.join(", ")
    );

    let mut q = sqlx::query(&query).bind(tenant_id).bind(id);

    if let Some(ref name) = input.name {
        q = q.bind(name);
    }
    if let Some(ref description) = input.description {
        q = q.bind(description);
    }
    if let Some(ref owner_opt) = input.owner_id {
        q = q.bind(*owner_opt);
    }
    if let Some(ref backup_opt) = input.backup_owner_id {
        q = q.bind(*backup_opt);
    }
    if let Some(ref expires_opt) = input.expires_at {
        q = q.bind(*expires_opt);
    }
    if let Some(ref inactivity_opt) = input.inactivity_threshold_days {
        q = q.bind(*inactivity_opt);
    }
    if let Some(ref rotation_opt) = input.rotation_interval_days {
        q = q.bind(*rotation_opt);
    }

    q.execute(&mut **tx).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn agent_routes(state: NhiState) -> Router {
    Router::new()
        .route("/agents", post(create_agent).get(list_agents))
        .route(
            "/agents/:id",
            get(get_agent).patch(update_agent).delete(delete_agent),
        )
        .with_state(state)
}
