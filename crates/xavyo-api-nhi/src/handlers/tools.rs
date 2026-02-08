//! Tool-specific CRUD handlers.
//!
//! Provides endpoints for tool management:
//! - `POST /nhi/tools` — Register a new tool
//! - `GET /nhi/tools` — List tools
//! - `GET /nhi/tools/{id}` — Get a specific tool
//! - `PATCH /nhi/tools/{id}` — Update a tool
//! - `DELETE /nhi/tools/{id}` — Delete a tool

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
    nhi_identity::{NhiIdentity, UpdateNhiIdentity},
    nhi_tool::{NhiTool, NhiToolFilter, NhiToolWithIdentity, UpdateNhiTool},
};
use xavyo_nhi::{NhiLifecycleState, NhiType};

use crate::error::NhiApiError;
use crate::state::NhiState;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateToolRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    pub description: Option<String>,
    pub owner_id: Option<Uuid>,
    pub backup_owner_id: Option<Uuid>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub inactivity_threshold_days: Option<i32>,
    pub rotation_interval_days: Option<i32>,
    // Tool-specific fields
    pub category: Option<String>,
    pub input_schema: serde_json::Value,
    pub output_schema: Option<serde_json::Value>,
    #[serde(default)]
    pub requires_approval: bool,
    pub max_calls_per_hour: Option<i32>,
    pub provider: Option<String>,
    #[serde(default)]
    pub provider_verified: bool,
    pub checksum: Option<String>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateToolRequest {
    // Base fields
    pub name: Option<String>,
    pub description: Option<String>,
    pub owner_id: Option<Option<Uuid>>,
    pub backup_owner_id: Option<Option<Uuid>>,
    pub expires_at: Option<Option<chrono::DateTime<chrono::Utc>>>,
    pub inactivity_threshold_days: Option<Option<i32>>,
    pub rotation_interval_days: Option<Option<i32>>,
    // Tool-specific fields
    pub category: Option<String>,
    pub input_schema: Option<serde_json::Value>,
    pub output_schema: Option<serde_json::Value>,
    pub requires_approval: Option<bool>,
    pub max_calls_per_hour: Option<i32>,
    pub provider: Option<String>,
    pub provider_verified: Option<bool>,
    pub checksum: Option<String>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct ListToolsQuery {
    pub category: Option<String>,
    pub lifecycle_state: Option<NhiLifecycleState>,
    pub owner_id: Option<Uuid>,
    pub requires_approval: Option<bool>,
    pub provider_verified: Option<bool>,
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

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /nhi/tools — Create a new tool.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/tools",
    tag = "NHI Tools",
    operation_id = "createNhiTool",
    request_body = CreateToolRequest,
    responses(
        (status = 201, description = "Tool created successfully", body = NhiToolWithIdentity),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden")
    ),
    security(("bearerAuth" = []))
))]
pub async fn create_tool(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateToolRequest>,
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
    .bind(NhiType::Tool)
    .bind(&request.name)
    .bind(&request.description)
    .bind(request.owner_id)
    .bind(request.backup_owner_id)
    .bind(request.expires_at)
    .bind(request.inactivity_threshold_days)
    .bind(request.rotation_interval_days)
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;

    // 2. Insert tool extension
    let _tool: crate::handlers::tools::RawNhiTool = sqlx::query_as(
        r"
        INSERT INTO nhi_tools (
            nhi_id, category, input_schema, output_schema, requires_approval,
            max_calls_per_hour, provider, provider_verified, checksum
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *
        ",
    )
    .bind(identity.id)
    .bind(&request.category)
    .bind(&request.input_schema)
    .bind(&request.output_schema)
    .bind(request.requires_approval)
    .bind(request.max_calls_per_hour)
    .bind(&request.provider)
    .bind(request.provider_verified)
    .bind(&request.checksum)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await.map_err(|e| {
        tracing::error!("Failed to commit transaction: {e}");
        NhiApiError::Internal("Failed to commit transaction".into())
    })?;

    // Re-fetch the joined result
    let result = NhiTool::find_by_nhi_id(&state.pool, tenant_uuid, identity.id)
        .await?
        .ok_or(NhiApiError::Internal("Failed to fetch created tool".into()))?;

    Ok((StatusCode::CREATED, Json(result)))
}

/// Minimal struct for RETURNING * from nhi_tools insert (avoids pulling in full join).
#[derive(Debug, sqlx::FromRow)]
struct RawNhiTool {
    #[allow(dead_code)]
    pub nhi_id: Uuid,
}

/// GET /nhi/tools — List tools with filters.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/tools",
    tag = "NHI Tools",
    operation_id = "listNhiTools",
    params(ListToolsQuery),
    responses(
        (status = 200, description = "Paginated list of tools", body = PaginatedResponse<NhiToolWithIdentity>),
        (status = 401, description = "Authentication required")
    ),
    security(("bearerAuth" = []))
))]
pub async fn list_tools(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Query(query): Query<ListToolsQuery>,
) -> Result<Json<PaginatedResponse<NhiToolWithIdentity>>, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    let offset = query.offset.unwrap_or(0).max(0);

    let filter = NhiToolFilter {
        category: query.category,
        requires_approval: query.requires_approval,
        provider_verified: query.provider_verified,
        lifecycle_state: query.lifecycle_state,
        owner_id: query.owner_id,
    };

    let data = NhiTool::list(&state.pool, tenant_uuid, &filter, limit, offset).await?;

    // Count total using a parallel query
    let total = count_tools(&state.pool, tenant_uuid, &filter).await?;

    Ok(Json(PaginatedResponse {
        data,
        total,
        limit,
        offset,
    }))
}

/// Count tools matching a filter.
async fn count_tools(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    filter: &NhiToolFilter,
) -> Result<i64, sqlx::Error> {
    let mut query = String::from(
        r"
        SELECT COUNT(*)
        FROM nhi_identities i
        INNER JOIN nhi_tools t ON t.nhi_id = i.id
        WHERE i.tenant_id = $1
        ",
    );
    let mut param_idx = 2;

    if filter.category.is_some() {
        query.push_str(&format!(" AND t.category = ${param_idx}"));
        param_idx += 1;
    }
    if filter.requires_approval.is_some() {
        query.push_str(&format!(" AND t.requires_approval = ${param_idx}"));
        param_idx += 1;
    }
    if filter.provider_verified.is_some() {
        query.push_str(&format!(" AND t.provider_verified = ${param_idx}"));
        param_idx += 1;
    }
    if filter.lifecycle_state.is_some() {
        query.push_str(&format!(" AND i.lifecycle_state = ${param_idx}"));
        param_idx += 1;
    }
    if filter.owner_id.is_some() {
        query.push_str(&format!(" AND i.owner_id = ${param_idx}"));
    }

    let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

    if let Some(ref category) = filter.category {
        q = q.bind(category);
    }
    if let Some(requires_approval) = filter.requires_approval {
        q = q.bind(requires_approval);
    }
    if let Some(provider_verified) = filter.provider_verified {
        q = q.bind(provider_verified);
    }
    if let Some(lifecycle_state) = filter.lifecycle_state {
        q = q.bind(lifecycle_state);
    }
    if let Some(owner_id) = filter.owner_id {
        q = q.bind(owner_id);
    }

    q.fetch_one(pool).await
}

/// GET /nhi/tools/{id} — Get a specific tool.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/tools/{id}",
    tag = "NHI Tools",
    operation_id = "getNhiTool",
    params(
        ("id" = Uuid, Path, description = "NHI tool ID")
    ),
    responses(
        (status = 200, description = "Tool details", body = NhiToolWithIdentity),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Tool not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn get_tool(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Path(id): Path<Uuid>,
) -> Result<Json<NhiToolWithIdentity>, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();

    let tool = NhiTool::find_by_nhi_id(&state.pool, tenant_uuid, id)
        .await?
        .ok_or(NhiApiError::NotFound)?;

    Ok(Json(tool))
}

/// PATCH /nhi/tools/{id} — Update a tool.
#[cfg_attr(feature = "openapi", utoipa::path(
    patch,
    path = "/nhi/tools/{id}",
    tag = "NHI Tools",
    operation_id = "updateNhiTool",
    params(
        ("id" = Uuid, Path, description = "NHI tool ID")
    ),
    request_body = UpdateToolRequest,
    responses(
        (status = 200, description = "Tool updated successfully", body = NhiToolWithIdentity),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Tool not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn update_tool(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateToolRequest>,
) -> Result<Json<NhiToolWithIdentity>, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }
    let tenant_uuid = *tenant_id.as_uuid();

    // Check existence first
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
        // Use inline query in txn
        update_identity_in_tx(&mut tx, tenant_uuid, id, base_update).await?;
    }

    // Update tool extension fields if any are set
    let has_tool_update = request.category.is_some()
        || request.input_schema.is_some()
        || request.output_schema.is_some()
        || request.requires_approval.is_some()
        || request.max_calls_per_hour.is_some()
        || request.provider.is_some()
        || request.provider_verified.is_some()
        || request.checksum.is_some();

    if has_tool_update {
        let tool_update = UpdateNhiTool {
            category: request.category,
            input_schema: request.input_schema,
            output_schema: request.output_schema,
            requires_approval: request.requires_approval,
            max_calls_per_hour: request.max_calls_per_hour,
            provider: request.provider,
            provider_verified: request.provider_verified,
            checksum: request.checksum,
        };
        sqlx::query(
            r"
            UPDATE nhi_tools
            SET category = COALESCE($3, category),
                input_schema = COALESCE($4, input_schema),
                output_schema = COALESCE($5, output_schema),
                requires_approval = COALESCE($6, requires_approval),
                max_calls_per_hour = COALESCE($7, max_calls_per_hour),
                provider = COALESCE($8, provider),
                provider_verified = COALESCE($9, provider_verified),
                checksum = COALESCE($10, checksum)
            WHERE nhi_id = $2
              AND EXISTS (SELECT 1 FROM nhi_identities WHERE id = $2 AND tenant_id = $1)
            ",
        )
        .bind(tenant_uuid)
        .bind(id)
        .bind(&tool_update.category)
        .bind(&tool_update.input_schema)
        .bind(&tool_update.output_schema)
        .bind(tool_update.requires_approval)
        .bind(tool_update.max_calls_per_hour)
        .bind(&tool_update.provider)
        .bind(tool_update.provider_verified)
        .bind(&tool_update.checksum)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await.map_err(|e| {
        tracing::error!("Failed to commit transaction: {e}");
        NhiApiError::Internal("Failed to commit transaction".into())
    })?;

    let result = NhiTool::find_by_nhi_id(&state.pool, tenant_uuid, id)
        .await?
        .ok_or(NhiApiError::NotFound)?;

    Ok(Json(result))
}

/// DELETE /nhi/tools/{id} — Delete a tool.
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/nhi/tools/{id}",
    tag = "NHI Tools",
    operation_id = "deleteNhiTool",
    params(
        ("id" = Uuid, Path, description = "NHI tool ID")
    ),
    responses(
        (status = 204, description = "Tool deleted"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Tool not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn delete_tool(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }
    let tenant_uuid = *tenant_id.as_uuid();

    // Delete from base table (CASCADE will handle nhi_tools)
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

pub fn tool_routes(state: NhiState) -> Router {
    Router::new()
        .route("/tools", post(create_tool).get(list_tools))
        .route(
            "/tools/:id",
            get(get_tool).patch(update_tool).delete(delete_tool),
        )
        .with_state(state)
}
