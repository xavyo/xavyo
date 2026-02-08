//! Service account-specific CRUD handlers.
//!
//! Provides endpoints for service account management:
//! - `POST /nhi/service-accounts` — Create a new service account
//! - `GET /nhi/service-accounts` — List service accounts
//! - `GET /nhi/service-accounts/{id}` — Get a specific service account
//! - `PATCH /nhi/service-accounts/{id}` — Update a service account
//! - `DELETE /nhi/service-accounts/{id}` — Delete a service account

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
    nhi_service_account::{
        NhiServiceAccount, NhiServiceAccountFilter, NhiServiceAccountWithIdentity,
        UpdateNhiServiceAccount,
    },
};
use xavyo_nhi::{NhiLifecycleState, NhiType};

use crate::error::NhiApiError;
use crate::state::NhiState;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateServiceAccountRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    pub description: Option<String>,
    pub owner_id: Option<Uuid>,
    pub backup_owner_id: Option<Uuid>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub inactivity_threshold_days: Option<i32>,
    pub rotation_interval_days: Option<i32>,
    // Service-account-specific fields
    #[validate(length(min = 1, max = 500))]
    pub purpose: String,
    pub environment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateServiceAccountRequest {
    // Base fields
    pub name: Option<String>,
    pub description: Option<String>,
    pub owner_id: Option<Option<Uuid>>,
    pub backup_owner_id: Option<Option<Uuid>>,
    pub expires_at: Option<Option<chrono::DateTime<chrono::Utc>>>,
    pub inactivity_threshold_days: Option<Option<i32>>,
    pub rotation_interval_days: Option<Option<i32>>,
    // Service-account-specific fields
    pub purpose: Option<String>,
    pub environment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct ListServiceAccountsQuery {
    pub environment: Option<String>,
    pub lifecycle_state: Option<NhiLifecycleState>,
    pub owner_id: Option<Uuid>,
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

/// POST /nhi/service-accounts — Create a new service account.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/service-accounts",
    tag = "NHI Service Accounts",
    operation_id = "createNhiServiceAccount",
    request_body = CreateServiceAccountRequest,
    responses(
        (status = 201, description = "Service account created successfully", body = NhiServiceAccountWithIdentity),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden")
    ),
    security(("bearerAuth" = []))
))]
pub async fn create_service_account(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<CreateServiceAccountRequest>,
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
    .bind(NhiType::ServiceAccount)
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

    // 2. Insert service account extension
    sqlx::query(
        r"
        INSERT INTO nhi_service_accounts (nhi_id, purpose, environment)
        VALUES ($1, $2, $3)
        ",
    )
    .bind(identity.id)
    .bind(&request.purpose)
    .bind(&request.environment)
    .execute(&mut *tx)
    .await?;

    tx.commit().await.map_err(|e| {
        tracing::error!("Failed to commit transaction: {e}");
        NhiApiError::Internal("Failed to commit transaction".into())
    })?;

    let result = NhiServiceAccount::find_by_nhi_id(&state.pool, tenant_uuid, identity.id)
        .await?
        .ok_or(NhiApiError::Internal(
            "Failed to fetch created service account".into(),
        ))?;

    Ok((StatusCode::CREATED, Json(result)))
}

/// GET /nhi/service-accounts — List service accounts with filters.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/service-accounts",
    tag = "NHI Service Accounts",
    operation_id = "listNhiServiceAccounts",
    params(ListServiceAccountsQuery),
    responses(
        (status = 200, description = "Paginated list of service accounts", body = PaginatedResponse<NhiServiceAccountWithIdentity>),
        (status = 401, description = "Authentication required")
    ),
    security(("bearerAuth" = []))
))]
pub async fn list_service_accounts(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Query(query): Query<ListServiceAccountsQuery>,
) -> Result<Json<PaginatedResponse<NhiServiceAccountWithIdentity>>, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    let offset = query.offset.unwrap_or(0).max(0);

    let filter = NhiServiceAccountFilter {
        environment: query.environment,
        lifecycle_state: query.lifecycle_state,
        owner_id: query.owner_id,
    };

    let data = NhiServiceAccount::list(&state.pool, tenant_uuid, &filter, limit, offset).await?;
    let total = count_service_accounts(&state.pool, tenant_uuid, &filter).await?;

    Ok(Json(PaginatedResponse {
        data,
        total,
        limit,
        offset,
    }))
}

/// Count service accounts matching a filter.
async fn count_service_accounts(
    pool: &sqlx::PgPool,
    tenant_id: Uuid,
    filter: &NhiServiceAccountFilter,
) -> Result<i64, sqlx::Error> {
    let mut query = String::from(
        r"
        SELECT COUNT(*)
        FROM nhi_identities i
        INNER JOIN nhi_service_accounts s ON s.nhi_id = i.id
        WHERE i.tenant_id = $1
        ",
    );
    let mut param_idx = 2;

    if filter.environment.is_some() {
        query.push_str(&format!(" AND s.environment = ${param_idx}"));
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

    if let Some(ref environment) = filter.environment {
        q = q.bind(environment);
    }
    if let Some(lifecycle_state) = filter.lifecycle_state {
        q = q.bind(lifecycle_state);
    }
    if let Some(owner_id) = filter.owner_id {
        q = q.bind(owner_id);
    }

    q.fetch_one(pool).await
}

/// GET /nhi/service-accounts/{id} — Get a specific service account.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/service-accounts/{id}",
    tag = "NHI Service Accounts",
    operation_id = "getNhiServiceAccount",
    params(
        ("id" = Uuid, Path, description = "NHI service account ID")
    ),
    responses(
        (status = 200, description = "Service account details", body = NhiServiceAccountWithIdentity),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Service account not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn get_service_account(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Path(id): Path<Uuid>,
) -> Result<Json<NhiServiceAccountWithIdentity>, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();

    let sa = NhiServiceAccount::find_by_nhi_id(&state.pool, tenant_uuid, id)
        .await?
        .ok_or(NhiApiError::NotFound)?;

    Ok(Json(sa))
}

/// PATCH /nhi/service-accounts/{id} — Update a service account.
#[cfg_attr(feature = "openapi", utoipa::path(
    patch,
    path = "/nhi/service-accounts/{id}",
    tag = "NHI Service Accounts",
    operation_id = "updateNhiServiceAccount",
    params(
        ("id" = Uuid, Path, description = "NHI service account ID")
    ),
    request_body = UpdateServiceAccountRequest,
    responses(
        (status = 200, description = "Service account updated successfully", body = NhiServiceAccountWithIdentity),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Service account not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn update_service_account(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateServiceAccountRequest>,
) -> Result<Json<NhiServiceAccountWithIdentity>, NhiApiError> {
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

    // Update service account extension fields if any are set
    let has_sa_update = request.purpose.is_some() || request.environment.is_some();

    if has_sa_update {
        let sa_update = UpdateNhiServiceAccount {
            purpose: request.purpose,
            environment: request.environment,
        };
        sqlx::query(
            r"
            UPDATE nhi_service_accounts
            SET purpose = COALESCE($3, purpose),
                environment = COALESCE($4, environment)
            WHERE nhi_id = $2
              AND EXISTS (SELECT 1 FROM nhi_identities WHERE id = $2 AND tenant_id = $1)
            ",
        )
        .bind(tenant_uuid)
        .bind(id)
        .bind(&sa_update.purpose)
        .bind(&sa_update.environment)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await.map_err(|e| {
        tracing::error!("Failed to commit transaction: {e}");
        NhiApiError::Internal("Failed to commit transaction".into())
    })?;

    let result = NhiServiceAccount::find_by_nhi_id(&state.pool, tenant_uuid, id)
        .await?
        .ok_or(NhiApiError::NotFound)?;

    Ok(Json(result))
}

/// DELETE /nhi/service-accounts/{id} — Delete a service account.
#[cfg_attr(feature = "openapi", utoipa::path(
    delete,
    path = "/nhi/service-accounts/{id}",
    tag = "NHI Service Accounts",
    operation_id = "deleteNhiServiceAccount",
    params(
        ("id" = Uuid, Path, description = "NHI service account ID")
    ),
    responses(
        (status = 204, description = "Service account deleted"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Service account not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn delete_service_account(
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

pub fn service_account_routes(state: NhiState) -> Router {
    Router::new()
        .route(
            "/service-accounts",
            post(create_service_account).get(list_service_accounts),
        )
        .route(
            "/service-accounts/:id",
            get(get_service_account)
                .patch(update_service_account)
                .delete(delete_service_account),
        )
        .with_state(state)
}
