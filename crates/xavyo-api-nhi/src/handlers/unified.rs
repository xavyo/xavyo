//! Unified NHI list/get handlers.
//!
//! Provides polymorphic endpoints that operate across all NHI types:
//! - `GET /nhi` — List all NHIs with type filtering
//! - `GET /nhi/{id}` — Get a specific NHI by ID (includes type-specific extension data)

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;
use xavyo_db::models::{
    nhi_agent::{NhiAgent, NhiAgentWithIdentity},
    nhi_identity::{NhiIdentity, NhiIdentityFilter},
    nhi_service_account::{NhiServiceAccount, NhiServiceAccountWithIdentity},
    nhi_tool::{NhiTool, NhiToolWithIdentity},
    nhi_user_permission::NhiUserPermission,
};
use xavyo_nhi::{NhiLifecycleState, NhiType};

use crate::error::NhiApiError;
use crate::state::NhiState;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct ListNhiQuery {
    pub nhi_type: Option<NhiType>,
    pub lifecycle_state: Option<NhiLifecycleState>,
    pub owner_id: Option<Uuid>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", aliases(
    PaginatedNhiIdentityResponse = PaginatedResponse<NhiIdentity>,
))]
pub struct PaginatedResponse<T: Serialize> {
    pub data: Vec<T>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Polymorphic NHI detail — base identity + optional type-specific extension.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NhiIdentityDetail {
    #[serde(flatten)]
    pub identity: NhiIdentity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<ToolExtension>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentExtension>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_account: Option<ServiceAccountExtension>,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ToolExtension {
    pub category: Option<String>,
    pub input_schema: serde_json::Value,
    pub output_schema: Option<serde_json::Value>,
    pub requires_approval: bool,
    pub max_calls_per_hour: Option<i32>,
    pub provider: Option<String>,
    pub provider_verified: bool,
    pub checksum: Option<String>,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AgentExtension {
    pub agent_type: String,
    pub model_provider: Option<String>,
    pub model_name: Option<String>,
    pub model_version: Option<String>,
    pub agent_card_url: Option<String>,
    pub agent_card_signature: Option<String>,
    pub max_token_lifetime_secs: i32,
    pub requires_human_approval: bool,
}

#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ServiceAccountExtension {
    pub purpose: String,
    pub environment: Option<String>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /nhi — List all NHIs with optional type/state/owner filters.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi",
    tag = "NHI",
    operation_id = "listNhis",
    params(ListNhiQuery),
    responses(
        (status = 200, description = "Paginated list of NHI identities", body = PaginatedNhiIdentityResponse),
        (status = 401, description = "Authentication required")
    ),
    security(("bearerAuth" = []))
))]
pub async fn list_nhis(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<ListNhiQuery>,
) -> Result<Json<PaginatedResponse<NhiIdentity>>, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();
    let limit = query.limit.unwrap_or(20).clamp(1, 100);
    let offset = query.offset.unwrap_or(0).max(0);

    let filter = NhiIdentityFilter {
        nhi_type: query.nhi_type,
        lifecycle_state: query.lifecycle_state,
        owner_id: query.owner_id,
    };

    // Admin/super_admin see all NHIs; non-admin users only see permitted ones
    if claims.has_role("admin") || claims.has_role("super_admin") {
        let data = NhiIdentity::list(&state.pool, tenant_uuid, &filter, limit, offset).await?;
        let total = NhiIdentity::count(&state.pool, tenant_uuid, &filter).await?;
        Ok(Json(PaginatedResponse {
            data,
            total,
            limit,
            offset,
        }))
    } else {
        let user_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| NhiApiError::BadRequest("Invalid user ID".into()))?;

        // Get distinct NHI IDs this user has any non-expired permission for
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

        // Fetch all matching NHIs then filter to permitted ones
        // Use a generous fetch limit to account for filtering
        let fetch_limit = (limit + offset) * 10; // Over-fetch to compensate for filtering
        let all_data =
            NhiIdentity::list(&state.pool, tenant_uuid, &filter, fetch_limit.min(10000), 0).await?;
        let filtered: Vec<NhiIdentity> = all_data
            .into_iter()
            .filter(|nhi| permitted_nhi_ids.binary_search(&nhi.id).is_ok())
            .collect();

        let total = filtered.len() as i64;
        let data: Vec<NhiIdentity> = filtered
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

/// GET /nhi/{id} — Get a specific NHI by ID with type-specific extension data.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/nhi/{id}",
    tag = "NHI",
    operation_id = "getNhi",
    params(
        ("id" = Uuid, Path, description = "NHI identity ID")
    ),
    responses(
        (status = 200, description = "NHI identity detail with type-specific extension", body = NhiIdentityDetail),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "NHI identity not found")
    ),
    security(("bearerAuth" = []))
))]
pub async fn get_nhi(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<NhiIdentityDetail>, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();

    // Enforce user→NHI permission (admin/super_admin bypass)
    crate::services::nhi_user_permission_service::NhiUserPermissionService::enforce_access(
        &state.pool,
        tenant_uuid,
        &claims,
        id,
        "use",
    )
    .await?;

    let identity = NhiIdentity::find_by_id(&state.pool, tenant_uuid, id)
        .await?
        .ok_or(NhiApiError::NotFound)?;

    // Fetch type-specific extension data based on nhi_type
    let (tool, agent, service_account) = match identity.nhi_type {
        NhiType::Tool => {
            let ext = NhiTool::find_by_nhi_id(&state.pool, tenant_uuid, id).await?;
            (ext.map(to_tool_extension), None, None)
        }
        NhiType::Agent => {
            let ext = NhiAgent::find_by_nhi_id(&state.pool, tenant_uuid, id).await?;
            (None, ext.map(to_agent_extension), None)
        }
        NhiType::ServiceAccount => {
            let ext = NhiServiceAccount::find_by_nhi_id(&state.pool, tenant_uuid, id).await?;
            (None, None, ext.map(to_service_account_extension))
        }
        _ => (None, None, None),
    };

    Ok(Json(NhiIdentityDetail {
        identity,
        tool,
        agent,
        service_account,
    }))
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

fn to_tool_extension(t: NhiToolWithIdentity) -> ToolExtension {
    ToolExtension {
        category: t.category,
        input_schema: t.input_schema,
        output_schema: t.output_schema,
        requires_approval: t.requires_approval,
        max_calls_per_hour: t.max_calls_per_hour,
        provider: t.provider,
        provider_verified: t.provider_verified,
        checksum: t.checksum,
    }
}

fn to_agent_extension(a: NhiAgentWithIdentity) -> AgentExtension {
    AgentExtension {
        agent_type: a.agent_type,
        model_provider: a.model_provider,
        model_name: a.model_name,
        model_version: a.model_version,
        agent_card_url: a.agent_card_url,
        agent_card_signature: a.agent_card_signature,
        max_token_lifetime_secs: a.max_token_lifetime_secs,
        requires_human_approval: a.requires_human_approval,
    }
}

fn to_service_account_extension(s: NhiServiceAccountWithIdentity) -> ServiceAccountExtension {
    ServiceAccountExtension {
        purpose: s.purpose,
        environment: s.environment,
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn unified_routes(state: NhiState) -> Router {
    Router::new()
        .route("/", get(list_nhis))
        .route("/:id", get(get_nhi))
        .with_state(state)
}
