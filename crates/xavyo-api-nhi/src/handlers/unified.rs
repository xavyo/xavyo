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
use xavyo_core::TenantId;
use xavyo_db::models::{
    nhi_agent::{NhiAgent, NhiAgentWithIdentity},
    nhi_identity::{NhiIdentity, NhiIdentityFilter},
    nhi_service_account::{NhiServiceAccount, NhiServiceAccountWithIdentity},
    nhi_tool::{NhiTool, NhiToolWithIdentity},
};
use xavyo_nhi::{NhiLifecycleState, NhiType};

use crate::error::NhiApiError;
use crate::state::NhiState;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ListNhiQuery {
    pub nhi_type: Option<NhiType>,
    pub lifecycle_state: Option<NhiLifecycleState>,
    pub owner_id: Option<Uuid>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T: Serialize> {
    pub data: Vec<T>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// Polymorphic NHI detail — base identity + optional type-specific extension.
#[derive(Debug, Serialize)]
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
pub struct ServiceAccountExtension {
    pub purpose: String,
    pub environment: Option<String>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /nhi — List all NHIs with optional type/state/owner filters.
async fn list_nhis(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
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

    let data = NhiIdentity::list(&state.pool, tenant_uuid, &filter, limit, offset).await?;
    let total = NhiIdentity::count(&state.pool, tenant_uuid, &filter).await?;

    Ok(Json(PaginatedResponse {
        data,
        total,
        limit,
        offset,
    }))
}

/// GET /nhi/{id} — Get a specific NHI by ID with type-specific extension data.
async fn get_nhi(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Path(id): Path<Uuid>,
) -> Result<Json<NhiIdentityDetail>, NhiApiError> {
    let tenant_uuid = *tenant_id.as_uuid();

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
