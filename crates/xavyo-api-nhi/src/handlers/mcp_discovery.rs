//! MCP tool discovery and import handlers.
//!
//! Endpoints for discovering tools from AgentGateway via MCP protocol
//! and importing them as NHI tool records.
//!
//! - `GET /nhi/mcp-discovery/gateways` -- List resolved gateways for the tenant
//! - `GET /nhi/mcp-discovery/tools` -- Discover available MCP tools
//! - `POST /nhi/mcp-discovery/import` -- Import selected tools as NHI records

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;
use xavyo_db::{CreateGovNhiAuditEvent, GovNhiAuditEvent, NhiAuditEventType};

use crate::error::NhiApiError;
use crate::services::mcp_discovery_service::{
    DiscoverToolsQuery, DiscoverToolsResponse, GatewayInfo, ImportToolsRequest,
    ImportToolsResponse, McpDiscoveryError, SyncCheckQuery, MAX_IMPORT_BATCH_SIZE,
};
use crate::state::NhiState;

/// Extract the Bearer token from the Authorization header.
fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(String::from)
}

/// Map McpDiscoveryError to the appropriate NhiApiError HTTP response.
fn map_discovery_error(e: McpDiscoveryError) -> NhiApiError {
    match e {
        McpDiscoveryError::NotConfigured => NhiApiError::BadRequest(
            "No AgentGateway configured for this tenant. \
             Configure gateway URLs in tenant settings or set the AGENTGATEWAY_MCP_URL environment variable."
                .into(),
        ),
        McpDiscoveryError::GatewayNotFound(msg) => NhiApiError::BadRequest(msg),
        McpDiscoveryError::InvalidUrl(msg) => NhiApiError::BadRequest(msg),
        McpDiscoveryError::AlreadyExists(msg) => NhiApiError::Conflict(msg),
        McpDiscoveryError::Protocol(msg) => {
            NhiApiError::BadGateway(format!("MCP protocol error: {msg}"))
        }
        McpDiscoveryError::Http(e) => {
            NhiApiError::BadGateway(format!("Gateway connection failed: {e}"))
        }
        McpDiscoveryError::Json(e) => {
            NhiApiError::BadGateway(format!("Invalid gateway response: {e}"))
        }
        McpDiscoveryError::Database(e) => NhiApiError::Database(e),
    }
}

/// GET /nhi/mcp-discovery/gateways
///
/// List the resolved AgentGateway endpoints for the current tenant.
/// Returns gateway names only (no URLs exposed to the browser).
/// Requires `admin` role (which includes `super_admin`).
pub async fn list_gateways_handler(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();

    let gateways = state
        .mcp_discovery_service
        .resolve_gateways(&state.pool, tenant_uuid, None)
        .await
        .map_err(map_discovery_error)?;

    // Return name-only info (strip URLs)
    let infos: Vec<GatewayInfo> = gateways.iter().map(GatewayInfo::from).collect();

    Ok(Json(infos))
}

/// GET /nhi/mcp-discovery/tools
///
/// Discover available MCP tools from AgentGateway.
/// Requires `admin` role -- admin users bypass AgentGateway RBAC
/// and see all tools across all MCP targets.
///
/// Optional query parameter `gateway_name` filters to a single gateway.
pub async fn discover_tools_handler(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<DiscoverToolsQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();

    let token = extract_bearer_token(&headers)
        .ok_or_else(|| NhiApiError::BadRequest("No Bearer token in Authorization header".into()))?;

    let gateways = state
        .mcp_discovery_service
        .resolve_gateways(&state.pool, tenant_uuid, params.gateway_name.as_deref())
        .await
        .map_err(map_discovery_error)?;

    let gateway_infos: Vec<GatewayInfo> = gateways.iter().map(GatewayInfo::from).collect();

    let result = state
        .mcp_discovery_service
        .discover_all(&gateways, &token)
        .await;

    // E1: Audit log the discovery operation
    let user_id = Uuid::parse_str(&claims.sub).ok();
    tracing::info!(
        tenant_id = %tenant_uuid,
        actor_id = ?user_id,
        action = "mcp_discovery",
        tools_discovered = result.tools.len(),
        gateways_queried = gateway_infos.len(),
        errors = result.errors.len(),
        gateway_filter = ?params.gateway_name,
        "MCP tool discovery completed"
    );

    Ok(Json(DiscoverToolsResponse {
        tools: result.tools,
        gateways: gateway_infos,
        errors: result.errors,
    }))
}

/// POST /nhi/mcp-discovery/import
///
/// Import selected MCP tools as NHI tool records.
/// Requires `admin` role. Each tool is imported independently;
/// failures on individual tools don't block the batch.
pub async fn import_tools_handler(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Json(body): Json<ImportToolsRequest>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| NhiApiError::BadRequest("Invalid user ID".into()))?;

    if body.tools.is_empty() {
        return Err(NhiApiError::BadRequest("No tools provided".into()));
    }

    if body.tools.len() > MAX_IMPORT_BATCH_SIZE {
        return Err(NhiApiError::BadRequest(format!(
            "Too many tools in a single import ({}). Maximum is {MAX_IMPORT_BATCH_SIZE}.",
            body.tools.len()
        )));
    }

    // M2: Validate each tool in the request has a non-empty name
    for tool in &body.tools {
        if tool.name.trim().is_empty() {
            return Err(NhiApiError::BadRequest(
                "Each tool must have a non-empty name".into(),
            ));
        }
    }

    let results = state
        .mcp_discovery_service
        .import_tools(&body.tools, tenant_uuid, user_id, &state.pool)
        .await;

    // E1: Audit log each successfully imported tool
    let succeeded: Vec<_> = results.iter().filter(|r| r.nhi_id.is_some()).collect();
    let failed_count = results.iter().filter(|r| r.error.is_some()).count();

    for result in &succeeded {
        if let Some(nhi_id) = result.nhi_id {
            let audit_event = CreateGovNhiAuditEvent {
                nhi_id,
                event_type: NhiAuditEventType::Created,
                actor_id: Some(user_id),
                changes: None,
                metadata: Some(serde_json::json!({
                    "source": "mcp_discovery_import",
                    "tool_name": result.tool_name,
                })),
                source_ip: None,
            };
            if let Err(e) = GovNhiAuditEvent::create(&state.pool, tenant_uuid, audit_event).await {
                tracing::warn!(error = %e, nhi_id = %nhi_id, "Failed to create NHI audit event for imported tool");
            }
        }
    }

    // E1: Structured audit log for the batch operation
    tracing::info!(
        tenant_id = %tenant_uuid,
        actor_id = %user_id,
        action = "mcp_discovery_import",
        tools_requested = body.tools.len(),
        tools_imported = succeeded.len(),
        tools_failed = failed_count,
        "MCP tool import completed"
    );

    Ok((StatusCode::CREATED, Json(ImportToolsResponse { results })))
}

/// GET /nhi/mcp-discovery/sync-check
///
/// Compare live gateway tools against stored NHI records.
/// Returns which tools are up-to-date, changed, new, or removed.
/// Requires `admin` role and a Bearer token for gateway authentication.
pub async fn sync_check_handler(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Query(params): Query<SyncCheckQuery>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let tenant_uuid = *tenant_id.as_uuid();

    let token = extract_bearer_token(&headers)
        .ok_or_else(|| NhiApiError::BadRequest("No Bearer token in Authorization header".into()))?;

    let result = state
        .mcp_discovery_service
        .sync_check(
            &state.pool,
            tenant_uuid,
            &token,
            params.gateway_name.as_deref(),
        )
        .await
        .map_err(map_discovery_error)?;

    Ok(Json(result))
}
