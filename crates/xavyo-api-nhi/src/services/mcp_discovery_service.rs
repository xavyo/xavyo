//! MCP tool discovery service for AgentGateway integration.
//!
//! Implements the MCP StreamableHTTP client protocol to discover tools
//! from one or more AgentGateway instances and import them as NHI tool records.
//!
//! Supports multi-tenant gateway configurations: each tenant can store its own
//! `agentgateway_configs` in the `tenants.settings` JSONB column, falling back
//! to a system-level gateway URL set via `AGENTGATEWAY_MCP_URL`.

use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::sync::Semaphore;
use uuid::Uuid;
use xavyo_core::TenantId;
use xavyo_db::set_tenant_context;
use xavyo_nhi::{NhiLifecycleState, NhiType};

/// Maximum number of tools that can be imported in a single request.
pub const MAX_IMPORT_BATCH_SIZE: usize = 100;

/// Maximum allowed size (bytes) for a single tool's `input_schema` JSON.
const MAX_SCHEMA_SIZE_BYTES: usize = 256 * 1024; // 256 KiB

/// Maximum allowed length for a tool name.
const MAX_TOOL_NAME_LEN: usize = 255;

/// Maximum allowed length for a tool description.
const MAX_TOOL_DESCRIPTION_LEN: usize = 4096;

/// Maximum allowed size (bytes) for the raw SSE/JSON response body from AgentGateway.
const MAX_RESPONSE_BODY_BYTES: usize = 10 * 1024 * 1024; // 10 MiB

/// Maximum allowed length for a gateway name in tenant config.
const MAX_GATEWAY_NAME_LEN: usize = 128;

/// Maximum allowed length for an MCP session ID header value.
const MAX_SESSION_ID_LEN: usize = 512;

/// Maximum concurrent MCP discovery operations across all tenants.
const MAX_CONCURRENT_DISCOVERIES: usize = 3;

/// A named AgentGateway endpoint (internal — contains URL).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Human-readable gateway name (e.g., "Production", "Staging").
    pub name: String,
    /// MCP StreamableHTTP endpoint URL (e.g., `http://gw:4000/mcp`).
    pub url: String,
}

/// Gateway info exposed to the browser (name only — no URL to prevent info leakage).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayInfo {
    pub name: String,
}

impl From<&GatewayConfig> for GatewayInfo {
    fn from(gw: &GatewayConfig) -> Self {
        Self {
            name: gw.name.clone(),
        }
    }
}

/// A tool discovered from AgentGateway via MCP protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredTool {
    /// Tool name (may be prefixed with server name, e.g. `everything_fetch`).
    pub name: String,
    /// Human-readable description.
    pub description: Option<String>,
    /// JSON Schema for the tool's input parameters.
    pub input_schema: serde_json::Value,
    /// Server name extracted from the tool name prefix (e.g. `everything`).
    pub server_name: Option<String>,
    /// Which gateway this tool was discovered from.
    pub gateway_name: Option<String>,
}

/// Result of importing a single discovered tool.
#[derive(Debug, Serialize, Deserialize)]
pub struct ImportResult {
    pub tool_name: String,
    pub nhi_id: Option<Uuid>,
    pub error: Option<String>,
}

/// Per-gateway error reported when discovery partially fails.
#[derive(Debug, Serialize, Deserialize)]
pub struct GatewayError {
    pub gateway_name: String,
    pub error: String,
}

/// Result of discovering tools from multiple gateways.
///
/// Contains partial results — some gateways may succeed while others fail.
pub struct DiscoveryResult {
    pub tools: Vec<DiscoveredTool>,
    pub errors: Vec<GatewayError>,
}

/// Response from the discovery endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct DiscoverToolsResponse {
    pub tools: Vec<DiscoveredTool>,
    /// Which gateways were queried (name-only, no URLs).
    pub gateways: Vec<GatewayInfo>,
    /// Per-gateway errors (non-fatal — other gateways may have succeeded).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<GatewayError>,
}

/// Response from the import endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct ImportToolsResponse {
    pub results: Vec<ImportResult>,
}

/// Request body for the import endpoint.
#[derive(Debug, Deserialize)]
pub struct ImportToolsRequest {
    pub tools: Vec<DiscoveredTool>,
}

/// Query parameters for the discovery endpoint.
#[derive(Debug, Deserialize)]
pub struct DiscoverToolsQuery {
    /// Optional gateway name filter. When set, only discover from that gateway.
    pub gateway_name: Option<String>,
}

/// Errors from MCP discovery operations.
#[derive(Debug, thiserror::Error)]
pub enum McpDiscoveryError {
    #[error("No AgentGateway configured (neither tenant settings nor system default)")]
    NotConfigured,

    #[error("Gateway not found: {0}")]
    GatewayNotFound(String),

    #[error("Invalid gateway URL: {0}")]
    InvalidUrl(String),

    #[error("Tool already exists: {0}")]
    AlreadyExists(String),

    #[error("MCP protocol error: {0}")]
    Protocol(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// MCP discovery service that communicates with AgentGateway.
///
/// Holds an optional system-level gateway URL (from `AGENTGATEWAY_MCP_URL`).
/// Per-tenant gateway configs are resolved at request time from the
/// `tenants.settings` JSONB column.
#[derive(Clone)]
pub struct McpDiscoveryService {
    system_gateway_url: Option<String>,
    http_client: reqwest::Client,
    /// Limits concurrent MCP discovery operations to prevent gateway DDoS.
    discovery_semaphore: Arc<Semaphore>,
}

// ── MCP JSON-RPC types ──────────────────────────────────────────────────

#[derive(Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    id: Option<u64>,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct JsonRpcResponse {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: Option<serde_json::Value>,
    result: Option<serde_json::Value>,
    error: Option<JsonRpcError>,
}

#[derive(Deserialize)]
struct JsonRpcError {
    #[allow(dead_code)]
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct McpTool {
    name: String,
    description: Option<String>,
    #[serde(rename = "inputSchema", default)]
    input_schema: serde_json::Value,
}

#[derive(Deserialize)]
struct ToolsListResult {
    tools: Vec<McpTool>,
}

impl McpDiscoveryService {
    /// Create a new MCP discovery service.
    ///
    /// `system_gateway_url` is the fallback URL used when a tenant has no
    /// per-tenant gateway configs in its settings.
    pub fn new(system_gateway_url: Option<String>) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            // C1: Disable automatic redirects to prevent SSRF bypass.
            // A malicious gateway could redirect to internal IPs (e.g. cloud metadata)
            // after the initial URL validation passes on the external address.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build HTTP client");
        Self {
            system_gateway_url,
            http_client,
            discovery_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_DISCOVERIES)),
        }
    }

    /// Resolve the list of gateways for a tenant.
    ///
    /// Resolution order:
    /// 1. Read `settings->'agentgateway_configs'` from the `tenants` table.
    /// 2. If empty/absent, fall back to the system-level gateway URL.
    /// 3. If `gateway_name` is provided, filter to that single gateway.
    /// 4. Error if nothing is configured.
    pub async fn resolve_gateways(
        &self,
        pool: &PgPool,
        tenant_id: Uuid,
        gateway_name: Option<&str>,
    ) -> Result<Vec<GatewayConfig>, McpDiscoveryError> {
        // Try tenant-specific configs first
        let row: Option<(Option<serde_json::Value>,)> =
            sqlx::query_as("SELECT settings FROM tenants WHERE id = $1")
                .bind(tenant_id)
                .fetch_optional(pool)
                .await?;

        let mut gateways: Vec<GatewayConfig> = Vec::new();

        if let Some((Some(settings),)) = row {
            if let Some(configs) = settings.get("agentgateway_configs") {
                match serde_json::from_value::<Vec<GatewayConfig>>(configs.clone()) {
                    Ok(parsed) => gateways = parsed,
                    Err(e) => {
                        tracing::warn!(
                            tenant_id = %tenant_id,
                            error = %e,
                            "Malformed agentgateway_configs in tenant settings — falling back to system default"
                        );
                    }
                }
            }
        }

        // M4: Validate and sanitize gateway names from tenant-controlled JSONB
        gateways.retain(|g| {
            if g.name.is_empty() || g.name.len() > MAX_GATEWAY_NAME_LEN || g.url.is_empty() {
                tracing::warn!(
                    tenant_id = %tenant_id,
                    gateway_name = %g.name,
                    "Skipping gateway with invalid name or empty URL"
                );
                return false;
            }
            true
        });

        // Fall back to system gateway if no tenant configs
        if gateways.is_empty() {
            if let Some(ref url) = self.system_gateway_url {
                gateways.push(GatewayConfig {
                    name: "Default".to_string(),
                    url: url.clone(),
                });
            }
        }

        if gateways.is_empty() {
            return Err(McpDiscoveryError::NotConfigured);
        }

        // Filter by gateway name if requested
        if let Some(name) = gateway_name {
            gateways.retain(|g| g.name == name);
            if gateways.is_empty() {
                return Err(McpDiscoveryError::GatewayNotFound(format!(
                    "Gateway '{name}' not found in tenant configuration"
                )));
            }
        }

        Ok(gateways)
    }

    /// Discover tools from all provided gateways concurrently.
    ///
    /// Continues discovering from remaining gateways even if one fails,
    /// returning partial results + per-gateway errors.
    pub async fn discover_all(
        &self,
        gateways: &[GatewayConfig],
        admin_token: &str,
    ) -> DiscoveryResult {
        // E2: Acquire concurrency permit to prevent gateway DDoS.
        // This limits the total concurrent discovery operations across all tenants.
        let _permit = match self.discovery_semaphore.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                return DiscoveryResult {
                    tools: Vec::new(),
                    errors: vec![GatewayError {
                        gateway_name: "all".to_string(),
                        error: "Too many concurrent discovery operations. Please try again later."
                            .to_string(),
                    }],
                };
            }
        };

        let mut join_set = tokio::task::JoinSet::new();

        for gw in gateways {
            let svc = self.clone();
            let token = admin_token.to_string();
            let gw_name = gw.name.clone();
            let gw_url = gw.url.clone();
            join_set.spawn(async move {
                let result = svc.discover_tools(&gw_url, &token).await;
                (gw_name, result)
            });
        }

        let mut all_tools = Vec::new();
        let mut errors = Vec::new();

        while let Some(join_result) = join_set.join_next().await {
            match join_result {
                Ok((gw_name, Ok(tools))) => {
                    for mut tool in tools {
                        tool.gateway_name = Some(gw_name.clone());
                        all_tools.push(tool);
                    }
                }
                Ok((gw_name, Err(e))) => {
                    tracing::warn!(
                        gateway = %gw_name,
                        error = %e,
                        "Discovery failed for gateway"
                    );
                    errors.push(GatewayError {
                        gateway_name: gw_name,
                        error: e.to_string(),
                    });
                }
                Err(e) => {
                    tracing::error!(error = %e, "Discovery task panicked");
                    errors.push(GatewayError {
                        gateway_name: "unknown".to_string(),
                        error: format!("Internal error: {e}"),
                    });
                }
            }
        }

        DiscoveryResult {
            tools: all_tools,
            errors,
        }
    }

    /// Discover tools from a single AgentGateway via MCP StreamableHTTP protocol.
    ///
    /// Protocol flow:
    /// 1. POST `initialize` -> get session ID from `Mcp-Session-Id` header
    /// 2. POST `notifications/initialized` (no response expected)
    /// 3. POST `tools/list` -> parse SSE response for tool list
    /// 4. DELETE session (cleanup — always runs, even on error)
    pub async fn discover_tools(
        &self,
        gateway_url: &str,
        admin_token: &str,
    ) -> Result<Vec<DiscoveredTool>, McpDiscoveryError> {
        // SSRF protection: validate tenant-stored URLs (system URL is operator-trusted)
        let is_system_url = self.system_gateway_url.as_deref() == Some(gateway_url);
        if !is_system_url {
            validate_gateway_url(gateway_url).await?;
        }

        // Step 1: Initialize
        let init_request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: Some(1),
            method: "initialize".to_string(),
            params: Some(serde_json::json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": "xavyo-idp",
                    "version": env!("CARGO_PKG_VERSION")
                }
            })),
        };

        let init_response = self
            .http_client
            .post(gateway_url)
            .bearer_auth(admin_token)
            .header("Content-Type", "application/json")
            .header("Accept", "text/event-stream, application/json")
            .header("mcp-protocol-version", "2025-06-18")
            .json(&init_request)
            .send()
            .await?;

        if !init_response.status().is_success() {
            return Err(McpDiscoveryError::Protocol(format!(
                "Initialize failed with status {}",
                init_response.status()
            )));
        }

        // F2: Extract and validate session ID from response header
        let session_id = init_response
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| {
                if v.len() <= MAX_SESSION_ID_LEN && v.is_ascii() {
                    Some(v.to_string())
                } else {
                    tracing::warn!(
                        len = v.len(),
                        "MCP session ID exceeds max length or contains non-ASCII — ignoring"
                    );
                    None
                }
            });

        // C2: Limit init response body size (same protection as tools/list)
        let init_content_length = init_response.content_length().unwrap_or(0);
        if init_content_length > MAX_RESPONSE_BODY_BYTES as u64 {
            return Err(McpDiscoveryError::Protocol(format!(
                "Initialize response body too large ({init_content_length} bytes, max {MAX_RESPONSE_BODY_BYTES})"
            )));
        }
        let init_body = init_response.text().await?;
        if init_body.len() > MAX_RESPONSE_BODY_BYTES {
            return Err(McpDiscoveryError::Protocol(format!(
                "Initialize response body too large ({} bytes, max {MAX_RESPONSE_BODY_BYTES})",
                init_body.len()
            )));
        }
        // F1: Log only the size, not the full body (may contain sensitive data)
        tracing::debug!(
            body_len = init_body.len(),
            "MCP initialize response received"
        );

        // Run the rest inside a helper so we can always clean up the session
        let result = self
            .discover_tools_inner(gateway_url, admin_token, &session_id)
            .await;

        // Always cleanup session — even if inner steps failed
        if let Some(ref sid) = session_id {
            let _ = self
                .http_client
                .delete(gateway_url)
                .bearer_auth(admin_token)
                .header("mcp-session-id", sid)
                .header("mcp-protocol-version", "2025-06-18")
                .send()
                .await;
        }

        result
    }

    /// Inner discovery logic (steps 2-3) factored out so the caller can
    /// always run session cleanup regardless of success/failure.
    async fn discover_tools_inner(
        &self,
        gateway_url: &str,
        admin_token: &str,
        session_id: &Option<String>,
    ) -> Result<Vec<DiscoveredTool>, McpDiscoveryError> {
        // Step 2: Send initialized notification
        let notif_request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: None,
            method: "notifications/initialized".to_string(),
            params: None,
        };

        let mut notif_req = self
            .http_client
            .post(gateway_url)
            .bearer_auth(admin_token)
            .header("Content-Type", "application/json")
            .header("mcp-protocol-version", "2025-06-18")
            .json(&notif_request);

        if let Some(ref sid) = session_id {
            notif_req = notif_req.header("mcp-session-id", sid);
        }

        // E4: Check notification response — 200/204 are fine, 4xx may indicate auth failure
        let notif_resp = notif_req.send().await?;
        if notif_resp.status().is_client_error() {
            tracing::warn!(
                status = %notif_resp.status(),
                "MCP notifications/initialized returned client error — session may be invalid"
            );
        }

        // Step 3: List tools
        let tools_request = JsonRpcRequest {
            jsonrpc: "2.0",
            id: Some(2),
            method: "tools/list".to_string(),
            params: None,
        };

        let mut tools_req = self
            .http_client
            .post(gateway_url)
            .bearer_auth(admin_token)
            .header("Content-Type", "application/json")
            .header("Accept", "text/event-stream, application/json")
            .header("mcp-protocol-version", "2025-06-18")
            .json(&tools_request);

        if let Some(ref sid) = session_id {
            tools_req = tools_req.header("mcp-session-id", sid);
        }

        let tools_response = tools_req.send().await?;

        if !tools_response.status().is_success() {
            return Err(McpDiscoveryError::Protocol(format!(
                "tools/list failed with status {}",
                tools_response.status()
            )));
        }

        // M1: Limit response body size via incremental chunk reading.
        // This avoids allocating unbounded memory for chunked/SSE responses
        // where Content-Length is absent.
        let tools_body = read_body_limited(tools_response, MAX_RESPONSE_BODY_BYTES).await?;

        let tools = Self::parse_tools_response(&tools_body)?;

        // Convert to DiscoveredTool with server name extraction + validation
        let discovered: Vec<DiscoveredTool> = tools
            .into_iter()
            .map(|t| {
                let server_name = extract_server_name(&t.name);
                // E3: Use UTF-8 safe truncation to avoid panic on multi-byte boundaries
                let name = safe_truncate(&t.name, MAX_TOOL_NAME_LEN).to_string();
                let description = t.description.map(|d| {
                    if d.len() > MAX_TOOL_DESCRIPTION_LEN {
                        let truncated = safe_truncate(&d, MAX_TOOL_DESCRIPTION_LEN - 3);
                        format!("{truncated}...")
                    } else {
                        d
                    }
                });
                DiscoveredTool {
                    name,
                    description,
                    input_schema: t.input_schema,
                    server_name,
                    gateway_name: None,
                }
            })
            .collect();

        Ok(discovered)
    }

    /// Import a discovered tool as an NHI tool record.
    ///
    /// Validates input_schema size before inserting.
    /// Stores gateway provenance in the `tags` JSONB column so the UI
    /// can display which gateway the tool came from.
    pub async fn import_tool(
        &self,
        tool: &DiscoveredTool,
        tenant_id: Uuid,
        created_by: Uuid,
        pool: &PgPool,
    ) -> Result<Uuid, McpDiscoveryError> {
        // M2/M3: Validate tool name is not empty, and input_schema is a JSON object
        if tool.name.is_empty() {
            return Err(McpDiscoveryError::Protocol(
                "Tool name must not be empty".into(),
            ));
        }
        if !tool.input_schema.is_object() && !tool.input_schema.is_null() {
            return Err(McpDiscoveryError::Protocol(format!(
                "Tool '{}' input_schema must be a JSON object, got {}",
                tool.name,
                match &tool.input_schema {
                    serde_json::Value::Array(_) => "array",
                    serde_json::Value::String(_) => "string",
                    serde_json::Value::Number(_) => "number",
                    serde_json::Value::Bool(_) => "boolean",
                    _ => "unknown",
                }
            )));
        }

        // Validate input_schema size
        let schema_size = serde_json::to_string(&tool.input_schema)
            .map(|s| s.len())
            .unwrap_or(0);
        if schema_size > MAX_SCHEMA_SIZE_BYTES {
            return Err(McpDiscoveryError::Protocol(format!(
                "Tool '{}' input_schema exceeds maximum size ({schema_size} > {MAX_SCHEMA_SIZE_BYTES} bytes)",
                tool.name
            )));
        }

        let mut tx = pool.begin().await?;

        // Set RLS tenant context for the transaction
        set_tenant_context(&mut *tx, TenantId::from_uuid(tenant_id))
            .await
            .map_err(|e| McpDiscoveryError::Database(sqlx::Error::Protocol(e.to_string())))?;

        // Insert base NHI identity
        let identity_id: Uuid = sqlx::query_scalar(
            r"
            INSERT INTO nhi_identities (
                tenant_id, nhi_type, name, description, created_by, lifecycle_state
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            ",
        )
        .bind(tenant_id)
        .bind(NhiType::Tool)
        .bind(&tool.name)
        .bind(&tool.description)
        .bind(created_by)
        .bind(NhiLifecycleState::Active)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint() == Some("nhi_identities_tenant_type_name_unique") {
                    return McpDiscoveryError::AlreadyExists(format!(
                        "Tool '{}' already exists",
                        tool.name
                    ));
                }
            }
            McpDiscoveryError::Database(e)
        })?;

        // Compute checksum of the input_schema for freshness tracking
        let schema_json = serde_json::to_string(&tool.input_schema).unwrap_or_default();
        let checksum = schema_checksum(schema_json.as_bytes());

        // Build discovery_source from gateway/server info
        let discovery_source = tool
            .gateway_name
            .as_deref()
            .map(|gw| format!("mcp:{gw}"))
            .or_else(|| tool.server_name.as_deref().map(|s| format!("mcp:{s}")));

        // Insert tool extension with freshness fields
        sqlx::query(
            r"
            INSERT INTO nhi_tools (
                nhi_id, category, input_schema, provider, provider_verified,
                checksum, last_discovered_at, discovery_source
            )
            VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7)
            ",
        )
        .bind(identity_id)
        .bind("mcp")
        .bind(&tool.input_schema)
        .bind(&tool.server_name)
        .bind(false)
        .bind(&checksum)
        .bind(&discovery_source)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(identity_id)
    }

    /// Bulk import multiple discovered tools.
    pub async fn import_tools(
        &self,
        tools: &[DiscoveredTool],
        tenant_id: Uuid,
        created_by: Uuid,
        pool: &PgPool,
    ) -> Vec<ImportResult> {
        let mut results = Vec::with_capacity(tools.len());
        for tool in tools {
            match self.import_tool(tool, tenant_id, created_by, pool).await {
                Ok(nhi_id) => results.push(ImportResult {
                    tool_name: tool.name.clone(),
                    nhi_id: Some(nhi_id),
                    error: None,
                }),
                Err(e) => results.push(ImportResult {
                    tool_name: tool.name.clone(),
                    nhi_id: None,
                    error: Some(e.to_string()),
                }),
            }
        }
        results
    }

    /// Parse tools/list response -- handles both SSE and direct JSON formats.
    fn parse_tools_response(body: &str) -> Result<Vec<McpTool>, McpDiscoveryError> {
        // Try direct JSON first
        if let Ok(rpc) = serde_json::from_str::<JsonRpcResponse>(body) {
            return Self::extract_tools_from_rpc(rpc);
        }

        // Parse as SSE: look for `data: ` lines containing JSON-RPC
        for line in body.lines() {
            let line = line.trim();
            if let Some(data) = line.strip_prefix("data: ") {
                if let Ok(rpc) = serde_json::from_str::<JsonRpcResponse>(data) {
                    if let Ok(tools) = Self::extract_tools_from_rpc(rpc) {
                        return Ok(tools);
                    }
                }
            }
        }

        Err(McpDiscoveryError::Protocol(
            "No valid tools/list response found in SSE stream".to_string(),
        ))
    }

    fn extract_tools_from_rpc(rpc: JsonRpcResponse) -> Result<Vec<McpTool>, McpDiscoveryError> {
        if let Some(error) = rpc.error {
            return Err(McpDiscoveryError::Protocol(error.message));
        }
        let result = rpc.result.ok_or_else(|| {
            McpDiscoveryError::Protocol("No result in tools/list response".into())
        })?;
        let tools_result: ToolsListResult = serde_json::from_value(result)?;
        Ok(tools_result.tools)
    }
}

/// Query parameters for the sync-check endpoint.
#[derive(Debug, Deserialize)]
pub struct SyncCheckQuery {
    pub gateway_name: Option<String>,
}

/// A tool that has changed between NHI and the gateway.
#[derive(Debug, Serialize)]
pub struct ChangedTool {
    pub name: String,
    pub nhi_id: Uuid,
    pub old_checksum: Option<String>,
    pub new_checksum: String,
}

/// Result of comparing NHI tool records against live gateway discovery.
#[derive(Debug, Serialize)]
pub struct SyncCheckResult {
    /// Tools whose checksum matches the stored NHI record.
    pub up_to_date: Vec<String>,
    /// Tools whose input_schema has changed since last import.
    pub changed: Vec<ChangedTool>,
    /// Tools present in the gateway but not in NHI.
    pub new_tools: Vec<String>,
    /// Tools present in NHI (from this gateway) but no longer in the gateway.
    pub removed: Vec<String>,
}

impl McpDiscoveryService {
    /// Compare live gateway tools against stored NHI records.
    ///
    /// Discovers tools from the gateway, computes checksums, and compares with
    /// existing `nhi_tools` records that have `category = 'mcp'`.
    pub async fn sync_check(
        &self,
        pool: &PgPool,
        tenant_id: Uuid,
        admin_token: &str,
        gateway_name: Option<&str>,
    ) -> Result<SyncCheckResult, McpDiscoveryError> {
        // 1. Resolve gateways and discover tools
        let gateways = self.resolve_gateways(pool, tenant_id, gateway_name).await?;
        let discovery = self.discover_all(&gateways, admin_token).await;

        if !discovery.errors.is_empty() && discovery.tools.is_empty() {
            return Err(McpDiscoveryError::Protocol(
                discovery
                    .errors
                    .into_iter()
                    .map(|e| e.error)
                    .collect::<Vec<_>>()
                    .join("; "),
            ));
        }

        // 2. Load existing MCP tools from the DB.
        //    When gateway_name is provided, filter by discovery_source so that
        //    tools from other gateways don't incorrectly show as "removed".
        let discovery_source_filter = gateway_name.map(|gw| format!("mcp:{gw}"));

        let existing: Vec<(Uuid, String, Option<String>, Option<String>)> =
            if let Some(ref source) = discovery_source_filter {
                sqlx::query_as(
                    r"
                SELECT i.id, i.name, t.checksum, t.discovery_source
                FROM nhi_identities i
                INNER JOIN nhi_tools t ON t.nhi_id = i.id
                WHERE i.tenant_id = $1
                  AND t.category = 'mcp'
                  AND t.discovery_source = $2
                ",
                )
                .bind(tenant_id)
                .bind(source)
                .fetch_all(pool)
                .await?
            } else {
                sqlx::query_as(
                    r"
                SELECT i.id, i.name, t.checksum, t.discovery_source
                FROM nhi_identities i
                INNER JOIN nhi_tools t ON t.nhi_id = i.id
                WHERE i.tenant_id = $1
                  AND t.category = 'mcp'
                ",
                )
                .bind(tenant_id)
                .fetch_all(pool)
                .await?
            };

        let mut existing_map: std::collections::HashMap<String, (Uuid, Option<String>)> = existing
            .into_iter()
            .map(|(id, name, checksum, _source)| (name, (id, checksum)))
            .collect();

        // 3. Compare
        let mut up_to_date = Vec::new();
        let mut changed = Vec::new();
        let mut new_tools = Vec::new();

        for tool in &discovery.tools {
            let schema_json = serde_json::to_string(&tool.input_schema).unwrap_or_default();
            let new_checksum = schema_checksum(schema_json.as_bytes());

            if let Some((nhi_id, old_checksum)) = existing_map.remove(&tool.name) {
                if old_checksum.as_deref() == Some(&new_checksum) {
                    up_to_date.push(tool.name.clone());
                } else {
                    changed.push(ChangedTool {
                        name: tool.name.clone(),
                        nhi_id,
                        old_checksum,
                        new_checksum,
                    });
                }
            } else {
                new_tools.push(tool.name.clone());
            }
        }

        // 4. Remaining entries in existing_map are NHI tools not found in gateway
        let removed: Vec<String> = existing_map.into_keys().collect();

        Ok(SyncCheckResult {
            up_to_date,
            changed,
            new_tools,
            removed,
        })
    }
}

/// Compute a SHA-256 hex digest for schema checksum comparison.
///
/// SHA-256 is deterministic and stable across Rust versions, unlike
/// `DefaultHasher` (SipHash) which has no cross-version stability guarantee.
fn schema_checksum(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    format!("{hash:x}")
}

/// Extract server name from a tool name by splitting on the first underscore.
///
/// AgentGateway prefixes tool names with the MCP server name (e.g., `everything_fetch`).
fn extract_server_name(tool_name: &str) -> Option<String> {
    tool_name.find('_').map(|pos| tool_name[..pos].to_string())
}

// ── Helper functions ────────────────────────────────────────────────────

/// Truncate a string at a UTF-8 char boundary to avoid panics.
///
/// Returns the original string if it fits within `max_len` bytes.
/// Otherwise returns the longest prefix that is <= `max_len` bytes
/// and ends on a valid character boundary.
fn safe_truncate(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        return s;
    }
    let mut end = max_len;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Read a response body incrementally up to `max_bytes`, aborting early
/// if the limit is exceeded. Prevents unbounded memory allocation from
/// chunked/SSE responses where Content-Length may be absent.
async fn read_body_limited(
    response: reqwest::Response,
    max_bytes: usize,
) -> Result<String, McpDiscoveryError> {
    // Fast-path: if Content-Length is known and too large, reject immediately
    if let Some(len) = response.content_length() {
        if len > max_bytes as u64 {
            return Err(McpDiscoveryError::Protocol(format!(
                "Response body too large ({len} bytes, max {max_bytes})"
            )));
        }
    }

    let mut body = Vec::with_capacity(std::cmp::min(
        response.content_length().unwrap_or(4096) as usize,
        max_bytes,
    ));
    let mut stream = response;
    while let Some(chunk) = stream.chunk().await? {
        if body.len() + chunk.len() > max_bytes {
            return Err(McpDiscoveryError::Protocol(format!(
                "Response body exceeded {max_bytes} byte limit during streaming"
            )));
        }
        body.extend_from_slice(&chunk);
    }

    String::from_utf8(body)
        .map_err(|e| McpDiscoveryError::Protocol(format!("Response body is not valid UTF-8: {e}")))
}

// ── SSRF protection ─────────────────────────────────────────────────────

/// Validate a gateway URL to prevent SSRF attacks on tenant-stored URLs.
///
/// Rejects:
/// - Non-HTTP(S) schemes
/// - IP literals in private/reserved ranges
/// - Hostnames that resolve to private IPs
async fn validate_gateway_url(url_str: &str) -> Result<(), McpDiscoveryError> {
    let parsed = url::Url::parse(url_str)
        .map_err(|e| McpDiscoveryError::InvalidUrl(format!("Invalid URL '{url_str}': {e}")))?;

    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(McpDiscoveryError::InvalidUrl(format!(
                "Unsupported scheme '{scheme}': only http and https are allowed"
            )));
        }
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| McpDiscoveryError::InvalidUrl("URL has no host".into()))?;

    // Check IP literals directly
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_ip(&ip) {
            return Err(McpDiscoveryError::InvalidUrl(
                "Gateway URL must not point to a private or reserved IP address".into(),
            ));
        }
        return Ok(());
    }

    // DNS-resolve hostnames and check all resolved IPs
    let port = parsed.port_or_known_default().unwrap_or(80);
    match tokio::net::lookup_host(format!("{host}:{port}")).await {
        Ok(addrs) => {
            let addrs: Vec<_> = addrs.collect();
            if addrs.is_empty() {
                return Err(McpDiscoveryError::InvalidUrl(format!(
                    "DNS resolution returned no addresses for '{host}'"
                )));
            }
            for addr in &addrs {
                if is_private_ip(&addr.ip()) {
                    return Err(McpDiscoveryError::InvalidUrl(format!(
                        "Gateway host '{host}' resolves to private IP {}",
                        addr.ip()
                    )));
                }
            }
        }
        Err(e) => {
            return Err(McpDiscoveryError::InvalidUrl(format!(
                "DNS resolution failed for '{host}': {e}"
            )));
        }
    }

    Ok(())
}

/// Check whether an IP address is in a private or reserved range.
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()        // 127.0.0.0/8
            || v4.is_private()      // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            || v4.is_link_local()   // 169.254.0.0/16 (includes AWS metadata 169.254.169.254)
            || v4.is_broadcast()    // 255.255.255.255
            || v4.is_unspecified()  // 0.0.0.0
            || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64) // 100.64.0.0/10 (CGNAT)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()        // ::1
            || v6.is_unspecified()  // ::
            || {
                let s = v6.segments();
                (s[0] & 0xfe00) == 0xfc00   // fc00::/7 (unique local)
                || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 (link-local)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_server_name() {
        assert_eq!(
            extract_server_name("everything_fetch"),
            Some("everything".to_string())
        );
        assert_eq!(
            extract_server_name("context7_resolve_library"),
            Some("context7".to_string())
        );
        assert_eq!(extract_server_name("standalone"), None);
    }

    #[test]
    fn test_parse_tools_direct_json() {
        let body = r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"everything_fetch","description":"Fetch a URL","inputSchema":{"type":"object","properties":{"url":{"type":"string"}}}}]}}"#;
        let tools = McpDiscoveryService::parse_tools_response(body).unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "everything_fetch");
    }

    #[test]
    fn test_parse_tools_sse_format() {
        let body = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"test_tool\",\"description\":\"A test\",\"inputSchema\":{}}]}}\n\n";
        let tools = McpDiscoveryService::parse_tools_response(body).unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "test_tool");
    }

    #[test]
    fn test_parse_tools_error_response() {
        let body =
            r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"Method not found"}}"#;
        let result = McpDiscoveryService::parse_tools_response(body);
        assert!(result.is_err());
    }

    #[test]
    fn test_safe_truncate_ascii() {
        assert_eq!(safe_truncate("hello", 10), "hello");
        assert_eq!(safe_truncate("hello", 5), "hello");
        assert_eq!(safe_truncate("hello", 3), "hel");
        assert_eq!(safe_truncate("hello", 0), "");
    }

    #[test]
    fn test_safe_truncate_multibyte() {
        // "cafe\u{0301}" = "café" — the é is 2 bytes (0xC3 0xA9)
        let s = "caf\u{00e9}!"; // 6 bytes: c(1) a(1) f(1) é(2) !(1)
        assert_eq!(safe_truncate(s, 10), s);
        assert_eq!(safe_truncate(s, 6), s);
        // Truncate at 5 — includes é (bytes 0..5)
        assert_eq!(safe_truncate(s, 5), "caf\u{00e9}");
        // Truncate at 4 — would split é, so back up to 3
        assert_eq!(safe_truncate(s, 4), "caf");
    }

    #[test]
    fn test_safe_truncate_emoji() {
        // 🦀 is 4 bytes
        let s = "hi🦀bye";
        assert_eq!(safe_truncate(s, 6), "hi🦀");
        assert_eq!(safe_truncate(s, 5), "hi"); // would split emoji, backs up
        assert_eq!(safe_truncate(s, 4), "hi"); // would split emoji, backs up
        assert_eq!(safe_truncate(s, 3), "hi"); // would split emoji, backs up
        assert_eq!(safe_truncate(s, 2), "hi");
    }

    #[test]
    fn test_new_with_none() {
        let svc = McpDiscoveryService::new(None);
        assert!(svc.system_gateway_url.is_none());
    }

    #[test]
    fn test_new_with_url() {
        let svc = McpDiscoveryService::new(Some("http://gw:4000/mcp".to_string()));
        assert_eq!(
            svc.system_gateway_url.as_deref(),
            Some("http://gw:4000/mcp")
        );
    }

    #[test]
    fn test_gateway_config_serde() {
        let gw = GatewayConfig {
            name: "Production".to_string(),
            url: "http://gw:4000/mcp".to_string(),
        };
        let json = serde_json::to_string(&gw).unwrap();
        let parsed: GatewayConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "Production");
        assert_eq!(parsed.url, "http://gw:4000/mcp");
    }

    #[test]
    fn test_gateway_info_from_config() {
        let gw = GatewayConfig {
            name: "Production".to_string(),
            url: "http://gw:4000/mcp".to_string(),
        };
        let info = GatewayInfo::from(&gw);
        assert_eq!(info.name, "Production");
        // Verify URL is not in GatewayInfo JSON
        let json = serde_json::to_string(&info).unwrap();
        assert!(!json.contains("gw:4000"));
    }

    // ── SSRF validation tests ───────────────────────────────────────────

    #[test]
    fn test_is_private_ip_v4() {
        use std::net::Ipv4Addr;
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            169, 254, 169, 254
        )))); // AWS metadata
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)))); // CGNAT

        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
    }

    #[test]
    fn test_is_private_ip_v6() {
        use std::net::Ipv6Addr;
        assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        // fc00::/7 (unique local)
        assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        ))));
        // fe80::/10 (link-local)
        assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));

        assert!(!is_private_ip(&IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[tokio::test]
    async fn test_validate_gateway_url_rejects_file_scheme() {
        let result = validate_gateway_url("file:///etc/passwd").await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Unsupported scheme"));
    }

    #[tokio::test]
    async fn test_validate_gateway_url_rejects_private_ip() {
        let result = validate_gateway_url("http://127.0.0.1:4000/mcp").await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("private"));
    }

    #[tokio::test]
    async fn test_validate_gateway_url_rejects_metadata_ip() {
        let result = validate_gateway_url("http://169.254.169.254/latest/meta-data/").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_gateway_url_rejects_private_ranges() {
        for url in &[
            "http://10.0.0.1:4000/mcp",
            "http://172.16.0.1:4000/mcp",
            "http://192.168.1.1:4000/mcp",
        ] {
            let result = validate_gateway_url(url).await;
            assert!(result.is_err(), "Expected rejection for {url}");
        }
    }

    #[test]
    fn test_discover_tools_response_omits_empty_errors() {
        let resp = DiscoverToolsResponse {
            tools: vec![],
            gateways: vec![],
            errors: vec![],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("errors"));
    }

    #[test]
    fn test_discover_tools_response_includes_errors() {
        let resp = DiscoverToolsResponse {
            tools: vec![],
            gateways: vec![],
            errors: vec![GatewayError {
                gateway_name: "Bad".into(),
                error: "timeout".into(),
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("errors"));
        assert!(json.contains("timeout"));
    }
}
