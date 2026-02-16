//! Composite provisioning handler for NHI agents.
//!
//! Provides a single endpoint to provision a fully-functional NHI agent:
//! - `POST /nhi/provision-agent` — Create NHI identity, agent extension,
//!   entitlement assignments, and optionally an OAuth client and delegation grant.

use std::collections::HashSet;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;
use xavyo_db::models::{
    gov_entitlement_assignment::GovEntitlementAssignment,
    nhi_delegation_grant::{CreateNhiDelegationGrant, NhiDelegationGrant},
    nhi_identity::NhiIdentity,
};
use xavyo_db::set_tenant_context;
use xavyo_nhi::NhiType;
use xavyo_api_oauth::models::{ClientType, CreateClientRequest};

use crate::error::NhiApiError;
use crate::state::NhiState;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

/// OAuth client configuration for provisioning.
#[derive(Debug, Deserialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProvisionOAuthClient {
    /// Human-readable client name. Defaults to `"{agent_name}-client"`.
    pub client_name: Option<String>,
    /// Allowed grant types. Defaults to `["client_credentials"]`.
    pub grant_types: Option<Vec<String>>,
    /// Allowed scopes. Defaults to `["openid", "profile"]`.
    pub scope: Option<String>,
}

/// Delegation configuration for provisioning.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProvisionDelegation {
    /// Whether delegation is enabled for this agent.
    #[serde(default)]
    pub enabled: bool,
    /// The principal (user) who delegates authority. Required if enabled.
    pub principal_id: Option<Uuid>,
    /// Allowed scopes for delegation. Empty = all scopes.
    #[serde(default)]
    pub allowed_scopes: Vec<String>,
    /// Allowed resource types. Empty = all resource types.
    #[serde(default)]
    pub allowed_resource_types: Vec<String>,
    /// Maximum delegation chain depth (1–5). Defaults to 1.
    pub max_delegation_depth: Option<i32>,
    /// When the delegation grant expires.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Request to provision an NHI agent.
#[derive(Debug, Deserialize, Validate)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProvisionAgentRequest {
    /// Agent name. Must be unique per tenant.
    #[validate(length(min = 1, max = 255))]
    pub name: String,

    /// NHI type. Defaults to `"agent"`.
    #[serde(default = "default_nhi_type")]
    pub nhi_type: String,

    /// Agent type (e.g., `"autonomous"`, `"delegated"`). Defaults to `"autonomous"`.
    #[serde(default = "default_agent_type")]
    pub agent_type: String,

    /// Model provider (e.g., `"anthropic"`, `"openai"`).
    pub model_provider: Option<String>,

    /// Model name (e.g., `"claude-sonnet-4-20250514"`).
    pub model_name: Option<String>,

    /// Whether the agent requires human approval for actions.
    #[serde(default)]
    pub requires_human_approval: bool,

    /// Max token lifetime in seconds. Defaults to 900 (15 min).
    #[serde(default = "default_max_token_lifetime")]
    pub max_token_lifetime_secs: i32,

    /// Optional description.
    pub description: Option<String>,

    /// Optional owner user ID.
    pub owner_id: Option<Uuid>,

    /// Entitlement names to assign to this agent.
    /// Each name must match an existing entitlement in the tenant.
    /// Maximum 50 entitlements per provisioning request.
    #[serde(default)]
    #[validate(length(max = 50))]
    pub entitlements: Vec<String>,

    /// OAuth client configuration. Omit to skip OAuth client creation.
    pub oauth_client: Option<ProvisionOAuthClient>,

    /// Delegation configuration. Defaults to disabled.
    pub delegation: Option<ProvisionDelegation>,
}

fn default_nhi_type() -> String {
    "agent".to_string()
}

fn default_agent_type() -> String {
    "autonomous".to_string()
}

fn default_max_token_lifetime() -> i32 {
    900
}

/// OAuth client details in provisioning response.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProvisionOAuthClientResponse {
    pub client_id: String,
    pub client_secret: Option<String>,
}

/// Provisioning response.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProvisionAgentResponse {
    /// The NHI identity ID.
    pub nhi_id: Uuid,
    /// The agent extension ID (same as nhi_id).
    pub agent_id: Uuid,
    /// OAuth client credentials (if requested).
    pub oauth_client: Option<ProvisionOAuthClientResponse>,
    /// IDs of created entitlement assignments.
    pub entitlement_assignments: Vec<Uuid>,
    /// Delegation grant ID (if delegation was enabled).
    pub delegation_grant_id: Option<Uuid>,
    /// Whether the agent is fully ready to use.
    /// `false` if OAuth client or delegation grant creation failed after the
    /// core resources (identity, agent, entitlements) were committed.
    pub ready: bool,
    /// Warnings about partial failures (e.g., OAuth client or delegation grant).
    /// Present only when `ready` is `false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// POST /nhi/provision-agent — Provision a fully-functional NHI agent.
///
/// Creates an NHI identity, agent extension, entitlement assignments,
/// and optionally an OAuth client and delegation grant in a single
/// transactional operation.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/nhi/provision-agent",
    tag = "NHI Provisioning",
    operation_id = "provisionNhiAgent",
    request_body = ProvisionAgentRequest,
    responses(
        (status = 201, description = "Agent provisioned successfully", body = ProvisionAgentResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Forbidden"),
        (status = 409, description = "Agent name already exists")
    ),
    security(("bearerAuth" = []))
))]
pub async fn provision_agent(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<ProvisionAgentRequest>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }
    request.validate()?;

    let tenant_uuid = *tenant_id.as_uuid();
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| NhiApiError::BadRequest("Invalid user ID".into()))?;

    // Resolve NHI type from string
    let nhi_type = match request.nhi_type.as_str() {
        "agent" => NhiType::Agent,
        "tool" => NhiType::Tool,
        "service_account" => NhiType::ServiceAccount,
        other => {
            return Err(NhiApiError::BadRequest(format!(
                "Invalid nhi_type: '{other}'. Must be 'agent', 'tool', or 'service_account'"
            )));
        }
    };

    // Deduplicate entitlement names (preserving order).
    let unique_entitlement_names: Vec<&String> = {
        let mut seen = HashSet::new();
        request
            .entitlements
            .iter()
            .filter(|name| seen.insert(name.as_str()))
            .collect()
    };

    // Pre-resolve entitlement names to IDs before starting the transaction.
    // We query entitlements by name across all applications in the tenant.
    // If a name matches multiple entitlements, the first match is used and a warning is logged.
    let mut entitlement_ids = Vec::new();
    for ent_name in &unique_entitlement_names {
        let eids: Vec<Uuid> = sqlx::query_scalar(
            r"
            SELECT id FROM gov_entitlements
            WHERE tenant_id = $1 AND name = $2 AND status = 'active'
            ORDER BY created_at ASC
            ",
        )
        .bind(tenant_uuid)
        .bind(ent_name)
        .fetch_all(&state.pool)
        .await
        .map_err(|e| {
            tracing::error!("Failed to look up entitlement '{}': {}", ent_name, e);
            NhiApiError::Internal("Failed to look up entitlement".into())
        })?;

        match eids.len() {
            0 => {
                return Err(NhiApiError::BadRequest(format!(
                    "Entitlement '{}' not found or inactive",
                    ent_name
                )));
            }
            1 => entitlement_ids.push(eids[0]),
            n => {
                tracing::warn!(
                    tenant_id = %tenant_uuid,
                    entitlement_name = %ent_name,
                    match_count = n,
                    selected_id = %eids[0],
                    "Ambiguous entitlement name matches multiple entitlements; using oldest"
                );
                entitlement_ids.push(eids[0]);
            }
        }
    }

    // --- Begin transaction ---
    let mut tx = state.pool.begin().await.map_err(|e| {
        tracing::error!("Failed to begin transaction: {e}");
        NhiApiError::Internal("Failed to begin transaction".into())
    })?;

    // Set tenant context for RLS enforcement
    set_tenant_context(&mut *tx, tenant_id).await.map_err(|e| {
        tracing::error!("Failed to set tenant context: {e}");
        NhiApiError::Internal("Failed to set tenant context".into())
    })?;

    // 1. Create NHI identity
    let identity: NhiIdentity = sqlx::query_as(
        r"
        INSERT INTO nhi_identities (
            tenant_id, nhi_type, name, description, owner_id, created_by
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
        ",
    )
    .bind(tenant_uuid)
    .bind(nhi_type)
    .bind(&request.name)
    .bind(&request.description)
    .bind(request.owner_id)
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

    let nhi_id = identity.id;

    // 2. Create agent extension
    sqlx::query(
        r"
        INSERT INTO nhi_agents (
            nhi_id, agent_type, model_provider, model_name,
            max_token_lifetime_secs, requires_human_approval
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        ",
    )
    .bind(nhi_id)
    .bind(&request.agent_type)
    .bind(&request.model_provider)
    .bind(&request.model_name)
    .bind(request.max_token_lifetime_secs)
    .bind(request.requires_human_approval)
    .execute(&mut *tx)
    .await?;

    // 3. Create entitlement assignments (target_type = 'nhi')
    let mut assignment_ids = Vec::new();
    for eid in &entitlement_ids {
        let assignment: GovEntitlementAssignment = sqlx::query_as(
            r"
            INSERT INTO gov_entitlement_assignments (
                tenant_id, entitlement_id, target_type, target_id, assigned_by
            )
            VALUES ($1, $2, 'nhi', $3, $4)
            RETURNING *
            ",
        )
        .bind(tenant_uuid)
        .bind(eid)
        .bind(nhi_id)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint() == Some("gov_assignments_unique_active") {
                    return NhiApiError::Conflict(format!(
                        "Entitlement assignment already exists for NHI {}",
                        nhi_id
                    ));
                }
            }
            NhiApiError::Database(e)
        })?;
        assignment_ids.push(assignment.id);
    }

    // Commit the core resources before creating the OAuth client
    // (OAuth client service manages its own connection/tenant context)
    tx.commit().await.map_err(|e| {
        tracing::error!("Failed to commit transaction: {e}");
        NhiApiError::Internal("Failed to commit transaction".into())
    })?;

    // 4. Create OAuth client (outside transaction — service manages its own connection)
    let mut oauth_response = None;
    let mut warnings: Vec<String> = Vec::new();
    if let Some(ref oauth_config) = request.oauth_client {
        let client_name = oauth_config
            .client_name
            .clone()
            .unwrap_or_else(|| format!("{}-client", request.name));

        let grant_types = oauth_config
            .grant_types
            .clone()
            .unwrap_or_else(|| vec!["client_credentials".to_string()]);

        let scopes: Vec<String> = oauth_config
            .scope
            .as_deref()
            .unwrap_or("openid profile")
            .split_whitespace()
            .map(String::from)
            .collect();

        let create_req = CreateClientRequest {
            name: client_name,
            client_type: ClientType::Confidential,
            redirect_uris: vec![],
            grant_types,
            scopes,
            logo_url: None,
            description: Some(format!("Auto-provisioned client for NHI agent '{}'", request.name)),
            nhi_id: Some(nhi_id),
        };

        match state
            .oauth_client_service
            .create_client(tenant_uuid, create_req)
            .await
        {
            Ok((client_resp, secret)) => {
                oauth_response = Some(ProvisionOAuthClientResponse {
                    client_id: client_resp.client_id,
                    client_secret: secret,
                });
            }
            Err(e) => {
                tracing::error!(nhi_id = %nhi_id, error = %e, "Failed to create OAuth client during provisioning");
                warnings.push("OAuth client creation failed".to_string());
            }
        }
    }

    // 5. Create delegation grant (if enabled)
    let mut delegation_grant_id = None;
    if let Some(ref deleg) = request.delegation {
        if deleg.enabled {
            let principal_id = deleg.principal_id.unwrap_or(user_id);

            match NhiDelegationGrant::grant(
                &state.pool,
                tenant_uuid,
                CreateNhiDelegationGrant {
                    principal_id,
                    principal_type: "user".to_string(),
                    actor_nhi_id: nhi_id,
                    allowed_scopes: deleg.allowed_scopes.clone(),
                    allowed_resource_types: deleg.allowed_resource_types.clone(),
                    max_delegation_depth: deleg.max_delegation_depth,
                    granted_by: Some(user_id),
                    expires_at: deleg.expires_at,
                },
            )
            .await
            {
                Ok(grant) => {
                    delegation_grant_id = Some(grant.id);
                }
                Err(e) => {
                    tracing::error!(nhi_id = %nhi_id, error = %e, "Failed to create delegation grant during provisioning");
                    warnings.push("Delegation grant creation failed".to_string());
                }
            }
        }
    }

    // Agent is "ready" only when all requested resources were created successfully.
    // OAuth client was requested but failed → not ready.
    // Delegation was requested but failed → not ready.
    let ready = warnings.is_empty();

    let response = ProvisionAgentResponse {
        nhi_id,
        agent_id: nhi_id,
        oauth_client: oauth_response,
        entitlement_assignments: assignment_ids,
        delegation_grant_id,
        ready,
        warnings: if warnings.is_empty() { None } else { Some(warnings) },
    };

    Ok((StatusCode::CREATED, Json(response)))
}
