//! Identity Federation handlers for Workload Identity Federation (F121).
//!
//! Provides endpoints for:
//! - Cloud credential exchange (agent JWT → AWS/GCP/Azure credentials)
//! - Token verification (Kubernetes service account tokens)
//! - Identity audit trail queries

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiAgentsError;
use crate::providers::{CloudCredential, TokenValidation};
use crate::router::AgentsState;
use xavyo_auth::JwtClaims;
use xavyo_db::models::{CloudProviderType, IdentityAuditEventFilter, IdentityAuditOutcome};

/// Extract tenant_id from JWT claims.
fn extract_tenant_id(claims: &JwtClaims) -> Result<Uuid, ApiAgentsError> {
    claims
        .tenant_id()
        .map(|t| *t.as_uuid())
        .ok_or(ApiAgentsError::MissingTenant)
}

// ============================================================================
// Request/Response DTOs
// ============================================================================

/// Request for cloud credentials.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CloudCredentialRequest {
    /// Provider type (aws, gcp, azure).
    pub provider_type: CloudProviderType,
    /// Requested TTL in seconds (900-43200).
    #[serde(default = "default_ttl")]
    pub ttl_seconds: i32,
    /// Override scopes (if allowed by mapping).
    #[serde(default)]
    pub scopes: Vec<String>,
}

fn default_ttl() -> i32 {
    3600 // 1 hour
}

/// Response for cloud credentials.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CloudCredentialResponseDto {
    pub provider_type: CloudProviderType,
    #[serde(flatten)]
    pub credentials: CloudCredentialData,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub ttl_seconds: i32,
}

/// Cloud credential data (provider-specific).
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CloudCredentialData {
    /// AWS access key ID (if AWS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_key_id: Option<String>,
    /// AWS secret access key (if AWS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_access_key: Option<String>,
    /// AWS session token (if AWS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_token: Option<String>,
    /// AWS region (if AWS).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// OAuth2 access token (GCP, Azure, Kubernetes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    /// Token type (Bearer for OAuth2 tokens).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// Kubernetes namespace (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

impl From<&CloudCredential> for CloudCredentialData {
    fn from(cred: &CloudCredential) -> Self {
        match cred.credential_type.as_str() {
            "aws-sts" => CloudCredentialData {
                access_key_id: cred.access_key.clone(),
                secret_access_key: cred.secret_key.clone(),
                session_token: cred.session_token.clone(),
                region: cred.metadata.get("region").cloned(),
                access_token: None,
                token_type: None,
                namespace: None,
            },
            "gcp-access-token" | "azure-token" => CloudCredentialData {
                access_key_id: None,
                secret_access_key: None,
                session_token: None,
                region: None,
                access_token: cred.access_token.clone(),
                token_type: Some("Bearer".to_string()),
                namespace: None,
            },
            "kubernetes-token" => CloudCredentialData {
                access_key_id: None,
                secret_access_key: None,
                session_token: None,
                region: None,
                access_token: cred.access_token.clone(),
                token_type: Some("Bearer".to_string()),
                namespace: cred.metadata.get("namespace").cloned(),
            },
            _ => CloudCredentialData {
                access_key_id: cred.access_key.clone(),
                secret_access_key: cred.secret_key.clone(),
                session_token: cred.session_token.clone(),
                region: None,
                access_token: cred.access_token.clone(),
                token_type: Some("Bearer".to_string()),
                namespace: None,
            },
        }
    }
}

/// Request to verify an identity token.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VerifyTokenRequest {
    /// The token to verify (e.g., Kubernetes service account token).
    pub token: String,
    /// Expected audience (optional).
    pub expected_audience: Option<String>,
    /// Provider type hint (optional, for multi-provider tenants).
    pub provider_type: Option<CloudProviderType>,
}

/// Response for token verification.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct VerifyTokenResponse {
    pub verified: bool,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub agent_id: Option<Uuid>,
    pub claims: serde_json::Value,
    pub provider_config_id: Option<Uuid>,
    pub error: Option<String>,
}

impl From<TokenValidation> for VerifyTokenResponse {
    fn from(validation: TokenValidation) -> Self {
        // Convert claims HashMap to serde_json::Value
        let claims_value =
            serde_json::to_value(&validation.claims).unwrap_or_else(|_| serde_json::json!({}));

        Self {
            verified: validation.valid,
            issuer: validation.issuer,
            subject: validation.subject,
            agent_id: None, // Token validation doesn't map to a specific agent
            claims: claims_value,
            provider_config_id: None, // Would need to be passed separately
            error: validation.error,
        }
    }
}

/// Query parameters for identity audit.
#[derive(Debug, Default, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::IntoParams))]
pub struct IdentityAuditQuery {
    /// Filter by event type.
    pub event_type: Option<String>,
    /// Filter by agent ID.
    pub agent_id: Option<Uuid>,
    /// Filter by provider type.
    pub provider_type: Option<CloudProviderType>,
    /// Filter by outcome.
    pub outcome: Option<String>,
    /// Start time filter.
    pub from: Option<chrono::DateTime<chrono::Utc>>,
    /// End time filter.
    pub to: Option<chrono::DateTime<chrono::Utc>>,
    /// Maximum results.
    #[serde(default = "default_limit")]
    pub limit: i64,
    /// Offset for pagination.
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    100
}

/// Response for identity audit query.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IdentityAuditResponse {
    pub events: Vec<IdentityAuditEventDto>,
    pub total: i64,
    pub has_more: bool,
}

/// Identity audit event DTO.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IdentityAuditEventDto {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub event_type: String,
    pub agent_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub provider_type: Option<String>,
    pub operation: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<Uuid>,
    pub details: serde_json::Value,
    pub outcome: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// ============================================================================
// Handlers
// ============================================================================

/// POST /agents/{agent_id}/cloud-credentials - Request cloud credentials for an agent.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/agents/{agent_id}/cloud-credentials",
    tag = "Identity Federation",
    operation_id = "requestCloudCredentials",
    params(
        ("agent_id" = Uuid, Path, description = "Agent ID")
    ),
    request_body = CloudCredentialRequest,
    responses(
        (status = 200, description = "Cloud credentials issued", body = CloudCredentialResponseDto),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "No role mapping found for agent type"),
        (status = 429, description = "Rate limit exceeded"),
        (status = 502, description = "Cloud provider error"),
        (status = 503, description = "Cloud provider unavailable")
    ),
    security(("bearerAuth" = []))
))]
pub async fn request_cloud_credentials(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Path(agent_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<CloudCredentialRequest>,
) -> Result<impl IntoResponse, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    // Get the agent to verify it exists and get its type
    let agent = state.agent_service.get(tenant_id, agent_id).await?;

    // Extract the raw JWT token from the Authorization header
    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(ApiAgentsError::MissingToken)?;

    // Request credentials through the federation service
    let response = state
        .identity_federation_service
        .request_credentials(
            tenant_id,
            agent_id,
            &agent.agent_type,
            request.provider_type,
            auth_header,
            request.ttl_seconds,
        )
        .await?;

    let expires_at = chrono::DateTime::from_timestamp(response.credential.expires_at, 0)
        .unwrap_or_else(chrono::Utc::now);

    let dto = CloudCredentialResponseDto {
        provider_type: request.provider_type,
        credentials: CloudCredentialData::from(&response.credential),
        expires_at,
        ttl_seconds: response.granted_ttl_seconds,
    };

    // Add rate limit headers
    let mut headers = HeaderMap::new();
    headers.insert("X-RateLimit-Remaining", "99".parse().unwrap()); // Placeholder
    headers.insert(
        "X-RateLimit-Reset",
        chrono::Utc::now().timestamp().to_string().parse().unwrap(),
    );

    Ok((StatusCode::OK, headers, Json(dto)))
}

/// POST /identity/verify-token - Verify an external identity token.
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    path = "/identity/verify-token",
    tag = "Identity Federation",
    operation_id = "verifyIdentityToken",
    request_body = VerifyTokenRequest,
    responses(
        (status = 200, description = "Token verified and identity mapped", body = VerifyTokenResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Token verification failed"),
        (status = 404, description = "No provider configured for issuer")
    ),
    security(("bearerAuth" = []))
))]
pub async fn verify_identity_token(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Json(request): Json<VerifyTokenRequest>,
) -> Result<Json<VerifyTokenResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    // Default to Kubernetes provider if not specified
    let provider_type = request
        .provider_type
        .unwrap_or(CloudProviderType::Kubernetes);

    let validation = state
        .identity_federation_service
        .verify_token(tenant_id, provider_type, &request.token)
        .await?;

    Ok(Json(VerifyTokenResponse::from(validation)))
}

/// GET /identity/audit - Query IAM audit events.
#[cfg_attr(feature = "openapi", utoipa::path(
    get,
    path = "/identity/audit",
    tag = "Audit",
    operation_id = "queryIdentityAudit",
    params(IdentityAuditQuery),
    responses(
        (status = 200, description = "Audit events", body = IdentityAuditResponse),
        (status = 401, description = "Authentication required")
    ),
    security(("bearerAuth" = []))
))]
pub async fn query_identity_audit(
    State(state): State<AgentsState>,
    Extension(claims): Extension<JwtClaims>,
    Query(query): Query<IdentityAuditQuery>,
) -> Result<Json<IdentityAuditResponse>, ApiAgentsError> {
    let tenant_id = extract_tenant_id(&claims)?;

    // Parse outcome filter
    let outcome = query.outcome.as_deref().and_then(|o| match o {
        "success" => Some(IdentityAuditOutcome::Success),
        "failure" => Some(IdentityAuditOutcome::Failure),
        _ => None,
    });

    let filter = IdentityAuditEventFilter {
        event_type: query.event_type,
        agent_id: query.agent_id,
        user_id: None,
        provider_type: query.provider_type.map(|pt| pt.to_string()),
        outcome,
        from: query.from,
        to: query.to,
        limit: Some(query.limit),
        offset: Some(query.offset),
    };

    let (events, total) = state
        .identity_audit_service
        .query_events(tenant_id, &filter)
        .await?;

    let events_dto: Vec<IdentityAuditEventDto> = events
        .into_iter()
        .map(|e| IdentityAuditEventDto {
            id: e.id,
            tenant_id: e.tenant_id,
            event_type: e.event_type,
            agent_id: e.agent_id,
            user_id: e.user_id,
            provider_type: e.provider_type,
            operation: e.operation,
            resource_type: e.resource_type,
            resource_id: e.resource_id,
            details: e.details,
            outcome: e.outcome,
            created_at: e.created_at,
        })
        .collect();

    let has_more = (query.offset + events_dto.len() as i64) < total;

    Ok(Json(IdentityAuditResponse {
        events: events_dto,
        total,
        has_more,
    }))
}
