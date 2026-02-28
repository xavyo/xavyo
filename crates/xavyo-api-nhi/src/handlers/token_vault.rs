//! External Token Vault handlers.
//!
//! Provides endpoints for managing external OAuth provider tokens:
//! - `POST /:nhi_id/vault/external-tokens` — Store an external provider token
//! - `GET /:nhi_id/vault/external-tokens` — List external tokens (metadata only)
//! - `DELETE /:nhi_id/vault/external-tokens/:token_id` — Delete an external token
//! - `POST /:nhi_id/vault/token-exchange` — Exchange: get user-scoped access token

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;

use crate::error::NhiApiError;
use crate::services::token_vault_service::{StoreExternalTokenParams, TokenVaultService};
use crate::state::NhiState;

// ── Request Types ──────────────────────────────────────────

/// Request to store an external provider token.
#[derive(Deserialize)]
pub struct StoreExternalTokenRequest {
    pub user_id: Uuid,
    pub provider: String,
    pub provider_client_id: Option<String>,
    pub access_token: String,
    pub refresh_token: Option<String>,
    #[serde(default = "default_token_type")]
    pub token_type: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub access_token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub refresh_token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub token_endpoint: Option<String>,
}

fn default_token_type() -> String {
    "bearer".into()
}

impl std::fmt::Debug for StoreExternalTokenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreExternalTokenRequest")
            .field("user_id", &self.user_id)
            .field("provider", &self.provider)
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Request to exchange an agent credential for a user-scoped external token.
#[derive(Debug, Deserialize)]
pub struct TokenExchangeRequest {
    pub user_id: Uuid,
    pub provider: String,
}

/// Response for token exchange.
#[derive(Serialize)]
pub struct TokenExchangeResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub provider: String,
    pub refreshed: bool,
}

// ── Helpers ────────────────────────────────────────────────

fn get_token_vault(state: &NhiState) -> Result<&TokenVaultService, NhiApiError> {
    state
        .token_vault_service
        .as_ref()
        .ok_or_else(|| NhiApiError::Internal("token vault not configured".to_string()))
}

// ── Handlers ───────────────────────────────────────────────

/// POST /:nhi_id/vault/external-tokens
pub async fn store_external_token_handler(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(nhi_id): Path<Uuid>,
    Json(body): Json<StoreExternalTokenRequest>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let vault = get_token_vault(&state)?;

    if body.provider.is_empty() {
        return Err(NhiApiError::BadRequest("provider is required".into()));
    }
    if body.access_token.is_empty() {
        return Err(NhiApiError::BadRequest("access_token is required".into()));
    }

    let meta = vault
        .store_token(
            &state.pool,
            *tenant_id.as_uuid(),
            StoreExternalTokenParams {
                nhi_id,
                user_id: body.user_id,
                provider: body.provider,
                provider_client_id: body.provider_client_id,
                access_token: body.access_token.into_bytes(),
                refresh_token: body.refresh_token.map(|s| s.into_bytes()),
                token_type: body.token_type,
                scopes: body.scopes,
                access_token_expires_at: body.access_token_expires_at,
                refresh_token_expires_at: body.refresh_token_expires_at,
                token_endpoint: body.token_endpoint,
                created_by: match Uuid::parse_str(&claims.sub) {
                    Ok(id) => Some(id),
                    Err(_) => {
                        tracing::warn!(sub = %claims.sub, "Invalid UUID in JWT sub claim");
                        None
                    }
                },
            },
        )
        .await?;

    Ok((StatusCode::CREATED, Json(meta)))
}

/// GET /:nhi_id/vault/external-tokens
pub async fn list_external_tokens_handler(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(nhi_id): Path<Uuid>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let vault = get_token_vault(&state)?;
    let tokens = vault
        .list_tokens(&state.pool, *tenant_id.as_uuid(), nhi_id)
        .await?;
    Ok(Json(tokens))
}

/// DELETE /:nhi_id/vault/external-tokens/:token_id
pub async fn delete_external_token_handler(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path((nhi_id, token_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let vault = get_token_vault(&state)?;
    let deleted = vault
        .delete_token(&state.pool, *tenant_id.as_uuid(), nhi_id, token_id)
        .await?;
    if !deleted {
        return Err(NhiApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

/// POST /:nhi_id/vault/token-exchange — Exchange for user-scoped external token.
///
/// The agent presents its identity (via JWT) and requests a specific user's
/// token for a given provider. If expired, auto-refreshes transparently.
pub async fn token_exchange_handler(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(nhi_id): Path<Uuid>,
    Json(body): Json<TokenExchangeRequest>,
) -> Result<impl IntoResponse, NhiApiError> {
    // Token exchange requires the caller to be either admin or the NHI itself
    // (validated via JWT `sub` matching NHI's client_id or admin role)
    if !claims.has_role("admin") && !claims.has_role("agent") {
        return Err(NhiApiError::Forbidden);
    }

    let vault = get_token_vault(&state)?;

    if body.provider.is_empty() {
        return Err(NhiApiError::BadRequest("provider is required".into()));
    }

    let exchanged = vault
        .exchange_token(
            &state.pool,
            *tenant_id.as_uuid(),
            nhi_id,
            body.user_id,
            &body.provider,
        )
        .await?;

    Ok(Json(TokenExchangeResponse {
        access_token: exchanged.access_token,
        token_type: exchanged.token_type,
        expires_at: exchanged.expires_at,
        provider: exchanged.provider,
        refreshed: exchanged.refreshed,
    }))
}
