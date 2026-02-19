//! Vault handlers for NHI secret and lease management.
//!
//! All endpoints require `admin` role.

use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;

use crate::error::NhiApiError;
use crate::services::vault_service::StoreSecretParams;
use crate::state::NhiState;

// ── Request Types ──────────────────────────────────────────

/// Request to store a new secret. Custom Debug impl to avoid logging the value.
#[derive(Deserialize)]
pub struct StoreSecretRequest {
    pub name: String,
    pub secret_type: Option<String>,
    pub value: String,
    pub description: Option<String>,
    pub inject_as: Option<String>,
    pub inject_format: Option<String>,
    #[serde(default)]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub rotation_interval_days: Option<i32>,
    pub max_lease_duration_secs: Option<i32>,
    pub max_concurrent_leases: Option<i32>,
}

impl std::fmt::Debug for StoreSecretRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoreSecretRequest")
            .field("name", &self.name)
            .field("secret_type", &self.secret_type)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Request to rotate a secret's value. Custom Debug to redact value.
#[derive(Deserialize)]
pub struct RotateSecretRequest {
    pub value: String,
}

impl std::fmt::Debug for RotateSecretRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotateSecretRequest")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateLeaseRequest {
    pub secret_id: Uuid,
    pub lessee_nhi_id: Uuid,
    pub lessee_type: Option<String>,
    pub duration_secs: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct RenewLeaseRequest {
    pub extend_secs: i64,
}

// ── Helpers ────────────────────────────────────────────────

fn get_vault(
    state: &NhiState,
) -> Result<&crate::services::vault_service::VaultService, NhiApiError> {
    state
        .vault_service
        .as_ref()
        .ok_or_else(|| NhiApiError::Internal("vault not configured".to_string()))
}

// ── Secret Handlers ────────────────────────────────────────

/// POST /nhi/{nhi_id}/vault/secrets
pub async fn store_secret_handler(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(nhi_id): Path<Uuid>,
    Json(body): Json<StoreSecretRequest>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let vault = get_vault(&state)?;

    if body.name.is_empty() {
        return Err(NhiApiError::BadRequest("name is required".to_string()));
    }
    if body.value.is_empty() {
        return Err(NhiApiError::BadRequest("value is required".to_string()));
    }

    let secret = vault
        .store_secret(
            &state.pool,
            *tenant_id.as_uuid(),
            StoreSecretParams {
                nhi_id,
                name: body.name,
                secret_type: body.secret_type.unwrap_or_else(|| "opaque".to_string()),
                plaintext_value: body.value.into_bytes(),
                description: body.description,
                inject_as: body.inject_as,
                inject_format: body.inject_format,
                expires_at: body.expires_at,
                rotation_interval_days: body.rotation_interval_days,
                max_lease_duration_secs: body.max_lease_duration_secs,
                max_concurrent_leases: body.max_concurrent_leases,
                created_by: Uuid::parse_str(&claims.sub).ok(),
            },
        )
        .await?;

    Ok((axum::http::StatusCode::CREATED, Json(secret)))
}

/// GET /nhi/{nhi_id}/vault/secrets
pub async fn list_secrets_handler(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(nhi_id): Path<Uuid>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let vault = get_vault(&state)?;
    let secrets = vault
        .list_secrets(&state.pool, *tenant_id.as_uuid(), nhi_id)
        .await?;
    Ok(Json(secrets))
}

/// DELETE /nhi/{nhi_id}/vault/secrets/{secret_id}
pub async fn delete_secret_handler(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path((nhi_id, secret_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let vault = get_vault(&state)?;
    let deleted = vault
        .delete_secret(&state.pool, *tenant_id.as_uuid(), nhi_id, secret_id)
        .await?;
    if !deleted {
        return Err(NhiApiError::NotFound);
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// POST /nhi/{nhi_id}/vault/secrets/{secret_id}/rotate
pub async fn rotate_secret_handler(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path((nhi_id, secret_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<RotateSecretRequest>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let vault = get_vault(&state)?;

    if body.value.is_empty() {
        return Err(NhiApiError::BadRequest("value is required".to_string()));
    }

    let secret = vault
        .rotate_secret(
            &state.pool,
            *tenant_id.as_uuid(),
            nhi_id,
            secret_id,
            body.value.into_bytes(),
        )
        .await?;
    Ok(Json(secret))
}

// ── Lease Handlers ─────────────────────────────────────────

/// POST /nhi/{nhi_id}/vault/leases
pub async fn create_lease_handler(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(nhi_id): Path<Uuid>,
    Json(body): Json<CreateLeaseRequest>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let vault = get_vault(&state)?;

    let lease = vault
        .create_lease(
            &state.pool,
            *tenant_id.as_uuid(),
            nhi_id,
            body.secret_id,
            body.lessee_nhi_id,
            body.lessee_type.unwrap_or_else(|| "agent".to_string()),
            body.duration_secs.unwrap_or(3600),
            Uuid::parse_str(&claims.sub).ok(),
        )
        .await?;

    Ok((axum::http::StatusCode::CREATED, Json(lease)))
}

/// GET /nhi/{nhi_id}/vault/leases
pub async fn list_leases_handler(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path(nhi_id): Path<Uuid>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let vault = get_vault(&state)?;
    let leases = vault
        .list_leases(&state.pool, *tenant_id.as_uuid(), nhi_id)
        .await?;
    Ok(Json(leases))
}

/// POST /nhi/{nhi_id}/vault/leases/{lease_id}/renew
pub async fn renew_lease_handler(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path((nhi_id, lease_id)): Path<(Uuid, Uuid)>,
    Json(body): Json<RenewLeaseRequest>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let vault = get_vault(&state)?;
    let lease = vault
        .renew_lease(
            &state.pool,
            *tenant_id.as_uuid(),
            nhi_id,
            lease_id,
            body.extend_secs,
        )
        .await?;
    Ok(Json(lease))
}

/// DELETE /nhi/{nhi_id}/vault/leases/{lease_id}
pub async fn revoke_lease_handler(
    State(state): State<NhiState>,
    Extension(tenant_id): Extension<TenantId>,
    Extension(claims): Extension<JwtClaims>,
    Path((nhi_id, lease_id)): Path<(Uuid, Uuid)>,
) -> Result<impl IntoResponse, NhiApiError> {
    if !claims.has_role("admin") {
        return Err(NhiApiError::Forbidden);
    }

    let vault = get_vault(&state)?;
    vault
        .revoke_lease(
            &state.pool,
            *tenant_id.as_uuid(),
            nhi_id,
            lease_id,
            "admin_revocation",
        )
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
