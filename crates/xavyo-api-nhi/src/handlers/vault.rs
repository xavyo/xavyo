//! Vault handlers for NHI secret and lease management.
//!
//! All endpoints require `admin` role.

use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use xavyo_auth::JwtClaims;
use xavyo_core::TenantId;
use xavyo_db::models::NhiSecretLease;

use crate::error::NhiApiError;
use crate::services::vault_service::StoreSecretParams;
use crate::state::NhiState;

// ── Request Types ──────────────────────────────────────────

/// Request to store a new secret. Custom Debug impl to avoid logging the value.
#[derive(Deserialize)]
pub struct StoreSecretRequest {
    pub name: String,
    pub secret_type: Option<String>,
    #[serde(alias = "secret_value")]
    pub value: String,
    pub description: Option<String>,
    pub inject_as: Option<String>,
    pub inject_format: Option<String>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
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
    #[serde(alias = "new_value")]
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
    #[serde(alias = "consumer_nhi_id")]
    pub lessee_nhi_id: Uuid,
    pub lessee_type: Option<String>,
    #[serde(alias = "ttl_seconds")]
    pub duration_secs: Option<i64>,
}

/// Lease GET/POST response with advertised docs aliases.
#[derive(Debug, Clone, Serialize)]
pub struct LeaseResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub secret_id: Uuid,
    pub lessee_nhi_id: Uuid,
    /// Advertised docs alias of `lessee_nhi_id`.
    pub consumer_nhi_id: Uuid,
    pub lessee_type: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub renewed_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub status: String,
    pub revocation_reason: Option<String>,
    pub issued_by: Option<Uuid>,
    pub source_ip: Option<String>,
}

impl From<NhiSecretLease> for LeaseResponse {
    fn from(lease: NhiSecretLease) -> Self {
        Self {
            id: lease.id,
            tenant_id: lease.tenant_id,
            secret_id: lease.secret_id,
            lessee_nhi_id: lease.lessee_nhi_id,
            consumer_nhi_id: lease.lessee_nhi_id,
            lessee_type: lease.lessee_type,
            issued_at: lease.issued_at,
            expires_at: lease.expires_at,
            renewed_at: lease.renewed_at,
            revoked_at: lease.revoked_at,
            status: lease.status,
            revocation_reason: lease.revocation_reason,
            issued_by: lease.issued_by,
            source_ip: lease.source_ip,
        }
    }
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
                created_by: Some(
                    Uuid::parse_str(&claims.sub)
                        .map_err(|_| NhiApiError::BadRequest("Invalid user ID".into()))?,
                ),
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
            Some(
                Uuid::parse_str(&claims.sub)
                    .map_err(|_| NhiApiError::BadRequest("Invalid user ID".into()))?,
            ),
        )
        .await?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(LeaseResponse::from(lease)),
    ))
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
    Ok(Json(
        leases
            .into_iter()
            .map(LeaseResponse::from)
            .collect::<Vec<_>>(),
    ))
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
    Ok(Json(LeaseResponse::from(lease)))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_mutations_do_not_drop_malformed_actor() {
        let src = include_str!("vault.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            !production.contains("Uuid::parse_str(&claims.sub).ok()"),
            "vault store/lease must refuse a malformed JWT sub"
        );
        assert!(
            production.contains("Invalid user ID"),
            "vault actor parse errors must be BadRequest"
        );
    }

    #[test]
    fn store_secret_accepts_advertised_secret_value_alias() {
        let req: StoreSecretRequest =
            serde_json::from_str(r#"{"name":"db","secret_value":"s3cret"}"#)
                .expect("secret_value alias");
        assert_eq!(req.value, "s3cret");
    }

    #[test]
    fn rotate_secret_accepts_advertised_new_value_alias() {
        let req: RotateSecretRequest =
            serde_json::from_str(r#"{"new_value":"rotated"}"#).expect("new_value alias");
        assert_eq!(req.value, "rotated");
    }

    #[test]
    fn create_lease_accepts_advertised_consumer_and_ttl_aliases() {
        let consumer = Uuid::new_v4();
        let secret = Uuid::new_v4();
        let json = format!(
            r#"{{"secret_id":"{secret}","consumer_nhi_id":"{consumer}","ttl_seconds":3600}}"#
        );
        let req: CreateLeaseRequest = serde_json::from_str(&json).expect("lease aliases");
        assert_eq!(req.lessee_nhi_id, consumer);
        assert_eq!(req.duration_secs, Some(3600));
    }

    #[test]
    fn lease_response_serializes_advertised_consumer_nhi_id() {
        let lessee = Uuid::new_v4();
        let now = Utc::now();
        let json = serde_json::to_string(&LeaseResponse {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            secret_id: Uuid::new_v4(),
            lessee_nhi_id: lessee,
            consumer_nhi_id: lessee,
            lessee_type: "agent".to_string(),
            issued_at: now,
            expires_at: now,
            renewed_at: None,
            revoked_at: None,
            status: "active".to_string(),
            revocation_reason: None,
            issued_by: None,
            source_ip: None,
        })
        .expect("serialize");
        assert!(json.contains(&format!("\"consumer_nhi_id\":\"{lessee}\"")));
        assert!(json.contains(&format!("\"lessee_nhi_id\":\"{lessee}\"")));
    }
}
