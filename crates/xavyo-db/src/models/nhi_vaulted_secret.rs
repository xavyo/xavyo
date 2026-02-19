//! Database model for NHI vaulted secrets.
//!
//! Secrets are encrypted at rest with AES-256-GCM. Only metadata
//! (name, type, injection config) is stored in plaintext.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// An encrypted secret bound to an NHI identity.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct NhiVaultedSecret {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub nhi_id: Uuid,
    pub name: String,
    pub secret_type: String,
    pub description: Option<String>,
    #[serde(skip_serializing)]
    pub encrypted_value: Vec<u8>,
    #[serde(skip_serializing)]
    pub encryption_nonce: Vec<u8>,
    #[serde(skip_serializing)]
    pub encryption_key_id: String,
    pub inject_as: Option<String>,
    pub inject_format: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_rotated_at: Option<DateTime<Utc>>,
    pub rotation_interval_days: Option<i32>,
    pub max_lease_duration_secs: i32,
    pub max_concurrent_leases: i32,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Metadata-only view of a vaulted secret (no encrypted data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub id: Uuid,
    pub nhi_id: Uuid,
    pub name: String,
    pub secret_type: String,
    pub description: Option<String>,
    pub inject_as: Option<String>,
    pub inject_format: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_rotated_at: Option<DateTime<Utc>>,
    pub rotation_interval_days: Option<i32>,
    pub max_lease_duration_secs: i32,
    pub max_concurrent_leases: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<NhiVaultedSecret> for SecretMetadata {
    fn from(s: NhiVaultedSecret) -> Self {
        Self {
            id: s.id,
            nhi_id: s.nhi_id,
            name: s.name,
            secret_type: s.secret_type,
            description: s.description,
            inject_as: s.inject_as,
            inject_format: s.inject_format,
            expires_at: s.expires_at,
            last_rotated_at: s.last_rotated_at,
            rotation_interval_days: s.rotation_interval_days,
            max_lease_duration_secs: s.max_lease_duration_secs,
            max_concurrent_leases: s.max_concurrent_leases,
            created_at: s.created_at,
            updated_at: s.updated_at,
        }
    }
}

/// Parameters for creating a new vaulted secret.
pub struct CreateVaultedSecret {
    pub nhi_id: Uuid,
    pub name: String,
    pub secret_type: String,
    pub description: Option<String>,
    pub encrypted_value: Vec<u8>,
    pub encryption_nonce: Vec<u8>,
    pub encryption_key_id: String,
    pub inject_as: Option<String>,
    pub inject_format: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub rotation_interval_days: Option<i32>,
    pub max_lease_duration_secs: Option<i32>,
    pub max_concurrent_leases: Option<i32>,
    pub created_by: Option<Uuid>,
}

impl NhiVaultedSecret {
    /// Insert a new vaulted secret.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        params: CreateVaultedSecret,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO nhi_vaulted_secrets (
                tenant_id, nhi_id, name, secret_type, description,
                encrypted_value, encryption_nonce, encryption_key_id,
                inject_as, inject_format,
                expires_at, rotation_interval_days,
                max_lease_duration_secs, max_concurrent_leases,
                created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(params.nhi_id)
        .bind(&params.name)
        .bind(&params.secret_type)
        .bind(&params.description)
        .bind(&params.encrypted_value)
        .bind(&params.encryption_nonce)
        .bind(&params.encryption_key_id)
        .bind(&params.inject_as)
        .bind(&params.inject_format)
        .bind(params.expires_at)
        .bind(params.rotation_interval_days)
        .bind(params.max_lease_duration_secs.unwrap_or(3600))
        .bind(params.max_concurrent_leases.unwrap_or(5))
        .bind(params.created_by)
        .fetch_one(pool)
        .await
    }

    /// List secrets for an NHI identity (metadata only — no encrypted values exposed).
    pub async fn list_for_nhi(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            "SELECT * FROM nhi_vaulted_secrets WHERE tenant_id = $1 AND nhi_id = $2 ORDER BY name",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .fetch_all(pool)
        .await
    }

    /// Get a single secret by ID (includes encrypted data for decryption).
    pub async fn get_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        secret_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as("SELECT * FROM nhi_vaulted_secrets WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(secret_id)
            .fetch_optional(pool)
            .await
    }

    /// Rotate a secret's encrypted value.
    pub async fn rotate(
        pool: &PgPool,
        tenant_id: Uuid,
        secret_id: Uuid,
        encrypted_value: &[u8],
        encryption_nonce: &[u8],
        encryption_key_id: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE nhi_vaulted_secrets
            SET encrypted_value = $3,
                encryption_nonce = $4,
                encryption_key_id = $5,
                last_rotated_at = NOW(),
                updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(secret_id)
        .bind(encrypted_value)
        .bind(encryption_nonce)
        .bind(encryption_key_id)
        .fetch_optional(pool)
        .await
    }

    /// Delete a secret by ID.
    pub async fn delete(
        pool: &PgPool,
        tenant_id: Uuid,
        secret_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result =
            sqlx::query("DELETE FROM nhi_vaulted_secrets WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(secret_id)
                .execute(pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }
}
