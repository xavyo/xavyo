//! Vault service for managing encrypted NHI secrets and leases.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::Zeroize;

use super::vault_crypto::{VaultCrypto, VaultCryptoError};
use crate::error::NhiApiError;
use xavyo_db::models::{CreateVaultedSecret, NhiSecretLease, NhiVaultedSecret, SecretMetadata};

/// Parameters for storing a new vault secret.
#[derive(Debug)]
pub struct StoreSecretParams {
    pub nhi_id: Uuid,
    pub name: String,
    pub secret_type: String,
    pub plaintext_value: Vec<u8>,
    pub description: Option<String>,
    pub inject_as: Option<String>,
    pub inject_format: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub rotation_interval_days: Option<i32>,
    pub max_lease_duration_secs: Option<i32>,
    pub max_concurrent_leases: Option<i32>,
    pub created_by: Option<Uuid>,
}

/// Service for vault secret management and lease operations.
#[derive(Clone)]
pub struct VaultService {
    crypto: VaultCrypto,
}

impl VaultService {
    /// Create a new vault service with the given crypto backend.
    pub fn new(crypto: VaultCrypto) -> Self {
        Self { crypto }
    }

    // ── Secret Management ──────────────────────────────────────

    /// Store a new secret (encrypts the value before persisting).
    ///
    /// Validates that the NHI identity exists before inserting.
    pub async fn store_secret(
        &self,
        pool: &PgPool,
        tenant_id: Uuid,
        mut params: StoreSecretParams,
    ) -> Result<SecretMetadata, NhiApiError> {
        // Validate NHI exists
        Self::verify_nhi_exists(pool, tenant_id, params.nhi_id).await?;

        let (encrypted_value, encryption_nonce, encryption_key_id) = self
            .crypto
            .encrypt(&params.plaintext_value)
            .map_err(crypto_err)?;
        // Scrub plaintext from memory now that it's encrypted
        params.plaintext_value.zeroize();

        let secret = NhiVaultedSecret::create(
            pool,
            tenant_id,
            CreateVaultedSecret {
                nhi_id: params.nhi_id,
                name: params.name,
                secret_type: params.secret_type,
                description: params.description,
                encrypted_value,
                encryption_nonce,
                encryption_key_id,
                inject_as: params.inject_as,
                inject_format: params.inject_format,
                expires_at: params.expires_at,
                rotation_interval_days: params.rotation_interval_days,
                max_lease_duration_secs: params.max_lease_duration_secs,
                max_concurrent_leases: params.max_concurrent_leases,
                created_by: params.created_by,
            },
        )
        .await
        .map_err(NhiApiError::Database)?;

        Ok(SecretMetadata::from(secret))
    }

    /// List secrets for an NHI identity (metadata only, no values).
    pub async fn list_secrets(
        &self,
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<Vec<SecretMetadata>, NhiApiError> {
        let secrets = NhiVaultedSecret::list_for_nhi(pool, tenant_id, nhi_id)
            .await
            .map_err(NhiApiError::Database)?;
        Ok(secrets.into_iter().map(SecretMetadata::from).collect())
    }

    /// Rotate a secret's value (re-encrypts with new nonce).
    ///
    /// Verifies the secret belongs to the specified NHI identity.
    /// Takes ownership of the plaintext so it can be zeroized after encryption.
    pub async fn rotate_secret(
        &self,
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        secret_id: Uuid,
        mut new_plaintext: Vec<u8>,
    ) -> Result<SecretMetadata, NhiApiError> {
        // Verify ownership: secret must belong to this nhi_id
        let existing = NhiVaultedSecret::get_by_id(pool, tenant_id, secret_id)
            .await
            .map_err(NhiApiError::Database)?
            .ok_or(NhiApiError::NotFound)?;

        if existing.nhi_id != nhi_id {
            return Err(NhiApiError::NotFound);
        }

        let (encrypted_value, encryption_nonce, encryption_key_id) =
            self.crypto.encrypt(&new_plaintext).map_err(crypto_err)?;
        // Scrub plaintext from memory now that it's encrypted
        new_plaintext.zeroize();

        let secret = NhiVaultedSecret::rotate(
            pool,
            tenant_id,
            secret_id,
            &encrypted_value,
            &encryption_nonce,
            &encryption_key_id,
        )
        .await
        .map_err(NhiApiError::Database)?
        .ok_or(NhiApiError::NotFound)?;

        Ok(SecretMetadata::from(secret))
    }

    /// Delete a secret. Verifies the secret belongs to the specified NHI.
    pub async fn delete_secret(
        &self,
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        secret_id: Uuid,
    ) -> Result<bool, NhiApiError> {
        // Verify ownership
        let existing = NhiVaultedSecret::get_by_id(pool, tenant_id, secret_id)
            .await
            .map_err(NhiApiError::Database)?
            .ok_or(NhiApiError::NotFound)?;

        if existing.nhi_id != nhi_id {
            return Err(NhiApiError::NotFound);
        }

        NhiVaultedSecret::delete(pool, tenant_id, secret_id)
            .await
            .map_err(NhiApiError::Database)
    }

    // ── Lease Management ───────────────────────────────────────

    /// Create a lease (time-bounded access to a secret).
    ///
    /// Uses a transaction with SELECT FOR UPDATE to prevent TOCTOU races
    /// on the concurrent lease count check. Verifies the secret belongs
    /// to the specified NHI identity.
    pub async fn create_lease(
        &self,
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        secret_id: Uuid,
        lessee_nhi_id: Uuid,
        lessee_type: String,
        duration_secs: i64,
        issued_by: Option<Uuid>,
    ) -> Result<NhiSecretLease, NhiApiError> {
        let mut tx = pool.begin().await.map_err(NhiApiError::Database)?;

        // Lock the secret row to prevent concurrent lease race
        let secret: NhiVaultedSecret = sqlx::query_as(
            "SELECT * FROM nhi_vaulted_secrets WHERE tenant_id = $1 AND id = $2 FOR UPDATE",
        )
        .bind(tenant_id)
        .bind(secret_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(NhiApiError::Database)?
        .ok_or(NhiApiError::NotFound)?;

        // Verify the secret belongs to the NHI from the URL path
        if secret.nhi_id != nhi_id {
            return Err(NhiApiError::NotFound);
        }

        // Validate: duration within limits
        if duration_secs <= 0 {
            return Err(NhiApiError::BadRequest(
                "duration_secs must be positive".to_string(),
            ));
        }
        if duration_secs > i64::from(secret.max_lease_duration_secs) {
            return Err(NhiApiError::BadRequest(format!(
                "requested duration {}s exceeds max {}s",
                duration_secs, secret.max_lease_duration_secs
            )));
        }

        // Count active leases within the transaction (race-safe)
        let (active_count,): (i64,) = sqlx::query_as(
            r"
            SELECT COUNT(*) FROM nhi_secret_leases
            WHERE tenant_id = $1 AND secret_id = $2 AND status = 'active' AND expires_at > NOW()
            ",
        )
        .bind(tenant_id)
        .bind(secret_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(NhiApiError::Database)?;

        if active_count >= i64::from(secret.max_concurrent_leases) {
            return Err(NhiApiError::Conflict(format!(
                "max concurrent leases ({}) reached",
                secret.max_concurrent_leases
            )));
        }

        // Insert the lease within the same transaction
        let sql = r"
            INSERT INTO nhi_secret_leases (
                tenant_id, secret_id, lessee_nhi_id, lessee_type,
                expires_at, issued_by
            )
            VALUES ($1, $2, $3, $4, NOW() + ($5 || ' seconds')::interval, $6)
            RETURNING
                id, tenant_id, secret_id, lessee_nhi_id, lessee_type,
                issued_at, expires_at, renewed_at, revoked_at,
                status, revocation_reason, issued_by, source_ip::text AS source_ip
        ";
        let lease: NhiSecretLease = sqlx::query_as(sql)
            .bind(tenant_id)
            .bind(secret_id)
            .bind(lessee_nhi_id)
            .bind(&lessee_type)
            .bind(duration_secs.to_string())
            .bind(issued_by)
            .fetch_one(&mut *tx)
            .await
            .map_err(NhiApiError::Database)?;

        tx.commit().await.map_err(NhiApiError::Database)?;

        Ok(lease)
    }

    /// List active leases for an NHI's secrets.
    pub async fn list_leases(
        &self,
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<Vec<NhiSecretLease>, NhiApiError> {
        NhiSecretLease::list_for_nhi(pool, tenant_id, nhi_id)
            .await
            .map_err(NhiApiError::Database)
    }

    /// Renew a lease by extending its expiry.
    ///
    /// Validates that the new expiry doesn't exceed `max_lease_duration_secs`
    /// from NOW (prevents unbounded lease extensions). Verifies the lease's
    /// secret belongs to the specified NHI identity.
    pub async fn renew_lease(
        &self,
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        lease_id: Uuid,
        extend_secs: i64,
    ) -> Result<NhiSecretLease, NhiApiError> {
        if extend_secs <= 0 {
            return Err(NhiApiError::BadRequest(
                "extend_secs must be positive".to_string(),
            ));
        }

        // Look up the lease and its parent secret to enforce max duration
        let lease = NhiSecretLease::get_by_id(pool, tenant_id, lease_id)
            .await
            .map_err(NhiApiError::Database)?
            .ok_or(NhiApiError::NotFound)?;

        if lease.status != "active" {
            return Err(NhiApiError::BadRequest("lease is not active".to_string()));
        }

        let secret = NhiVaultedSecret::get_by_id(pool, tenant_id, lease.secret_id)
            .await
            .map_err(NhiApiError::Database)?
            .ok_or(NhiApiError::NotFound)?;

        // Verify the secret belongs to the NHI from the URL path
        if secret.nhi_id != nhi_id {
            return Err(NhiApiError::NotFound);
        }

        // The renewed expiry (NOW + extend_secs) must not exceed max_lease_duration_secs from NOW
        if extend_secs > i64::from(secret.max_lease_duration_secs) {
            return Err(NhiApiError::BadRequest(format!(
                "extend_secs {}s exceeds max_lease_duration {}s",
                extend_secs, secret.max_lease_duration_secs
            )));
        }

        NhiSecretLease::renew(pool, tenant_id, lease_id, extend_secs)
            .await
            .map_err(NhiApiError::Database)?
            .ok_or(NhiApiError::NotFound)
    }

    /// Revoke a lease. Verifies the lease's secret belongs to the specified NHI.
    pub async fn revoke_lease(
        &self,
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        lease_id: Uuid,
        reason: &str,
    ) -> Result<(), NhiApiError> {
        // Verify the lease's secret belongs to this NHI
        let lease = NhiSecretLease::get_by_id(pool, tenant_id, lease_id)
            .await
            .map_err(NhiApiError::Database)?
            .ok_or(NhiApiError::NotFound)?;

        let secret = NhiVaultedSecret::get_by_id(pool, tenant_id, lease.secret_id)
            .await
            .map_err(NhiApiError::Database)?
            .ok_or(NhiApiError::NotFound)?;

        if secret.nhi_id != nhi_id {
            return Err(NhiApiError::NotFound);
        }

        let revoked = NhiSecretLease::revoke(pool, tenant_id, lease_id, reason)
            .await
            .map_err(NhiApiError::Database)?;
        if !revoked {
            return Err(NhiApiError::NotFound);
        }
        Ok(())
    }

    /// Revoke ALL active leases for an NHI identity.
    /// Called on lifecycle transitions (suspend, deactivate, archive).
    pub async fn revoke_all_leases_for_nhi(
        &self,
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        reason: &str,
    ) -> Result<u64, NhiApiError> {
        NhiSecretLease::revoke_all_for_nhi(pool, tenant_id, nhi_id, reason)
            .await
            .map_err(NhiApiError::Database)
    }

    // ── Helpers ────────────────────────────────────────────────

    /// Verify that an NHI identity exists for the given tenant.
    async fn verify_nhi_exists(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
    ) -> Result<(), NhiApiError> {
        let exists: (bool,) = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM nhi_identities WHERE tenant_id = $1 AND id = $2)",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .fetch_one(pool)
        .await
        .map_err(NhiApiError::Database)?;

        if !exists.0 {
            return Err(NhiApiError::NotFound);
        }
        Ok(())
    }
}

/// Map crypto errors to NhiApiError.
fn crypto_err(e: VaultCryptoError) -> NhiApiError {
    NhiApiError::Internal(format!("vault crypto error: {e}"))
}
