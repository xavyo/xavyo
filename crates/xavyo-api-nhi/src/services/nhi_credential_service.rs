//! Unified NHI credential management service.
//!
//! Provides credential lifecycle operations for all NHI types:
//! - Issue credentials (API keys, secrets, certificates)
//! - Rotate credentials with grace periods
//! - Revoke credentials
//! - Validate NHI lifecycle state before credential operations

use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use rand::rngs::OsRng;
use sqlx::PgPool;
use uuid::Uuid;
use xavyo_db::models::{CreateNhiCredential, NhiCredential, NhiIdentity};
use xavyo_nhi::NhiLifecycleState;

use crate::error::NhiApiError;

/// Service for unified NHI credential lifecycle management.
pub struct NhiCredentialService;

impl NhiCredentialService {
    /// Issue a new credential for an NHI.
    ///
    /// Returns `(credential_record, plaintext_secret)`. The plaintext is returned
    /// exactly once — it is never stored and cannot be recovered.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the NHI identity does not exist in the given tenant.
    /// - `InvalidTransition` if the NHI lifecycle state does not allow credential operations.
    /// - `Internal` if hashing or database operations fail.
    pub async fn issue(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        credential_type: String,
        valid_days: i64,
        issued_by: Uuid,
    ) -> Result<(NhiCredential, String), NhiApiError> {
        // 1. Verify NHI exists and lifecycle allows credential ops
        let identity = NhiIdentity::find_by_id(pool, tenant_id, nhi_id)
            .await?
            .ok_or(NhiApiError::NotFound)?;
        Self::validate_lifecycle_for_credentials(&identity)?;

        // 2. Generate random 32-byte secret, base64url-encode
        let mut secret_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut secret_bytes);
        let plaintext = URL_SAFE_NO_PAD.encode(secret_bytes);

        // 3. Hash with Argon2id
        let salt = SaltString::generate(&mut OsRng);
        let credential_hash = Argon2::default()
            .hash_password(plaintext.as_bytes(), &salt)
            .map_err(|e| NhiApiError::Internal(format!("credential hashing failed: {e}")))?
            .to_string();

        // 4. Store in nhi_credentials
        let now = Utc::now();
        let valid_until = now + Duration::days(valid_days);

        let credential = NhiCredential::create(
            pool,
            tenant_id,
            CreateNhiCredential {
                nhi_id,
                credential_type,
                credential_hash,
                valid_from: now,
                valid_until,
                rotated_by: Some(issued_by),
            },
        )
        .await?;

        Ok((credential, plaintext))
    }

    /// Rotate a credential: issue a new one and set the old one to a grace period.
    ///
    /// The old credential remains valid for `grace_period_hours` after rotation,
    /// allowing clients to transition to the new credential without downtime.
    ///
    /// Returns `(new_credential, plaintext_secret)`.
    ///
    /// # Errors
    ///
    /// - `NotFound` if the NHI or old credential does not exist.
    /// - `BadRequest` if the old credential does not belong to the specified NHI.
    /// - `InvalidTransition` if the NHI lifecycle state disallows credential operations.
    pub async fn rotate(
        pool: &PgPool,
        tenant_id: Uuid,
        nhi_id: Uuid,
        old_credential_id: Uuid,
        credential_type: String,
        valid_days: i64,
        grace_period_hours: i64,
        rotated_by: Uuid,
    ) -> Result<(NhiCredential, String), NhiApiError> {
        // 1. Verify old credential exists and belongs to this NHI
        let old_cred = NhiCredential::find_by_id(pool, tenant_id, old_credential_id)
            .await?
            .ok_or(NhiApiError::NotFound)?;

        if old_cred.nhi_id != nhi_id {
            return Err(NhiApiError::BadRequest(
                "credential does not belong to this NHI".to_string(),
            ));
        }

        // 2. Issue new credential
        let (new_cred, plaintext) = Self::issue(
            pool,
            tenant_id,
            nhi_id,
            credential_type,
            valid_days,
            rotated_by,
        )
        .await?;

        // 3. Set old credential valid_until to NOW() + grace_period
        let grace_until = Utc::now() + Duration::hours(grace_period_hours);
        sqlx::query(
            r"
            UPDATE nhi_credentials
            SET valid_until = $3
            WHERE tenant_id = $1 AND id = $2 AND is_active = true
            ",
        )
        .bind(tenant_id)
        .bind(old_credential_id)
        .bind(grace_until)
        .execute(pool)
        .await?;

        Ok((new_cred, plaintext))
    }

    /// Revoke a credential by deactivating it.
    ///
    /// Returns `true` if the credential was deactivated, `false` if it was
    /// already inactive or not found.
    pub async fn revoke(
        pool: &PgPool,
        tenant_id: Uuid,
        credential_id: Uuid,
    ) -> Result<bool, NhiApiError> {
        let deactivated = NhiCredential::deactivate(pool, tenant_id, credential_id).await?;
        Ok(deactivated)
    }

    /// Validate that an NHI's lifecycle state allows credential operations.
    ///
    /// Credentials can only be issued/rotated for NHIs in `Active` or `Inactive` state.
    /// Suspended, deprecated, and archived NHIs cannot have new credentials.
    fn validate_lifecycle_for_credentials(identity: &NhiIdentity) -> Result<(), NhiApiError> {
        match identity.lifecycle_state {
            NhiLifecycleState::Active | NhiLifecycleState::Inactive => Ok(()),
            NhiLifecycleState::Suspended => Err(NhiApiError::InvalidTransition(
                "cannot issue credentials for a suspended NHI".to_string(),
            )),
            NhiLifecycleState::Deprecated => Err(NhiApiError::InvalidTransition(
                "cannot issue credentials for a deprecated NHI".to_string(),
            )),
            NhiLifecycleState::Archived => Err(NhiApiError::InvalidTransition(
                "cannot issue credentials for an archived NHI".to_string(),
            )),
            _ => Err(NhiApiError::InvalidTransition(
                "cannot issue credentials in this lifecycle state".to_string(),
            )),
        }
    }
}
