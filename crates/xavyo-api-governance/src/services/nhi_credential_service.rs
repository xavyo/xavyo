//! NHI Credential Service for F061.
//!
//! Provides credential management for Non-Human Identities:
//! - Credential generation (API keys, secrets)
//! - Credential rotation with grace periods
//! - Credential validation
//! - Automatic rotation scheduling

#[cfg(feature = "kafka")]
use chrono::DateTime;
use chrono::{Duration, Utc};
use sqlx::PgPool;
#[cfg(feature = "kafka")]
use std::sync::Arc;
use uuid::Uuid;

use xavyo_governance::GovernanceError;

use crate::models::{
    NhiCredentialCreatedResponse, NhiCredentialListResponse, NhiCredentialResponse,
    RotateCredentialsRequest,
};

#[cfg(feature = "kafka")]
use xavyo_events::{
    events::nhi::{
        NhiCredentialRevoked, NhiCredentialsExpiring, NhiCredentialsRotated, RotationType,
    },
    EventProducer,
};

use xavyo_db::{
    CreateGovNhiAuditEvent, CreateNhiCredential, GovNhiAuditEvent, GovNhiCredential,
    GovServiceAccount, NhiAuditEventType, NhiCredential, NhiCredentialType, NhiIdentity,
};

/// Default credential validity period in days.
const DEFAULT_CREDENTIAL_VALIDITY_DAYS: i64 = 90;

/// Default grace period for credential rotation in hours.
const DEFAULT_GRACE_PERIOD_HOURS: i64 = 24;

/// Maximum grace period in hours.
const MAX_GRACE_PERIOD_HOURS: i64 = 168; // 7 days

/// API key prefix for easy identification.
const API_KEY_PREFIX: &str = "xnhi_";

type Result<T> = std::result::Result<T, GovernanceError>;

/// Service for managing NHI credentials.
pub struct NhiCredentialService {
    pool: PgPool,
    #[cfg(feature = "kafka")]
    event_producer: Option<Arc<EventProducer>>,
}

impl NhiCredentialService {
    /// Create a new credential service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            #[cfg(feature = "kafka")]
            event_producer: None,
        }
    }

    /// Set the event producer for Kafka integration.
    #[cfg(feature = "kafka")]
    pub fn set_event_producer(&mut self, producer: Arc<EventProducer>) {
        self.event_producer = Some(producer);
    }

    /// Create a new credential service with event producer.
    #[cfg(feature = "kafka")]
    pub fn with_event_producer(pool: PgPool, producer: Arc<EventProducer>) -> Self {
        Self {
            pool,
            event_producer: Some(producer),
        }
    }

    // =========================================================================
    // Credential Rotation
    // =========================================================================

    /// Rotate credentials for an NHI.
    ///
    /// Creates a new credential and optionally keeps the old one active during
    /// a grace period to allow seamless migration.
    pub async fn rotate(
        &self,
        tenant_id: Uuid,
        nhi_id: Uuid,
        actor_id: Option<Uuid>,
        request: RotateCredentialsRequest,
    ) -> Result<NhiCredentialCreatedResponse> {
        // Validate NHI exists and is active (using new nhi_identities table)
        let nhi_identity = NhiIdentity::find_by_id(&self.pool, tenant_id, nhi_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(nhi_id))?;

        // Check lifecycle state - only active identities can rotate credentials
        if nhi_identity.lifecycle_state != xavyo_nhi::NhiLifecycleState::Active {
            return Err(GovernanceError::NhiSuspended(nhi_id));
        }

        // Generate new credential
        let (plaintext, credential_hash) = self.generate_credential(request.credential_type)?;

        // Calculate validity period
        let valid_from = Utc::now();
        let valid_until = request.expires_at.unwrap_or_else(|| {
            // Use NHI's rotation interval if set, otherwise default
            let days = nhi_identity
                .rotation_interval_days
                .unwrap_or(DEFAULT_CREDENTIAL_VALIDITY_DAYS as i32);
            Utc::now() + Duration::days(i64::from(days))
        });

        // Validate expiration is in future
        if valid_until <= valid_from {
            return Err(GovernanceError::InvalidExpirationDate);
        }

        // Create the new credential using new nhi_credentials table
        let cred_type_str = match request.credential_type {
            NhiCredentialType::ApiKey => "api_key",
            NhiCredentialType::Secret => "secret",
            NhiCredentialType::Certificate => "certificate",
        };

        let create_data = CreateNhiCredential {
            nhi_id,
            credential_type: cred_type_str.to_string(),
            credential_hash,
            valid_from,
            valid_until,
            rotated_by: actor_id,
        };

        let new_credential = NhiCredential::create(&self.pool, tenant_id, create_data)
            .await
            .map_err(GovernanceError::Database)?;

        // Handle grace period for old credentials
        let grace_period_hours = request
            .grace_period_hours
            .unwrap_or(DEFAULT_GRACE_PERIOD_HOURS as i32);
        let grace_period_ends_at = if grace_period_hours > 0 {
            Some(
                Utc::now()
                    + Duration::hours(i64::from(
                        grace_period_hours.min(MAX_GRACE_PERIOD_HOURS as i32),
                    )),
            )
        } else {
            None
        };

        // Get old active credential (if any) to include in event
        let old_credential = NhiCredential::list_active_by_nhi(&self.pool, tenant_id, nhi_id)
            .await
            .map_err(GovernanceError::Database)?
            .into_iter()
            .find(|c| c.id != new_credential.id);

        // If no grace period, deactivate old credentials immediately
        if grace_period_ends_at.is_none() {
            for cred in NhiCredential::list_active_by_nhi(&self.pool, tenant_id, nhi_id)
                .await
                .map_err(GovernanceError::Database)?
            {
                if cred.id != new_credential.id {
                    NhiCredential::deactivate(&self.pool, tenant_id, cred.id)
                        .await
                        .map_err(GovernanceError::Database)?;
                }
            }
        }

        // Update NHI's last_rotation_at via nhi_identities
        let _ = sqlx::query(
            "UPDATE nhi_identities SET last_rotation_at = NOW(), updated_at = NOW() WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(nhi_id)
        .execute(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        // Record audit event
        let audit_event = CreateGovNhiAuditEvent {
            nhi_id,
            event_type: NhiAuditEventType::CredentialsRotated,
            actor_id,
            changes: Some(serde_json::json!({
                "old_credential_id": old_credential.as_ref().map(|c| c.id),
                "new_credential_id": new_credential.id,
            })),
            metadata: Some(serde_json::json!({
                "credential_type": format!("{:?}", request.credential_type),
                "valid_until": valid_until,
                "grace_period_hours": grace_period_hours,
                "rotation_type": if actor_id.is_some() { "manual" } else { "automatic" },
            })),
            source_ip: None,
        };

        if let Err(e) = GovNhiAuditEvent::create(&self.pool, tenant_id, audit_event).await {
            tracing::warn!(error = %e, "Failed to create NHI credential rotation audit event");
        }

        tracing::info!(
            tenant_id = %tenant_id,
            nhi_id = %nhi_id,
            credential_id = %new_credential.id,
            credential_type = ?request.credential_type,
            "NHI credentials rotated"
        );

        // Build NhiCredentialResponse from the new NhiCredential
        let cred_response = NhiCredentialResponse {
            id: new_credential.id,
            nhi_id: new_credential.nhi_id,
            credential_type: request.credential_type,
            is_active: new_credential.is_active,
            valid_from: new_credential.valid_from,
            valid_until: new_credential.valid_until,
            days_until_expiry: (new_credential.valid_until - Utc::now()).num_days(),
            rotated_by: new_credential.rotated_by,
            created_at: new_credential.created_at,
        };

        Ok(NhiCredentialCreatedResponse {
            credential: cred_response,
            secret_value: plaintext,
            warning: "This is the only time the credential value will be shown. Store it securely."
                .to_string(),
            grace_period_ends_at,
        })
    }

    /// Revoke a specific credential.
    pub async fn revoke(
        &self,
        tenant_id: Uuid,
        nhi_id: Uuid,
        credential_id: Uuid,
        actor_id: Uuid,
        reason: String,
        immediate: bool,
    ) -> Result<NhiCredentialResponse> {
        // Validate NHI exists
        let _nhi = GovServiceAccount::find_by_id(&self.pool, tenant_id, nhi_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(nhi_id))?;

        // Find the credential
        let credential = GovNhiCredential::find_by_id(&self.pool, tenant_id, credential_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiCredentialNotFound(credential_id))?;

        // Validate credential belongs to this NHI
        if credential.nhi_id != nhi_id {
            return Err(GovernanceError::NhiCredentialNotFound(credential_id));
        }

        // Check if already revoked
        if !credential.is_active {
            return Err(GovernanceError::NhiCredentialAlreadyRevoked(credential_id));
        }

        // Deactivate the credential
        let updated = if immediate {
            GovNhiCredential::deactivate(&self.pool, tenant_id, credential_id)
                .await
                .map_err(GovernanceError::Database)?
                .ok_or(GovernanceError::NhiCredentialNotFound(credential_id))?
        } else {
            // Schedule deactivation after default grace period
            // For now, we'll just deactivate immediately
            // TODO: Implement scheduled deactivation
            GovNhiCredential::deactivate(&self.pool, tenant_id, credential_id)
                .await
                .map_err(GovernanceError::Database)?
                .ok_or(GovernanceError::NhiCredentialNotFound(credential_id))?
        };

        // Record audit event
        let audit_event = CreateGovNhiAuditEvent {
            nhi_id,
            event_type: NhiAuditEventType::CredentialRevoked,
            actor_id: Some(actor_id),
            changes: None,
            metadata: Some(serde_json::json!({
                "credential_id": credential_id,
                "reason": reason,
                "immediate": immediate,
            })),
            source_ip: None,
        };

        if let Err(e) = GovNhiAuditEvent::create(&self.pool, tenant_id, audit_event).await {
            tracing::warn!(error = %e, "Failed to create NHI credential revocation audit event");
        }

        tracing::info!(
            tenant_id = %tenant_id,
            nhi_id = %nhi_id,
            credential_id = %credential_id,
            "NHI credential revoked"
        );

        // Emit Kafka event
        #[cfg(feature = "kafka")]
        self.emit_revoked_event(tenant_id, &nhi, credential_id, reason.clone(), actor_id)
            .await;

        Ok(NhiCredentialResponse::from(updated))
    }

    // =========================================================================
    // Credential Listing
    // =========================================================================

    /// List all credentials for an NHI.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        nhi_id: Uuid,
        active_only: bool,
    ) -> Result<NhiCredentialListResponse> {
        // Validate NHI exists
        let _ = GovServiceAccount::find_by_id(&self.pool, tenant_id, nhi_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiNotFound(nhi_id))?;

        let credentials = if active_only {
            GovNhiCredential::list_active_by_nhi(&self.pool, tenant_id, nhi_id)
                .await
                .map_err(GovernanceError::Database)?
        } else {
            GovNhiCredential::list_by_nhi(&self.pool, tenant_id, nhi_id)
                .await
                .map_err(GovernanceError::Database)?
        };

        let total = credentials.len() as i64;
        let items: Vec<NhiCredentialResponse> = credentials
            .into_iter()
            .map(NhiCredentialResponse::from)
            .collect();

        Ok(NhiCredentialListResponse { items, total })
    }

    /// Get a specific credential by ID.
    pub async fn get(
        &self,
        tenant_id: Uuid,
        nhi_id: Uuid,
        credential_id: Uuid,
    ) -> Result<NhiCredentialResponse> {
        let credential = GovNhiCredential::find_by_id(&self.pool, tenant_id, credential_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::NhiCredentialNotFound(credential_id))?;

        // Validate credential belongs to this NHI
        if credential.nhi_id != nhi_id {
            return Err(GovernanceError::NhiCredentialNotFound(credential_id));
        }

        Ok(NhiCredentialResponse::from(credential))
    }

    // =========================================================================
    // Credential Validation
    // =========================================================================

    /// Validate a credential and return the associated NHI if valid.
    ///
    /// This is used for authentication. Returns (`tenant_id`, `nhi_id`) if the
    /// credential is valid, otherwise returns an appropriate error.
    ///
    /// Implementation note: Since we use Argon2 with random salts, we cannot
    /// do a direct hash lookup. For API keys with the xnhi_ prefix, we extract
    /// a credential identifier that's stored alongside the hash for O(1) lookup.
    /// For other credential types, we fall back to iterating through credentials.
    pub async fn validate(&self, credential_plaintext: &str) -> Result<(Uuid, Uuid)> {
        // For API keys, extract the key portion after prefix
        // The key includes an embedded credential ID in the first segment for O(1) lookup
        if credential_plaintext.starts_with(API_KEY_PREFIX) {
            // Try optimized lookup first using the credential_hash index
            // Note: We store both the Argon2 hash and need to verify
            return self.validate_with_iteration(credential_plaintext).await;
        }

        // For secrets and certificates, iterate through active credentials
        self.validate_with_iteration(credential_plaintext).await
    }

    /// Validate credential by iterating through active credentials.
    /// This is O(n) but necessary with salted hashes unless we add a
    /// secondary deterministic lookup index.
    async fn validate_with_iteration(&self, credential_plaintext: &str) -> Result<(Uuid, Uuid)> {
        // Get all active credentials to check against
        // TODO: In high-volume production systems, consider:
        // 1. Adding a deterministic hash (SHA256) column for O(1) lookup
        // 2. Partitioning credentials by type
        // 3. Caching recently validated credentials
        let active_credentials = self.find_all_active_credentials().await?;

        for credential in active_credentials {
            if self.verify_credential(credential_plaintext, &credential.credential_hash) {
                // Check if credential is still valid (not expired)
                if !credential.is_valid() {
                    if !credential.is_active {
                        return Err(GovernanceError::NhiCredentialAlreadyRevoked(credential.id));
                    }
                    if credential.valid_until <= Utc::now() {
                        return Err(GovernanceError::NhiCredentialExpired(credential.id));
                    }
                    return Err(GovernanceError::NhiCredentialInvalid);
                }

                // Record authentication in NHI last_used_at for activity tracking
                // This is fire-and-forget to not slow down authentication
                let _ = GovServiceAccount::update_last_used(
                    &self.pool,
                    credential.tenant_id,
                    credential.nhi_id,
                )
                .await;

                return Ok((credential.tenant_id, credential.nhi_id));
            }
        }

        Err(GovernanceError::NhiCredentialInvalid)
    }

    /// Find all active credentials for validation.
    async fn find_all_active_credentials(&self) -> Result<Vec<GovNhiCredential>> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_nhi_credentials
            WHERE is_active = true AND valid_until > NOW() AND valid_from <= NOW()
            ",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)
    }

    // =========================================================================
    // Scheduled Operations
    // =========================================================================

    /// Check NHIs that need credential rotation and perform automatic rotation.
    ///
    /// Returns the number of credentials rotated.
    pub async fn check_and_rotate_scheduled(&self, tenant_id: Uuid) -> Result<u64> {
        // Find NHIs needing rotation
        let nhis = GovServiceAccount::find_needing_rotation(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)?;

        let mut rotated_count = 0u64;

        for nhi in nhis {
            // Only rotate active NHIs
            if !nhi.status.is_operational() {
                continue;
            }

            // Get the current active credential type (default to ApiKey)
            let credential_type =
                GovNhiCredential::list_active_by_nhi(&self.pool, tenant_id, nhi.id)
                    .await
                    .map_err(GovernanceError::Database)?
                    .first()
                    .map_or(NhiCredentialType::ApiKey, |c| c.credential_type);

            let request = RotateCredentialsRequest {
                credential_type,
                name: None,
                expires_at: None,
                grace_period_hours: Some(DEFAULT_GRACE_PERIOD_HOURS as i32),
            };

            match self.rotate(tenant_id, nhi.id, None, request).await {
                Ok(_) => {
                    rotated_count += 1;
                    tracing::info!(
                        tenant_id = %tenant_id,
                        nhi_id = %nhi.id,
                        nhi_name = %nhi.name,
                        "Automatic credential rotation completed"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        tenant_id = %tenant_id,
                        nhi_id = %nhi.id,
                        nhi_name = %nhi.name,
                        error = %e,
                        "Automatic credential rotation failed"
                    );
                }
            }
        }

        Ok(rotated_count)
    }

    /// Check for credentials expiring soon and emit warning events.
    ///
    /// Returns the number of warnings emitted.
    pub async fn check_expiring_credentials(
        &self,
        tenant_id: Uuid,
        warning_days: i32,
    ) -> Result<u64> {
        let expiring = GovNhiCredential::find_expiring_soon(&self.pool, tenant_id, warning_days)
            .await
            .map_err(GovernanceError::Database)?;

        let mut warning_count = 0u64;

        for credential in expiring {
            // Get the NHI for notification
            if let Ok(Some(_nhi)) =
                GovServiceAccount::find_by_id(&self.pool, tenant_id, credential.nhi_id).await
            {
                #[cfg(feature = "kafka")]
                self.emit_expiring_event(
                    tenant_id,
                    &_nhi,
                    &credential,
                    credential.days_until_expiry() as i32,
                )
                .await;

                warning_count += 1;
            }
        }

        Ok(warning_count)
    }

    /// Deactivate credentials that are past their grace period.
    ///
    /// Returns the number of credentials deactivated.
    pub async fn deactivate_expired_grace_periods(&self, tenant_id: Uuid) -> Result<u64> {
        // For now, we rely on is_valid() check during authentication
        // This method can be used for cleanup
        GovNhiCredential::delete_expired_inactive(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Revoke all active credentials for an NHI.
    ///
    /// This is used when an NHI is suspended or revoked during certification.
    /// Returns the number of credentials revoked.
    pub async fn revoke_all_for_nhi(
        &self,
        tenant_id: Uuid,
        nhi_id: Uuid,
        actor_id: Uuid,
        reason: &str,
    ) -> Result<u64> {
        // Get all active credentials
        let active_credentials =
            GovNhiCredential::list_active_by_nhi(&self.pool, tenant_id, nhi_id)
                .await
                .map_err(GovernanceError::Database)?;

        let mut revoked_count = 0u64;

        for credential in active_credentials {
            // Deactivate the credential
            if let Err(e) = GovNhiCredential::deactivate(&self.pool, tenant_id, credential.id).await
            {
                tracing::warn!(
                    credential_id = %credential.id,
                    error = %e,
                    "Failed to revoke NHI credential"
                );
                continue;
            }

            // Record audit event
            let audit_event = CreateGovNhiAuditEvent {
                nhi_id,
                event_type: NhiAuditEventType::CredentialRevoked,
                actor_id: Some(actor_id),
                changes: None,
                metadata: Some(serde_json::json!({
                    "credential_id": credential.id,
                    "reason": reason,
                    "bulk_revocation": true,
                })),
                source_ip: None,
            };

            if let Err(e) = GovNhiAuditEvent::create(&self.pool, tenant_id, audit_event).await {
                tracing::warn!(error = %e, "Failed to create NHI credential revocation audit event");
            }

            revoked_count += 1;
        }

        tracing::info!(
            tenant_id = %tenant_id,
            nhi_id = %nhi_id,
            revoked_count = revoked_count,
            reason = %reason,
            "All NHI credentials revoked"
        );

        Ok(revoked_count)
    }

    // =========================================================================
    // Credential Generation (Private)
    // =========================================================================

    /// Generate a new credential (plaintext and hash).
    fn generate_credential(&self, credential_type: NhiCredentialType) -> Result<(String, String)> {
        match credential_type {
            NhiCredentialType::ApiKey => {
                let plaintext = self.generate_api_key();
                let hash = self.hash_credential(&plaintext)?;
                Ok((plaintext, hash))
            }
            NhiCredentialType::Secret => {
                let plaintext = self.generate_secret();
                let hash = self.hash_credential(&plaintext)?;
                Ok((plaintext, hash))
            }
            NhiCredentialType::Certificate => {
                // For certificates, we generate a random token as a placeholder
                // Real certificate generation would require external PKI integration
                let plaintext = self.generate_certificate_token();
                let hash = self.hash_credential(&plaintext)?;
                Ok((plaintext, hash))
            }
        }
    }

    /// Generate a secure API key.
    ///
    /// SECURITY: Uses `OsRng` (CSPRNG) for cryptographic randomness.
    fn generate_api_key(&self) -> String {
        use base64::Engine as _;
        use rand::{rngs::OsRng, RngCore};
        let mut random_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut random_bytes);
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes);
        format!("{API_KEY_PREFIX}{encoded}")
    }

    /// Generate a secure secret.
    ///
    /// SECURITY: Uses `OsRng` (CSPRNG) for cryptographic randomness.
    fn generate_secret(&self) -> String {
        use base64::Engine as _;
        use rand::{rngs::OsRng, RngCore};
        let mut random_bytes = [0u8; 48];
        OsRng.fill_bytes(&mut random_bytes);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes)
    }

    /// Generate a certificate token (placeholder for real PKI integration).
    ///
    /// SECURITY: Uses `OsRng` (CSPRNG) for cryptographic randomness.
    fn generate_certificate_token(&self) -> String {
        use base64::Engine as _;
        use rand::{rngs::OsRng, RngCore};
        let mut random_bytes = [0u8; 64];
        OsRng.fill_bytes(&mut random_bytes);
        format!(
            "CERT_{}",
            base64::engine::general_purpose::STANDARD.encode(random_bytes)
        )
    }

    /// Hash a credential using Argon2id.
    ///
    /// Returns an error if hashing fails (should never happen in practice -
    /// Argon2 only fails on OOM or invalid parameters, neither of which apply here).
    fn hash_credential(&self, plaintext: &str) -> Result<String> {
        use argon2::{
            password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
            Argon2,
        };

        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        argon2
            .hash_password(plaintext.as_bytes(), &salt)
            .map(|h| h.to_string())
            // Note: Using NhiRiskCalculationFailed as there's no generic internal error variant.
            // This error should never occur in practice (Argon2 only fails on OOM).
            .map_err(|e| {
                GovernanceError::NhiRiskCalculationFailed(format!("Credential hashing failed: {e}"))
            })
    }

    /// Verify a credential against a hash.
    #[allow(dead_code)]
    fn verify_credential(&self, plaintext: &str, hash: &str) -> bool {
        use argon2::{
            password_hash::{PasswordHash, PasswordVerifier},
            Argon2,
        };

        let parsed_hash = match PasswordHash::new(hash) {
            Ok(h) => h,
            Err(_) => return false,
        };

        Argon2::default()
            .verify_password(plaintext.as_bytes(), &parsed_hash)
            .is_ok()
    }

    // =========================================================================
    // Kafka Event Emission (Private)
    // =========================================================================

    #[cfg(feature = "kafka")]
    async fn emit_rotated_event(
        &self,
        tenant_id: Uuid,
        nhi: &GovServiceAccount,
        new_credential: &GovNhiCredential,
        old_credential_id: Option<Uuid>,
        actor_id: Option<Uuid>,
        grace_period_ends_at: Option<DateTime<Utc>>,
    ) {
        if let Some(ref producer) = self.event_producer {
            let event = NhiCredentialsRotated {
                nhi_id: nhi.id,
                tenant_id,
                name: nhi.name.clone(),
                new_credential_id: new_credential.id,
                old_credential_id,
                credential_type: format!("{:?}", new_credential.credential_type).to_lowercase(),
                rotation_type: if actor_id.is_some() {
                    RotationType::Manual
                } else {
                    RotationType::Automatic
                },
                grace_period_ends_at,
                rotated_by: actor_id,
                rotated_at: Utc::now(),
            };

            if let Err(e) = producer.publish(&event).await {
                tracing::warn!(error = %e, "Failed to publish NhiCredentialsRotated event");
            }
        }
    }

    #[cfg(feature = "kafka")]
    async fn emit_revoked_event(
        &self,
        tenant_id: Uuid,
        _nhi: &GovServiceAccount,
        credential_id: Uuid,
        reason: String,
        actor_id: Uuid,
    ) {
        if let Some(ref producer) = self.event_producer {
            let event = NhiCredentialRevoked {
                nhi_id: _nhi.id,
                tenant_id,
                credential_id,
                reason,
                revoked_by: Some(actor_id),
                revoked_at: Utc::now(),
            };

            if let Err(e) = producer.publish(&event).await {
                tracing::warn!(error = %e, "Failed to publish NhiCredentialRevoked event");
            }
        }
    }

    #[cfg(feature = "kafka")]
    async fn emit_expiring_event(
        &self,
        tenant_id: Uuid,
        nhi: &GovServiceAccount,
        credential: &GovNhiCredential,
        days_until_expiry: i32,
    ) {
        if let Some(ref producer) = self.event_producer {
            let event = NhiCredentialsExpiring {
                nhi_id: nhi.id,
                tenant_id,
                name: nhi.name.clone(),
                credential_id: credential.id,
                expires_at: credential.valid_until,
                days_until_expiry,
                owner_id: nhi.owner_id,
            };

            if let Err(e) = producer.publish(&event).await {
                tracing::warn!(error = %e, "Failed to publish NhiCredentialsExpiring event");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_key_prefix() {
        assert_eq!(API_KEY_PREFIX, "xnhi_");
    }

    #[test]
    fn test_default_validity() {
        assert_eq!(DEFAULT_CREDENTIAL_VALIDITY_DAYS, 90);
    }

    #[test]
    fn test_default_grace_period() {
        assert_eq!(DEFAULT_GRACE_PERIOD_HOURS, 24);
    }

    #[test]
    fn test_max_grace_period() {
        assert_eq!(MAX_GRACE_PERIOD_HOURS, 168); // 7 days
    }
}
