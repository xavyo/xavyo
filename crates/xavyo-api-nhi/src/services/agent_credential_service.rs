//! Agent Credential Service for F110.
//!
//! Provides credential management for AI Agents:
//! - Credential generation (API keys, secrets)
//! - Credential rotation with grace periods
//! - Credential revocation
//! - Credential listing
//!
//! This service mirrors `NhiCredentialService` but validates against `ai_agents` table
//! instead of `gov_service_accounts`.

use chrono::{Duration, Utc};
use sqlx::PgPool;
#[cfg(feature = "kafka")]
use std::sync::Arc;
use uuid::Uuid;

use xavyo_db::{
    AiAgent, CreateGovNhiCredential, GovNhiCredential, NhiCredentialType, NhiEntityType,
};

use xavyo_api_governance::models::{
    NhiCredentialCreatedResponse, NhiCredentialListResponse, NhiCredentialResponse,
    RotateCredentialsRequest,
};

#[cfg(feature = "kafka")]
use xavyo_events::EventProducer;

use crate::error::ApiNhiError;

/// Default credential validity period in days.
const DEFAULT_CREDENTIAL_VALIDITY_DAYS: i64 = 90;

/// Default grace period for credential rotation in hours.
const DEFAULT_GRACE_PERIOD_HOURS: i64 = 24;

/// Maximum grace period in hours.
const MAX_GRACE_PERIOD_HOURS: i64 = 168; // 7 days

/// Minimum time between credential rotations in minutes.
/// This prevents rapid rotation attacks (`DoS`).
const MIN_ROTATION_INTERVAL_MINUTES: i64 = 60; // 1 hour

/// API key prefix for easy identification.
const API_KEY_PREFIX: &str = "xnhi_";

type Result<T> = std::result::Result<T, ApiNhiError>;

/// Service for managing AI agent credentials.
#[derive(Clone)]
pub struct AgentCredentialService {
    pool: PgPool,
    #[cfg(feature = "kafka")]
    #[allow(dead_code)]
    event_producer: Option<Arc<EventProducer>>,
}

impl AgentCredentialService {
    /// Create a new agent credential service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            #[cfg(feature = "kafka")]
            event_producer: None,
        }
    }

    /// Create a new agent credential service with event producer.
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

    /// Rotate credentials for an AI agent.
    ///
    /// Creates a new credential and optionally keeps the old one active during
    /// a grace period to allow seamless migration.
    pub async fn rotate(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        actor_id: Option<Uuid>,
        request: RotateCredentialsRequest,
    ) -> Result<NhiCredentialCreatedResponse> {
        // Validate agent exists and is active
        let agent = AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await
            .map_err(|e| ApiNhiError::Database(e.to_string()))?
            .ok_or(ApiNhiError::AgentNotFound(agent_id))?;

        if agent.status != "active" {
            return Err(ApiNhiError::AgentSuspended(agent_id));
        }

        // Check rate limit: prevent rotation if last rotation was less than MIN_ROTATION_INTERVAL_MINUTES ago
        if let Some(last_rotation) = agent.last_rotation_at {
            let now = Utc::now();
            let min_interval = Duration::minutes(MIN_ROTATION_INTERVAL_MINUTES);
            let next_allowed = last_rotation + min_interval;

            if now < next_allowed {
                let remaining = next_allowed - now;
                return Err(ApiNhiError::RotationRateLimitExceeded(format!(
                    "Credential rotation is rate limited. Please wait {} minutes before rotating again.",
                    remaining.num_minutes() + 1
                )));
            }
        }

        // Generate new credential
        let (plaintext, credential_hash) = self.generate_credential(request.credential_type)?;

        // Calculate validity period
        let valid_from = Utc::now();
        let valid_until = request.expires_at.unwrap_or_else(|| {
            // Use agent's rotation interval if set, otherwise default
            let days = agent
                .rotation_interval_days
                .unwrap_or(DEFAULT_CREDENTIAL_VALIDITY_DAYS as i32);
            Utc::now() + Duration::days(i64::from(days))
        });

        // Validate expiration is in future
        if valid_until <= valid_from {
            return Err(ApiNhiError::InvalidExpirationDate);
        }

        // Create the new credential
        let create_data = CreateGovNhiCredential {
            nhi_id: agent_id,
            credential_type: request.credential_type,
            credential_hash,
            valid_from,
            valid_until,
            rotated_by: actor_id,
            nhi_type: NhiEntityType::Agent,
        };

        let new_credential = GovNhiCredential::create(&self.pool, tenant_id, create_data)
            .await
            .map_err(|e| ApiNhiError::Database(e.to_string()))?;

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

        // If no grace period, deactivate old credentials immediately
        if grace_period_ends_at.is_none() {
            for cred in GovNhiCredential::list_active_by_nhi(&self.pool, tenant_id, agent_id)
                .await
                .map_err(|e| ApiNhiError::Database(e.to_string()))?
            {
                if cred.id != new_credential.id {
                    GovNhiCredential::deactivate(&self.pool, tenant_id, cred.id)
                        .await
                        .map_err(|e| ApiNhiError::Database(e.to_string()))?;
                }
            }
        }

        // Update agent's last_rotation_at
        AiAgent::update_last_rotation(&self.pool, tenant_id, agent_id)
            .await
            .map_err(|e| ApiNhiError::Database(e.to_string()))?;

        tracing::info!(
            tenant_id = %tenant_id,
            agent_id = %agent_id,
            credential_id = %new_credential.id,
            credential_type = ?request.credential_type,
            "Agent credentials rotated"
        );

        Ok(NhiCredentialCreatedResponse {
            credential: NhiCredentialResponse::from(new_credential),
            secret_value: plaintext,
            warning: "This is the only time the credential value will be shown. Store it securely."
                .to_string(),
            grace_period_ends_at,
        })
    }

    // =========================================================================
    // Credential Revocation
    // =========================================================================

    /// Revoke a specific credential.
    pub async fn revoke(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        credential_id: Uuid,
        _actor_id: Uuid,
        reason: String,
        immediate: bool,
    ) -> Result<NhiCredentialResponse> {
        // Validate agent exists
        let _agent = AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await
            .map_err(|e| ApiNhiError::Database(e.to_string()))?
            .ok_or(ApiNhiError::AgentNotFound(agent_id))?;

        // Find the credential
        let credential = GovNhiCredential::find_by_id(&self.pool, tenant_id, credential_id)
            .await
            .map_err(|e| ApiNhiError::Database(e.to_string()))?
            .ok_or(ApiNhiError::CredentialNotFound(credential_id))?;

        // Validate credential belongs to this agent
        if credential.nhi_id != agent_id {
            return Err(ApiNhiError::CredentialNotFound(credential_id));
        }

        // Check if already revoked
        if !credential.is_active {
            return Err(ApiNhiError::CredentialAlreadyRevoked(credential_id));
        }

        // Deactivate the credential
        let updated = if immediate {
            GovNhiCredential::deactivate(&self.pool, tenant_id, credential_id)
                .await
                .map_err(|e| ApiNhiError::Database(e.to_string()))?
                .ok_or(ApiNhiError::CredentialNotFound(credential_id))?
        } else {
            // For non-immediate revocation, still deactivate
            // (future: implement scheduled deactivation)
            GovNhiCredential::deactivate(&self.pool, tenant_id, credential_id)
                .await
                .map_err(|e| ApiNhiError::Database(e.to_string()))?
                .ok_or(ApiNhiError::CredentialNotFound(credential_id))?
        };

        tracing::info!(
            tenant_id = %tenant_id,
            agent_id = %agent_id,
            credential_id = %credential_id,
            reason = %reason,
            "Agent credential revoked"
        );

        Ok(NhiCredentialResponse::from(updated))
    }

    // =========================================================================
    // Credential Listing
    // =========================================================================

    /// List all credentials for an agent.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        agent_id: Uuid,
        active_only: bool,
    ) -> Result<NhiCredentialListResponse> {
        // Validate agent exists
        let _ = AiAgent::find_by_id(&self.pool, tenant_id, agent_id)
            .await
            .map_err(|e| ApiNhiError::Database(e.to_string()))?
            .ok_or(ApiNhiError::AgentNotFound(agent_id))?;

        let credentials = if active_only {
            GovNhiCredential::list_active_by_nhi(&self.pool, tenant_id, agent_id)
                .await
                .map_err(|e| ApiNhiError::Database(e.to_string()))?
        } else {
            GovNhiCredential::list_by_nhi(&self.pool, tenant_id, agent_id)
                .await
                .map_err(|e| ApiNhiError::Database(e.to_string()))?
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
        agent_id: Uuid,
        credential_id: Uuid,
    ) -> Result<NhiCredentialResponse> {
        let credential = GovNhiCredential::find_by_id(&self.pool, tenant_id, credential_id)
            .await
            .map_err(|e| ApiNhiError::Database(e.to_string()))?
            .ok_or(ApiNhiError::CredentialNotFound(credential_id))?;

        // Validate credential belongs to this agent
        if credential.nhi_id != agent_id {
            return Err(ApiNhiError::CredentialNotFound(credential_id));
        }

        Ok(NhiCredentialResponse::from(credential))
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

    /// Generate a certificate token (placeholder).
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
    /// Returns an error if hashing fails (should never happen in practice).
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
            .map_err(|e| ApiNhiError::Internal(format!("Failed to hash credential: {e}")))
    }

    // =========================================================================
    // Credential Validation
    // =========================================================================

    /// Validate a credential and return the associated NHI information.
    ///
    /// Returns (`tenant_id`, `nhi_id`, `nhi_type`) if valid.
    pub async fn validate(&self, credential: &str) -> Result<(Uuid, Uuid, NhiEntityType)> {
        // Find all active credentials
        let credentials = GovNhiCredential::find_all_active_for_auth(&self.pool)
            .await
            .map_err(|e| ApiNhiError::Database(e.to_string()))?;

        // Validate the credential against each stored hash
        for cred in credentials {
            if cred.verify_credential(credential) {
                // Check if credential is within valid time window
                let now = chrono::Utc::now();
                if now < cred.valid_from {
                    continue; // Not yet valid
                }
                if now > cred.valid_until {
                    continue; // Expired
                }

                // Check that it's an agent credential
                if cred.nhi_type != NhiEntityType::Agent {
                    continue; // Not an agent credential
                }

                return Ok((cred.tenant_id, cred.nhi_id, cred.nhi_type));
            }
        }

        Err(ApiNhiError::InvalidCredential)
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

    #[test]
    fn test_min_rotation_interval() {
        assert_eq!(MIN_ROTATION_INTERVAL_MINUTES, 60); // 1 hour
    }
}
