//! `WebAuthn` Service for FIDO2/WebAuthn authentication.
//!
//! Handles `WebAuthn` credential registration, authentication, and management.

use crate::error::ApiAuthError;
use sqlx::PgPool;
use std::net::IpAddr;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::*;
use xavyo_db::{
    set_tenant_context, CeremonyType, CreateWebAuthnAuditLog, CreateWebAuthnChallenge,
    CreateWebAuthnCredential, CredentialInfo, TenantWebAuthnPolicy, UserWebAuthnCredential,
    WebAuthnAuditAction, WebAuthnAuditLog, WebAuthnChallenge,
};

/// Maximum failed `WebAuthn` authentication attempts before lockout.
pub const MAX_FAILED_ATTEMPTS: i64 = 5;

/// Lockout duration in minutes after max failed attempts.
pub const LOCKOUT_MINUTES: i64 = 5;

/// Configuration for the `WebAuthn` service.
#[derive(Debug, Clone)]
pub struct WebAuthnConfig {
    /// Relying Party ID (usually the domain, e.g., "xavyo.net").
    pub rp_id: String,
    /// Relying Party name (displayed to users).
    pub rp_name: String,
    /// Origin URL for `WebAuthn` requests.
    pub origin: Url,
}

impl WebAuthnConfig {
    /// Create from environment variables.
    pub fn from_env() -> Result<Self, ApiAuthError> {
        let rp_id = std::env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".to_string());
        let rp_name = std::env::var("WEBAUTHN_RP_NAME").unwrap_or_else(|_| "xavyo".to_string());
        let origin_str = std::env::var("WEBAUTHN_ORIGIN")
            .unwrap_or_else(|_| "http://localhost:8080".to_string());

        let origin = Url::parse(&origin_str)
            .map_err(|e| ApiAuthError::Internal(format!("Invalid WEBAUTHN_ORIGIN: {e}")))?;

        Ok(Self {
            rp_id,
            rp_name,
            origin,
        })
    }
}

/// `WebAuthn` Service for handling FIDO2/WebAuthn operations.
#[derive(Clone)]
pub struct WebAuthnService {
    pool: PgPool,
    webauthn: Webauthn,
    config: WebAuthnConfig,
}

impl WebAuthnService {
    /// Create a new `WebAuthn` service.
    pub fn new(pool: PgPool, config: WebAuthnConfig) -> Result<Self, ApiAuthError> {
        let rp_origin = config.origin.clone();
        let builder = WebauthnBuilder::new(&config.rp_id, &rp_origin)
            .map_err(|e| ApiAuthError::Internal(format!("WebAuthn builder error: {e}")))?
            .rp_name(&config.rp_name);

        let webauthn = builder
            .build()
            .map_err(|e| ApiAuthError::Internal(format!("WebAuthn build error: {e}")))?;

        Ok(Self {
            pool,
            webauthn,
            config,
        })
    }

    /// Create from environment configuration.
    pub fn from_env(pool: PgPool) -> Result<Self, ApiAuthError> {
        let config = WebAuthnConfig::from_env()?;
        Self::new(pool, config)
    }

    /// Start `WebAuthn` credential registration.
    ///
    /// Returns the creation challenge options to send to the client.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_registration(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        user_name: &str,
        user_display_name: &str,
        credential_name: Option<String>,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<CreationChallengeResponse, ApiAuthError> {
        let mut tx = self.pool.begin().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *tx, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Check tenant policy
        let policy = TenantWebAuthnPolicy::get_or_create(&mut *tx, tenant_id)
            .await
            .map_err(ApiAuthError::Database)?;

        if !policy.webauthn_enabled {
            return Err(ApiAuthError::WebAuthnDisabled);
        }

        // Check max credentials limit
        let credential_count = UserWebAuthnCredential::count_by_user_id(&mut *tx, user_id)
            .await
            .map_err(ApiAuthError::Database)?;

        if credential_count >= i64::from(policy.max_credentials_per_user) {
            return Err(ApiAuthError::MaxWebAuthnCredentials);
        }

        // Get existing credentials to exclude (prevent re-registration)
        let existing_creds = UserWebAuthnCredential::find_by_user_id(&mut *tx, user_id)
            .await
            .map_err(ApiAuthError::Database)?;

        let exclude_credentials: Vec<CredentialID> = existing_creds
            .iter()
            .map(|c| CredentialID::from(c.credential_id.clone()))
            .collect();

        // Delete any pending registration challenges
        WebAuthnChallenge::delete_by_user_and_type(
            &mut *tx,
            tenant_id,
            user_id,
            CeremonyType::Registration,
        )
        .await
        .map_err(ApiAuthError::Database)?;

        // Create user for webauthn-rs
        let user_unique_id = Uuid::new_v4(); // User handle for WebAuthn (not the actual user_id for privacy)

        // Start registration ceremony
        let (ccr, reg_state) = self
            .webauthn
            .start_passkey_registration(
                user_unique_id,
                user_name,
                user_display_name,
                Some(exclude_credentials),
            )
            .map_err(|e| {
                ApiAuthError::Internal(format!("WebAuthn registration start failed: {e}"))
            })?;

        // Serialize and store the registration state
        let state_json = serde_json::to_value(&reg_state).map_err(|e| {
            ApiAuthError::Internal(format!("Failed to serialize registration state: {e}"))
        })?;

        // Extract challenge bytes (use serialization to get the underlying bytes)
        let challenge_bytes: Vec<u8> = ccr.public_key.challenge.clone().into();

        WebAuthnChallenge::create(
            &mut *tx,
            CreateWebAuthnChallenge {
                user_id,
                tenant_id,
                challenge: challenge_bytes,
                ceremony_type: CeremonyType::Registration,
                state_json,
                credential_name,
            },
        )
        .await
        .map_err(ApiAuthError::Database)?;

        // Log audit event
        WebAuthnAuditLog::create(
            &mut *tx,
            CreateWebAuthnAuditLog {
                user_id,
                tenant_id,
                credential_id: None,
                action: WebAuthnAuditAction::RegistrationStarted,
                ip_address: ip_address.map(|ip| ip.to_string()),
                user_agent,
                metadata: None,
            },
        )
        .await
        .map_err(ApiAuthError::Database)?;

        tx.commit().await.map_err(ApiAuthError::Database)?;

        Ok(ccr)
    }

    /// Complete `WebAuthn` credential registration.
    ///
    /// Verifies the authenticator response and stores the credential.
    pub async fn finish_registration(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        reg_response: &RegisterPublicKeyCredential,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<CredentialInfo, ApiAuthError> {
        let mut tx = self.pool.begin().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *tx, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Get tenant policy for policy enforcement (T064, T066)
        let policy = TenantWebAuthnPolicy::get_or_create(&mut *tx, tenant_id)
            .await
            .map_err(ApiAuthError::Database)?;

        // Get pending registration challenge
        let challenge = WebAuthnChallenge::find_active(
            &mut *tx,
            tenant_id,
            user_id,
            CeremonyType::Registration,
        )
        .await
        .map_err(ApiAuthError::Database)?
        .ok_or(ApiAuthError::WebAuthnChallengeNotFound)?;

        if challenge.is_expired() {
            return Err(ApiAuthError::WebAuthnChallengeExpired);
        }

        // Deserialize registration state
        let reg_state: PasskeyRegistration = serde_json::from_value(challenge.state_json.clone())
            .map_err(|e| {
            ApiAuthError::Internal(format!("Failed to deserialize registration state: {e}"))
        })?;

        // Complete registration
        let passkey = self
            .webauthn
            .finish_passkey_registration(reg_response, &reg_state)
            .map_err(|e| {
                tracing::error!("WebAuthn registration finish failed: {:?}", e);
                ApiAuthError::WebAuthnVerificationFailed(format!("{e:?}"))
            })?;

        // T064: Enforce require_attestation policy
        // If attestation is required, verify the response has a valid attestation statement
        if policy.require_attestation {
            // Check attestation object format - attestation is present if the fmt is not "none"
            let attestation_bytes: &[u8] = reg_response.response.attestation_object.as_ref();
            // Decode the attestation object to check the format
            // The attestation object is CBOR-encoded
            if let Ok(attestation) = ciborium::from_reader::<ciborium::Value, _>(attestation_bytes)
            {
                if let Some(fmt) = attestation
                    .as_map()
                    .and_then(|m| m.iter().find(|(k, _)| k.as_text() == Some("fmt")))
                    .and_then(|(_, v)| v.as_text())
                {
                    if fmt == "none" {
                        return Err(ApiAuthError::WebAuthnAttestationRequired);
                    }
                }
            }
        }

        // T066: Enforce allowed_authenticator_types policy
        // Determine authenticator type from attachment hint
        // Platform authenticators (Touch ID, Windows Hello) use "internal" transport
        let auth_type = if reg_response.response.transports.as_ref().is_some_and(|t| {
            t.iter().any(|transport| {
                matches!(
                    transport,
                    webauthn_rs_proto::AuthenticatorTransport::Internal
                )
            })
        }) {
            "platform"
        } else {
            "cross-platform"
        };

        if let Some(ref allowed_types) = policy.allowed_authenticator_types {
            if !allowed_types.is_empty() && !allowed_types.contains(&auth_type.to_string()) {
                return Err(ApiAuthError::WebAuthnAuthenticatorTypeNotAllowed(
                    auth_type.to_string(),
                ));
            }
        }

        // Check for duplicate credential ID
        let cred_id_bytes: Vec<u8> = passkey.cred_id().to_vec();
        if UserWebAuthnCredential::exists_by_credential_id(&mut *tx, tenant_id, &cred_id_bytes)
            .await
            .map_err(ApiAuthError::Database)?
        {
            return Err(ApiAuthError::WebAuthnCredentialExists);
        }

        // Serialize passkey for storage (we'll use this to reconstruct for authentication)
        let passkey_json = serde_json::to_vec(&passkey)
            .map_err(|e| ApiAuthError::Internal(format!("Failed to serialize passkey: {e}")))?;

        // Use default authenticator type since we can't access private cred field
        let auth_type = "cross-platform";

        // Get credential name from challenge or use default
        let credential_name = challenge
            .credential_name
            .unwrap_or_else(|| "Security Key".to_string());

        // Create the credential record
        let credential = UserWebAuthnCredential::create(
            &mut *tx,
            CreateWebAuthnCredential {
                user_id,
                tenant_id,
                credential_id: cred_id_bytes,
                public_key: passkey_json,
                sign_count: 0, // Initial sign count
                aaguid: None, // Can't access AAGUID from passkey without danger-credential-internals
                name: credential_name,
                authenticator_type: auth_type.to_string(),
                transports: None,
                backup_eligible: false,
                backup_state: false,
            },
        )
        .await
        .map_err(ApiAuthError::Database)?;

        // Delete the used challenge
        WebAuthnChallenge::delete(&mut *tx, tenant_id, challenge.id)
            .await
            .map_err(ApiAuthError::Database)?;

        // Log audit event
        WebAuthnAuditLog::create(
            &mut *tx,
            CreateWebAuthnAuditLog {
                user_id,
                tenant_id,
                credential_id: Some(credential.id),
                action: WebAuthnAuditAction::RegistrationCompleted,
                ip_address: ip_address.map(|ip| ip.to_string()),
                user_agent,
                metadata: Some(serde_json::json!({
                    "credential_name": credential.name,
                    "authenticator_type": credential.authenticator_type,
                })),
            },
        )
        .await
        .map_err(ApiAuthError::Database)?;

        tx.commit().await.map_err(ApiAuthError::Database)?;

        Ok(credential.into())
    }

    /// Start `WebAuthn` authentication.
    ///
    /// Returns the request challenge options to send to the client.
    pub async fn start_authentication(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<RequestChallengeResponse, ApiAuthError> {
        let mut tx = self.pool.begin().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *tx, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Check rate limiting
        let recent_failures =
            WebAuthnAuditLog::count_recent_failures(&mut *tx, user_id, LOCKOUT_MINUTES)
                .await
                .map_err(ApiAuthError::Database)?;

        if recent_failures >= MAX_FAILED_ATTEMPTS {
            return Err(ApiAuthError::WebAuthnRateLimited);
        }

        // Get user's credentials
        let credentials = UserWebAuthnCredential::find_by_user_id(&mut *tx, user_id)
            .await
            .map_err(ApiAuthError::Database)?;

        if credentials.is_empty() {
            return Err(ApiAuthError::WebAuthnNoCredentials);
        }

        // Convert to passkeys for webauthn-rs
        let passkeys: Vec<Passkey> = credentials
            .iter()
            .filter_map(|c| {
                let cred: webauthn_rs::prelude::Credential =
                    serde_json::from_slice(&c.public_key).ok()?;
                Some(Passkey::from(cred))
            })
            .collect();

        if passkeys.is_empty() {
            return Err(ApiAuthError::WebAuthnNoCredentials);
        }

        // Delete any pending authentication challenges
        WebAuthnChallenge::delete_by_user_and_type(
            &mut *tx,
            tenant_id,
            user_id,
            CeremonyType::Authentication,
        )
        .await
        .map_err(ApiAuthError::Database)?;

        // Start authentication ceremony
        let (rcr, auth_state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| {
                ApiAuthError::Internal(format!("WebAuthn authentication start failed: {e}"))
            })?;

        // Serialize and store the authentication state
        let state_json = serde_json::to_value(&auth_state).map_err(|e| {
            ApiAuthError::Internal(format!("Failed to serialize authentication state: {e}"))
        })?;

        // Extract challenge bytes
        let challenge_bytes: Vec<u8> = rcr.public_key.challenge.clone().into();

        WebAuthnChallenge::create(
            &mut *tx,
            CreateWebAuthnChallenge {
                user_id,
                tenant_id,
                challenge: challenge_bytes,
                ceremony_type: CeremonyType::Authentication,
                state_json,
                credential_name: None,
            },
        )
        .await
        .map_err(ApiAuthError::Database)?;

        // Log audit event
        WebAuthnAuditLog::create(
            &mut *tx,
            CreateWebAuthnAuditLog {
                user_id,
                tenant_id,
                credential_id: None,
                action: WebAuthnAuditAction::AuthenticationStarted,
                ip_address: ip_address.map(|ip| ip.to_string()),
                user_agent,
                metadata: None,
            },
        )
        .await
        .map_err(ApiAuthError::Database)?;

        tx.commit().await.map_err(ApiAuthError::Database)?;

        Ok(rcr)
    }

    /// Complete `WebAuthn` authentication.
    ///
    /// Verifies the authenticator assertion and updates the credential counter.
    pub async fn finish_authentication(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        auth_response: &PublicKeyCredential,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<Uuid, ApiAuthError> {
        let mut tx = self.pool.begin().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *tx, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Get tenant policy for policy enforcement (T065)
        let policy = TenantWebAuthnPolicy::get_or_create(&mut *tx, tenant_id)
            .await
            .map_err(ApiAuthError::Database)?;

        // Get pending authentication challenge
        let challenge = WebAuthnChallenge::find_active(
            &mut *tx,
            tenant_id,
            user_id,
            CeremonyType::Authentication,
        )
        .await
        .map_err(ApiAuthError::Database)?
        .ok_or(ApiAuthError::WebAuthnChallengeNotFound)?;

        if challenge.is_expired() {
            return Err(ApiAuthError::WebAuthnChallengeExpired);
        }

        // Deserialize authentication state
        let auth_state: PasskeyAuthentication =
            serde_json::from_value(challenge.state_json.clone()).map_err(|e| {
                ApiAuthError::Internal(format!("Failed to deserialize authentication state: {e}"))
            })?;

        // Complete authentication
        let auth_result = self
            .webauthn
            .finish_passkey_authentication(auth_response, &auth_state)
            .map_err(|e| {
                tracing::error!("WebAuthn authentication finish failed: {:?}", e);
                ApiAuthError::WebAuthnVerificationFailed(format!("{e:?}"))
            })?;

        // T065: Enforce user_verification policy
        // If policy requires user verification, check if it was performed
        if policy.user_verification == "required" && !auth_result.user_verified() {
            return Err(ApiAuthError::WebAuthnUserVerificationRequired);
        }

        // Find the credential that was used
        let cred_id_bytes: Vec<u8> = auth_result.cred_id().to_vec();
        let credential = UserWebAuthnCredential::find_by_credential_id_and_tenant(
            &mut *tx,
            tenant_id,
            &cred_id_bytes,
        )
        .await
        .map_err(ApiAuthError::Database)?
        .ok_or(ApiAuthError::WebAuthnCredentialNotFound)?;

        // Check sign counter for clone detection
        let new_counter = auth_result.counter();
        if new_counter <= credential.sign_count as u32 && new_counter != 0 {
            // Counter anomaly detected - possible cloned credential
            WebAuthnAuditLog::create(
                &mut *tx,
                CreateWebAuthnAuditLog {
                    user_id,
                    tenant_id,
                    credential_id: Some(credential.id),
                    action: WebAuthnAuditAction::CounterAnomalyDetected,
                    ip_address: ip_address.map(|ip| ip.to_string()),
                    user_agent: user_agent.clone(),
                    metadata: Some(serde_json::json!({
                        "stored_counter": credential.sign_count,
                        "received_counter": new_counter,
                    })),
                },
            )
            .await
            .map_err(ApiAuthError::Database)?;

            tx.commit().await.map_err(ApiAuthError::Database)?;
            return Err(ApiAuthError::WebAuthnCounterAnomaly);
        }

        // Update sign counter
        UserWebAuthnCredential::update_sign_count(
            &mut *tx,
            tenant_id,
            credential.id,
            i64::from(new_counter),
        )
        .await
        .map_err(ApiAuthError::Database)?;

        // Delete the used challenge
        WebAuthnChallenge::delete(&mut *tx, tenant_id, challenge.id)
            .await
            .map_err(ApiAuthError::Database)?;

        // Log audit event
        WebAuthnAuditLog::create(
            &mut *tx,
            CreateWebAuthnAuditLog {
                user_id,
                tenant_id,
                credential_id: Some(credential.id),
                action: WebAuthnAuditAction::AuthenticationSuccess,
                ip_address: ip_address.map(|ip| ip.to_string()),
                user_agent,
                metadata: Some(serde_json::json!({
                    "credential_name": credential.name,
                })),
            },
        )
        .await
        .map_err(ApiAuthError::Database)?;

        tx.commit().await.map_err(ApiAuthError::Database)?;

        Ok(credential.id)
    }

    /// List all `WebAuthn` credentials for a user.
    pub async fn list_credentials(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Vec<CredentialInfo>, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let credentials = UserWebAuthnCredential::find_by_user_id(&mut *conn, user_id)
            .await
            .map_err(ApiAuthError::Database)?;

        Ok(credentials.into_iter().map(Into::into).collect())
    }

    /// Rename a `WebAuthn` credential.
    pub async fn rename_credential(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        credential_id: Uuid,
        new_name: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<CredentialInfo, ApiAuthError> {
        let mut tx = self.pool.begin().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *tx, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Verify credential belongs to user
        let credential =
            UserWebAuthnCredential::find_by_id_and_tenant(&mut *tx, tenant_id, credential_id)
                .await
                .map_err(ApiAuthError::Database)?
                .ok_or(ApiAuthError::WebAuthnCredentialNotFound)?;

        if credential.user_id != user_id {
            return Err(ApiAuthError::WebAuthnCredentialNotFound);
        }

        // Rename
        let updated = UserWebAuthnCredential::rename(&mut *tx, tenant_id, credential_id, new_name)
            .await
            .map_err(ApiAuthError::Database)?;

        // Log audit event
        WebAuthnAuditLog::create(
            &mut *tx,
            CreateWebAuthnAuditLog {
                user_id,
                tenant_id,
                credential_id: Some(credential_id),
                action: WebAuthnAuditAction::CredentialRenamed,
                ip_address: ip_address.map(|ip| ip.to_string()),
                user_agent,
                metadata: Some(serde_json::json!({
                    "old_name": credential.name,
                    "new_name": new_name,
                })),
            },
        )
        .await
        .map_err(ApiAuthError::Database)?;

        tx.commit().await.map_err(ApiAuthError::Database)?;

        Ok(updated.into())
    }

    /// Delete a `WebAuthn` credential.
    pub async fn delete_credential(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        credential_id: Uuid,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<(), ApiAuthError> {
        let mut tx = self.pool.begin().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *tx, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Verify credential belongs to user
        let credential =
            UserWebAuthnCredential::find_by_id_and_tenant(&mut *tx, tenant_id, credential_id)
                .await
                .map_err(ApiAuthError::Database)?
                .ok_or(ApiAuthError::WebAuthnCredentialNotFound)?;

        if credential.user_id != user_id {
            return Err(ApiAuthError::WebAuthnCredentialNotFound);
        }

        // Delete
        UserWebAuthnCredential::delete(&mut *tx, tenant_id, credential_id)
            .await
            .map_err(ApiAuthError::Database)?;

        // Log audit event
        WebAuthnAuditLog::create(
            &mut *tx,
            CreateWebAuthnAuditLog {
                user_id,
                tenant_id,
                credential_id: Some(credential_id),
                action: WebAuthnAuditAction::CredentialDeleted,
                ip_address: ip_address.map(|ip| ip.to_string()),
                user_agent,
                metadata: Some(serde_json::json!({
                    "credential_name": credential.name,
                })),
            },
        )
        .await
        .map_err(ApiAuthError::Database)?;

        tx.commit().await.map_err(ApiAuthError::Database)?;

        Ok(())
    }

    /// Check if user has any enabled `WebAuthn` credentials.
    pub async fn has_webauthn_enabled(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<bool, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        UserWebAuthnCredential::has_enabled_credentials(&mut *conn, user_id)
            .await
            .map_err(ApiAuthError::Database)
    }

    /// Get tenant `WebAuthn` policy.
    pub async fn get_tenant_policy(
        &self,
        tenant_id: Uuid,
    ) -> Result<TenantWebAuthnPolicy, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        TenantWebAuthnPolicy::get_or_create(&mut *conn, tenant_id)
            .await
            .map_err(ApiAuthError::Database)
    }

    /// Admin: List credentials for a specific user.
    pub async fn admin_list_user_credentials(
        &self,
        admin_user_id: Uuid,
        target_user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Vec<CredentialInfo>, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        tracing::info!(
            admin_user_id = %admin_user_id,
            target_user_id = %target_user_id,
            "Admin listing WebAuthn credentials for user"
        );

        let credentials = UserWebAuthnCredential::find_by_user_id(&mut *conn, target_user_id)
            .await
            .map_err(ApiAuthError::Database)?;

        Ok(credentials.into_iter().map(Into::into).collect())
    }

    /// Admin: Revoke a user's credential.
    pub async fn admin_revoke_credential(
        &self,
        admin_user_id: Uuid,
        target_user_id: Uuid,
        credential_id: Uuid,
        tenant_id: Uuid,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<(), ApiAuthError> {
        let mut tx = self.pool.begin().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *tx, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Verify credential belongs to target user
        let credential =
            UserWebAuthnCredential::find_by_id_and_tenant(&mut *tx, tenant_id, credential_id)
                .await
                .map_err(ApiAuthError::Database)?
                .ok_or(ApiAuthError::WebAuthnCredentialNotFound)?;

        if credential.user_id != target_user_id {
            return Err(ApiAuthError::WebAuthnCredentialNotFound);
        }

        // Delete (revoke)
        UserWebAuthnCredential::delete(&mut *tx, tenant_id, credential_id)
            .await
            .map_err(ApiAuthError::Database)?;

        // Log audit event
        WebAuthnAuditLog::create(
            &mut *tx,
            CreateWebAuthnAuditLog {
                user_id: target_user_id,
                tenant_id,
                credential_id: Some(credential_id),
                action: WebAuthnAuditAction::CredentialRevokedByAdmin,
                ip_address: ip_address.map(|ip| ip.to_string()),
                user_agent,
                metadata: Some(serde_json::json!({
                    "admin_user_id": admin_user_id.to_string(),
                    "credential_name": credential.name,
                })),
            },
        )
        .await
        .map_err(ApiAuthError::Database)?;

        tx.commit().await.map_err(ApiAuthError::Database)?;

        tracing::info!(
            admin_user_id = %admin_user_id,
            target_user_id = %target_user_id,
            credential_id = %credential_id,
            "Admin revoked WebAuthn credential"
        );

        Ok(())
    }

    /// Delete expired challenges (cleanup job).
    pub async fn cleanup_expired_challenges(&self) -> Result<u64, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        WebAuthnChallenge::delete_expired(&mut *conn)
            .await
            .map_err(ApiAuthError::Database)
    }
}

impl std::fmt::Debug for WebAuthnService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebAuthnService")
            .field("pool", &"[PgPool]")
            .field("webauthn", &"[Webauthn]")
            .field("config", &self.config)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webauthn_config_defaults() {
        // Test that from_env doesn't panic with missing env vars
        std::env::remove_var("WEBAUTHN_RP_ID");
        std::env::remove_var("WEBAUTHN_RP_NAME");
        std::env::remove_var("WEBAUTHN_ORIGIN");

        let config = WebAuthnConfig::from_env().unwrap();
        assert_eq!(config.rp_id, "localhost");
        assert_eq!(config.rp_name, "xavyo");
        assert_eq!(config.origin.as_str(), "http://localhost:8080/");
    }

    #[test]
    fn test_constants() {
        assert_eq!(MAX_FAILED_ATTEMPTS, 5);
        assert_eq!(LOCKOUT_MINUTES, 5);
    }
}
