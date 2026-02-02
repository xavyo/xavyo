//! MFA Service for TOTP authentication.
//!
//! Handles TOTP secret generation, verification, and recovery code management.

use crate::crypto::{TotpEncryption, TotpEncryptionError};
use crate::error::ApiAuthError;
use chrono::{DateTime, Utc};
use data_encoding::BASE32;
use image::Luma;
use qrcode::QrCode;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::io::Cursor;
use std::net::IpAddr;
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;
use xavyo_db::{
    set_tenant_context, CreateMfaAuditLog, CreateTotpSecret, MfaAuditAction, MfaAuditLog,
    UserRecoveryCode, UserTotpSecret,
};

/// Length of recovery codes (16 alphanumeric characters).
const RECOVERY_CODE_LENGTH: usize = 16;

/// Number of recovery codes to generate.
const RECOVERY_CODE_COUNT: usize = 10;

/// TOTP secret length in bytes (160 bits / 8 = 20 bytes).
const TOTP_SECRET_LENGTH: usize = 20;

/// Maximum failed TOTP attempts before lockout.
pub const MAX_FAILED_ATTEMPTS: i32 = 5;

/// Lockout duration in minutes after max failed attempts.
pub const LOCKOUT_MINUTES: i64 = 5;

/// TOTP setup expiration in minutes.
pub const SETUP_EXPIRY_MINUTES: i64 = 10;

/// Data returned when initiating TOTP setup.
#[derive(Debug)]
pub struct TotpSetupData {
    /// Base32-encoded secret for manual entry.
    pub secret_base32: String,
    /// otpauth:// URI for QR code scanning.
    pub otpauth_uri: String,
    /// QR code as PNG image encoded in base64.
    pub qr_code_base64: String,
}

/// MFA user status information.
#[derive(Debug)]
pub struct MfaStatus {
    pub totp_enabled: bool,
    pub recovery_codes_remaining: i64,
    pub setup_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// MFA Service for handling TOTP and recovery codes.
#[derive(Clone)]
pub struct MfaService {
    pool: PgPool,
    encryption: TotpEncryption,
    issuer: String,
}

impl MfaService {
    /// Create a new MFA service.
    pub fn new(pool: PgPool, encryption: TotpEncryption, issuer: String) -> Self {
        Self {
            pool,
            encryption,
            issuer,
        }
    }

    /// Create from environment configuration.
    pub fn from_env(pool: PgPool) -> Result<Self, TotpEncryptionError> {
        let encryption = TotpEncryption::from_env()?;
        let issuer = std::env::var("MFA_ISSUER").unwrap_or_else(|_| "Xavyo".to_string());
        Ok(Self::new(pool, encryption, issuer))
    }

    /// Generate a new TOTP secret.
    ///
    /// SECURITY: Uses OsRng directly from the operating system's CSPRNG for maximum security.
    fn generate_secret() -> Vec<u8> {
        use rand::rngs::OsRng;
        use rand::RngCore;
        let mut secret = vec![0u8; TOTP_SECRET_LENGTH];
        OsRng.fill_bytes(&mut secret[..]);
        secret
    }

    /// Initiate TOTP setup for a user.
    ///
    /// Returns setup data including QR code. The user must verify with a code
    /// before MFA is fully enabled.
    pub async fn initiate_setup(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        email: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<TotpSetupData, ApiAuthError> {
        // Set tenant context
        let mut tx = self.pool.begin().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *tx, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Check if user already has MFA enabled
        if let Some(existing) = UserTotpSecret::find_by_user_id(&mut *tx, user_id)
            .await
            .map_err(ApiAuthError::Database)?
        {
            if existing.is_enabled {
                return Err(ApiAuthError::MfaAlreadyEnabled);
            }
            // Delete incomplete setup to allow retry
            UserTotpSecret::delete_if_not_enabled(&mut *tx, user_id)
                .await
                .map_err(ApiAuthError::Database)?;
        }

        // Generate secret
        let secret_bytes = Self::generate_secret();
        let secret_base32 = BASE32.encode(&secret_bytes);

        // Create TOTP instance for URI generation
        // SECURITY: Properly handle potential secret conversion failure instead of panicking
        let secret_for_totp = Secret::Raw(secret_bytes.clone())
            .to_bytes()
            .map_err(|e| ApiAuthError::Internal(format!("TOTP secret conversion failed: {}", e)))?;

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_for_totp,
            Some(self.issuer.clone()),
            email.to_string(),
        )
        .map_err(|e| ApiAuthError::Internal(format!("TOTP creation failed: {}", e)))?;

        let otpauth_uri = totp.get_url();

        // Generate QR code
        let qr_code_base64 = self.generate_qr_code(&otpauth_uri)?;

        // Encrypt and store secret
        let (encrypted, iv) = self
            .encryption
            .encrypt(&secret_bytes)
            .map_err(|e| ApiAuthError::Internal(format!("Encryption failed: {}", e)))?;

        UserTotpSecret::create(
            &mut *tx,
            CreateTotpSecret {
                user_id,
                tenant_id,
                secret_encrypted: encrypted,
                iv,
            },
        )
        .await
        .map_err(ApiAuthError::Database)?;

        // Log audit event
        MfaAuditLog::create(
            &mut *tx,
            CreateMfaAuditLog {
                user_id,
                tenant_id,
                action: MfaAuditAction::SetupInitiated,
                ip_address: ip_address.map(|ip| ip.to_string()),
                user_agent,
                metadata: None,
            },
        )
        .await
        .map_err(ApiAuthError::Database)?;

        tx.commit().await.map_err(ApiAuthError::Database)?;

        Ok(TotpSetupData {
            secret_base32,
            otpauth_uri,
            qr_code_base64,
        })
    }

    /// Generate a QR code as base64-encoded PNG.
    fn generate_qr_code(&self, content: &str) -> Result<String, ApiAuthError> {
        let code = QrCode::new(content.as_bytes())
            .map_err(|e| ApiAuthError::Internal(format!("QR code generation failed: {}", e)))?;

        let image = code.render::<Luma<u8>>().build();

        let mut png_bytes = Vec::new();
        let mut cursor = Cursor::new(&mut png_bytes);
        image
            .write_to(&mut cursor, image::ImageFormat::Png)
            .map_err(|e| ApiAuthError::Internal(format!("PNG encoding failed: {}", e)))?;

        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &png_bytes,
        ))
    }

    /// Verify TOTP code and complete setup.
    ///
    /// On success, generates and returns recovery codes.
    pub async fn verify_setup(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        code: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<Vec<String>, ApiAuthError> {
        let mut tx = self.pool.begin().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *tx, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Get pending TOTP secret
        let secret = UserTotpSecret::find_by_user_id(&mut *tx, user_id)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::MfaSetupNotInitiated)?;

        if secret.is_enabled {
            return Err(ApiAuthError::MfaAlreadyEnabled);
        }

        if secret.is_setup_expired() {
            // Clean up expired setup
            UserTotpSecret::delete_if_not_enabled(&mut *tx, user_id)
                .await
                .map_err(ApiAuthError::Database)?;
            return Err(ApiAuthError::MfaSetupExpired);
        }

        // Decrypt and verify code
        let secret_bytes = self
            .encryption
            .decrypt(&secret.secret_encrypted, &secret.iv)
            .map_err(|e| ApiAuthError::Internal(format!("Decryption failed: {}", e)))?;

        if !self.verify_totp_code(&secret_bytes, code)? {
            return Err(ApiAuthError::InvalidTotpCode);
        }

        // Enable MFA
        UserTotpSecret::enable(&mut *tx, user_id)
            .await
            .map_err(ApiAuthError::Database)?;

        // Generate recovery codes
        let (codes, hashes) = self.generate_recovery_codes();
        UserRecoveryCode::create_batch(&mut *tx, user_id, tenant_id, &hashes)
            .await
            .map_err(ApiAuthError::Database)?;

        // Log audit event
        MfaAuditLog::create(
            &mut *tx,
            CreateMfaAuditLog {
                user_id,
                tenant_id,
                action: MfaAuditAction::SetupCompleted,
                ip_address: ip_address.map(|ip| ip.to_string()),
                user_agent,
                metadata: None,
            },
        )
        .await
        .map_err(ApiAuthError::Database)?;

        tx.commit().await.map_err(ApiAuthError::Database)?;

        Ok(codes)
    }

    /// Verify a TOTP code during login.
    ///
    /// SECURITY: Implements replay protection by tracking the last used TOTP time step.
    /// A code that was already used in a previous time step will be rejected.
    pub async fn verify_login_code(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        code: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<(), ApiAuthError> {
        let mut tx = self.pool.begin().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *tx, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Get TOTP secret
        let secret = UserTotpSecret::find_by_user_id(&mut *tx, user_id)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::MfaNotEnabled)?;

        if !secret.is_enabled {
            return Err(ApiAuthError::MfaNotEnabled);
        }

        // Check lockout
        if secret.is_locked() {
            return Err(ApiAuthError::TotpVerificationLocked);
        }

        // SECURITY: Check for replay attack - reject codes used in the same or earlier time step.
        // TOTP uses 30-second windows, and we allow ±1 window tolerance.
        // If last_used_at is within the current code's validity window, reject as replay.
        if let Some(last_used) = secret.last_used_at {
            let now = Utc::now();
            let step_size = 30i64; // TOTP step size in seconds
            let tolerance = 1i64; // ±1 window tolerance

            // Calculate time steps
            let current_step = now.timestamp() / step_size;
            let last_used_step = last_used.timestamp() / step_size;

            // If the code was used in the current step or within tolerance window, it's a replay
            if current_step <= last_used_step + tolerance {
                tracing::warn!(
                    user_id = %user_id,
                    current_step = current_step,
                    last_used_step = last_used_step,
                    "TOTP replay attack detected - code already used in this time window"
                );
                return Err(ApiAuthError::InvalidTotpCode);
            }
        }

        // Decrypt and verify code
        let secret_bytes = self
            .encryption
            .decrypt(&secret.secret_encrypted, &secret.iv)
            .map_err(|e| ApiAuthError::Internal(format!("Decryption failed: {}", e)))?;

        if self.verify_totp_code(&secret_bytes, code)? {
            // Success - record and return
            UserTotpSecret::record_success(&mut *tx, user_id)
                .await
                .map_err(ApiAuthError::Database)?;

            MfaAuditLog::create(
                &mut *tx,
                CreateMfaAuditLog {
                    user_id,
                    tenant_id,
                    action: MfaAuditAction::VerifySuccess,
                    ip_address: ip_address.map(|ip| ip.to_string()),
                    user_agent,
                    metadata: None,
                },
            )
            .await
            .map_err(ApiAuthError::Database)?;

            tx.commit().await.map_err(ApiAuthError::Database)?;
            Ok(())
        } else {
            // Failure - record and possibly lock
            let attempts = UserTotpSecret::record_failure(
                &mut *tx,
                user_id,
                MAX_FAILED_ATTEMPTS,
                LOCKOUT_MINUTES,
            )
            .await
            .map_err(ApiAuthError::Database)?;

            let locked = attempts >= MAX_FAILED_ATTEMPTS;
            MfaAuditLog::create(
                &mut *tx,
                CreateMfaAuditLog {
                    user_id,
                    tenant_id,
                    action: if locked {
                        MfaAuditAction::AccountLocked
                    } else {
                        MfaAuditAction::VerifyFailed
                    },
                    ip_address: ip_address.map(|ip| ip.to_string()),
                    user_agent,
                    metadata: Some(serde_json::json!({ "attempts": attempts })),
                },
            )
            .await
            .map_err(ApiAuthError::Database)?;

            tx.commit().await.map_err(ApiAuthError::Database)?;

            if locked {
                Err(ApiAuthError::TotpVerificationLocked)
            } else {
                Err(ApiAuthError::InvalidTotpCode)
            }
        }
    }

    /// Verify a TOTP code against a secret.
    fn verify_totp_code(&self, secret_bytes: &[u8], code: &str) -> Result<bool, ApiAuthError> {
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1, // 1 step tolerance (±30 seconds)
            30,
            secret_bytes.to_vec(),
            None,          // No issuer needed for verification
            String::new(), // No account name needed for verification
        )
        .map_err(|e| ApiAuthError::Internal(format!("TOTP creation failed: {}", e)))?;

        Ok(totp.check_current(code).unwrap_or(false))
    }

    /// Verify a recovery code during login.
    pub async fn verify_recovery_code(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        code: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<(), ApiAuthError> {
        let mut tx = self.pool.begin().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *tx, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Normalize code (remove dashes/spaces, uppercase)
        let normalized = code.replace(['-', ' '], "").to_uppercase();
        let code_hash = Self::hash_recovery_code(&normalized);

        // Try to mark as used (constant-time lookup via database)
        let marked = UserRecoveryCode::mark_used(&mut *tx, user_id, &code_hash)
            .await
            .map_err(ApiAuthError::Database)?;

        if marked {
            // Success
            MfaAuditLog::create(
                &mut *tx,
                CreateMfaAuditLog {
                    user_id,
                    tenant_id,
                    action: MfaAuditAction::RecoveryUsed,
                    ip_address: ip_address.map(|ip| ip.to_string()),
                    user_agent,
                    metadata: None,
                },
            )
            .await
            .map_err(ApiAuthError::Database)?;

            // Reset TOTP lockout since they successfully authenticated
            UserTotpSecret::record_success(&mut *tx, user_id)
                .await
                .map_err(ApiAuthError::Database)?;

            tx.commit().await.map_err(ApiAuthError::Database)?;
            Ok(())
        } else {
            // Check if user has any remaining codes
            let remaining = UserRecoveryCode::count_unused(&mut *tx, user_id)
                .await
                .map_err(ApiAuthError::Database)?;

            tx.commit().await.map_err(ApiAuthError::Database)?;

            if remaining == 0 {
                Err(ApiAuthError::NoRecoveryCodesRemaining)
            } else {
                Err(ApiAuthError::InvalidRecoveryCode)
            }
        }
    }

    /// Regenerate recovery codes.
    ///
    /// Deletes all existing codes and generates new ones.
    pub async fn regenerate_recovery_codes(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<Vec<String>, ApiAuthError> {
        let mut tx = self.pool.begin().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *tx, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Verify MFA is enabled
        let secret = UserTotpSecret::find_by_user_id(&mut *tx, user_id)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::MfaNotEnabled)?;

        if !secret.is_enabled {
            return Err(ApiAuthError::MfaNotEnabled);
        }

        // Delete existing codes
        UserRecoveryCode::delete_all_for_user(&mut *tx, user_id)
            .await
            .map_err(ApiAuthError::Database)?;

        // Generate new codes
        let (codes, hashes) = self.generate_recovery_codes();
        UserRecoveryCode::create_batch(&mut *tx, user_id, tenant_id, &hashes)
            .await
            .map_err(ApiAuthError::Database)?;

        // Log audit event
        MfaAuditLog::create(
            &mut *tx,
            CreateMfaAuditLog {
                user_id,
                tenant_id,
                action: MfaAuditAction::RecoveryRegenerated,
                ip_address: ip_address.map(|ip| ip.to_string()),
                user_agent,
                metadata: None,
            },
        )
        .await
        .map_err(ApiAuthError::Database)?;

        tx.commit().await.map_err(ApiAuthError::Database)?;

        Ok(codes)
    }

    /// Generate recovery codes.
    ///
    /// Returns (plaintext_codes, hashed_codes).
    ///
    /// SECURITY: Uses OsRng directly from the operating system's CSPRNG for maximum security.
    fn generate_recovery_codes(&self) -> (Vec<String>, Vec<String>) {
        use rand::distributions::Alphanumeric;
        use rand::rngs::OsRng;
        use rand::Rng;
        let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
        let mut hashes = Vec::with_capacity(RECOVERY_CODE_COUNT);

        for _ in 0..RECOVERY_CODE_COUNT {
            let code: String = (0..RECOVERY_CODE_LENGTH)
                .map(|_| OsRng.sample(Alphanumeric) as char)
                .collect::<String>()
                .to_uppercase();

            let hash = Self::hash_recovery_code(&code);
            codes.push(code);
            hashes.push(hash);
        }

        (codes, hashes)
    }

    /// Hash a recovery code using SHA-256.
    fn hash_recovery_code(code: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(code.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Disable MFA for a user.
    pub async fn disable_mfa(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        totp_code: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<(), ApiAuthError> {
        let mut tx = self.pool.begin().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *tx, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Get TOTP secret
        let secret = UserTotpSecret::find_by_user_id(&mut *tx, user_id)
            .await
            .map_err(ApiAuthError::Database)?
            .ok_or(ApiAuthError::MfaNotEnabled)?;

        if !secret.is_enabled {
            return Err(ApiAuthError::MfaNotEnabled);
        }

        // Verify TOTP code
        let secret_bytes = self
            .encryption
            .decrypt(&secret.secret_encrypted, &secret.iv)
            .map_err(|e| ApiAuthError::Internal(format!("Decryption failed: {}", e)))?;

        if !self.verify_totp_code(&secret_bytes, totp_code)? {
            return Err(ApiAuthError::InvalidTotpCode);
        }

        // Delete TOTP secret and recovery codes
        UserTotpSecret::delete(&mut *tx, user_id)
            .await
            .map_err(ApiAuthError::Database)?;

        UserRecoveryCode::delete_all_for_user(&mut *tx, user_id)
            .await
            .map_err(ApiAuthError::Database)?;

        // Log audit event
        MfaAuditLog::create(
            &mut *tx,
            CreateMfaAuditLog {
                user_id,
                tenant_id,
                action: MfaAuditAction::Disabled,
                ip_address: ip_address.map(|ip| ip.to_string()),
                user_agent,
                metadata: None,
            },
        )
        .await
        .map_err(ApiAuthError::Database)?;

        tx.commit().await.map_err(ApiAuthError::Database)?;

        Ok(())
    }

    /// Get MFA status for a user.
    pub async fn get_status(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<MfaStatus, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let secret = UserTotpSecret::find_by_user_id(&mut *conn, user_id)
            .await
            .map_err(ApiAuthError::Database)?;

        let (totp_enabled, setup_at, last_used_at) = if let Some(s) = secret {
            (s.is_enabled, s.setup_completed_at, s.last_used_at)
        } else {
            (false, None, None)
        };

        let recovery_codes_remaining = if totp_enabled {
            UserRecoveryCode::count_unused(&mut *conn, user_id)
                .await
                .map_err(ApiAuthError::Database)?
        } else {
            0
        };

        Ok(MfaStatus {
            totp_enabled,
            recovery_codes_remaining,
            setup_at,
            last_used_at,
        })
    }

    /// Check if user has MFA enabled.
    pub async fn has_mfa_enabled(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<bool, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let secret = UserTotpSecret::find_by_user_id(&mut *conn, user_id)
            .await
            .map_err(ApiAuthError::Database)?;

        Ok(secret.map(|s| s.is_enabled).unwrap_or(false))
    }
}

impl std::fmt::Debug for MfaService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MfaService")
            .field("pool", &"[PgPool]")
            .field("encryption", &"[TotpEncryption]")
            .field("issuer", &self.issuer)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::distributions::Alphanumeric;
    use rand::Rng;

    /// Generate recovery codes without needing a service instance.
    fn generate_test_recovery_codes() -> (Vec<String>, Vec<String>) {
        let mut rng = rand::thread_rng();
        let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
        let mut hashes = Vec::with_capacity(RECOVERY_CODE_COUNT);

        for _ in 0..RECOVERY_CODE_COUNT {
            let code: String = (0..RECOVERY_CODE_LENGTH)
                .map(|_| rng.sample(Alphanumeric) as char)
                .collect::<String>()
                .to_uppercase();

            let hash = MfaService::hash_recovery_code(&code);
            codes.push(code);
            hashes.push(hash);
        }

        (codes, hashes)
    }

    #[test]
    fn test_generate_recovery_codes() {
        let (codes, hashes) = generate_test_recovery_codes();

        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        assert_eq!(hashes.len(), RECOVERY_CODE_COUNT);

        for code in &codes {
            assert_eq!(code.len(), RECOVERY_CODE_LENGTH);
            assert!(code.chars().all(|c| c.is_ascii_alphanumeric()));
        }

        // Verify hashes match codes
        for (code, hash) in codes.iter().zip(hashes.iter()) {
            assert_eq!(MfaService::hash_recovery_code(code), *hash);
        }
    }

    #[test]
    fn test_hash_recovery_code() {
        let code = "ABC123DEF456GH78";
        let hash1 = MfaService::hash_recovery_code(code);
        let hash2 = MfaService::hash_recovery_code(code);

        // Same input produces same hash
        assert_eq!(hash1, hash2);

        // Hash is 64 hex characters (SHA-256)
        assert_eq!(hash1.len(), 64);

        // Different input produces different hash
        let hash3 = MfaService::hash_recovery_code("DIFFERENT12345678");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_generate_secret() {
        let secret1 = MfaService::generate_secret();
        let secret2 = MfaService::generate_secret();

        assert_eq!(secret1.len(), TOTP_SECRET_LENGTH);
        assert_eq!(secret2.len(), TOTP_SECRET_LENGTH);
        assert_ne!(secret1, secret2); // Random secrets should differ
    }
}
