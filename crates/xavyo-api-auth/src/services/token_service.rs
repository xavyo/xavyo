//! Token service for refresh token management.
//!
//! Handles creation, validation, refresh, and revocation of refresh tokens.
//! Also provides secure token generation for password reset and email verification.

use crate::error::ApiAuthError;
use crate::services::security_audit::{SecurityAudit, SecurityEventType};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::net::IpAddr;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use xavyo_auth::{encode_token, JwtClaims};
use xavyo_core::{TenantId, UserId};
use xavyo_db::{RefreshToken, UserRole};
use zeroize::Zeroizing;

/// Default refresh token validity in days.
pub const REFRESH_TOKEN_VALIDITY_DAYS: i64 = 7;

/// Default access token validity in minutes.
pub const ACCESS_TOKEN_VALIDITY_MINUTES: i64 = 15;

/// Password reset token validity in hours.
pub const PASSWORD_RESET_TOKEN_VALIDITY_HOURS: i64 = 1;

/// Email verification token validity in hours.
pub const EMAIL_VERIFICATION_TOKEN_VALIDITY_HOURS: i64 = 24;

/// Size of secure tokens in bytes (256 bits of entropy).
pub const SECURE_TOKEN_BYTES: usize = 32;

/// Authentication context captured when a user completes login, surfaced as the
/// OIDC `acr` / `amr` / `auth_time` claims on the issued access token.
///
/// ACR is xavyo's scheme: `"1"` = single-factor, `"2"` = multi-factor satisfied
/// (consumed by RFC 9470 step-up). `amr` values follow RFC 8176. The
/// constructors are the single source of truth for the method→acr/amr mapping,
/// so call sites just name the method they completed.
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Authentication context class reference (`"1"` or `"2"`).
    pub acr: String,
    /// Authentication methods references (RFC 8176).
    pub amr: Vec<String>,
    /// When the end-user authentication occurred (Unix seconds).
    pub auth_time: i64,
}

impl AuthContext {
    fn now(acr: &str, amr: &[&str]) -> Self {
        Self {
            acr: acr.to_string(),
            amr: amr.iter().map(|s| (*s).to_string()).collect(),
            auth_time: Utc::now().timestamp(),
        }
    }

    /// Password only — single factor.
    #[must_use]
    pub fn password() -> Self {
        Self::now("1", &["pwd"])
    }

    /// Password + TOTP — multi-factor.
    #[must_use]
    pub fn mfa_totp() -> Self {
        Self::now("2", &["pwd", "otp", "mfa"])
    }

    /// Password + MFA recovery code — multi-factor (proves prior MFA enrollment).
    #[must_use]
    pub fn mfa_recovery_code() -> Self {
        Self::now("2", &["pwd", "mfa"])
    }

    /// WebAuthn / passkey — multi-factor, hardware-backed.
    #[must_use]
    pub fn webauthn() -> Self {
        Self::now("2", &["mfa", "hwk"])
    }

    /// Passwordless email link / OTP — single factor (a one-time credential).
    #[must_use]
    pub fn passwordless() -> Self {
        Self::now("1", &["otp"])
    }

    /// Reconstruct from stored values (e.g. carried forward across refresh).
    #[must_use]
    pub fn from_parts(acr: String, amr: Vec<String>, auth_time: i64) -> Self {
        Self {
            acr,
            amr,
            auth_time,
        }
    }
}

/// Configuration for JWT token generation.
///
/// `private_key` is held inside `Arc<Zeroizing<Vec<u8>>>` so:
/// - `Clone` stays cheap (Arc bumps a refcount; no plaintext copy)
/// - the bytes are zeroed when the last reference drops
///
/// Construct via [`TokenConfig::new`] which takes ownership of the raw
/// `Vec<u8>` and wraps it in the zeroizing buffer in one move — no extra
/// plaintext copy.
#[derive(Clone)]
pub struct TokenConfig {
    /// PEM-encoded RSA private key for signing JWTs (zeroized on drop).
    pub private_key: Arc<Zeroizing<Vec<u8>>>,
    /// Token issuer (iss claim).
    pub issuer: String,
    /// Token audience (aud claim).
    pub audience: String,
}

impl TokenConfig {
    /// Construct a `TokenConfig`, moving the PEM bytes into the zeroizing
    /// buffer. The caller's `Vec<u8>` is consumed and the only owned
    /// plaintext copy from this point on lives inside `Zeroizing`.
    #[must_use]
    pub fn new(private_key: Vec<u8>, issuer: String, audience: String) -> Self {
        Self {
            private_key: Arc::new(Zeroizing::new(private_key)),
            issuer,
            audience,
        }
    }
}

/// Service for managing JWT and refresh tokens.
#[derive(Clone)]
pub struct TokenService {
    config: TokenConfig,
    pool: PgPool,
    access_token_validity: Duration,
    refresh_token_validity: Duration,
}

impl TokenService {
    /// Create a new token service.
    #[must_use]
    pub fn new(config: TokenConfig, pool: PgPool) -> Self {
        Self {
            config,
            pool,
            access_token_validity: Duration::minutes(ACCESS_TOKEN_VALIDITY_MINUTES),
            refresh_token_validity: Duration::days(REFRESH_TOKEN_VALIDITY_DAYS),
        }
    }

    /// Create a token service with custom validity periods.
    #[must_use]
    pub fn with_validity(
        config: TokenConfig,
        pool: PgPool,
        access_token_minutes: i64,
        refresh_token_days: i64,
    ) -> Self {
        Self {
            config,
            pool,
            access_token_validity: Duration::minutes(access_token_minutes),
            refresh_token_validity: Duration::days(refresh_token_days),
        }
    }

    /// Create access and refresh tokens for a user.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user's ID
    /// * `tenant_id` - The user's tenant ID
    /// * `roles` - User's roles for the JWT claims
    /// * `email` - User's email address for the JWT claims
    /// * `auth_context` - OIDC `acr`/`amr`/`auth_time` for interactive logins;
    ///   `None` for non-interactive issuance (refresh re-issue, federated, etc.)
    /// * `user_agent` - Optional client user agent
    /// * `ip_address` - Optional client IP address
    ///
    /// # Returns
    ///
    /// A tuple of (`access_token`, `refresh_token`, `expires_in_seconds`).
    pub async fn create_tokens(
        &self,
        user_id: UserId,
        tenant_id: TenantId,
        roles: Vec<String>,
        email: Option<String>,
        auth_context: Option<AuthContext>,
        user_agent: Option<String>,
        ip_address: Option<IpAddr>,
    ) -> Result<(String, String, i64), ApiAuthError> {
        // Generate access token
        let access_token =
            self.create_access_token(user_id, tenant_id, roles, email, auth_context.as_ref())?;

        // Generate refresh token
        let refresh_token = self
            .create_refresh_token(user_id, tenant_id, user_agent, ip_address)
            .await?;

        let expires_in = self.access_token_validity.num_seconds();

        Ok((access_token, refresh_token, expires_in))
    }

    /// Create a JWT access token.
    fn create_access_token(
        &self,
        user_id: UserId,
        tenant_id: TenantId,
        roles: Vec<String>,
        email: Option<String>,
        auth_context: Option<&AuthContext>,
    ) -> Result<String, ApiAuthError> {
        let mut builder = JwtClaims::builder()
            .subject(user_id.to_string())
            .tenant_id(tenant_id)
            .issuer(&self.config.issuer)
            .audience(vec![&self.config.audience])
            .roles(roles)
            .expires_in_secs(self.access_token_validity.num_seconds());

        if let Some(email) = email {
            builder = builder.email(email);
        }

        // OIDC authentication context (acr/amr/auth_time). Emitted on
        // interactive-login tokens (always present there, so resource-side
        // step-up logic is uniform); absent when None — e.g. the refresh
        // re-issue path, which cannot yet carry forward the original context
        // (a follow-up will store + forward it).
        if let Some(ctx) = auth_context {
            builder = builder
                .acr(&ctx.acr)
                .amr(ctx.amr.clone())
                .auth_time(ctx.auth_time);
        }

        let claims = builder.build();

        encode_token(&claims, self.config.private_key.as_slice()).map_err(|e| {
            tracing::error!("Failed to encode JWT: {}", e);
            ApiAuthError::Internal(format!("Token generation error: {e}"))
        })
    }

    /// Create a partial token for MFA verification.
    ///
    /// This token is short-lived (5 minutes) and can only be used
    /// to complete MFA verification.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user's ID
    /// * `tenant_id` - The user's tenant ID
    ///
    /// # Returns
    ///
    /// A tuple of (`partial_token`, `expires_in_seconds`).
    pub fn create_partial_token(
        &self,
        user_id: UserId,
        tenant_id: TenantId,
    ) -> Result<(String, i64), ApiAuthError> {
        const MFA_TOKEN_VALIDITY_SECONDS: i64 = 300; // 5 minutes

        let claims = JwtClaims::builder()
            .subject(user_id.to_string())
            .tenant_id(tenant_id)
            .issuer(&self.config.issuer)
            .audience(vec![&self.config.audience])
            .roles(Vec::<String>::new()) // No roles in partial token
            .expires_in_secs(MFA_TOKEN_VALIDITY_SECONDS)
            .purpose("mfa_verification")
            .build();

        let token = encode_token(&claims, self.config.private_key.as_slice()).map_err(|e| {
            tracing::error!("Failed to encode partial JWT: {}", e);
            ApiAuthError::Internal(format!("Token generation error: {e}"))
        })?;

        Ok((token, MFA_TOKEN_VALIDITY_SECONDS))
    }

    /// Create an opaque refresh token and store its hash in the database.
    async fn create_refresh_token(
        &self,
        user_id: UserId,
        tenant_id: TenantId,
        user_agent: Option<String>,
        ip_address: Option<IpAddr>,
    ) -> Result<String, ApiAuthError> {
        // SECURITY: Generate a cryptographically secure random token using OsRng
        // Do NOT use Uuid::new_v4() as it is not designed for cryptographic security
        let opaque_token = generate_secure_token();
        let token_hash = hash_token(&opaque_token);
        let expires_at = Utc::now() + self.refresh_token_validity;

        // Store the hash in the database
        let query = r"
            INSERT INTO refresh_tokens (user_id, tenant_id, token_hash, expires_at, user_agent, ip_address)
            VALUES ($1, $2, $3, $4, $5, $6)
        ";

        sqlx::query(query)
            .bind(user_id.as_uuid())
            .bind(tenant_id.as_uuid())
            .bind(&token_hash)
            .bind(expires_at)
            .bind(user_agent)
            .bind(ip_address.map(|ip| ip.to_string()))
            .execute(&self.pool)
            .await?;

        Ok(opaque_token)
    }

    /// Validate a refresh token and return the associated token record.
    ///
    /// C-3: Accepts optional `expected_tenant_id` for defense-in-depth tenant isolation.
    /// When provided, the query filters by tenant_id at the DB level.
    /// When None (e.g., refresh endpoint where tenant comes from the token itself),
    /// the lookup is by hash alone — acceptable because refresh token hashes (SHA-256
    /// of 256-bit random tokens) have negligible collision probability.
    pub async fn validate_refresh_token(
        &self,
        opaque_token: &str,
    ) -> Result<RefreshToken, ApiAuthError> {
        self.validate_refresh_token_with_tenant(opaque_token, None)
            .await
    }

    /// Validate a refresh token with optional tenant_id filtering.
    pub async fn validate_refresh_token_with_tenant(
        &self,
        opaque_token: &str,
        expected_tenant_id: Option<uuid::Uuid>,
    ) -> Result<RefreshToken, ApiAuthError> {
        let token_hash = hash_token(opaque_token);

        let token: RefreshToken = if let Some(tid) = expected_tenant_id {
            // C-3: Filter by tenant_id at DB level when available
            let query = r"
                SELECT id, user_id, tenant_id, token_hash, expires_at, revoked_at, created_at, user_agent,
                       COALESCE(ip_address::text, '') as ip_address
                FROM refresh_tokens
                WHERE token_hash = $1 AND tenant_id = $2
            ";
            sqlx::query_as(query)
                .bind(&token_hash)
                .bind(tid)
                .fetch_optional(&self.pool)
                .await?
        } else {
            let query = r"
                SELECT id, user_id, tenant_id, token_hash, expires_at, revoked_at, created_at, user_agent,
                       COALESCE(ip_address::text, '') as ip_address
                FROM refresh_tokens
                WHERE token_hash = $1
            ";
            sqlx::query_as(query)
                .bind(&token_hash)
                .fetch_optional(&self.pool)
                .await?
        }
        .ok_or(ApiAuthError::InvalidToken)?;

        // Check if revoked
        if token.is_revoked() {
            tracing::warn!(
                "Attempted use of revoked refresh token: user_id={}",
                token.user_id
            );
            return Err(ApiAuthError::TokenRevoked);
        }

        // Check if expired
        if token.is_expired() {
            tracing::debug!("Refresh token expired: user_id={}", token.user_id);
            return Err(ApiAuthError::TokenExpired);
        }

        Ok(token)
    }

    /// Refresh tokens: validate the refresh token, revoke it, and issue new tokens.
    ///
    /// Implements token rotation for security.
    pub async fn refresh_tokens(
        &self,
        opaque_token: &str,
        user_agent: Option<String>,
        ip_address: Option<IpAddr>,
    ) -> Result<(String, String, i64), ApiAuthError> {
        // Validate the current refresh token
        let token = self.validate_refresh_token(opaque_token).await?;

        // Log IP change on refresh for security monitoring
        if let Some(current_ip) = ip_address {
            let current_ip_str = current_ip.to_string();
            if let Some(ref original_ip) = token.ip_address {
                if !original_ip.is_empty() && *original_ip != current_ip_str {
                    SecurityAudit::emit(
                        SecurityEventType::RefreshTokenIpChange,
                        Some(token.tenant_id),
                        Some(token.user_id),
                        Some(&current_ip_str),
                        user_agent.as_deref(),
                        "warning",
                        &format!(
                            "Refresh token used from different IP: original={}, current={}",
                            original_ip, current_ip_str
                        ),
                    );
                }
            }
        }

        // Check if user is still active (include tenant_id for defense-in-depth)
        let user_active = self.is_user_active(token.user_id, token.tenant_id).await?;
        if !user_active {
            return Err(ApiAuthError::AccountInactive);
        }

        // Revoke the old refresh token (token rotation)
        self.revoke_token_by_hash(&token.token_hash).await?;

        // Fetch user roles from database
        let roles = UserRole::get_user_roles(&self.pool, token.user_id, token.tenant_id)
            .await
            .unwrap_or_else(|_| vec!["user".to_string()]);

        // Fetch user email for JWT claims
        let email = xavyo_db::User::get_email_by_id(&self.pool, token.user_id)
            .await
            .ok()
            .flatten();

        // Issue new tokens
        let user_id = UserId::from_uuid(token.user_id);
        let tenant_id = TenantId::from_uuid(token.tenant_id);

        // FOLLOW-UP (acr/amr/auth_time): the refresh re-issue path cannot yet
        // carry forward the original authentication context — refresh_tokens does
        // not store it — so refreshed access tokens currently drop acr/amr/
        // auth_time. Must be fixed (store at issuance, forward here) before
        // step-up auth (RFC 9470) ships, or post-refresh tokens would fail
        // step-up checks.
        self.create_tokens(
            user_id, tenant_id, roles, email, None, user_agent, ip_address,
        )
        .await
    }

    /// Revoke a refresh token by its opaque value.
    pub async fn revoke_token(&self, opaque_token: &str) -> Result<(), ApiAuthError> {
        let token_hash = hash_token(opaque_token);
        self.revoke_token_by_hash(&token_hash).await
    }

    /// Revoke a refresh token by its hash.
    async fn revoke_token_by_hash(&self, token_hash: &str) -> Result<(), ApiAuthError> {
        let query = r"
            UPDATE refresh_tokens
            SET revoked_at = NOW()
            WHERE token_hash = $1 AND revoked_at IS NULL
        ";

        sqlx::query(query)
            .bind(token_hash)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Revoke all refresh tokens for a user within a tenant.
    ///
    /// M-7: Includes `tenant_id` filter for defense-in-depth tenant isolation.
    pub async fn revoke_all_user_tokens(
        &self,
        user_id: UserId,
        tenant_id: uuid::Uuid,
    ) -> Result<u64, ApiAuthError> {
        let result = sqlx::query(
            r"
            UPDATE refresh_tokens
            SET revoked_at = NOW()
            WHERE user_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
            ",
        )
        .bind(user_id.as_uuid())
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Check if a user is active (includes `tenant_id` for defense-in-depth).
    async fn is_user_active(
        &self,
        user_id: uuid::Uuid,
        tenant_id: uuid::Uuid,
    ) -> Result<bool, ApiAuthError> {
        let query = "SELECT is_active FROM users WHERE id = $1 AND tenant_id = $2";

        let active: Option<bool> = sqlx::query_scalar(query)
            .bind(user_id)
            .bind(tenant_id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(active.unwrap_or(false))
    }

    /// Get access token validity in seconds.
    #[must_use]
    pub fn access_token_validity_secs(&self) -> i64 {
        self.access_token_validity.num_seconds()
    }
}

/// Hash a token using SHA-256.
#[must_use]
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate a cryptographically secure token.
///
/// Returns a URL-safe base64-encoded string of 32 random bytes (256 bits of entropy).
/// The resulting token is 43 characters long.
///
/// SECURITY: Uses `OsRng` directly from the operating system's CSPRNG for maximum security.
/// This is preferred over `thread_rng()` for security-critical operations like token generation.
#[must_use]
pub fn generate_secure_token() -> String {
    use rand::rngs::OsRng;
    let mut bytes = [0u8; SECURE_TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Verify a token hash using constant-time comparison.
///
/// This prevents timing attacks by ensuring the comparison takes the same
/// amount of time regardless of where the first difference occurs.
///
/// # Arguments
///
/// * `provided_token` - The raw token provided by the user
/// * `stored_hash` - The SHA-256 hash stored in the database (hex-encoded)
///
/// # Returns
///
/// `true` if the token matches the hash, `false` otherwise.
#[must_use]
pub fn verify_token_hash_constant_time(provided_token: &str, stored_hash: &str) -> bool {
    let provided_hash = hash_token(provided_token);
    provided_hash
        .as_bytes()
        .ct_eq(stored_hash.as_bytes())
        .into()
}

/// Generate a password reset token and its hash.
///
/// Returns a tuple of (`raw_token`, `token_hash`).
/// The raw token should be sent to the user via email.
/// The token hash should be stored in the database.
#[must_use]
pub fn generate_password_reset_token() -> (String, String) {
    let token = generate_secure_token();
    let hash = hash_token(&token);
    (token, hash)
}

/// Generate an email verification token and its hash.
///
/// Returns a tuple of (`raw_token`, `token_hash`).
/// The raw token should be sent to the user via email.
/// The token hash should be stored in the database.
#[must_use]
pub fn generate_email_verification_token() -> (String, String) {
    let token = generate_secure_token();
    let hash = hash_token(&token);
    (token, hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_hash_deterministic() {
        let token = "test-token";
        let hash1 = hash_token(token);
        let hash2 = hash_token(token);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn different_tokens_different_hashes() {
        let hash1 = hash_token("token1");
        let hash2 = hash_token("token2");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn hash_is_hex_encoded() {
        let hash = hash_token("test");
        // SHA-256 produces 32 bytes = 64 hex characters
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn secure_token_generation() {
        let token = generate_secure_token();
        // 32 bytes in URL-safe base64 = 43 characters
        assert_eq!(token.len(), 43);
        // Should be URL-safe (no + or /)
        assert!(!token.contains('+'));
        assert!(!token.contains('/'));
        // Should be valid base64
        assert!(URL_SAFE_NO_PAD.decode(&token).is_ok());
    }

    #[test]
    fn secure_tokens_are_unique() {
        let token1 = generate_secure_token();
        let token2 = generate_secure_token();
        assert_ne!(token1, token2);
    }

    #[test]
    fn constant_time_verification_correct_token() {
        let token = "test-token-123";
        let hash = hash_token(token);
        assert!(verify_token_hash_constant_time(token, &hash));
    }

    #[test]
    fn constant_time_verification_wrong_token() {
        let correct_token = "correct-token";
        let wrong_token = "wrong-token";
        let hash = hash_token(correct_token);
        assert!(!verify_token_hash_constant_time(wrong_token, &hash));
    }

    #[test]
    fn constant_time_verification_empty_inputs() {
        let hash = hash_token("");
        assert!(verify_token_hash_constant_time("", &hash));
        assert!(!verify_token_hash_constant_time("not-empty", &hash));
    }

    #[test]
    fn password_reset_token_generation() {
        let (token, hash) = generate_password_reset_token();
        // Token should be 43 characters (32 bytes in URL-safe base64)
        assert_eq!(token.len(), 43);
        // Hash should be 64 characters (SHA-256 in hex)
        assert_eq!(hash.len(), 64);
        // Token should verify against its hash
        assert!(verify_token_hash_constant_time(&token, &hash));
    }

    #[test]
    fn email_verification_token_generation() {
        let (token, hash) = generate_email_verification_token();
        // Token should be 43 characters (32 bytes in URL-safe base64)
        assert_eq!(token.len(), 43);
        // Hash should be 64 characters (SHA-256 in hex)
        assert_eq!(hash.len(), 64);
        // Token should verify against its hash
        assert!(verify_token_hash_constant_time(&token, &hash));
    }

    #[test]
    fn auth_context_constructors_map_method_to_acr_amr() {
        // Single-factor methods → acr "1".
        assert_eq!(AuthContext::password().acr, "1");
        assert_eq!(AuthContext::password().amr, vec!["pwd".to_string()]);
        assert_eq!(AuthContext::passwordless().acr, "1");
        assert_eq!(AuthContext::passwordless().amr, vec!["otp".to_string()]);

        // Multi-factor methods → acr "2", with an "mfa" amr value so resource
        // step-up checks can be `amr.contains("mfa")`.
        for ctx in [
            AuthContext::mfa_totp(),
            AuthContext::mfa_recovery_code(),
            AuthContext::webauthn(),
        ] {
            assert_eq!(ctx.acr, "2", "MFA methods must be acr 2");
            assert!(
                ctx.amr.iter().any(|m| m == "mfa"),
                "MFA methods must include the 'mfa' amr value, got {:?}",
                ctx.amr
            );
        }

        // auth_time is populated for fresh logins.
        assert!(AuthContext::password().auth_time > 0);
    }
}
