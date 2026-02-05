//! Passwordless authentication service.
//!
//! Business logic for magic link and email OTP authentication flows.
//! Handles token generation, verification, policy checking, and rate limiting.

use crate::error::ApiAuthError;
use crate::services::email_service::EmailSender;
use crate::services::token_service::{
    generate_secure_token, hash_token, verify_token_hash_constant_time, TokenService,
};
use chrono::{Duration, Utc};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;
use xavyo_core::{TenantId, UserId};
use xavyo_db::{PasswordlessPolicy, PasswordlessToken, PasswordlessTokenType, User, UserRole};

/// Maximum magic link requests per email within the rate limit window.
const EMAIL_RATE_LIMIT: usize = 5;

/// Maximum requests per IP within the rate limit window.
const IP_RATE_LIMIT: usize = 20;

/// Rate limit window in seconds (15 minutes).
const RATE_LIMIT_WINDOW_SECS: u64 = 900;

/// Result of a passwordless verification attempt.
#[derive(Debug)]
pub enum PasswordlessVerifyResult {
    /// Verification succeeded, tokens issued.
    Success {
        access_token: String,
        refresh_token: String,
        expires_in: i64,
    },
    /// MFA is required after passwordless authentication.
    MfaRequired {
        partial_token: String,
        expires_in: i64,
    },
}

/// In-memory rate limiter for passwordless endpoints.
#[derive(Debug)]
pub struct PasswordlessRateLimiter {
    /// Per-email request timestamps.
    email_requests: HashMap<String, Vec<Instant>>,
    /// Per-IP request timestamps.
    ip_requests: HashMap<IpAddr, Vec<Instant>>,
}

impl PasswordlessRateLimiter {
    /// Create a new rate limiter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            email_requests: HashMap::new(),
            ip_requests: HashMap::new(),
        }
    }

    /// Check if the email rate limit has been exceeded.
    pub fn check_email_limit(&mut self, email: &str) -> bool {
        self.cleanup_expired_entries();
        let now = Instant::now();
        let window = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);
        let key = email.to_lowercase();

        let entries = self.email_requests.entry(key).or_default();
        entries.retain(|t| now.duration_since(*t) < window);

        entries.len() < EMAIL_RATE_LIMIT
    }

    /// Check if the IP rate limit has been exceeded.
    pub fn check_ip_limit(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

        let entries = self.ip_requests.entry(ip).or_default();
        entries.retain(|t| now.duration_since(*t) < window);

        entries.len() < IP_RATE_LIMIT
    }

    /// Record a request for rate limiting.
    pub fn record_request(&mut self, email: &str, ip: IpAddr) {
        let now = Instant::now();
        let key = email.to_lowercase();

        self.email_requests.entry(key).or_default().push(now);
        self.ip_requests.entry(ip).or_default().push(now);
    }

    /// Remove expired entries from all maps.
    fn cleanup_expired_entries(&mut self) {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(RATE_LIMIT_WINDOW_SECS);

        self.email_requests.retain(|_, entries| {
            entries.retain(|t| now.duration_since(*t) < window);
            !entries.is_empty()
        });

        self.ip_requests.retain(|_, entries| {
            entries.retain(|t| now.duration_since(*t) < window);
            !entries.is_empty()
        });
    }
}

impl Default for PasswordlessRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Service for passwordless authentication flows.
#[derive(Clone)]
pub struct PasswordlessService {
    pool: PgPool,
    email_sender: Arc<dyn EmailSender>,
    token_service: Arc<TokenService>,
    rate_limiter: Arc<Mutex<PasswordlessRateLimiter>>,
}

impl PasswordlessService {
    /// Create a new passwordless service.
    pub fn new(
        pool: PgPool,
        email_sender: Arc<dyn EmailSender>,
        token_service: Arc<TokenService>,
        rate_limiter: Arc<Mutex<PasswordlessRateLimiter>>,
    ) -> Self {
        Self {
            pool,
            email_sender,
            token_service,
            rate_limiter,
        }
    }

    /// Generate a magic link token and its hash.
    fn generate_magic_link_token() -> (String, String) {
        let token = generate_secure_token();
        let hash = hash_token(&token);
        (token, hash)
    }

    /// Generate a 6-digit OTP code and its hash.
    ///
    /// SECURITY: Uses `OsRng` directly from the operating system's CSPRNG.
    fn generate_otp_code() -> (String, String) {
        use rand::rngs::OsRng;
        use rand::Rng;
        let code = OsRng.gen_range(0..1_000_000);
        let code_str = format!("{code:06}");
        let mut hasher = Sha256::new();
        hasher.update(code_str.as_bytes());
        let hash = hex::encode(hasher.finalize());
        (code_str, hash)
    }

    /// Get the passwordless policy for a tenant (or default).
    pub async fn get_policy(&self, tenant_id: Uuid) -> Result<PasswordlessPolicy, ApiAuthError> {
        PasswordlessPolicy::get_or_default(&self.pool, tenant_id)
            .await
            .map_err(|e| ApiAuthError::Internal(format!("Failed to get policy: {e}")))
    }

    /// Check if a specific method is enabled in the policy.
    fn is_method_enabled(policy: &PasswordlessPolicy, method: PasswordlessTokenType) -> bool {
        match method {
            PasswordlessTokenType::MagicLink => policy.magic_link_enabled(),
            PasswordlessTokenType::EmailOtp => policy.email_otp_enabled(),
        }
    }

    /// Request a magic link for passwordless login.
    ///
    /// Always returns success to prevent email enumeration.
    pub async fn request_magic_link(
        &self,
        tenant_id: Uuid,
        email: &str,
        ip: Option<IpAddr>,
        user_agent: Option<&str>,
    ) -> Result<i32, ApiAuthError> {
        // Check rate limits
        if let Some(ip_addr) = ip {
            let mut limiter = self.rate_limiter.lock();
            if !limiter.check_email_limit(email) || !limiter.check_ip_limit(ip_addr) {
                return Err(ApiAuthError::RateLimitExceeded);
            }
            limiter.record_request(email, ip_addr);
        }

        // Get policy and check method is enabled
        let policy = self.get_policy(tenant_id).await?;
        if !Self::is_method_enabled(&policy, PasswordlessTokenType::MagicLink) {
            return Err(ApiAuthError::Validation(
                "Magic link authentication is not enabled for this tenant.".to_string(),
            ));
        }

        let expiry_minutes = policy.magic_link_expiry_minutes;

        // Look up user by email and tenant — silently succeed if user doesn't exist
        let user = self.find_user_by_email(tenant_id, email).await?;
        if let Some(user) = user {
            // Check email is verified
            if !user.email_verified {
                // Silently return success to prevent enumeration
                return Ok(expiry_minutes);
            }

            // Check user is active
            if !user.is_active {
                return Ok(expiry_minutes);
            }

            let user_id = user.id;
            let tid = TenantId::from_uuid(tenant_id);

            // Invalidate previous magic link tokens for this user
            PasswordlessToken::invalidate_previous_for_user_type(
                &self.pool,
                tenant_id,
                user_id,
                PasswordlessTokenType::MagicLink,
            )
            .await
            .map_err(|e| ApiAuthError::Internal(format!("Failed to invalidate tokens: {e}")))?;

            // Generate token
            let (raw_token, token_hash) = Self::generate_magic_link_token();

            let expires_at = Utc::now() + Duration::minutes(i64::from(expiry_minutes));

            // Store token in database
            PasswordlessToken::create(
                &self.pool,
                tenant_id,
                user_id,
                &token_hash,
                PasswordlessTokenType::MagicLink,
                None, // no OTP code hash
                None, // no OTP attempts
                expires_at,
                ip.map(|i| i.to_string()).as_deref(),
                user_agent,
            )
            .await
            .map_err(|e| ApiAuthError::Internal(format!("Failed to create token: {e}")))?;

            // Send email with raw token
            if let Err(e) = self
                .email_sender
                .send_magic_link(email, &raw_token, tid)
                .await
            {
                tracing::error!(
                    tenant_id = %tenant_id,
                    email = email,
                    error = %e,
                    "Failed to send magic link email"
                );
            }
        }

        Ok(expiry_minutes)
    }

    /// Verify a magic link token and return tokens or MFA requirement.
    pub async fn verify_magic_link(
        &self,
        tenant_id: Uuid,
        token: &str,
        ip: Option<IpAddr>,
        user_agent: Option<&str>,
    ) -> Result<PasswordlessVerifyResult, ApiAuthError> {
        // Hash the provided token
        let token_hash = hash_token(token);

        // Look up token by hash
        let db_token = PasswordlessToken::find_by_token_hash(&self.pool, tenant_id, &token_hash)
            .await
            .map_err(|e| ApiAuthError::Internal(format!("Failed to find token: {e}")))?
            .ok_or(ApiAuthError::InvalidToken)?;

        // Verify token type
        if db_token.token_type != "magic_link" {
            return Err(ApiAuthError::InvalidToken);
        }

        // Verify tenant isolation
        if db_token.tenant_id != tenant_id {
            return Err(ApiAuthError::InvalidToken);
        }

        // Check if already used
        if db_token.is_used() {
            return Err(ApiAuthError::TokenUsed);
        }

        // Check if expired
        if db_token.is_expired() {
            return Err(ApiAuthError::TokenExpired);
        }

        // Check account lockout
        let user_id = db_token.user_id;
        self.check_lockout(tenant_id, user_id).await?;

        // Mark token as used
        PasswordlessToken::mark_used(&self.pool, tenant_id, db_token.id)
            .await
            .map_err(|e| ApiAuthError::Internal(format!("Failed to mark token used: {e}")))?;

        // Check if MFA is required
        let policy = self.get_policy(tenant_id).await?;
        if policy.require_mfa_after_passwordless {
            let uid = UserId::from_uuid(user_id);
            let tid = TenantId::from_uuid(tenant_id);
            let (partial_token, expires_in) = self.token_service.create_partial_token(uid, tid)?;
            return Ok(PasswordlessVerifyResult::MfaRequired {
                partial_token,
                expires_in,
            });
        }

        // Issue full tokens
        self.issue_tokens(tenant_id, user_id, ip, user_agent).await
    }

    /// Request an email OTP for passwordless login.
    ///
    /// Always returns success to prevent email enumeration.
    pub async fn request_email_otp(
        &self,
        tenant_id: Uuid,
        email: &str,
        ip: Option<IpAddr>,
        user_agent: Option<&str>,
    ) -> Result<i32, ApiAuthError> {
        // Check rate limits
        if let Some(ip_addr) = ip {
            let mut limiter = self.rate_limiter.lock();
            if !limiter.check_email_limit(email) || !limiter.check_ip_limit(ip_addr) {
                return Err(ApiAuthError::RateLimitExceeded);
            }
            limiter.record_request(email, ip_addr);
        }

        // Get policy and check method is enabled
        let policy = self.get_policy(tenant_id).await?;
        if !Self::is_method_enabled(&policy, PasswordlessTokenType::EmailOtp) {
            return Err(ApiAuthError::Validation(
                "Email OTP authentication is not enabled for this tenant.".to_string(),
            ));
        }

        let expiry_minutes = policy.otp_expiry_minutes;
        let max_attempts = policy.otp_max_attempts;

        // Look up user — silently succeed if user doesn't exist
        let user = self.find_user_by_email(tenant_id, email).await?;
        if let Some(user) = user {
            if !user.email_verified || !user.is_active {
                return Ok(expiry_minutes);
            }

            let user_id = user.id;
            let tid = TenantId::from_uuid(tenant_id);

            // Invalidate previous email OTP tokens
            PasswordlessToken::invalidate_previous_for_user_type(
                &self.pool,
                tenant_id,
                user_id,
                PasswordlessTokenType::EmailOtp,
            )
            .await
            .map_err(|e| ApiAuthError::Internal(format!("Failed to invalidate tokens: {e}")))?;

            // Generate token (for lookup) and OTP code
            let (raw_token, token_hash) = Self::generate_magic_link_token();
            let (otp_code, otp_code_hash) = Self::generate_otp_code();

            let expires_at = Utc::now() + Duration::minutes(i64::from(expiry_minutes));

            // Store in database
            PasswordlessToken::create(
                &self.pool,
                tenant_id,
                user_id,
                &token_hash,
                PasswordlessTokenType::EmailOtp,
                Some(&otp_code_hash),
                Some(max_attempts),
                expires_at,
                ip.map(|i| i.to_string()).as_deref(),
                user_agent,
            )
            .await
            .map_err(|e| ApiAuthError::Internal(format!("Failed to create token: {e}")))?;

            // Send OTP code via email (not the token)
            if let Err(e) = self
                .email_sender
                .send_email_otp(email, &otp_code, tid)
                .await
            {
                tracing::error!(
                    tenant_id = %tenant_id,
                    email = email,
                    error = %e,
                    "Failed to send email OTP"
                );
            }

            // Drop raw_token — user doesn't need it for OTP flow
            let _ = raw_token;
        }

        Ok(expiry_minutes)
    }

    /// Verify an email OTP code.
    pub async fn verify_email_otp(
        &self,
        tenant_id: Uuid,
        email: &str,
        code: &str,
        ip: Option<IpAddr>,
        user_agent: Option<&str>,
    ) -> Result<PasswordlessVerifyResult, ApiAuthError> {
        // Look up user by email
        let user = self
            .find_user_by_email(tenant_id, email)
            .await?
            .ok_or(ApiAuthError::InvalidCredentials)?;

        let user_id = user.id;

        // Find latest unused email_otp token for this user
        let db_token = PasswordlessToken::find_latest_for_user(
            &self.pool,
            tenant_id,
            user_id,
            PasswordlessTokenType::EmailOtp,
        )
        .await
        .map_err(|e| ApiAuthError::Internal(format!("Failed to find token: {e}")))?
        .ok_or(ApiAuthError::InvalidToken)?;

        // Check if expired
        if db_token.is_expired() {
            return Err(ApiAuthError::TokenExpired);
        }

        // Check if attempts exhausted
        if db_token.is_exhausted() {
            return Err(ApiAuthError::Validation(
                "Maximum verification attempts exceeded. Please request a new code.".to_string(),
            ));
        }

        // Constant-time compare OTP code hash
        let stored_hash = db_token
            .otp_code_hash
            .as_deref()
            .ok_or(ApiAuthError::InvalidToken)?;

        if !verify_token_hash_constant_time(code, stored_hash) {
            // Wrong code — decrement attempts
            let remaining =
                PasswordlessToken::decrement_otp_attempts(&self.pool, tenant_id, db_token.id)
                    .await
                    .map_err(|e| {
                        ApiAuthError::Internal(format!("Failed to decrement attempts: {e}"))
                    })?;

            return Err(ApiAuthError::Validation(format!(
                "Invalid verification code. {remaining} attempts remaining."
            )));
        }

        // Code is correct — check account lockout
        self.check_lockout(tenant_id, user_id).await?;

        // Mark token as used
        PasswordlessToken::mark_used(&self.pool, tenant_id, db_token.id)
            .await
            .map_err(|e| ApiAuthError::Internal(format!("Failed to mark token used: {e}")))?;

        // Check MFA requirement
        let policy = self.get_policy(tenant_id).await?;
        if policy.require_mfa_after_passwordless {
            let uid = UserId::from_uuid(user_id);
            let tid = TenantId::from_uuid(tenant_id);
            let (partial_token, expires_in) = self.token_service.create_partial_token(uid, tid)?;
            return Ok(PasswordlessVerifyResult::MfaRequired {
                partial_token,
                expires_in,
            });
        }

        // Issue full tokens
        self.issue_tokens(tenant_id, user_id, ip, user_agent).await
    }

    /// Issue access + refresh tokens for a user.
    async fn issue_tokens(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        ip: Option<IpAddr>,
        user_agent: Option<&str>,
    ) -> Result<PasswordlessVerifyResult, ApiAuthError> {
        let uid = UserId::from_uuid(user_id);
        let tid = TenantId::from_uuid(tenant_id);

        // Fetch user roles
        let roles = UserRole::get_user_roles(&self.pool, user_id)
            .await
            .unwrap_or_else(|_| vec!["user".to_string()]);

        // Fetch user email for JWT claims
        let email = User::get_email_by_id(&self.pool, user_id)
            .await
            .ok()
            .flatten();

        let (access_token, refresh_token, expires_in) = self
            .token_service
            .create_tokens(uid, tid, roles, email, user_agent.map(String::from), ip)
            .await?;

        Ok(PasswordlessVerifyResult::Success {
            access_token,
            refresh_token,
            expires_in,
        })
    }

    /// Find a user by email and tenant.
    async fn find_user_by_email(
        &self,
        tenant_id: Uuid,
        email: &str,
    ) -> Result<Option<UserBasic>, ApiAuthError> {
        let user = sqlx::query_as::<_, UserBasic>(
            r"
            SELECT id, email, email_verified, is_active
            FROM users
            WHERE tenant_id = $1 AND LOWER(email) = LOWER($2)
            ",
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    /// Check if the user's account is locked out.
    async fn check_lockout(&self, tenant_id: Uuid, user_id: Uuid) -> Result<(), ApiAuthError> {
        // Check if there's an active lockout for this user
        let locked: Option<bool> = sqlx::query_scalar(
            r"
            SELECT EXISTS(
                SELECT 1 FROM account_lockouts
                WHERE tenant_id = $1 AND user_id = $2 AND locked_until > NOW()
            )
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        if locked == Some(true) {
            return Err(ApiAuthError::AccountLocked);
        }

        Ok(())
    }
}

/// Minimal user info for passwordless authentication.
#[derive(Debug, Clone, sqlx::FromRow)]
#[allow(dead_code)]
struct UserBasic {
    pub id: Uuid,
    pub email: String,
    pub email_verified: bool,
    pub is_active: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_otp_code() {
        let (code, hash) = PasswordlessService::generate_otp_code();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(hash.len(), 64); // SHA-256 hex
                                    // Verify hash matches
        assert!(verify_token_hash_constant_time(&code, &hash));
    }

    #[test]
    fn test_generate_otp_code_uniqueness() {
        let (code1, _) = PasswordlessService::generate_otp_code();
        let (code2, _) = PasswordlessService::generate_otp_code();
        // They could be the same by chance (1/1M), but statistically unlikely
        // Just verify both are valid 6-digit codes
        assert_eq!(code1.len(), 6);
        assert_eq!(code2.len(), 6);
    }

    #[test]
    fn test_generate_magic_link_token() {
        let (token, hash) = PasswordlessService::generate_magic_link_token();
        assert_eq!(token.len(), 43); // 32 bytes base64url
        assert_eq!(hash.len(), 64); // SHA-256 hex
        assert!(verify_token_hash_constant_time(&token, &hash));
    }

    #[test]
    fn test_rate_limiter_email_allows_within_limit() {
        let mut limiter = PasswordlessRateLimiter::new();
        for _ in 0..EMAIL_RATE_LIMIT {
            assert!(limiter.check_email_limit("test@example.com"));
            limiter.record_request("test@example.com", "127.0.0.1".parse().unwrap());
        }
        // Next one should be rejected
        assert!(!limiter.check_email_limit("test@example.com"));
    }

    #[test]
    fn test_rate_limiter_ip_allows_within_limit() {
        let mut limiter = PasswordlessRateLimiter::new();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for i in 0..IP_RATE_LIMIT {
            assert!(limiter.check_ip_limit(ip));
            limiter.record_request(&format!("user{i}@example.com"), ip);
        }
        // Next one should be rejected
        assert!(!limiter.check_ip_limit(ip));
    }

    #[test]
    fn test_rate_limiter_different_emails_independent() {
        let mut limiter = PasswordlessRateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..EMAIL_RATE_LIMIT {
            limiter.record_request("a@example.com", ip);
        }
        assert!(!limiter.check_email_limit("a@example.com"));
        assert!(limiter.check_email_limit("b@example.com"));
    }

    #[test]
    fn test_rate_limiter_case_insensitive() {
        let mut limiter = PasswordlessRateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..EMAIL_RATE_LIMIT {
            limiter.record_request("Test@Example.COM", ip);
        }
        assert!(!limiter.check_email_limit("test@example.com"));
    }

    #[test]
    fn test_is_method_enabled() {
        let tenant_id = Uuid::new_v4();

        let mut policy = PasswordlessPolicy::default_for_tenant(tenant_id);
        assert!(PasswordlessService::is_method_enabled(
            &policy,
            PasswordlessTokenType::MagicLink
        ));
        assert!(PasswordlessService::is_method_enabled(
            &policy,
            PasswordlessTokenType::EmailOtp
        ));

        policy.enabled_methods = "magic_link_only".to_string();
        assert!(PasswordlessService::is_method_enabled(
            &policy,
            PasswordlessTokenType::MagicLink
        ));
        assert!(!PasswordlessService::is_method_enabled(
            &policy,
            PasswordlessTokenType::EmailOtp
        ));

        policy.enabled_methods = "otp_only".to_string();
        assert!(!PasswordlessService::is_method_enabled(
            &policy,
            PasswordlessTokenType::MagicLink
        ));
        assert!(PasswordlessService::is_method_enabled(
            &policy,
            PasswordlessTokenType::EmailOtp
        ));

        policy.enabled_methods = "disabled".to_string();
        assert!(!PasswordlessService::is_method_enabled(
            &policy,
            PasswordlessTokenType::MagicLink
        ));
        assert!(!PasswordlessService::is_method_enabled(
            &policy,
            PasswordlessTokenType::EmailOtp
        ));
    }
}
