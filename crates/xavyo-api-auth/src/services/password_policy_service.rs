//! Password policy service.
//!
//! Handles password validation against tenant policies, history checking, and expiration.

use crate::error::ApiAuthError;
use chrono::{Duration, Utc};
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;
use xavyo_db::{set_tenant_context, PasswordHistory, TenantPasswordPolicy, UpsertPasswordPolicy};

/// Special characters allowed in passwords.
pub const SPECIAL_CHARS: &str = "!@#$%^&*()_+-=[]{}|;:,.<>?";

/// Password validation error types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordPolicyError {
    /// Password is too short.
    TooShort { min: i32, actual: usize },
    /// Password is too long.
    TooLong { max: i32, actual: usize },
    /// Missing uppercase letter.
    MissingUppercase,
    /// Missing lowercase letter.
    MissingLowercase,
    /// Missing digit.
    MissingDigit,
    /// Missing special character.
    MissingSpecialChar,
    /// Password was recently used.
    RecentlyUsed,
    /// Password changed too recently (min age not met).
    TooSoonToChange { min_hours: i32 },
}

impl std::fmt::Display for PasswordPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { min, actual } => {
                write!(
                    f,
                    "Password must be at least {min} characters (got {actual})"
                )
            }
            Self::TooLong { max, actual } => {
                write!(
                    f,
                    "Password must be at most {max} characters (got {actual})"
                )
            }
            Self::MissingUppercase => {
                write!(f, "Password must contain at least one uppercase letter")
            }
            Self::MissingLowercase => {
                write!(f, "Password must contain at least one lowercase letter")
            }
            Self::MissingDigit => write!(f, "Password must contain at least one digit"),
            Self::MissingSpecialChar => {
                write!(f, "Password must contain at least one special character")
            }
            Self::RecentlyUsed => {
                write!(
                    f,
                    "Password was recently used. Please choose a different password"
                )
            }
            Self::TooSoonToChange { min_hours } => {
                write!(
                    f,
                    "Password can only be changed after {min_hours} hours from the last change"
                )
            }
        }
    }
}

/// Result of password validation against policy.
#[derive(Debug, Clone)]
pub struct PasswordValidationResult {
    /// Whether the password is valid.
    pub is_valid: bool,
    /// List of validation errors (empty if valid).
    pub errors: Vec<PasswordPolicyError>,
}

impl PasswordValidationResult {
    /// Create a valid result.
    #[must_use]
    pub fn valid() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
        }
    }

    /// Create a result with errors.
    #[must_use]
    pub fn with_errors(errors: Vec<PasswordPolicyError>) -> Self {
        Self {
            is_valid: errors.is_empty(),
            errors,
        }
    }

    /// Get all error messages as a single string.
    #[must_use]
    pub fn error_message(&self) -> String {
        self.errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Password policy service for validating passwords against tenant policies.
#[derive(Clone)]
pub struct PasswordPolicyService {
    pool: PgPool,
}

impl PasswordPolicyService {
    /// Create a new password policy service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Validate a password against the tenant's policy.
    ///
    /// This checks length and character requirements only.
    /// Use `check_password_history` separately for history validation.
    #[must_use]
    pub fn validate_password(
        password: &str,
        policy: &TenantPasswordPolicy,
    ) -> PasswordValidationResult {
        let mut errors = Vec::new();
        let len = password.chars().count();

        // Length checks
        if len < policy.min_length as usize {
            errors.push(PasswordPolicyError::TooShort {
                min: policy.min_length,
                actual: len,
            });
        }

        if len > policy.max_length as usize {
            errors.push(PasswordPolicyError::TooLong {
                max: policy.max_length,
                actual: len,
            });
        }

        // Character class checks (only if required by policy)
        if policy.require_uppercase && !password.chars().any(|c| c.is_ascii_uppercase()) {
            errors.push(PasswordPolicyError::MissingUppercase);
        }

        if policy.require_lowercase && !password.chars().any(|c| c.is_ascii_lowercase()) {
            errors.push(PasswordPolicyError::MissingLowercase);
        }

        if policy.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
            errors.push(PasswordPolicyError::MissingDigit);
        }

        if policy.require_special && !password.chars().any(|c| SPECIAL_CHARS.contains(c)) {
            errors.push(PasswordPolicyError::MissingSpecialChar);
        }

        PasswordValidationResult::with_errors(errors)
    }

    /// Get the password policy for a tenant.
    pub async fn get_password_policy(
        &self,
        tenant_id: Uuid,
    ) -> Result<TenantPasswordPolicy, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        TenantPasswordPolicy::get_or_default(&mut *conn, tenant_id)
            .await
            .map_err(ApiAuthError::Database)
    }

    /// Update the password policy for a tenant.
    pub async fn update_password_policy(
        &self,
        tenant_id: Uuid,
        data: UpsertPasswordPolicy,
    ) -> Result<TenantPasswordPolicy, ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let policy = TenantPasswordPolicy::upsert(&mut *conn, tenant_id, data)
            .await
            .map_err(ApiAuthError::Database)?;

        info!(tenant_id = %tenant_id, "Password policy updated");

        Ok(policy)
    }

    /// Check if a password matches any in the user's recent history.
    ///
    /// Returns true if the password was recently used and should be rejected.
    pub async fn check_password_history(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        password: &str,
        history_count: i32,
    ) -> Result<bool, ApiAuthError> {
        if history_count <= 0 {
            return Ok(false); // History check disabled
        }

        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let history = PasswordHistory::get_recent(&mut *conn, user_id, tenant_id, history_count)
            .await
            .map_err(ApiAuthError::Database)?;

        // Check each historical password hash
        for entry in history {
            if xavyo_auth::verify_password(password, &entry.password_hash)
                .map_err(|e| ApiAuthError::Internal(e.to_string()))?
            {
                warn!(
                    user_id = %user_id,
                    "Password matches recent history, rejecting"
                );
                return Ok(true); // Password was recently used
            }
        }

        Ok(false) // Password not in history
    }

    /// Add a password hash to the user's history.
    pub async fn add_to_password_history(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        password_hash: &str,
        max_history: i32,
    ) -> Result<(), ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        // Add new entry
        PasswordHistory::create(&mut *conn, user_id, tenant_id, password_hash)
            .await
            .map_err(ApiAuthError::Database)?;

        // Prune old entries if we have a limit
        if max_history > 0 {
            let pruned = PasswordHistory::prune(&mut *conn, user_id, tenant_id, max_history)
                .await
                .map_err(ApiAuthError::Database)?;

            if pruned > 0 {
                info!(
                    user_id = %user_id,
                    pruned_count = pruned,
                    "Pruned old password history entries"
                );
            }
        }

        Ok(())
    }

    /// Check if a user's password has expired.
    pub fn check_password_expired(
        password_changed_at: Option<chrono::DateTime<chrono::Utc>>,
        expiration_days: i32,
    ) -> bool {
        if expiration_days <= 0 {
            return false; // Expiration disabled
        }

        let changed_at = match password_changed_at {
            Some(dt) => dt,
            None => return true, // No password change recorded, consider expired
        };

        let expires_at = changed_at + Duration::days(i64::from(expiration_days));
        Utc::now() > expires_at
    }

    /// Check if minimum password age requirement is met.
    ///
    /// Returns an error if the password was changed too recently.
    pub fn check_min_password_age(
        password_changed_at: Option<chrono::DateTime<chrono::Utc>>,
        min_age_hours: i32,
    ) -> Result<(), PasswordPolicyError> {
        if min_age_hours <= 0 {
            return Ok(()); // Min age disabled
        }

        let changed_at = match password_changed_at {
            Some(dt) => dt,
            None => return Ok(()), // No previous password, allow change
        };

        let can_change_at = changed_at + Duration::hours(i64::from(min_age_hours));
        if Utc::now() < can_change_at {
            return Err(PasswordPolicyError::TooSoonToChange {
                min_hours: min_age_hours,
            });
        }

        Ok(())
    }

    /// Calculate the password expiration timestamp based on policy.
    ///
    /// Returns None if expiration is disabled (expiration_days = 0).
    #[must_use]
    pub fn calculate_password_expiration(
        expiration_days: i32,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        if expiration_days <= 0 {
            return None;
        }

        Some(Utc::now() + Duration::days(i64::from(expiration_days)))
    }

    /// Update user's password timestamps after a password change.
    ///
    /// This should be called after successfully changing a user's password.
    pub async fn update_password_timestamps(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        expiration_days: i32,
    ) -> Result<(), ApiAuthError> {
        let mut conn = self.pool.acquire().await.map_err(ApiAuthError::Database)?;
        set_tenant_context(&mut *conn, xavyo_core::TenantId::from_uuid(tenant_id))
            .await
            .map_err(ApiAuthError::DatabaseInternal)?;

        let now = Utc::now();
        let expires_at = Self::calculate_password_expiration(expiration_days);

        sqlx::query(
            r#"
            UPDATE users
            SET password_changed_at = $2,
                password_expires_at = $3,
                must_change_password = false,
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .bind(now)
        .bind(expires_at)
        .execute(&mut *conn)
        .await
        .map_err(ApiAuthError::Database)?;

        info!(
            user_id = %user_id,
            expires_at = ?expires_at,
            "Updated password timestamps"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_policy() -> TenantPasswordPolicy {
        TenantPasswordPolicy::default()
    }

    fn strict_policy() -> TenantPasswordPolicy {
        TenantPasswordPolicy {
            min_length: 12,
            max_length: 64,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: true,
            expiration_days: 90,
            history_count: 5,
            min_age_hours: 24,
            ..default_policy()
        }
    }

    #[test]
    fn test_validate_password_default_policy() {
        let policy = default_policy();

        // Valid: 8 chars, no requirements
        let result = PasswordPolicyService::validate_password("password", &policy);
        assert!(result.is_valid);

        // Invalid: too short
        let result = PasswordPolicyService::validate_password("short", &policy);
        assert!(!result.is_valid);
        assert!(matches!(
            result.errors.first(),
            Some(PasswordPolicyError::TooShort { .. })
        ));
    }

    #[test]
    fn test_validate_password_strict_policy() {
        let policy = strict_policy();

        // Valid: meets all requirements
        let result = PasswordPolicyService::validate_password("SecureP@ss123!", &policy);
        assert!(result.is_valid);

        // Invalid: missing uppercase
        let result = PasswordPolicyService::validate_password("securep@ss123!", &policy);
        assert!(!result.is_valid);
        assert!(result
            .errors
            .contains(&PasswordPolicyError::MissingUppercase));

        // Invalid: missing digit
        let result = PasswordPolicyService::validate_password("SecureP@ssword!", &policy);
        assert!(!result.is_valid);
        assert!(result.errors.contains(&PasswordPolicyError::MissingDigit));

        // Invalid: missing special
        let result = PasswordPolicyService::validate_password("SecurePassword123", &policy);
        assert!(!result.is_valid);
        assert!(result
            .errors
            .contains(&PasswordPolicyError::MissingSpecialChar));

        // Invalid: too short
        let result = PasswordPolicyService::validate_password("Aa1!", &policy);
        assert!(!result.is_valid);
        assert!(matches!(
            result.errors.first(),
            Some(PasswordPolicyError::TooShort { min: 12, .. })
        ));
    }

    #[test]
    fn test_validate_password_too_long() {
        let policy = strict_policy();
        let long_pass = "A".repeat(100) + "a1!";
        let result = PasswordPolicyService::validate_password(&long_pass, &policy);
        assert!(!result.is_valid);
        assert!(matches!(
            result.errors.first(),
            Some(PasswordPolicyError::TooLong { max: 64, .. })
        ));
    }

    #[test]
    fn test_check_password_expired() {
        // No expiration
        assert!(!PasswordPolicyService::check_password_expired(
            Some(Utc::now()),
            0
        ));

        // Not expired
        assert!(!PasswordPolicyService::check_password_expired(
            Some(Utc::now()),
            90
        ));

        // Expired
        let old_date = Utc::now() - Duration::days(100);
        assert!(PasswordPolicyService::check_password_expired(
            Some(old_date),
            90
        ));

        // No password change recorded
        assert!(PasswordPolicyService::check_password_expired(None, 90));
    }

    #[test]
    fn test_check_min_password_age() {
        // No min age
        assert!(PasswordPolicyService::check_min_password_age(Some(Utc::now()), 0).is_ok());

        // Min age met
        let old_date = Utc::now() - Duration::hours(48);
        assert!(PasswordPolicyService::check_min_password_age(Some(old_date), 24).is_ok());

        // Min age not met
        let recent_date = Utc::now() - Duration::hours(12);
        let result = PasswordPolicyService::check_min_password_age(Some(recent_date), 24);
        assert!(matches!(
            result,
            Err(PasswordPolicyError::TooSoonToChange { min_hours: 24 })
        ));

        // No previous password
        assert!(PasswordPolicyService::check_min_password_age(None, 24).is_ok());
    }

    #[test]
    fn test_calculate_password_expiration() {
        // Disabled
        assert!(PasswordPolicyService::calculate_password_expiration(0).is_none());

        // Enabled
        let expires = PasswordPolicyService::calculate_password_expiration(90);
        assert!(expires.is_some());
        let diff = expires.unwrap() - Utc::now();
        assert!(diff.num_days() >= 89 && diff.num_days() <= 90);
    }

    #[test]
    fn test_error_message() {
        let result = PasswordValidationResult::with_errors(vec![
            PasswordPolicyError::TooShort { min: 12, actual: 8 },
            PasswordPolicyError::MissingUppercase,
        ]);
        let msg = result.error_message();
        assert!(msg.contains("at least 12 characters"));
        assert!(msg.contains("uppercase"));
    }
}
