//! Authentication service for user operations.
//!
//! Handles user registration, login, and credential verification.

use crate::error::ApiAuthError;
use crate::services::validation::{normalize_email, validate_email, validate_password};
use sqlx::PgPool;
use xavyo_auth::PasswordHasher;
use xavyo_core::{TenantId, UserId};
use xavyo_db::User;

/// Service for user authentication operations.
#[derive(Clone)]
pub struct AuthService {
    pool: PgPool,
    password_hasher: PasswordHasher,
}

impl AuthService {
    /// Create a new authentication service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            password_hasher: PasswordHasher::default(),
        }
    }

    /// Register a new user.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - The tenant to register the user in
    /// * `email` - User's email address
    /// * `password` - User's plaintext password
    ///
    /// # Returns
    ///
    /// The newly created user's ID.
    ///
    /// # Errors
    ///
    /// - `ApiAuthError::InvalidEmail` if email format is invalid
    /// - `ApiAuthError::WeakPassword` if password doesn't meet requirements
    /// - `ApiAuthError::EmailInUse` if email is already registered for the tenant
    pub async fn register(
        &self,
        tenant_id: TenantId,
        email: &str,
        password: &str,
    ) -> Result<(UserId, String, chrono::DateTime<chrono::Utc>), ApiAuthError> {
        // Validate email
        let email_result = validate_email(email);
        if !email_result.is_valid {
            return Err(ApiAuthError::InvalidEmail(
                email_result
                    .error.map_or_else(|| "Invalid email format".to_string(), |e| e.to_string()),
            ));
        }

        // Validate password
        let password_result = validate_password(password);
        if !password_result.is_valid {
            let errors: Vec<String> = password_result
                .errors
                .iter()
                .map(std::string::ToString::to_string)
                .collect();
            return Err(ApiAuthError::WeakPassword(errors));
        }

        // Normalize email
        let normalized_email = normalize_email(email);

        // Check if email already exists for this tenant
        let exists = self
            .email_exists_for_tenant(&normalized_email, tenant_id)
            .await?;
        if exists {
            return Err(ApiAuthError::EmailInUse);
        }

        // Hash password
        let password_hash = self
            .password_hasher
            .hash(password)
            .map_err(|e| ApiAuthError::Internal(format!("Password hashing failed: {e}")))?;

        // Insert user
        let id = uuid::Uuid::new_v4();
        let created_at = chrono::Utc::now();

        sqlx::query(
            r"
            INSERT INTO users (id, tenant_id, email, password_hash, is_active, created_at, updated_at)
            VALUES ($1, $2, $3, $4, true, $5, $5)
            ",
        )
        .bind(id)
        .bind(tenant_id.as_uuid())
        .bind(&normalized_email)
        .bind(&password_hash)
        .bind(created_at)
        .execute(&self.pool)
        .await
        ?;

        tracing::info!(
            user_id = %id,
            tenant_id = %tenant_id,
            "User registered successfully"
        );

        Ok((UserId::from_uuid(id), normalized_email, created_at))
    }

    /// Authenticate a user with email and password.
    ///
    /// # Arguments
    ///
    /// * `tenant_id` - The tenant context
    /// * `email` - User's email address
    /// * `password` - User's plaintext password
    ///
    /// # Returns
    ///
    /// The authenticated user.
    ///
    /// # Errors
    ///
    /// - `ApiAuthError::InvalidCredentials` if email/password combination is invalid
    /// - `ApiAuthError::AccountInactive` if the user account is deactivated
    pub async fn login(
        &self,
        tenant_id: TenantId,
        email: &str,
        password: &str,
    ) -> Result<User, ApiAuthError> {
        let normalized_email = normalize_email(email);

        // Find user by email and tenant
        let user: Option<User> = sqlx::query_as(
            r"
            SELECT *
            FROM users
            WHERE email = $1 AND tenant_id = $2
            ",
        )
        .bind(&normalized_email)
        .bind(tenant_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        let user = user.ok_or_else(|| {
            // Use generic error to prevent email enumeration
            tracing::debug!(email = %normalized_email, "Login attempt for non-existent user");
            ApiAuthError::InvalidCredentials
        })?;

        // Check if account is active
        if !user.is_active {
            tracing::warn!(user_id = %user.id, "Login attempt for inactive account");
            return Err(ApiAuthError::AccountInactive);
        }

        // Check if email is verified
        if !user.email_verified {
            tracing::warn!(user_id = %user.id, "Login attempt with unverified email");
            return Err(ApiAuthError::EmailNotVerified);
        }

        // Verify password
        let valid = self
            .password_hasher
            .verify(password, &user.password_hash)
            .map_err(|e| {
                tracing::error!("Password verification error: {}", e);
                ApiAuthError::Internal(format!("Password verification failed: {e}"))
            })?;

        if !valid {
            tracing::debug!(user_id = %user.id, "Invalid password attempt");
            return Err(ApiAuthError::InvalidCredentials);
        }

        tracing::info!(user_id = %user.id, "User logged in successfully");
        Ok(user)
    }

    /// Check if an email is already registered for a tenant.
    async fn email_exists_for_tenant(
        &self,
        email: &str,
        tenant_id: TenantId,
    ) -> Result<bool, ApiAuthError> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = $1 AND tenant_id = $2")
                .bind(email)
                .bind(tenant_id.as_uuid())
                .fetch_one(&self.pool)
                .await?;

        Ok(count > 0)
    }

    /// Get a user by ID.
    pub async fn get_user(&self, user_id: UserId) -> Result<Option<User>, ApiAuthError> {
        let user: Option<User> = sqlx::query_as(
            r"
            SELECT *
            FROM users
            WHERE id = $1
            ",
        )
        .bind(user_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    /// Get a user by email for a tenant.
    ///
    /// This is used for lockout tracking when we need to find a user
    /// without verifying credentials.
    pub async fn get_user_by_email(
        &self,
        tenant_id: TenantId,
        email: &str,
    ) -> Result<Option<User>, ApiAuthError> {
        let normalized_email = normalize_email(email);

        let user: Option<User> = sqlx::query_as(
            r"
            SELECT *
            FROM users
            WHERE email = $1 AND tenant_id = $2
            ",
        )
        .bind(&normalized_email)
        .bind(tenant_id.as_uuid())
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Unit tests for validation logic
    // Integration tests require database setup

    #[test]
    fn email_normalization() {
        assert_eq!(normalize_email("TEST@EXAMPLE.COM"), "test@example.com");
    }
}
