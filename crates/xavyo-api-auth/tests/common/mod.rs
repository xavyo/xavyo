//! Test helpers for xavyo-api-auth integration tests.
//!
//! Provides utilities for setting up test database, mock services,
//! and common test fixtures.

#![allow(dead_code)]

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::time::Duration;
use uuid::Uuid;
use xavyo_api_auth::services::{generate_secure_token, hash_token};
use xavyo_core::{TenantId, UserId};

/// Test database URL environment variable.
pub const TEST_DATABASE_URL_ENV: &str = "TEST_DATABASE_URL";

/// Get test database connection pool.
///
/// Uses `TEST_DATABASE_URL` environment variable, falls back to default test database.
pub async fn get_test_pool() -> PgPool {
    let database_url = std::env::var(TEST_DATABASE_URL_ENV)
        .unwrap_or_else(|_| "postgres://xavyo:xavyo@localhost:5432/xavyo_test".to_string());

    PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await
        .expect("Failed to connect to test database")
}

/// Create a test tenant and return its ID.
pub async fn create_test_tenant(pool: &PgPool) -> TenantId {
    let id = Uuid::new_v4();
    let slug = format!("test-tenant-{}", &id.to_string()[..8]);

    sqlx::query(
        r"
        INSERT INTO tenants (id, name, slug, settings, created_at)
        VALUES ($1, $2, $3, '{}', NOW())
        ON CONFLICT (id) DO NOTHING
        ",
    )
    .bind(id)
    .bind(&slug)
    .bind(&slug)
    .execute(pool)
    .await
    .expect("Failed to create test tenant");

    TenantId::from_uuid(id)
}

/// Create a test user and return its ID.
pub async fn create_test_user(
    pool: &PgPool,
    tenant_id: TenantId,
    email: &str,
    password_hash: &str,
) -> UserId {
    create_test_user_with_options(pool, tenant_id, email, password_hash, true, true).await
}

/// Create a test user with custom options for `is_active` and `email_verified`.
pub async fn create_test_user_with_options(
    pool: &PgPool,
    tenant_id: TenantId,
    email: &str,
    password_hash: &str,
    is_active: bool,
    email_verified: bool,
) -> UserId {
    let id = Uuid::new_v4();
    let email_verified_at = if email_verified {
        Some(Utc::now())
    } else {
        None
    };

    sqlx::query(
        r"
        INSERT INTO users (id, tenant_id, email, password_hash, is_active, email_verified, email_verified_at, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
        ",
    )
    .bind(id)
    .bind(tenant_id.as_uuid())
    .bind(email)
    .bind(password_hash)
    .bind(is_active)
    .bind(email_verified)
    .bind(email_verified_at)
    .execute(pool)
    .await
    .expect("Failed to create test user");

    UserId::from_uuid(id)
}

/// Set tenant context for the test connection.
pub async fn set_tenant_context(pool: &PgPool, tenant_id: TenantId) {
    sqlx::query(&format!(
        "SET LOCAL app.current_tenant = '{}'",
        tenant_id.as_uuid()
    ))
    .execute(pool)
    .await
    .expect("Failed to set tenant context");
}

/// Clean up test data for a specific tenant.
pub async fn cleanup_test_tenant(pool: &PgPool, tenant_id: TenantId) {
    // Delete password reset tokens first (foreign key constraint)
    sqlx::query("DELETE FROM password_reset_tokens WHERE tenant_id = $1")
        .bind(tenant_id.as_uuid())
        .execute(pool)
        .await
        .ok();

    // Delete email verification tokens
    sqlx::query("DELETE FROM email_verification_tokens WHERE tenant_id = $1")
        .bind(tenant_id.as_uuid())
        .execute(pool)
        .await
        .ok();

    // Delete refresh tokens (foreign key constraint)
    sqlx::query("DELETE FROM refresh_tokens WHERE tenant_id = $1")
        .bind(tenant_id.as_uuid())
        .execute(pool)
        .await
        .ok();

    // Delete users
    sqlx::query("DELETE FROM users WHERE tenant_id = $1")
        .bind(tenant_id.as_uuid())
        .execute(pool)
        .await
        .ok();

    // Delete tenant
    sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant_id.as_uuid())
        .execute(pool)
        .await
        .ok();
}

/// Test fixture for a complete auth test setup.
pub struct TestFixture {
    pub pool: PgPool,
    pub tenant_id: TenantId,
}

impl TestFixture {
    /// Create a new test fixture with a fresh tenant.
    pub async fn new() -> Self {
        let pool = get_test_pool().await;
        let tenant_id = create_test_tenant(&pool).await;

        Self { pool, tenant_id }
    }

    /// Clean up the test fixture.
    pub async fn cleanup(&self) {
        cleanup_test_tenant(&self.pool, self.tenant_id).await;
    }

    /// Create a user in this fixture's tenant.
    pub async fn create_user(&self, email: &str, password_hash: &str) -> UserId {
        create_test_user(&self.pool, self.tenant_id, email, password_hash).await
    }
}

/// Generate a test password that meets all requirements.
#[must_use]
pub fn valid_test_password() -> &'static str {
    "TestP@ss123"
}

/// Generate an invalid test password (too short).
#[must_use]
pub fn invalid_test_password_short() -> &'static str {
    "Aa1!"
}

/// Generate an invalid test password (no special char).
#[must_use]
pub fn invalid_test_password_no_special() -> &'static str {
    "TestPass123"
}

/// Generate a valid test email.
#[must_use]
pub fn valid_test_email() -> String {
    format!("test-{}@example.com", Uuid::new_v4())
}

/// Generate an invalid test email.
#[must_use]
pub fn invalid_test_email() -> &'static str {
    "not-an-email"
}

/// Create a test password reset token and return (`raw_token`, `token_hash`).
pub fn create_test_password_reset_token() -> (String, String) {
    let token = generate_secure_token();
    let hash = hash_token(&token);
    (token, hash)
}

/// Create a test email verification token and return (`raw_token`, `token_hash`).
pub fn create_test_verification_token() -> (String, String) {
    let token = generate_secure_token();
    let hash = hash_token(&token);
    (token, hash)
}

/// Insert a password reset token into the database for testing.
pub async fn insert_password_reset_token(
    pool: &PgPool,
    tenant_id: TenantId,
    user_id: UserId,
    token_hash: &str,
    expires_at: DateTime<Utc>,
) -> Uuid {
    let id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO password_reset_tokens (id, tenant_id, user_id, token_hash, expires_at, created_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
        ",
    )
    .bind(id)
    .bind(tenant_id.as_uuid())
    .bind(user_id.as_uuid())
    .bind(token_hash)
    .bind(expires_at)
    .execute(pool)
    .await
    .expect("Failed to insert password reset token");

    id
}

/// Insert an email verification token into the database for testing.
pub async fn insert_email_verification_token(
    pool: &PgPool,
    tenant_id: TenantId,
    user_id: UserId,
    token_hash: &str,
    expires_at: DateTime<Utc>,
) -> Uuid {
    let id = Uuid::new_v4();

    sqlx::query(
        r"
        INSERT INTO email_verification_tokens (id, tenant_id, user_id, token_hash, expires_at, created_at)
        VALUES ($1, $2, $3, $4, $5, NOW())
        ",
    )
    .bind(id)
    .bind(tenant_id.as_uuid())
    .bind(user_id.as_uuid())
    .bind(token_hash)
    .bind(expires_at)
    .execute(pool)
    .await
    .expect("Failed to insert email verification token");

    id
}

/// Mark a password reset token as used.
pub async fn mark_password_reset_token_used(pool: &PgPool, token_hash: &str) {
    sqlx::query("UPDATE password_reset_tokens SET used_at = NOW() WHERE token_hash = $1")
        .bind(token_hash)
        .execute(pool)
        .await
        .expect("Failed to mark token as used");
}

/// Mark an email verification token as verified.
pub async fn mark_verification_token_verified(pool: &PgPool, token_hash: &str) {
    sqlx::query("UPDATE email_verification_tokens SET verified_at = NOW() WHERE token_hash = $1")
        .bind(token_hash)
        .execute(pool)
        .await
        .expect("Failed to mark token as verified");
}

/// Create an expired password reset token (1 hour ago).
pub async fn insert_expired_password_reset_token(
    pool: &PgPool,
    tenant_id: TenantId,
    user_id: UserId,
    token_hash: &str,
) -> Uuid {
    let expires_at = Utc::now() - ChronoDuration::hours(1);
    insert_password_reset_token(pool, tenant_id, user_id, token_hash, expires_at).await
}

/// Create an expired email verification token (24 hours ago).
pub async fn insert_expired_verification_token(
    pool: &PgPool,
    tenant_id: TenantId,
    user_id: UserId,
    token_hash: &str,
) -> Uuid {
    let expires_at = Utc::now() - ChronoDuration::hours(24);
    insert_email_verification_token(pool, tenant_id, user_id, token_hash, expires_at).await
}

/// Create a valid (not expired) password reset token.
pub async fn insert_valid_password_reset_token(
    pool: &PgPool,
    tenant_id: TenantId,
    user_id: UserId,
    token_hash: &str,
) -> Uuid {
    let expires_at = Utc::now() + ChronoDuration::hours(1);
    insert_password_reset_token(pool, tenant_id, user_id, token_hash, expires_at).await
}

/// Create a valid (not expired) email verification token.
pub async fn insert_valid_verification_token(
    pool: &PgPool,
    tenant_id: TenantId,
    user_id: UserId,
    token_hash: &str,
) -> Uuid {
    let expires_at = Utc::now() + ChronoDuration::hours(24);
    insert_email_verification_token(pool, tenant_id, user_id, token_hash, expires_at).await
}

/// Update user to set `email_verified` status.
pub async fn set_user_email_verified(pool: &PgPool, user_id: UserId, verified: bool) {
    if verified {
        sqlx::query(
            "UPDATE users SET email_verified = true, email_verified_at = NOW() WHERE id = $1",
        )
        .bind(user_id.as_uuid())
        .execute(pool)
        .await
        .expect("Failed to update user email_verified");
    } else {
        sqlx::query(
            "UPDATE users SET email_verified = false, email_verified_at = NULL WHERE id = $1",
        )
        .bind(user_id.as_uuid())
        .execute(pool)
        .await
        .expect("Failed to update user email_verified");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_password_meets_requirements() {
        let password = valid_test_password();
        assert!(password.len() >= 8);
        assert!(password.chars().any(|c| c.is_ascii_uppercase()));
        assert!(password.chars().any(|c| c.is_ascii_lowercase()));
        assert!(password.chars().any(|c| c.is_ascii_digit()));
        assert!(password
            .chars()
            .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c)));
    }

    #[test]
    fn valid_email_format() {
        let email = valid_test_email();
        assert!(email.contains('@'));
        assert!(email.ends_with("@example.com"));
    }
}
