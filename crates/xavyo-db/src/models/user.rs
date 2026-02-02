//! User entity model.
//!
//! Represents a user account in the multi-tenant system.

use chrono::{DateTime, Utc};
use serde_json;
use sqlx::FromRow;
use xavyo_core::{TenantId, UserId};

/// A user account in the system.
///
/// Users are scoped to a tenant and have tenant-isolated email uniqueness.
#[derive(Debug, Clone, FromRow)]
pub struct User {
    /// Unique identifier for the user.
    pub id: uuid::Uuid,

    /// The tenant this user belongs to.
    pub tenant_id: uuid::Uuid,

    /// User's email address (unique within tenant).
    pub email: String,

    /// Argon2id password hash.
    pub password_hash: String,

    /// User's display name.
    pub display_name: Option<String>,

    /// Whether the account is active (false = deactivated).
    pub is_active: bool,

    /// Whether the user's email address has been verified.
    pub email_verified: bool,

    /// When the email was verified (None if not yet verified).
    pub email_verified_at: Option<DateTime<Utc>>,

    /// When the user was created.
    pub created_at: DateTime<Utc>,

    /// When the user was last updated.
    pub updated_at: DateTime<Utc>,

    // SCIM fields
    /// External ID from SCIM provider (e.g., Azure AD object ID).
    pub external_id: Option<String>,

    /// User's first name (given name).
    pub first_name: Option<String>,

    /// User's last name (family name).
    pub last_name: Option<String>,

    /// Whether the user was provisioned via SCIM.
    pub scim_provisioned: bool,

    /// When the user was last synced via SCIM.
    pub scim_last_sync: Option<DateTime<Utc>>,

    // Lockout tracking fields (F024)
    /// Current count of consecutive failed login attempts.
    pub failed_login_count: i32,

    /// Timestamp of most recent failed login attempt.
    pub last_failed_login_at: Option<DateTime<Utc>>,

    /// Timestamp when account was locked (None if not locked).
    pub locked_at: Option<DateTime<Utc>>,

    /// Timestamp when lockout expires (None for permanent lockout).
    pub locked_until: Option<DateTime<Utc>>,

    /// Why account was locked: max_attempts, admin_action, security.
    pub lockout_reason: Option<String>,

    // Password expiration tracking fields (F024)
    /// Timestamp of most recent password change.
    pub password_changed_at: Option<DateTime<Utc>>,

    /// Timestamp when current password expires (None if no expiration).
    pub password_expires_at: Option<DateTime<Utc>>,

    /// Admin-forced password change required on next login.
    pub must_change_password: bool,

    // Self-service profile fields (F027)
    /// URL to user's avatar image.
    pub avatar_url: Option<String>,

    // Lifecycle state fields (F052)
    /// Current lifecycle state ID (None if no lifecycle config exists for users).
    pub lifecycle_state_id: Option<uuid::Uuid>,

    // Manager hierarchy fields (F054)
    /// Manager's user ID for escalation support. Must be in same tenant.
    pub manager_id: Option<uuid::Uuid>,

    // Custom attributes fields (F070)
    /// JSONB custom attributes for extensible user schema.
    #[sqlx(default)]
    pub custom_attributes: serde_json::Value,
}

impl User {
    /// Get the user ID as a typed `UserId`.
    #[must_use]
    pub fn user_id(&self) -> UserId {
        UserId::from_uuid(self.id)
    }

    /// Get the tenant ID as a typed `TenantId`.
    #[must_use]
    pub fn tenant_id(&self) -> TenantId {
        TenantId::from_uuid(self.tenant_id)
    }

    /// Check if the user account is currently locked.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        if self.locked_at.is_none() {
            return false;
        }

        // If locked_until is None, it's a permanent lock
        match self.locked_until {
            None => true, // Permanent lockout
            Some(until) => Utc::now() < until,
        }
    }

    /// Check if the user's password has expired.
    #[must_use]
    pub fn is_password_expired(&self) -> bool {
        match self.password_expires_at {
            None => false,
            Some(expires_at) => Utc::now() > expires_at,
        }
    }

    /// Check if the user needs to change their password.
    #[must_use]
    pub fn needs_password_change(&self) -> bool {
        self.must_change_password || self.is_password_expired()
    }

    /// Find a user by ID (without tenant filter).
    ///
    /// # Warning
    /// This method does not filter by tenant_id. Use `find_by_id_in_tenant()` for
    /// most use cases. This method should only be used when:
    /// - Looking up a user to discover their tenant_id (e.g., in event consumers)
    /// - Internal operations where tenant isolation is enforced elsewhere
    ///
    /// Always prefer `find_by_id_in_tenant()` when tenant_id is available.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        id: uuid::Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
    }

    /// Find a user by ID within a specific tenant.
    pub async fn find_by_id_in_tenant(
        pool: &sqlx::PgPool,
        tenant_id: uuid::Uuid,
        id: uuid::Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as("SELECT * FROM users WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .fetch_optional(pool)
            .await
    }

    /// Get a user's email by ID (without tenant filter).
    ///
    /// This is a lightweight query used for JWT claims during token refresh.
    pub async fn get_email_by_id(
        pool: &sqlx::PgPool,
        id: uuid::Uuid,
    ) -> Result<Option<String>, sqlx::Error> {
        let result: Option<(String,)> = sqlx::query_as("SELECT email FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?;
        Ok(result.map(|(email,)| email))
    }

    /// Check if a user exists within a specific tenant.
    pub async fn exists_in_tenant(
        pool: &sqlx::PgPool,
        tenant_id: uuid::Uuid,
        id: uuid::Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM users WHERE id = $1 AND tenant_id = $2")
                .bind(id)
                .bind(tenant_id)
                .fetch_one(pool)
                .await?;
        Ok(count.0 > 0)
    }

    /// Find a user by email within a tenant.
    pub async fn find_by_email(
        pool: &sqlx::PgPool,
        tenant_id: uuid::Uuid,
        email: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as("SELECT * FROM users WHERE tenant_id = $1 AND email = $2")
            .bind(tenant_id)
            .bind(email)
            .fetch_optional(pool)
            .await
    }

    /// Create a federated user (no password, email pre-verified).
    pub async fn create_federated(
        pool: &sqlx::PgPool,
        tenant_id: uuid::Uuid,
        email: String,
        display_name: Option<String>,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO users (tenant_id, email, password_hash, display_name, is_active, email_verified, email_verified_at)
            VALUES ($1, $2, '', $3, true, true, NOW())
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(&email)
        .bind(&display_name)
        .fetch_one(pool)
        .await
    }

    /// Update user's display name within a specific tenant.
    pub async fn update_display_name(
        pool: &sqlx::PgPool,
        tenant_id: uuid::Uuid,
        id: uuid::Uuid,
        display_name: Option<String>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE users SET display_name = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&display_name)
        .fetch_optional(pool)
        .await
    }

    /// Update user's profile fields (display_name, first_name, last_name, avatar_url) within a specific tenant.
    pub async fn update_profile(
        pool: &sqlx::PgPool,
        tenant_id: uuid::Uuid,
        id: uuid::Uuid,
        display_name: Option<String>,
        first_name: Option<String>,
        last_name: Option<String>,
        avatar_url: Option<String>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE users
            SET display_name = COALESCE($3, display_name),
                first_name = COALESCE($4, first_name),
                last_name = COALESCE($5, last_name),
                avatar_url = COALESCE($6, avatar_url),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&display_name)
        .bind(&first_name)
        .bind(&last_name)
        .bind(&avatar_url)
        .fetch_optional(pool)
        .await
    }

    /// Update user's email address (after verification) within a specific tenant.
    pub async fn update_email(
        pool: &sqlx::PgPool,
        tenant_id: uuid::Uuid,
        id: uuid::Uuid,
        new_email: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE users
            SET email = $3,
                email_verified = true,
                email_verified_at = NOW(),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(new_email)
        .fetch_optional(pool)
        .await
    }

    /// Update user's lifecycle state (F052).
    pub async fn update_lifecycle_state(
        pool: &sqlx::PgPool,
        tenant_id: uuid::Uuid,
        user_id: uuid::Uuid,
        lifecycle_state_id: Option<uuid::Uuid>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE users
            SET lifecycle_state_id = $3,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(lifecycle_state_id)
        .fetch_optional(pool)
        .await
    }

    /// Get user's current lifecycle state ID.
    pub async fn get_lifecycle_state_id(
        pool: &sqlx::PgPool,
        tenant_id: uuid::Uuid,
        user_id: uuid::Uuid,
    ) -> Result<Option<uuid::Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT lifecycle_state_id FROM users
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_one(pool)
        .await
    }

    /// Get user's manager (F054).
    pub async fn get_manager(
        pool: &sqlx::PgPool,
        tenant_id: uuid::Uuid,
        user_id: uuid::Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT m.* FROM users u
            JOIN users m ON m.id = u.manager_id AND m.tenant_id = u.tenant_id
            WHERE u.id = $1 AND u.tenant_id = $2
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Get manager chain up to specified depth (F054).
    /// Returns managers in order from direct manager to highest level.
    pub async fn get_manager_chain(
        pool: &sqlx::PgPool,
        tenant_id: uuid::Uuid,
        user_id: uuid::Uuid,
        max_depth: i32,
    ) -> Result<Vec<uuid::Uuid>, sqlx::Error> {
        let rows: Vec<(uuid::Uuid,)> = sqlx::query_as(
            r#"
            SELECT manager_id FROM get_manager_chain($1, $2, $3)
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(max_depth)
        .fetch_all(pool)
        .await?;

        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Update user's manager (F054).
    pub async fn update_manager(
        pool: &sqlx::PgPool,
        tenant_id: uuid::Uuid,
        user_id: uuid::Uuid,
        manager_id: Option<uuid::Uuid>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE users
            SET manager_id = $3,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(tenant_id)
        .bind(manager_id)
        .fetch_optional(pool)
        .await
    }

    /// Check if setting a manager would create a circular reference (F054).
    pub async fn would_create_manager_cycle(
        pool: &sqlx::PgPool,
        tenant_id: uuid::Uuid,
        user_id: uuid::Uuid,
        proposed_manager_id: uuid::Uuid,
    ) -> Result<bool, sqlx::Error> {
        // Check if user_id appears in the proposed manager's manager chain
        let chain = Self::get_manager_chain(pool, tenant_id, proposed_manager_id, 10).await?;
        Ok(chain.contains(&user_id))
    }

    // ========================================================================
    // F097: Tenant Provisioning API Methods
    // ========================================================================

    /// Create an admin user for a newly provisioned tenant.
    ///
    /// This creates a user without a password (passwordless), with email
    /// already verified since it comes from the system tenant authentication.
    pub async fn create_admin_in_tx<'e>(
        tx: &mut sqlx::Transaction<'e, sqlx::Postgres>,
        tenant_id: uuid::Uuid,
        email: &str,
        display_name: Option<&str>,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO users (
                tenant_id, email, password_hash, display_name,
                is_active, email_verified, email_verified_at
            )
            VALUES ($1, $2, '', $3, true, true, NOW())
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(email)
        .bind(display_name)
        .fetch_one(&mut **tx)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_id_conversion() {
        let uuid = uuid::Uuid::new_v4();
        let user = User {
            id: uuid,
            tenant_id: uuid::Uuid::new_v4(),
            email: "test@example.com".to_string(),
            password_hash: "hash".to_string(),
            display_name: Some("Test User".to_string()),
            is_active: true,
            email_verified: false,
            email_verified_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            external_id: None,
            first_name: None,
            last_name: None,
            scim_provisioned: false,
            scim_last_sync: None,
            // Lockout tracking fields (F024)
            failed_login_count: 0,
            last_failed_login_at: None,
            locked_at: None,
            locked_until: None,
            lockout_reason: None,
            // Password expiration tracking fields (F024)
            password_changed_at: None,
            password_expires_at: None,
            must_change_password: false,
            // Self-service profile fields (F027)
            avatar_url: None,
            // Lifecycle state fields (F052)
            lifecycle_state_id: None,
            // Manager hierarchy fields (F054)
            manager_id: None,
            // Custom attributes (F070)
            custom_attributes: serde_json::json!({}),
        };
        assert_eq!(*user.user_id().as_uuid(), uuid);
    }
}
