//! User role entity model.
//!
//! Represents role assignments for users in the multi-tenant system.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use xavyo_core::UserId;

/// A role assignment for a user.
///
/// Roles are simple strings (e.g., "admin", "user") and are stored
/// in a normalized table with a composite primary key (`user_id`, `role_name`).
#[derive(Debug, Clone, FromRow)]
pub struct UserRole {
    /// The user this role is assigned to.
    pub user_id: uuid::Uuid,

    /// The role identifier (e.g., "admin", "user").
    pub role_name: String,

    /// When the role was assigned.
    pub created_at: DateTime<Utc>,
}

impl UserRole {
    /// Get the user ID as a typed `UserId`.
    #[must_use]
    pub fn user_id(&self) -> UserId {
        UserId::from_uuid(self.user_id)
    }

    /// Fetch all role names for a user within a tenant.
    ///
    /// Returns a list of role strings (e.g., ["admin", "user", "`super_admin`"]).
    ///
    /// M3/C1: Joins through `users` table to enforce tenant isolation even though
    /// `user_roles` doesn't have its own `tenant_id` column. This prevents
    /// cross-tenant role leakage if a user_id is guessed.
    pub async fn get_user_roles(
        pool: &sqlx::PgPool,
        user_id: uuid::Uuid,
        tenant_id: uuid::Uuid,
    ) -> Result<Vec<String>, sqlx::Error> {
        let roles: Vec<UserRole> = sqlx::query_as(
            r"SELECT ur.user_id, ur.role_name, ur.created_at
             FROM user_roles ur
             JOIN users u ON ur.user_id = u.id AND u.tenant_id = $2
             WHERE ur.user_id = $1
             LIMIT 20",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(pool)
        .await?;

        Ok(roles.into_iter().map(|r| r.role_name).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_role_user_id_conversion() {
        let uuid = uuid::Uuid::new_v4();
        let role = UserRole {
            user_id: uuid,
            role_name: "admin".to_string(),
            created_at: Utc::now(),
        };
        assert_eq!(*role.user_id().as_uuid(), uuid);
    }
}
