//! User role entity model.
//!
//! Represents role assignments for users in the multi-tenant system.

use chrono::{DateTime, Utc};
use sqlx::FromRow;
use xavyo_core::UserId;

/// A role assignment for a user.
///
/// Roles are simple strings (e.g., "admin", "user") and are stored
/// in a normalized table with a composite primary key (user_id, role_name).
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

    /// Fetch all role names for a user.
    ///
    /// Returns a list of role strings (e.g., ["admin", "user", "super_admin"]).
    pub async fn get_user_roles(
        pool: &sqlx::PgPool,
        user_id: uuid::Uuid,
    ) -> Result<Vec<String>, sqlx::Error> {
        let roles: Vec<UserRole> = sqlx::query_as(
            r#"SELECT user_id, role_name, created_at FROM user_roles WHERE user_id = $1"#,
        )
        .bind(user_id)
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
