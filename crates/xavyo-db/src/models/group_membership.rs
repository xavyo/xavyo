//! Group Membership entity model.
//!
//! Many-to-many relationship between users and groups.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A group membership linking a user to a group.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GroupMembership {
    /// Unique identifier for the membership.
    pub id: Uuid,

    /// The tenant this membership belongs to.
    pub tenant_id: Uuid,

    /// The group ID.
    pub group_id: Uuid,

    /// The user ID.
    pub user_id: Uuid,

    /// When the membership was created.
    pub created_at: DateTime<Utc>,
}

/// Member info for SCIM responses.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GroupMemberInfo {
    pub user_id: Uuid,
    pub display_name: Option<String>,
    pub email: String,
}

/// Group info for user's groups array.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct UserGroupInfo {
    pub group_id: Uuid,
    pub display_name: String,
}

impl GroupMembership {
    /// Add a user to a group.
    pub async fn add_member(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO group_memberships (tenant_id, group_id, user_id)
            VALUES ($1, $2, $3)
            ON CONFLICT (group_id, user_id) DO NOTHING
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(user_id)
        .fetch_one(pool)
        .await
    }

    /// Remove a user from a group.
    pub async fn remove_member(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM group_memberships
            WHERE tenant_id = $1 AND group_id = $2 AND user_id = $3
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Check if a user is a member of a group.
    pub async fn is_member(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        group_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result: Option<(i64,)> = sqlx::query_as(
            r"
            SELECT 1 FROM group_memberships
            WHERE tenant_id = $1 AND group_id = $2 AND user_id = $3
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(user_id)
        .fetch_optional(pool)
        .await?;

        Ok(result.is_some())
    }

    /// Get all members of a group.
    pub async fn get_group_members(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        group_id: Uuid,
    ) -> Result<Vec<GroupMemberInfo>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT u.id as user_id, u.display_name, u.email
            FROM group_memberships gm
            JOIN users u ON gm.user_id = u.id AND u.tenant_id = $1
            WHERE gm.tenant_id = $1 AND gm.group_id = $2
            ORDER BY u.email
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .fetch_all(pool)
        .await
    }

    /// Get all groups for a user.
    pub async fn get_user_groups(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<UserGroupInfo>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT g.id as group_id, g.display_name
            FROM group_memberships gm
            JOIN groups g ON gm.group_id = g.id AND g.tenant_id = $1
            WHERE gm.tenant_id = $1 AND gm.user_id = $2
            ORDER BY g.display_name
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(pool)
        .await
    }

    /// Remove all members from a group.
    pub async fn remove_all_members(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        group_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM group_memberships
            WHERE tenant_id = $1 AND group_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Set group members (replace all).
    pub async fn set_members(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        group_id: Uuid,
        user_ids: &[Uuid],
    ) -> Result<(), sqlx::Error> {
        // Start transaction
        let mut tx = pool.begin().await?;

        // Remove existing members
        sqlx::query(
            r"
            DELETE FROM group_memberships
            WHERE tenant_id = $1 AND group_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .execute(&mut *tx)
        .await?;

        // Add new members
        for user_id in user_ids {
            sqlx::query(
                r"
                INSERT INTO group_memberships (tenant_id, group_id, user_id)
                VALUES ($1, $2, $3)
                ",
            )
            .bind(tenant_id)
            .bind(group_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// Count members in a group.
    pub async fn count_members(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        group_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        let result: (i64,) = sqlx::query_as(
            r"
            SELECT COUNT(*) FROM group_memberships
            WHERE tenant_id = $1 AND group_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .fetch_one(pool)
        .await?;

        Ok(result.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_member_info() {
        let info = GroupMemberInfo {
            user_id: Uuid::new_v4(),
            display_name: Some("John Doe".to_string()),
            email: "john@example.com".to_string(),
        };

        assert_eq!(info.email, "john@example.com");
    }

    #[test]
    fn test_user_group_info() {
        let info = UserGroupInfo {
            group_id: Uuid::new_v4(),
            display_name: "Engineering".to_string(),
        };

        assert_eq!(info.display_name, "Engineering");
    }
}
