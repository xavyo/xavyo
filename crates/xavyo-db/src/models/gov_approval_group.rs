//! Governance Approval Group model (F054).
//!
//! Represents a reusable group of approvers for workflow escalation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A reusable group of approvers.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovApprovalGroup {
    /// Unique identifier for the group.
    pub id: Uuid,

    /// The tenant this group belongs to.
    pub tenant_id: Uuid,

    /// Group display name (unique within tenant).
    pub name: String,

    /// Optional description.
    pub description: Option<String>,

    /// Array of member user IDs.
    pub member_ids: Vec<Uuid>,

    /// Whether the group is active.
    pub is_active: bool,

    /// When the group was created.
    pub created_at: DateTime<Utc>,

    /// When the group was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new approval group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateApprovalGroup {
    pub name: String,
    pub description: Option<String>,
    pub member_ids: Vec<Uuid>,
}

/// Request to update an approval group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateApprovalGroup {
    pub name: Option<String>,
    pub description: Option<String>,
    pub is_active: Option<bool>,
}

/// Filter options for listing approval groups.
#[derive(Debug, Clone, Default)]
pub struct ApprovalGroupFilter {
    pub is_active: Option<bool>,
    pub member_id: Option<Uuid>,
}

impl GovApprovalGroup {
    /// Find a group by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_approval_groups
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a group by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_approval_groups
            WHERE tenant_id = $1 AND name = $2
            ",
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// List groups for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ApprovalGroupFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from("SELECT * FROM gov_approval_groups WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${param_count}"));
        }
        if filter.member_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND ${param_count} = ANY(member_ids)"));
        }

        query.push_str(&format!(
            " ORDER BY name LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(is_active) = filter.is_active {
            q = q.bind(is_active);
        }
        if let Some(member_id) = filter.member_id {
            q = q.bind(member_id);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count groups in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ApprovalGroupFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query =
            String::from("SELECT COUNT(*) FROM gov_approval_groups WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${param_count}"));
        }
        if filter.member_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND ${param_count} = ANY(member_ids)"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(is_active) = filter.is_active {
            q = q.bind(is_active);
        }
        if let Some(member_id) = filter.member_id {
            q = q.bind(member_id);
        }

        q.fetch_one(pool).await
    }

    /// Create a new approval group.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateApprovalGroup,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_approval_groups (tenant_id, name, description, member_ids)
            VALUES ($1, $2, $3, $4)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(&input.member_ids)
        .fetch_one(pool)
        .await
    }

    /// Update an approval group.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateApprovalGroup,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if input.name.is_some() {
            updates.push(format!("name = ${param_idx}"));
            param_idx += 1;
        }
        if input.description.is_some() {
            updates.push(format!("description = ${param_idx}"));
            param_idx += 1;
        }
        if input.is_active.is_some() {
            updates.push(format!("is_active = ${param_idx}"));
            // param_idx += 1;
        }

        let query = format!(
            "UPDATE gov_approval_groups SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, Self>(&query).bind(id).bind(tenant_id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(ref description) = input.description {
            q = q.bind(description);
        }
        if let Some(is_active) = input.is_active {
            q = q.bind(is_active);
        }

        q.fetch_optional(pool).await
    }

    /// Delete an approval group.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_approval_groups
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Add members to the group.
    pub async fn add_members(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        new_member_ids: &[Uuid],
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_approval_groups
            SET member_ids = (
                SELECT ARRAY(
                    SELECT DISTINCT unnest(member_ids || $3)
                )
            ),
            updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(new_member_ids)
        .fetch_optional(pool)
        .await
    }

    /// Remove members from the group.
    pub async fn remove_members(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        member_ids_to_remove: &[Uuid],
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_approval_groups
            SET member_ids = (
                SELECT ARRAY(
                    SELECT unnest(member_ids) EXCEPT SELECT unnest($3::uuid[])
                )
            ),
            updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(member_ids_to_remove)
        .fetch_optional(pool)
        .await
    }

    /// Get member count.
    #[must_use] 
    pub fn member_count(&self) -> usize {
        self.member_ids.len()
    }

    /// Check if a user is a member.
    #[must_use] 
    pub fn has_member(&self, user_id: Uuid) -> bool {
        self.member_ids.contains(&user_id)
    }

    /// Check if group is in use by any escalation levels.
    pub async fn is_in_use(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let count: i64 = sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_escalation_levels
            WHERE tenant_id = $1
              AND target_type = 'approval_group'
              AND target_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_one(pool)
        .await?;

        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_approval_group() {
        let input = CreateApprovalGroup {
            name: "Finance Approvers".to_string(),
            description: Some("Finance department approval group".to_string()),
            member_ids: vec![Uuid::new_v4(), Uuid::new_v4()],
        };

        assert_eq!(input.name, "Finance Approvers");
        assert_eq!(input.member_ids.len(), 2);
    }

    #[test]
    fn test_group_member_operations() {
        let group = GovApprovalGroup {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test Group".to_string(),
            description: None,
            member_ids: vec![Uuid::new_v4(), Uuid::new_v4()],
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert_eq!(group.member_count(), 2);
        assert!(group.has_member(group.member_ids[0]));
        assert!(!group.has_member(Uuid::new_v4()));
    }
}
