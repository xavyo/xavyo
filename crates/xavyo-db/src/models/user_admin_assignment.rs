//! User admin assignment model for delegated administration.
//!
//! Represents an assignment of a role template to a user with optional scope restrictions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

/// Scope type for restricting permissions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScopeType {
    Group,
    Department,
    Custom,
}

impl std::fmt::Display for ScopeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScopeType::Group => write!(f, "group"),
            ScopeType::Department => write!(f, "department"),
            ScopeType::Custom => write!(f, "custom"),
        }
    }
}

impl std::str::FromStr for ScopeType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "group" => Ok(ScopeType::Group),
            "department" => Ok(ScopeType::Department),
            "custom" => Ok(ScopeType::Custom),
            _ => Err(format!("Invalid scope type: {s}")),
        }
    }
}

/// User admin assignment entity.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserAdminAssignment {
    /// Unique identifier.
    pub id: Uuid,
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// Assigned user ID.
    pub user_id: Uuid,
    /// Role template ID.
    pub template_id: Uuid,
    /// Scope type (optional).
    pub scope_type: Option<String>,
    /// Scope values (optional).
    pub scope_value: Option<Vec<String>>,
    /// User who made the assignment.
    pub assigned_by: Uuid,
    /// When the assignment was made.
    pub assigned_at: DateTime<Utc>,
    /// When the assignment expires (optional).
    pub expires_at: Option<DateTime<Utc>>,
    /// When the assignment was revoked (optional, soft delete).
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Input for creating a new assignment.
#[derive(Debug, Clone)]
pub struct CreateAssignment {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub template_id: Uuid,
    pub scope_type: Option<String>,
    pub scope_value: Option<Vec<String>>,
    pub assigned_by: Uuid,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Filter options for listing assignments.
#[derive(Debug, Clone, Default)]
pub struct AssignmentFilter {
    pub user_id: Option<Uuid>,
    pub template_id: Option<Uuid>,
    pub include_expired: bool,
    pub include_revoked: bool,
}

impl UserAdminAssignment {
    /// Check if the assignment is currently active.
    #[must_use] 
    pub fn is_active(&self) -> bool {
        if self.revoked_at.is_some() {
            return false;
        }

        if let Some(expires_at) = self.expires_at {
            return expires_at > Utc::now();
        }

        true
    }

    /// Get the scope type as enum.
    #[must_use] 
    pub fn scope_type_enum(&self) -> Option<ScopeType> {
        self.scope_type.as_ref().and_then(|s| s.parse().ok())
    }

    /// Create a new assignment.
    pub async fn create<'e, E>(executor: E, input: CreateAssignment) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, Self>(
            r"
            INSERT INTO user_admin_assignments
                (tenant_id, user_id, template_id, scope_type, scope_value, assigned_by, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, tenant_id, user_id, template_id, scope_type, scope_value,
                      assigned_by, assigned_at, expires_at, revoked_at
            ",
        )
        .bind(input.tenant_id)
        .bind(input.user_id)
        .bind(input.template_id)
        .bind(&input.scope_type)
        .bind(&input.scope_value)
        .bind(input.assigned_by)
        .bind(input.expires_at)
        .fetch_one(executor)
        .await
    }

    /// Get an assignment by ID.
    pub async fn get_by_id<'e, E>(
        executor: E,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, user_id, template_id, scope_type, scope_value,
                   assigned_by, assigned_at, expires_at, revoked_at
            FROM user_admin_assignments
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(executor)
        .await
    }

    /// List assignments for a tenant with optional filters.
    pub async fn list<'e, E>(
        executor: E,
        tenant_id: Uuid,
        filter: &AssignmentFilter,
        cursor: Option<DateTime<Utc>>,
        limit: i32,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let mut conditions = vec!["tenant_id = $1".to_string()];
        let mut param_idx = 2;

        if filter.user_id.is_some() {
            conditions.push(format!("user_id = ${param_idx}"));
            param_idx += 1;
        }

        if filter.template_id.is_some() {
            conditions.push(format!("template_id = ${param_idx}"));
            param_idx += 1;
        }

        if !filter.include_revoked {
            conditions.push("revoked_at IS NULL".to_string());
        }

        if !filter.include_expired {
            conditions.push("(expires_at IS NULL OR expires_at > now())".to_string());
        }

        if cursor.is_some() {
            conditions.push(format!("assigned_at < ${param_idx}"));
            param_idx += 1;
        }

        let where_clause = conditions.join(" AND ");
        let query = format!(
            r"
            SELECT id, tenant_id, user_id, template_id, scope_type, scope_value,
                   assigned_by, assigned_at, expires_at, revoked_at
            FROM user_admin_assignments
            WHERE {where_clause}
            ORDER BY assigned_at DESC
            LIMIT ${param_idx}
            "
        );

        // Build the query dynamically
        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(user_id) = filter.user_id {
            q = q.bind(user_id);
        }

        if let Some(template_id) = filter.template_id {
            q = q.bind(template_id);
        }

        if let Some(c) = cursor {
            q = q.bind(c);
        }

        q = q.bind(limit);

        q.fetch_all(executor).await
    }

    /// Get active assignments for a user.
    pub async fn get_active_for_user<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, user_id, template_id, scope_type, scope_value,
                   assigned_by, assigned_at, expires_at, revoked_at
            FROM user_admin_assignments
            WHERE tenant_id = $1 AND user_id = $2
              AND revoked_at IS NULL
              AND (expires_at IS NULL OR expires_at > now())
            ORDER BY assigned_at DESC
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(executor)
        .await
    }

    /// Revoke an assignment.
    pub async fn revoke<'e, E>(
        executor: E,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, Self>(
            r"
            UPDATE user_admin_assignments
            SET revoked_at = now()
            WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL
            RETURNING id, tenant_id, user_id, template_id, scope_type, scope_value,
                      assigned_by, assigned_at, expires_at, revoked_at
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(executor)
        .await
    }

    /// Revoke all assignments for a template.
    /// Used when a template is deleted.
    pub async fn revoke_all_for_template<'e, E>(
        executor: E,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<u64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result = sqlx::query(
            r"
            UPDATE user_admin_assignments
            SET revoked_at = now()
            WHERE tenant_id = $1 AND template_id = $2 AND revoked_at IS NULL
            ",
        )
        .bind(tenant_id)
        .bind(template_id)
        .execute(executor)
        .await?;

        Ok(result.rows_affected())
    }

    /// Count active assignments for a tenant.
    pub async fn count_active<'e, E>(executor: E, tenant_id: Uuid) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let row: (i64,) = sqlx::query_as(
            r"
            SELECT COUNT(*) FROM user_admin_assignments
            WHERE tenant_id = $1 AND revoked_at IS NULL
              AND (expires_at IS NULL OR expires_at > now())
            ",
        )
        .bind(tenant_id)
        .fetch_one(executor)
        .await?;

        Ok(row.0)
    }

    /// Count all assignments for a tenant (including revoked/expired).
    pub async fn count_all<'e, E>(executor: E, tenant_id: Uuid) -> Result<i64, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let row: (i64,) = sqlx::query_as(
            r"
            SELECT COUNT(*) FROM user_admin_assignments
            WHERE tenant_id = $1
            ",
        )
        .bind(tenant_id)
        .fetch_one(executor)
        .await?;

        Ok(row.0)
    }

    /// Check if a user has any active assignments.
    pub async fn has_active_assignment<'e, E>(
        executor: E,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let row: (bool,) = sqlx::query_as(
            r"
            SELECT EXISTS(
                SELECT 1 FROM user_admin_assignments
                WHERE tenant_id = $1 AND user_id = $2
                  AND revoked_at IS NULL
                  AND (expires_at IS NULL OR expires_at > now())
            )
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(executor)
        .await?;

        Ok(row.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_type_display() {
        assert_eq!(ScopeType::Group.to_string(), "group");
        assert_eq!(ScopeType::Department.to_string(), "department");
        assert_eq!(ScopeType::Custom.to_string(), "custom");
    }

    #[test]
    fn test_scope_type_from_str() {
        assert_eq!("group".parse::<ScopeType>().unwrap(), ScopeType::Group);
        assert_eq!(
            "DEPARTMENT".parse::<ScopeType>().unwrap(),
            ScopeType::Department
        );
        assert!("invalid".parse::<ScopeType>().is_err());
    }

    #[test]
    fn test_is_active_not_revoked_no_expiry() {
        let assignment = UserAdminAssignment {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            template_id: Uuid::new_v4(),
            scope_type: None,
            scope_value: None,
            assigned_by: Uuid::new_v4(),
            assigned_at: Utc::now(),
            expires_at: None,
            revoked_at: None,
        };

        assert!(assignment.is_active());
    }

    #[test]
    fn test_is_active_revoked() {
        let assignment = UserAdminAssignment {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            template_id: Uuid::new_v4(),
            scope_type: None,
            scope_value: None,
            assigned_by: Uuid::new_v4(),
            assigned_at: Utc::now(),
            expires_at: None,
            revoked_at: Some(Utc::now()),
        };

        assert!(!assignment.is_active());
    }

    #[test]
    fn test_is_active_expired() {
        let assignment = UserAdminAssignment {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            template_id: Uuid::new_v4(),
            scope_type: None,
            scope_value: None,
            assigned_by: Uuid::new_v4(),
            assigned_at: Utc::now(),
            expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
            revoked_at: None,
        };

        assert!(!assignment.is_active());
    }
}
