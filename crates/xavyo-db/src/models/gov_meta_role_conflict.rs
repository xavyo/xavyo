//! Governance Meta-role Conflict model (F056).
//!
//! Represents detected conflicts between meta-roles affecting the same role.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::{MetaRoleConflictType, ResolutionStatus};

/// A detected conflict between two meta-roles.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovMetaRoleConflict {
    /// Unique identifier.
    pub id: Uuid,

    /// The tenant this belongs to.
    pub tenant_id: Uuid,

    /// First conflicting meta-role (lower UUID for ordering).
    pub meta_role_a_id: Uuid,

    /// Second conflicting meta-role (higher UUID for ordering).
    pub meta_role_b_id: Uuid,

    /// The role affected by the conflict.
    pub affected_role_id: Uuid,

    /// Type of conflict.
    pub conflict_type: MetaRoleConflictType,

    /// Details of conflicting policies (JSON format).
    pub conflicting_items: serde_json::Value,

    /// Resolution status.
    pub resolution_status: ResolutionStatus,

    /// User who resolved the conflict.
    pub resolved_by: Option<Uuid>,

    /// Resolution details (JSON format).
    pub resolution_choice: Option<serde_json::Value>,

    /// When the conflict was detected.
    pub detected_at: DateTime<Utc>,

    /// When the conflict was resolved.
    pub resolved_at: Option<DateTime<Utc>>,
}

/// Request to create a new conflict record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovMetaRoleConflict {
    pub meta_role_a_id: Uuid,
    pub meta_role_b_id: Uuid,
    pub affected_role_id: Uuid,
    pub conflict_type: MetaRoleConflictType,
    pub conflicting_items: serde_json::Value,
}

/// Request to resolve a conflict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveGovMetaRoleConflict {
    pub resolution_status: ResolutionStatus,
    pub resolution_choice: Option<serde_json::Value>,
}

/// Filter options for listing conflicts.
#[derive(Debug, Clone, Default)]
pub struct MetaRoleConflictFilter {
    pub affected_role_id: Option<Uuid>,
    pub meta_role_id: Option<Uuid>,
    pub conflict_type: Option<MetaRoleConflictType>,
    pub resolution_status: Option<ResolutionStatus>,
}

impl GovMetaRoleConflict {
    /// Find by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_meta_role_conflicts
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find existing conflict between two meta-roles for a role.
    pub async fn find_existing(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_a_id: Uuid,
        meta_role_b_id: Uuid,
        affected_role_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        // Ensure ordering (a < b)
        let (a, b) = if meta_role_a_id < meta_role_b_id {
            (meta_role_a_id, meta_role_b_id)
        } else {
            (meta_role_b_id, meta_role_a_id)
        };

        sqlx::query_as(
            r"
            SELECT * FROM gov_meta_role_conflicts
            WHERE tenant_id = $1 AND meta_role_a_id = $2 AND meta_role_b_id = $3
                  AND affected_role_id = $4
            ",
        )
        .bind(tenant_id)
        .bind(a)
        .bind(b)
        .bind(affected_role_id)
        .fetch_optional(pool)
        .await
    }

    /// List unresolved conflicts for a tenant.
    pub async fn list_unresolved(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_meta_role_conflicts
            WHERE tenant_id = $1 AND resolution_status = 'unresolved'
            ORDER BY detected_at DESC
            LIMIT $2 OFFSET $3
            ",
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List conflicts for a specific role.
    pub async fn list_by_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        affected_role_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_meta_role_conflicts
            WHERE tenant_id = $1 AND affected_role_id = $2
            ORDER BY detected_at DESC
            ",
        )
        .bind(tenant_id)
        .bind(affected_role_id)
        .fetch_all(pool)
        .await
    }

    /// List conflicts involving a meta-role.
    pub async fn list_by_meta_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_meta_role_conflicts
            WHERE tenant_id = $1 AND (meta_role_a_id = $2 OR meta_role_b_id = $2)
            ORDER BY detected_at DESC
            ",
        )
        .bind(tenant_id)
        .bind(meta_role_id)
        .fetch_all(pool)
        .await
    }

    /// List conflicts with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &MetaRoleConflictFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from("SELECT * FROM gov_meta_role_conflicts WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.affected_role_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND affected_role_id = ${param_count}"));
        }
        if filter.meta_role_id.is_some() {
            param_count += 1;
            query.push_str(&format!(
                " AND (meta_role_a_id = ${param_count} OR meta_role_b_id = ${param_count})"
            ));
        }
        if filter.conflict_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND conflict_type = ${param_count}"));
        }
        if filter.resolution_status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND resolution_status = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY detected_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(affected_role_id) = filter.affected_role_id {
            q = q.bind(affected_role_id);
        }
        if let Some(meta_role_id) = filter.meta_role_id {
            q = q.bind(meta_role_id);
        }
        if let Some(conflict_type) = filter.conflict_type {
            q = q.bind(conflict_type);
        }
        if let Some(resolution_status) = filter.resolution_status {
            q = q.bind(resolution_status);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count unresolved conflicts for a tenant.
    pub async fn count_unresolved(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_meta_role_conflicts
            WHERE tenant_id = $1 AND resolution_status = 'unresolved'
            ",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await
    }

    /// List conflicts with optional status filter.
    pub async fn list(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        status: Option<ResolutionStatus>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        if let Some(status) = status {
            sqlx::query_as(
                r"
                SELECT * FROM gov_meta_role_conflicts
                WHERE tenant_id = $1 AND resolution_status = $2
                ORDER BY detected_at DESC
                LIMIT $3 OFFSET $4
                ",
            )
            .bind(tenant_id)
            .bind(status)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await
        } else {
            sqlx::query_as(
                r"
                SELECT * FROM gov_meta_role_conflicts
                WHERE tenant_id = $1
                ORDER BY detected_at DESC
                LIMIT $2 OFFSET $3
                ",
            )
            .bind(tenant_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await
        }
    }

    /// Count conflicts with optional status filter.
    pub async fn count(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        status: Option<ResolutionStatus>,
    ) -> Result<i64, sqlx::Error> {
        if let Some(status) = status {
            sqlx::query_scalar(
                r"
                SELECT COUNT(*) FROM gov_meta_role_conflicts
                WHERE tenant_id = $1 AND resolution_status = $2
                ",
            )
            .bind(tenant_id)
            .bind(status)
            .fetch_one(pool)
            .await
        } else {
            sqlx::query_scalar(
                r"
                SELECT COUNT(*) FROM gov_meta_role_conflicts
                WHERE tenant_id = $1
                ",
            )
            .bind(tenant_id)
            .fetch_one(pool)
            .await
        }
    }

    /// Count conflicts for a role with optional status filter.
    pub async fn count_by_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        role_id: Uuid,
        status: Option<ResolutionStatus>,
    ) -> Result<i64, sqlx::Error> {
        if let Some(status) = status {
            sqlx::query_scalar(
                r"
                SELECT COUNT(*) FROM gov_meta_role_conflicts
                WHERE tenant_id = $1 AND affected_role_id = $2 AND resolution_status = $3
                ",
            )
            .bind(tenant_id)
            .bind(role_id)
            .bind(status)
            .fetch_one(pool)
            .await
        } else {
            sqlx::query_scalar(
                r"
                SELECT COUNT(*) FROM gov_meta_role_conflicts
                WHERE tenant_id = $1 AND affected_role_id = $2
                ",
            )
            .bind(tenant_id)
            .bind(role_id)
            .fetch_one(pool)
            .await
        }
    }

    /// Create a new conflict record.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovMetaRoleConflict,
    ) -> Result<Self, sqlx::Error> {
        // Ensure ordering (a < b)
        let (a, b) = if input.meta_role_a_id < input.meta_role_b_id {
            (input.meta_role_a_id, input.meta_role_b_id)
        } else {
            (input.meta_role_b_id, input.meta_role_a_id)
        };

        sqlx::query_as(
            r"
            INSERT INTO gov_meta_role_conflicts (
                tenant_id, meta_role_a_id, meta_role_b_id, affected_role_id,
                conflict_type, conflicting_items
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(a)
        .bind(b)
        .bind(input.affected_role_id)
        .bind(input.conflict_type)
        .bind(&input.conflicting_items)
        .fetch_one(pool)
        .await
    }

    /// Resolve a conflict.
    pub async fn resolve(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        resolved_by: Uuid,
        input: ResolveGovMetaRoleConflict,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_meta_role_conflicts
            SET resolution_status = $3,
                resolved_by = $4,
                resolution_choice = $5,
                resolved_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND resolution_status = 'unresolved'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(input.resolution_status)
        .bind(resolved_by)
        .bind(&input.resolution_choice)
        .fetch_optional(pool)
        .await
    }

    /// Delete a conflict.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_meta_role_conflicts
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Check if conflict is unresolved.
    #[must_use] 
    pub fn is_unresolved(&self) -> bool {
        self.resolution_status == ResolutionStatus::Unresolved
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_conflict() {
        let input = CreateGovMetaRoleConflict {
            meta_role_a_id: Uuid::new_v4(),
            meta_role_b_id: Uuid::new_v4(),
            affected_role_id: Uuid::new_v4(),
            conflict_type: MetaRoleConflictType::ConstraintConflict,
            conflicting_items: serde_json::json!({
                "constraint_type": "max_session_duration",
                "value_a": { "hours": 4 },
                "value_b": { "hours": 8 }
            }),
        };

        assert_eq!(
            input.conflict_type,
            MetaRoleConflictType::ConstraintConflict
        );
    }

    #[test]
    fn test_filter_default() {
        let filter = MetaRoleConflictFilter::default();
        assert!(filter.affected_role_id.is_none());
        assert!(filter.meta_role_id.is_none());
        assert!(filter.conflict_type.is_none());
        assert!(filter.resolution_status.is_none());
    }
}
