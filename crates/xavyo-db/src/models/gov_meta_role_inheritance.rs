//! Governance Meta-role Inheritance model (F056).
//!
//! Represents the relationship between a meta-role and a child role that inherits from it.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::InheritanceStatus;

/// An inheritance relationship between a meta-role and a child role.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovMetaRoleInheritance {
    /// Unique identifier.
    pub id: Uuid,

    /// The tenant this belongs to.
    pub tenant_id: Uuid,

    /// The parent meta-role.
    pub meta_role_id: Uuid,

    /// The child role (entitlement) that inherits.
    pub child_role_id: Uuid,

    /// Reason why this role matched (JSON format).
    pub match_reason: serde_json::Value,

    /// Current status of the inheritance.
    pub status: InheritanceStatus,

    /// When the inheritance was established.
    pub matched_at: DateTime<Utc>,

    /// When the inheritance was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new inheritance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovMetaRoleInheritance {
    pub meta_role_id: Uuid,
    pub child_role_id: Uuid,
    pub match_reason: serde_json::Value,
}

/// Filter options for listing inheritances.
#[derive(Debug, Clone, Default)]
pub struct InheritanceFilter {
    pub meta_role_id: Option<Uuid>,
    pub child_role_id: Option<Uuid>,
    pub status: Option<InheritanceStatus>,
}

impl GovMetaRoleInheritance {
    /// Find by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_meta_role_inheritances
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find by meta-role and child role.
    pub async fn find_by_meta_role_and_child(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        child_role_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_meta_role_inheritances
            WHERE tenant_id = $1 AND meta_role_id = $2 AND child_role_id = $3
            ",
        )
        .bind(tenant_id)
        .bind(meta_role_id)
        .bind(child_role_id)
        .fetch_optional(pool)
        .await
    }

    /// List all inheritances for a meta-role.
    pub async fn list_by_meta_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        status: Option<InheritanceStatus>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        if let Some(status) = status {
            sqlx::query_as(
                r"
                SELECT * FROM gov_meta_role_inheritances
                WHERE tenant_id = $1 AND meta_role_id = $2 AND status = $3
                ORDER BY matched_at ASC
                LIMIT $4 OFFSET $5
                ",
            )
            .bind(tenant_id)
            .bind(meta_role_id)
            .bind(status)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await
        } else {
            sqlx::query_as(
                r"
                SELECT * FROM gov_meta_role_inheritances
                WHERE tenant_id = $1 AND meta_role_id = $2
                ORDER BY matched_at ASC
                LIMIT $3 OFFSET $4
                ",
            )
            .bind(tenant_id)
            .bind(meta_role_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await
        }
    }

    /// List all meta-roles that apply to a child role.
    pub async fn list_by_child_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        child_role_id: Uuid,
        status: Option<InheritanceStatus>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        if let Some(status) = status {
            sqlx::query_as(
                r"
                SELECT * FROM gov_meta_role_inheritances
                WHERE tenant_id = $1 AND child_role_id = $2 AND status = $3
                ORDER BY matched_at ASC
                ",
            )
            .bind(tenant_id)
            .bind(child_role_id)
            .bind(status)
            .fetch_all(pool)
            .await
        } else {
            sqlx::query_as(
                r"
                SELECT * FROM gov_meta_role_inheritances
                WHERE tenant_id = $1 AND child_role_id = $2
                ORDER BY matched_at ASC
                ",
            )
            .bind(tenant_id)
            .bind(child_role_id)
            .fetch_all(pool)
            .await
        }
    }

    /// List inheritances with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &InheritanceFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query =
            String::from("SELECT * FROM gov_meta_role_inheritances WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.meta_role_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND meta_role_id = ${param_count}"));
        }
        if filter.child_role_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND child_role_id = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY matched_at ASC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(meta_role_id) = filter.meta_role_id {
            q = q.bind(meta_role_id);
        }
        if let Some(child_role_id) = filter.child_role_id {
            q = q.bind(child_role_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count inheritances with the same filters as `list_by_tenant`.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &InheritanceFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query =
            String::from("SELECT COUNT(*) FROM gov_meta_role_inheritances WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.meta_role_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND meta_role_id = ${param_count}"));
        }
        if filter.child_role_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND child_role_id = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(meta_role_id) = filter.meta_role_id {
            q = q.bind(meta_role_id);
        }
        if let Some(child_role_id) = filter.child_role_id {
            q = q.bind(child_role_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }

        q.fetch_one(pool).await
    }

    /// Count inheritances for a meta-role, optionally filtered by status.
    pub async fn count_by_meta_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        status: Option<InheritanceStatus>,
    ) -> Result<i64, sqlx::Error> {
        if let Some(status) = status {
            sqlx::query_scalar(
                r"
                SELECT COUNT(*) FROM gov_meta_role_inheritances
                WHERE tenant_id = $1 AND meta_role_id = $2 AND status = $3
                ",
            )
            .bind(tenant_id)
            .bind(meta_role_id)
            .bind(status)
            .fetch_one(pool)
            .await
        } else {
            sqlx::query_scalar(
                r"
                SELECT COUNT(*) FROM gov_meta_role_inheritances
                WHERE tenant_id = $1 AND meta_role_id = $2
                ",
            )
            .bind(tenant_id)
            .bind(meta_role_id)
            .fetch_one(pool)
            .await
        }
    }

    /// Count active inheritances for a meta-role.
    pub async fn count_active_by_meta_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_meta_role_inheritances
            WHERE tenant_id = $1 AND meta_role_id = $2 AND status = 'active'
            ",
        )
        .bind(tenant_id)
        .bind(meta_role_id)
        .fetch_one(pool)
        .await
    }

    /// Create a new inheritance.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovMetaRoleInheritance,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_meta_role_inheritances (
                tenant_id, meta_role_id, child_role_id, match_reason
            )
            VALUES ($1, $2, $3, $4)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.meta_role_id)
        .bind(input.child_role_id)
        .bind(&input.match_reason)
        .fetch_one(pool)
        .await
    }

    /// Update inheritance status.
    pub async fn update_status(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        status: InheritanceStatus,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_meta_role_inheritances
            SET status = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(status)
        .fetch_optional(pool)
        .await
    }

    /// Suspend all inheritances for a meta-role.
    pub async fn suspend_by_meta_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_meta_role_inheritances
            SET status = 'suspended', updated_at = NOW()
            WHERE tenant_id = $1 AND meta_role_id = $2 AND status = 'active'
            ",
        )
        .bind(tenant_id)
        .bind(meta_role_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Reactivate all suspended inheritances for a meta-role.
    pub async fn reactivate_by_meta_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        meta_role_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_meta_role_inheritances
            SET status = 'active', updated_at = NOW()
            WHERE tenant_id = $1 AND meta_role_id = $2 AND status = 'suspended'
            ",
        )
        .bind(tenant_id)
        .bind(meta_role_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Mark inheritance as removed.
    pub async fn mark_removed(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_meta_role_inheritances
            SET status = 'removed', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Delete an inheritance.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_meta_role_inheritances
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Check if inheritance is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.status == InheritanceStatus::Active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_inheritance() {
        let input = CreateGovMetaRoleInheritance {
            meta_role_id: Uuid::new_v4(),
            child_role_id: Uuid::new_v4(),
            match_reason: serde_json::json!({
                "field": "risk_level",
                "operator": "eq",
                "matched_value": "critical"
            }),
        };

        assert!(input.match_reason.is_object());
    }

    #[test]
    fn test_filter_default() {
        let filter = InheritanceFilter::default();
        assert!(filter.meta_role_id.is_none());
        assert!(filter.child_role_id.is_none());
        assert!(filter.status.is_none());
    }

    #[test]
    fn count_by_meta_role_filters_tenant_and_status() {
        let src = include_str!("gov_meta_role_inheritance.rs");
        let production = src.split("mod tests").next().expect("production source");
        let count = production
            .split("pub async fn count_by_meta_role")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("count_by_meta_role");
        assert!(
            count.contains("SELECT COUNT(*)")
                && count.contains("tenant_id = $1")
                && count.contains("meta_role_id = $2")
                && count.contains("status = $3"),
            "inheritance count must stay tenant-scoped and honor optional status"
        );
    }

    #[test]
    fn list_and_count_by_tenant_honor_child_role() {
        let src = include_str!("gov_meta_role_inheritance.rs");
        let production = src.split("mod tests").next().expect("production source");
        let list = production
            .split("pub async fn list_by_tenant")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("list_by_tenant");
        let count = production
            .split("pub async fn count_by_tenant")
            .nth(1)
            .and_then(|s| s.split("pub async fn ").next())
            .expect("count_by_tenant");
        assert!(
            list.contains("child_role_id = ${param_count}")
                && list.contains("meta_role_id = ${param_count}")
                && list.contains("status = ${param_count}"),
            "inheritance list must apply child_role_id, meta_role_id, and status"
        );
        assert!(
            count.contains("child_role_id = ${param_count}") && count.contains("SELECT COUNT(*)"),
            "inheritance count must apply child_role_id"
        );
    }
}
