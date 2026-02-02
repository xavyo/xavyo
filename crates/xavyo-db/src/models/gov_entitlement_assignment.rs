//! Governance Entitlement Assignment model.
//!
//! Represents entitlement assignments to users or groups.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Assignment target type (user or group).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_assignment_target_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum GovAssignmentTargetType {
    /// Assignment to a user.
    User,
    /// Assignment to a group.
    Group,
}

/// Assignment status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "gov_assignment_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum GovAssignmentStatus {
    /// Assignment is active.
    Active,
    /// Assignment is temporarily suspended.
    Suspended,
    /// Assignment has expired.
    Expired,
}

/// A governance entitlement assignment.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovEntitlementAssignment {
    /// Unique identifier for the assignment.
    pub id: Uuid,

    /// The tenant this assignment belongs to.
    pub tenant_id: Uuid,

    /// The entitlement being assigned.
    pub entitlement_id: Uuid,

    /// The type of target (user or group).
    pub target_type: GovAssignmentTargetType,

    /// The target ID (user_id or group_id).
    pub target_id: Uuid,

    /// Who assigned this entitlement.
    pub assigned_by: Uuid,

    /// When the assignment was made.
    pub assigned_at: DateTime<Utc>,

    /// When the assignment expires (optional).
    pub expires_at: Option<DateTime<Utc>>,

    /// Assignment status.
    pub status: GovAssignmentStatus,

    /// Business justification for the assignment.
    pub justification: Option<String>,

    /// SHA-256 hash of sorted parameter values (for F057 parametric roles).
    /// Allows same role to be assigned multiple times with different parameters.
    pub parameter_hash: Option<String>,

    /// When the assignment becomes active (for F057 temporal validity).
    pub valid_from: Option<DateTime<Utc>>,

    /// When the assignment becomes inactive (for F057 temporal validity).
    pub valid_to: Option<DateTime<Utc>>,

    /// When the assignment was created.
    pub created_at: DateTime<Utc>,

    /// When the assignment was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new assignment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovAssignment {
    pub entitlement_id: Uuid,
    pub target_type: GovAssignmentTargetType,
    pub target_id: Uuid,
    pub assigned_by: Uuid,
    pub expires_at: Option<DateTime<Utc>>,
    pub justification: Option<String>,
    /// SHA-256 hash of sorted parameter values (for F057 parametric roles).
    pub parameter_hash: Option<String>,
    /// When the assignment becomes active (for F057 temporal validity).
    pub valid_from: Option<DateTime<Utc>>,
    /// When the assignment becomes inactive (for F057 temporal validity).
    pub valid_to: Option<DateTime<Utc>>,
}

/// Request for bulk assignment creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkAssignmentRequest {
    pub entitlement_id: Uuid,
    pub target_type: GovAssignmentTargetType,
    pub target_ids: Vec<Uuid>,
    pub assigned_by: Uuid,
    pub expires_at: Option<DateTime<Utc>>,
    pub justification: Option<String>,
}

/// Filter options for listing governance assignments.
#[derive(Debug, Clone, Default)]
pub struct GovAssignmentFilter {
    pub entitlement_id: Option<Uuid>,
    pub target_type: Option<GovAssignmentTargetType>,
    pub target_id: Option<Uuid>,
    pub status: Option<GovAssignmentStatus>,
    pub assigned_by: Option<Uuid>,
}

/// Result of a bulk assignment operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkAssignmentResult {
    pub successful: Vec<Uuid>,
    pub failed: Vec<BulkAssignmentFailure>,
}

/// Details of a failed bulk assignment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkAssignmentFailure {
    pub target_id: Uuid,
    pub reason: String,
}

impl GovEntitlementAssignment {
    /// Find an assignment by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_entitlement_assignments
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find an existing assignment for a target.
    pub async fn find_by_target(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        entitlement_id: Uuid,
        target_type: GovAssignmentTargetType,
        target_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_entitlement_assignments
            WHERE tenant_id = $1 AND entitlement_id = $2 AND target_type = $3 AND target_id = $4
            "#,
        )
        .bind(tenant_id)
        .bind(entitlement_id)
        .bind(target_type)
        .bind(target_id)
        .fetch_optional(pool)
        .await
    }

    /// List assignments for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &GovAssignmentFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT * FROM gov_entitlement_assignments
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.entitlement_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND entitlement_id = ${}", param_count));
        }
        if filter.target_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND target_type = ${}", param_count));
        }
        if filter.target_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND target_id = ${}", param_count));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }
        if filter.assigned_by.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND assigned_by = ${}", param_count));
        }

        query.push_str(&format!(
            " ORDER BY assigned_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, GovEntitlementAssignment>(&query).bind(tenant_id);

        if let Some(entitlement_id) = filter.entitlement_id {
            q = q.bind(entitlement_id);
        }
        if let Some(target_type) = filter.target_type {
            q = q.bind(target_type);
        }
        if let Some(target_id) = filter.target_id {
            q = q.bind(target_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(assigned_by) = filter.assigned_by {
            q = q.bind(assigned_by);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count assignments in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &GovAssignmentFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r#"
            SELECT COUNT(*) FROM gov_entitlement_assignments
            WHERE tenant_id = $1
            "#,
        );
        let mut param_count = 1;

        if filter.entitlement_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND entitlement_id = ${}", param_count));
        }
        if filter.target_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND target_type = ${}", param_count));
        }
        if filter.target_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND target_id = ${}", param_count));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${}", param_count));
        }
        if filter.assigned_by.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND assigned_by = ${}", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(entitlement_id) = filter.entitlement_id {
            q = q.bind(entitlement_id);
        }
        if let Some(target_type) = filter.target_type {
            q = q.bind(target_type);
        }
        if let Some(target_id) = filter.target_id {
            q = q.bind(target_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(assigned_by) = filter.assigned_by {
            q = q.bind(assigned_by);
        }

        q.fetch_one(pool).await
    }

    /// Create a new assignment.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateGovAssignment,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_entitlement_assignments (
                tenant_id, entitlement_id, target_type, target_id, assigned_by,
                expires_at, justification, parameter_hash, valid_from, valid_to
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(input.entitlement_id)
        .bind(input.target_type)
        .bind(input.target_id)
        .bind(input.assigned_by)
        .bind(input.expires_at)
        .bind(&input.justification)
        .bind(&input.parameter_hash)
        .bind(input.valid_from)
        .bind(input.valid_to)
        .fetch_one(pool)
        .await
    }

    /// Revoke (delete) an assignment.
    pub async fn revoke(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_entitlement_assignments
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Suspend an assignment.
    pub async fn suspend(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_entitlement_assignments
            SET status = 'suspended', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Reactivate a suspended assignment.
    pub async fn reactivate(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_entitlement_assignments
            SET status = 'active', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'suspended'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// List all entitlement IDs assigned to a user (directly).
    pub async fn list_user_entitlement_ids(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT entitlement_id FROM gov_entitlement_assignments
            WHERE tenant_id = $1 AND target_type = 'user' AND target_id = $2 AND status = 'active'
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(pool)
        .await
    }

    /// List all entitlement IDs assigned to a group.
    pub async fn list_group_entitlement_ids(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        group_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT entitlement_id FROM gov_entitlement_assignments
            WHERE tenant_id = $1 AND target_type = 'group' AND target_id = $2 AND status = 'active'
            "#,
        )
        .bind(tenant_id)
        .bind(group_id)
        .fetch_all(pool)
        .await
    }

    /// Expire assignments past their expiration date.
    pub async fn expire_past_due(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            UPDATE gov_entitlement_assignments
            SET status = 'expired', updated_at = NOW()
            WHERE tenant_id = $1 AND status = 'active' AND expires_at IS NOT NULL AND expires_at < NOW()
            "#,
        )
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Check if assignment is active.
    pub fn is_active(&self) -> bool {
        matches!(self.status, GovAssignmentStatus::Active)
    }

    /// Check if assignment is expired.
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            expires_at < Utc::now()
        } else {
            false
        }
    }

    /// Get all user-entitlement mappings for role mining analysis.
    /// Returns a list of (user_id, entitlement_ids) tuples for all active assignments.
    pub async fn get_user_entitlement_mappings(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<(Uuid, Vec<Uuid>)>, sqlx::Error> {
        // Get all active user assignments grouped by user
        let rows: Vec<(Uuid, Vec<Uuid>)> = sqlx::query_as(
            r#"
            SELECT target_id as user_id, array_agg(entitlement_id) as entitlement_ids
            FROM gov_entitlement_assignments
            WHERE tenant_id = $1 AND target_type = 'user' AND status = 'active'
            GROUP BY target_id
            "#,
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await?;

        Ok(rows)
    }

    /// Get all user IDs with active assignments in a tenant.
    pub async fn get_all_assigned_user_ids(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT DISTINCT target_id
            FROM gov_entitlement_assignments
            WHERE tenant_id = $1 AND target_type = 'user' AND status = 'active'
            "#,
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    // =========================================================================
    // Parametric Role Methods (F057)
    // =========================================================================

    /// Find a parametric assignment by role, target, and parameter hash.
    pub async fn find_parametric(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        entitlement_id: Uuid,
        target_type: GovAssignmentTargetType,
        target_id: Uuid,
        parameter_hash: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_entitlement_assignments
            WHERE tenant_id = $1 AND entitlement_id = $2 AND target_type = $3
                AND target_id = $4 AND parameter_hash = $5
            "#,
        )
        .bind(tenant_id)
        .bind(entitlement_id)
        .bind(target_type)
        .bind(target_id)
        .bind(parameter_hash)
        .fetch_optional(pool)
        .await
    }

    /// List all parametric assignments for a user on a specific role.
    pub async fn list_parametric_by_user_and_role(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_entitlement_assignments
            WHERE tenant_id = $1 AND target_type = 'user' AND target_id = $2
                AND entitlement_id = $3 AND parameter_hash IS NOT NULL
            ORDER BY assigned_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(entitlement_id)
        .fetch_all(pool)
        .await
    }

    /// List all currently active parametric assignments for a user.
    /// Considers both status and temporal validity (valid_from/valid_to).
    pub async fn list_active_parametric_by_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        include_inactive: bool,
    ) -> Result<Vec<Self>, sqlx::Error> {
        if include_inactive {
            sqlx::query_as(
                r#"
                SELECT * FROM gov_entitlement_assignments
                WHERE tenant_id = $1 AND target_type = 'user' AND target_id = $2
                    AND parameter_hash IS NOT NULL
                ORDER BY entitlement_id, assigned_at DESC
                "#,
            )
            .bind(tenant_id)
            .bind(user_id)
            .fetch_all(pool)
            .await
        } else {
            sqlx::query_as(
                r#"
                SELECT * FROM gov_entitlement_assignments
                WHERE tenant_id = $1 AND target_type = 'user' AND target_id = $2
                    AND parameter_hash IS NOT NULL
                    AND status = 'active'
                    AND (valid_from IS NULL OR valid_from <= NOW())
                    AND (valid_to IS NULL OR valid_to > NOW())
                ORDER BY entitlement_id, assigned_at DESC
                "#,
            )
            .bind(tenant_id)
            .bind(user_id)
            .fetch_all(pool)
            .await
        }
    }

    /// Update the parameter hash for an assignment.
    pub async fn update_parameter_hash(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        parameter_hash: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_entitlement_assignments
            SET parameter_hash = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(parameter_hash)
        .fetch_optional(pool)
        .await
    }

    /// Update temporal validity for an assignment.
    pub async fn update_temporal_validity(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        valid_from: Option<DateTime<Utc>>,
        valid_to: Option<DateTime<Utc>>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_entitlement_assignments
            SET valid_from = $3, valid_to = $4, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(valid_from)
        .bind(valid_to)
        .fetch_optional(pool)
        .await
    }

    /// Check if assignment is temporally active (within valid_from/valid_to window).
    pub fn is_temporally_active(&self) -> bool {
        let now = Utc::now();
        let from_ok = self.valid_from.is_none_or(|from| from <= now);
        let to_ok = self.valid_to.is_none_or(|to| to > now);
        from_ok && to_ok
    }

    /// Check if this is a parametric assignment.
    pub fn is_parametric(&self) -> bool {
        self.parameter_hash.is_some()
    }

    /// Check if assignment is fully active (status + temporal validity).
    pub fn is_fully_active(&self) -> bool {
        self.is_active() && self.is_temporally_active()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_assignment_request() {
        let request = CreateGovAssignment {
            entitlement_id: Uuid::new_v4(),
            target_type: GovAssignmentTargetType::User,
            target_id: Uuid::new_v4(),
            assigned_by: Uuid::new_v4(),
            expires_at: None,
            justification: Some("Required for project X".to_string()),
            parameter_hash: None,
            valid_from: None,
            valid_to: None,
        };

        assert_eq!(request.target_type, GovAssignmentTargetType::User);
    }

    #[test]
    fn test_target_type_serialization() {
        let user = GovAssignmentTargetType::User;
        let json = serde_json::to_string(&user).unwrap();
        assert_eq!(json, "\"user\"");

        let group = GovAssignmentTargetType::Group;
        let json = serde_json::to_string(&group).unwrap();
        assert_eq!(json, "\"group\"");
    }

    #[test]
    fn test_assignment_status_serialization() {
        let active = GovAssignmentStatus::Active;
        let json = serde_json::to_string(&active).unwrap();
        assert_eq!(json, "\"active\"");
    }
}
