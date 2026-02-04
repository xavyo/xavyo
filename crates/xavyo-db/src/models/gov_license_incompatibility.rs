//! License Incompatibility model (F065).
//!
//! Defines rules for license pools that cannot be assigned to the same user
//! (similar to `SoD` rules for entitlements).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use super::gov_license_types::LicenseIncompatibilityId;

/// A rule defining two license pools that cannot be assigned to the same user.
///
/// For example, you might define that a user cannot have both
/// "Adobe Creative Cloud Individual" and "Adobe Creative Cloud Teams" licenses.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovLicenseIncompatibility {
    /// Unique identifier for the rule.
    pub id: Uuid,

    /// The tenant this rule belongs to.
    pub tenant_id: Uuid,

    /// First pool in the incompatible pair.
    pub pool_a_id: Uuid,

    /// Second pool in the incompatible pair.
    pub pool_b_id: Uuid,

    /// Reason for the incompatibility.
    pub reason: String,

    /// When the rule was created.
    pub created_at: DateTime<Utc>,

    /// Who created this rule.
    pub created_by: Uuid,
}

/// Request to create a new incompatibility rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovLicenseIncompatibility {
    /// First pool in the incompatible pair.
    pub pool_a_id: Uuid,

    /// Second pool in the incompatible pair.
    pub pool_b_id: Uuid,

    /// Reason for the incompatibility.
    pub reason: String,

    /// Who is creating this rule.
    pub created_by: Uuid,
}

/// Filter options for querying incompatibility rules.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LicenseIncompatibilityFilter {
    /// Filter by pool (matches either `pool_a` or `pool_b`).
    pub pool_id: Option<Uuid>,
}

/// Incompatibility with pool details for display.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct LicenseIncompatibilityWithDetails {
    /// The rule itself.
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub pool_a_id: Uuid,
    pub pool_b_id: Uuid,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub created_by: Uuid,

    /// Pool A name.
    pub pool_a_name: Option<String>,

    /// Pool A vendor.
    pub pool_a_vendor: Option<String>,

    /// Pool B name.
    pub pool_b_name: Option<String>,

    /// Pool B vendor.
    pub pool_b_vendor: Option<String>,
}

/// Result of checking for incompatibility violations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncompatibilityViolation {
    /// The incompatibility rule that was violated.
    pub rule_id: Uuid,

    /// The pool the user already has.
    pub existing_pool_id: Uuid,

    /// Name of the existing pool.
    pub existing_pool_name: String,

    /// The pool being requested.
    pub requested_pool_id: Uuid,

    /// Name of the requested pool.
    pub requested_pool_name: String,

    /// The reason for incompatibility.
    pub reason: String,
}

impl GovLicenseIncompatibility {
    // ========================================================================
    // QUERIES
    // ========================================================================

    /// Find an incompatibility rule by ID.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: LicenseIncompatibilityId,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            SELECT
                id,
                tenant_id,
                pool_a_id,
                pool_b_id,
                reason,
                created_at,
                created_by
            FROM gov_license_incompatibilities
            WHERE tenant_id = $1 AND id = $2
            "#,
            tenant_id,
            id.inner()
        )
        .fetch_optional(pool)
        .await
    }

    /// Find all incompatibility rules involving a specific pool.
    pub async fn find_by_pool(
        pool: &PgPool,
        tenant_id: Uuid,
        pool_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            SELECT
                id,
                tenant_id,
                pool_a_id,
                pool_b_id,
                reason,
                created_at,
                created_by
            FROM gov_license_incompatibilities
            WHERE tenant_id = $1
              AND (pool_a_id = $2 OR pool_b_id = $2)
            ORDER BY created_at DESC
            "#,
            tenant_id,
            pool_id
        )
        .fetch_all(pool)
        .await
    }

    /// Check if two pools are incompatible.
    pub async fn are_incompatible(
        pool: &PgPool,
        tenant_id: Uuid,
        pool_a_id: Uuid,
        pool_b_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        // Use LEAST/GREATEST to handle both orderings (symmetric lookup)
        // Need explicit casts for LEAST/GREATEST with UUID parameters
        sqlx::query_as!(
            Self,
            r#"
            SELECT
                id,
                tenant_id,
                pool_a_id,
                pool_b_id,
                reason,
                created_at,
                created_by
            FROM gov_license_incompatibilities
            WHERE tenant_id = $1
              AND LEAST(pool_a_id, pool_b_id) = LEAST($2::uuid, $3::uuid)
              AND GREATEST(pool_a_id, pool_b_id) = GREATEST($2::uuid, $3::uuid)
            "#,
            tenant_id,
            pool_a_id,
            pool_b_id
        )
        .fetch_optional(pool)
        .await
    }

    /// Check if a pool is incompatible with any pools the user already has.
    ///
    /// Returns the list of violations (incompatible pools the user has).
    pub async fn check_user_violations(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        requested_pool_id: Uuid,
    ) -> Result<Vec<IncompatibilityViolation>, sqlx::Error> {
        sqlx::query_as!(
            IncompatibilityViolation,
            r#"
            SELECT
                i.id as rule_id,
                CASE
                    WHEN i.pool_a_id = $3 THEN i.pool_b_id
                    ELSE i.pool_a_id
                END as "existing_pool_id!: Uuid",
                CASE
                    WHEN i.pool_a_id = $3 THEN pb.name
                    ELSE pa.name
                END as "existing_pool_name!",
                $3 as "requested_pool_id!: Uuid",
                rp.name as "requested_pool_name!",
                i.reason
            FROM gov_license_incompatibilities i
            JOIN gov_license_pools pa ON pa.id = i.pool_a_id
            JOIN gov_license_pools pb ON pb.id = i.pool_b_id
            JOIN gov_license_pools rp ON rp.id = $3
            WHERE i.tenant_id = $1
              AND (i.pool_a_id = $3 OR i.pool_b_id = $3)
              AND EXISTS (
                  SELECT 1 FROM gov_license_assignments a
                  WHERE a.tenant_id = $1
                    AND a.user_id = $2
                    AND a.status = 'active'
                    AND a.license_pool_id = CASE
                        WHEN i.pool_a_id = $3 THEN i.pool_b_id
                        ELSE i.pool_a_id
                    END
              )
            "#,
            tenant_id,
            user_id,
            requested_pool_id
        )
        .fetch_all(pool)
        .await
    }

    /// List all incompatibility rules with optional filtering.
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &LicenseIncompatibilityFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            SELECT
                id,
                tenant_id,
                pool_a_id,
                pool_b_id,
                reason,
                created_at,
                created_by
            FROM gov_license_incompatibilities
            WHERE tenant_id = $1
              AND ($2::uuid IS NULL OR pool_a_id = $2 OR pool_b_id = $2)
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            "#,
            tenant_id,
            filter.pool_id,
            limit,
            offset
        )
        .fetch_all(pool)
        .await
    }

    /// List incompatibilities with pool details.
    pub async fn list_with_details(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &LicenseIncompatibilityFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<LicenseIncompatibilityWithDetails>, sqlx::Error> {
        sqlx::query_as!(
            LicenseIncompatibilityWithDetails,
            r#"
            SELECT
                i.id,
                i.tenant_id,
                i.pool_a_id,
                i.pool_b_id,
                i.reason,
                i.created_at,
                i.created_by,
                pa.name as pool_a_name,
                pa.vendor as pool_a_vendor,
                pb.name as pool_b_name,
                pb.vendor as pool_b_vendor
            FROM gov_license_incompatibilities i
            LEFT JOIN gov_license_pools pa ON pa.id = i.pool_a_id
            LEFT JOIN gov_license_pools pb ON pb.id = i.pool_b_id
            WHERE i.tenant_id = $1
              AND ($2::uuid IS NULL OR i.pool_a_id = $2 OR i.pool_b_id = $2)
            ORDER BY i.created_at DESC
            LIMIT $3 OFFSET $4
            "#,
            tenant_id,
            filter.pool_id,
            limit,
            offset
        )
        .fetch_all(pool)
        .await
    }

    /// Count incompatibility rules matching filter.
    pub async fn count(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &LicenseIncompatibilityFilter,
    ) -> Result<i64, sqlx::Error> {
        let result = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM gov_license_incompatibilities
            WHERE tenant_id = $1
              AND ($2::uuid IS NULL OR pool_a_id = $2 OR pool_b_id = $2)
            "#,
            tenant_id,
            filter.pool_id
        )
        .fetch_one(pool)
        .await?;

        Ok(result)
    }

    // ========================================================================
    // MUTATIONS
    // ========================================================================

    /// Create a new incompatibility rule.
    ///
    /// Note: The database has a symmetric unique index, so (A, B) and (B, A)
    /// are treated as the same rule.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        req: &CreateGovLicenseIncompatibility,
    ) -> Result<Self, sqlx::Error> {
        let id = LicenseIncompatibilityId::new();

        // Normalize ordering for consistent storage
        let (pool_a, pool_b) = if req.pool_a_id < req.pool_b_id {
            (req.pool_a_id, req.pool_b_id)
        } else {
            (req.pool_b_id, req.pool_a_id)
        };

        sqlx::query_as!(
            Self,
            r#"
            INSERT INTO gov_license_incompatibilities (
                id, tenant_id, pool_a_id, pool_b_id, reason, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING
                id,
                tenant_id,
                pool_a_id,
                pool_b_id,
                reason,
                created_at,
                created_by
            "#,
            id.inner(),
            tenant_id,
            pool_a,
            pool_b,
            req.reason,
            req.created_by
        )
        .fetch_one(pool)
        .await
    }

    /// Update the reason for an incompatibility rule.
    pub async fn update_reason(
        pool: &PgPool,
        tenant_id: Uuid,
        id: LicenseIncompatibilityId,
        reason: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            UPDATE gov_license_incompatibilities
            SET reason = $3
            WHERE tenant_id = $1 AND id = $2
            RETURNING
                id,
                tenant_id,
                pool_a_id,
                pool_b_id,
                reason,
                created_at,
                created_by
            "#,
            tenant_id,
            id.inner(),
            reason
        )
        .fetch_optional(pool)
        .await
    }

    /// Delete an incompatibility rule.
    pub async fn delete(
        pool: &PgPool,
        tenant_id: Uuid,
        id: LicenseIncompatibilityId,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query!(
            r#"
            DELETE FROM gov_license_incompatibilities
            WHERE tenant_id = $1 AND id = $2
            "#,
            tenant_id,
            id.inner()
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete all incompatibility rules involving a pool.
    pub async fn delete_by_pool(
        pool: &PgPool,
        tenant_id: Uuid,
        pool_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query!(
            r#"
            DELETE FROM gov_license_incompatibilities
            WHERE tenant_id = $1
              AND (pool_a_id = $2 OR pool_b_id = $2)
            "#,
            tenant_id,
            pool_id
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_request() {
        let req = CreateGovLicenseIncompatibility {
            pool_a_id: Uuid::new_v4(),
            pool_b_id: Uuid::new_v4(),
            reason: "Redundant licenses".to_string(),
            created_by: Uuid::new_v4(),
        };

        assert!(!req.reason.is_empty());
    }

    #[test]
    fn test_filter_default() {
        let filter = LicenseIncompatibilityFilter::default();
        assert!(filter.pool_id.is_none());
    }
}
