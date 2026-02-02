//! License Reclamation Rule model (F065).
//!
//! Defines rules for automatically reclaiming licenses from users
//! based on inactivity or lifecycle state changes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use super::gov_license_types::{
    LicenseReclamationRuleId, LicenseReclamationTrigger, DEFAULT_NOTIFICATION_DAYS_BEFORE,
};

/// A rule for automatically reclaiming licenses.
///
/// Reclamation can be triggered by:
/// - Inactivity: User hasn't logged in for N days
/// - Lifecycle state: User enters a specific state (e.g., terminated, on_leave)
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovLicenseReclamationRule {
    /// Unique identifier for the rule.
    pub id: Uuid,

    /// The tenant this rule belongs to.
    pub tenant_id: Uuid,

    /// The license pool this rule applies to.
    pub license_pool_id: Uuid,

    /// Type of trigger (inactivity or lifecycle_state).
    pub trigger_type: LicenseReclamationTrigger,

    /// Days of inactivity before reclamation (for inactivity trigger).
    pub threshold_days: Option<i32>,

    /// Lifecycle state that triggers reclamation (for lifecycle_state trigger).
    pub lifecycle_state: Option<String>,

    /// Days before reclamation to notify the user.
    pub notification_days_before: i32,

    /// Whether this rule is active.
    pub enabled: bool,

    /// When the rule was created.
    pub created_at: DateTime<Utc>,

    /// When the rule was last updated.
    pub updated_at: DateTime<Utc>,

    /// Who created this rule.
    pub created_by: Uuid,
}

/// Request to create a new reclamation rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGovLicenseReclamationRule {
    /// The license pool this rule applies to.
    pub license_pool_id: Uuid,

    /// Type of trigger.
    pub trigger_type: LicenseReclamationTrigger,

    /// Days of inactivity (required for inactivity trigger).
    pub threshold_days: Option<i32>,

    /// Lifecycle state (required for lifecycle_state trigger).
    pub lifecycle_state: Option<String>,

    /// Days before reclamation to notify user (default: 7).
    pub notification_days_before: Option<i32>,

    /// Whether this rule is enabled (default: true).
    pub enabled: Option<bool>,

    /// Who is creating this rule.
    pub created_by: Uuid,
}

/// Request to update a reclamation rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdateGovLicenseReclamationRule {
    /// Update threshold days.
    pub threshold_days: Option<i32>,

    /// Update lifecycle state.
    pub lifecycle_state: Option<String>,

    /// Update notification days.
    pub notification_days_before: Option<i32>,

    /// Update enabled status.
    pub enabled: Option<bool>,
}

/// Filter options for querying reclamation rules.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LicenseReclamationRuleFilter {
    /// Filter by license pool.
    pub license_pool_id: Option<Uuid>,

    /// Filter by trigger type.
    pub trigger_type: Option<LicenseReclamationTrigger>,

    /// Filter by enabled status.
    pub enabled: Option<bool>,
}

/// Reclamation rule with pool details for display.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct LicenseReclamationRuleWithDetails {
    /// The rule itself.
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub license_pool_id: Uuid,
    pub trigger_type: LicenseReclamationTrigger,
    pub threshold_days: Option<i32>,
    pub lifecycle_state: Option<String>,
    pub notification_days_before: i32,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: Uuid,

    /// Pool name.
    pub pool_name: Option<String>,

    /// Pool vendor.
    pub pool_vendor: Option<String>,
}

/// User assignment eligible for reclamation based on a rule.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ReclamationCandidate {
    /// The assignment ID.
    pub assignment_id: Uuid,

    /// The user ID.
    pub user_id: Uuid,

    /// User's email (for notifications).
    pub user_email: Option<String>,

    /// The license pool ID.
    pub license_pool_id: Uuid,

    /// Pool name.
    pub pool_name: String,

    /// The rule that triggered this candidate.
    pub rule_id: Uuid,

    /// Days until reclamation.
    pub days_until_reclamation: i32,

    /// Whether notification has been sent.
    pub notification_sent: bool,
}

impl GovLicenseReclamationRule {
    // ========================================================================
    // QUERIES
    // ========================================================================

    /// Find a rule by ID.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: LicenseReclamationRuleId,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            SELECT
                id,
                tenant_id,
                license_pool_id,
                trigger_type as "trigger_type: LicenseReclamationTrigger",
                threshold_days,
                lifecycle_state,
                notification_days_before,
                enabled,
                created_at,
                updated_at,
                created_by
            FROM gov_license_reclamation_rules
            WHERE tenant_id = $1 AND id = $2
            "#,
            tenant_id,
            id.inner()
        )
        .fetch_optional(pool)
        .await
    }

    /// Find all rules for a license pool.
    pub async fn find_by_pool(
        pool: &PgPool,
        tenant_id: Uuid,
        license_pool_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            SELECT
                id,
                tenant_id,
                license_pool_id,
                trigger_type as "trigger_type: LicenseReclamationTrigger",
                threshold_days,
                lifecycle_state,
                notification_days_before,
                enabled,
                created_at,
                updated_at,
                created_by
            FROM gov_license_reclamation_rules
            WHERE tenant_id = $1 AND license_pool_id = $2
            ORDER BY created_at ASC
            "#,
            tenant_id,
            license_pool_id
        )
        .fetch_all(pool)
        .await
    }

    /// Find all enabled rules for a tenant (for batch reclamation processing).
    pub async fn find_enabled(pool: &PgPool, tenant_id: Uuid) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            SELECT
                id,
                tenant_id,
                license_pool_id,
                trigger_type as "trigger_type: LicenseReclamationTrigger",
                threshold_days,
                lifecycle_state,
                notification_days_before,
                enabled,
                created_at,
                updated_at,
                created_by
            FROM gov_license_reclamation_rules
            WHERE tenant_id = $1 AND enabled = true
            ORDER BY license_pool_id, trigger_type
            "#,
            tenant_id
        )
        .fetch_all(pool)
        .await
    }

    /// Find enabled inactivity rules for batch processing.
    pub async fn find_enabled_inactivity_rules(
        pool: &PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            SELECT
                id,
                tenant_id,
                license_pool_id,
                trigger_type as "trigger_type: LicenseReclamationTrigger",
                threshold_days,
                lifecycle_state,
                notification_days_before,
                enabled,
                created_at,
                updated_at,
                created_by
            FROM gov_license_reclamation_rules
            WHERE tenant_id = $1
              AND enabled = true
              AND trigger_type = 'inactivity'
            ORDER BY license_pool_id
            "#,
            tenant_id
        )
        .fetch_all(pool)
        .await
    }

    /// Find enabled lifecycle state rules for a specific state.
    pub async fn find_enabled_lifecycle_rules(
        pool: &PgPool,
        tenant_id: Uuid,
        lifecycle_state: &str,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            SELECT
                id,
                tenant_id,
                license_pool_id,
                trigger_type as "trigger_type: LicenseReclamationTrigger",
                threshold_days,
                lifecycle_state,
                notification_days_before,
                enabled,
                created_at,
                updated_at,
                created_by
            FROM gov_license_reclamation_rules
            WHERE tenant_id = $1
              AND enabled = true
              AND trigger_type = 'lifecycle_state'
              AND lifecycle_state = $2
            ORDER BY license_pool_id
            "#,
            tenant_id,
            lifecycle_state
        )
        .fetch_all(pool)
        .await
    }

    /// List rules with optional filtering.
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &LicenseReclamationRuleFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            SELECT
                id,
                tenant_id,
                license_pool_id,
                trigger_type as "trigger_type: LicenseReclamationTrigger",
                threshold_days,
                lifecycle_state,
                notification_days_before,
                enabled,
                created_at,
                updated_at,
                created_by
            FROM gov_license_reclamation_rules
            WHERE tenant_id = $1
              AND ($2::uuid IS NULL OR license_pool_id = $2)
              AND ($3::text IS NULL OR trigger_type::text = $3)
              AND ($4::boolean IS NULL OR enabled = $4)
            ORDER BY created_at DESC
            LIMIT $5 OFFSET $6
            "#,
            tenant_id,
            filter.license_pool_id,
            filter.trigger_type.as_ref().map(|t| match t {
                LicenseReclamationTrigger::Inactivity => "inactivity",
                LicenseReclamationTrigger::LifecycleState => "lifecycle_state",
            }),
            filter.enabled,
            limit,
            offset
        )
        .fetch_all(pool)
        .await
    }

    /// List rules with pool details.
    pub async fn list_with_details(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &LicenseReclamationRuleFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<LicenseReclamationRuleWithDetails>, sqlx::Error> {
        sqlx::query_as!(
            LicenseReclamationRuleWithDetails,
            r#"
            SELECT
                r.id,
                r.tenant_id,
                r.license_pool_id,
                r.trigger_type as "trigger_type: LicenseReclamationTrigger",
                r.threshold_days,
                r.lifecycle_state,
                r.notification_days_before,
                r.enabled,
                r.created_at,
                r.updated_at,
                r.created_by,
                p.name as pool_name,
                p.vendor as pool_vendor
            FROM gov_license_reclamation_rules r
            LEFT JOIN gov_license_pools p ON p.id = r.license_pool_id
            WHERE r.tenant_id = $1
              AND ($2::uuid IS NULL OR r.license_pool_id = $2)
              AND ($3::text IS NULL OR r.trigger_type::text = $3)
              AND ($4::boolean IS NULL OR r.enabled = $4)
            ORDER BY r.created_at DESC
            LIMIT $5 OFFSET $6
            "#,
            tenant_id,
            filter.license_pool_id,
            filter.trigger_type.as_ref().map(|t| match t {
                LicenseReclamationTrigger::Inactivity => "inactivity",
                LicenseReclamationTrigger::LifecycleState => "lifecycle_state",
            }),
            filter.enabled,
            limit,
            offset
        )
        .fetch_all(pool)
        .await
    }

    /// Count rules matching filter.
    pub async fn count(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &LicenseReclamationRuleFilter,
    ) -> Result<i64, sqlx::Error> {
        let result = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*) as "count!"
            FROM gov_license_reclamation_rules
            WHERE tenant_id = $1
              AND ($2::uuid IS NULL OR license_pool_id = $2)
              AND ($3::text IS NULL OR trigger_type::text = $3)
              AND ($4::boolean IS NULL OR enabled = $4)
            "#,
            tenant_id,
            filter.license_pool_id,
            filter.trigger_type.as_ref().map(|t| match t {
                LicenseReclamationTrigger::Inactivity => "inactivity",
                LicenseReclamationTrigger::LifecycleState => "lifecycle_state",
            }),
            filter.enabled
        )
        .fetch_one(pool)
        .await?;

        Ok(result)
    }

    // ========================================================================
    // MUTATIONS
    // ========================================================================

    /// Create a new reclamation rule.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        req: &CreateGovLicenseReclamationRule,
    ) -> Result<Self, sqlx::Error> {
        let id = LicenseReclamationRuleId::new();

        sqlx::query_as!(
            Self,
            r#"
            INSERT INTO gov_license_reclamation_rules (
                id, tenant_id, license_pool_id, trigger_type,
                threshold_days, lifecycle_state, notification_days_before,
                enabled, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING
                id,
                tenant_id,
                license_pool_id,
                trigger_type as "trigger_type: LicenseReclamationTrigger",
                threshold_days,
                lifecycle_state,
                notification_days_before,
                enabled,
                created_at,
                updated_at,
                created_by
            "#,
            id.inner(),
            tenant_id,
            req.license_pool_id,
            req.trigger_type as LicenseReclamationTrigger,
            req.threshold_days,
            req.lifecycle_state,
            req.notification_days_before
                .unwrap_or(DEFAULT_NOTIFICATION_DAYS_BEFORE),
            req.enabled.unwrap_or(true),
            req.created_by
        )
        .fetch_one(pool)
        .await
    }

    /// Update a reclamation rule.
    pub async fn update(
        pool: &PgPool,
        tenant_id: Uuid,
        id: LicenseReclamationRuleId,
        req: &UpdateGovLicenseReclamationRule,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            UPDATE gov_license_reclamation_rules
            SET
                threshold_days = COALESCE($3, threshold_days),
                lifecycle_state = COALESCE($4, lifecycle_state),
                notification_days_before = COALESCE($5, notification_days_before),
                enabled = COALESCE($6, enabled),
                updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            RETURNING
                id,
                tenant_id,
                license_pool_id,
                trigger_type as "trigger_type: LicenseReclamationTrigger",
                threshold_days,
                lifecycle_state,
                notification_days_before,
                enabled,
                created_at,
                updated_at,
                created_by
            "#,
            tenant_id,
            id.inner(),
            req.threshold_days,
            req.lifecycle_state,
            req.notification_days_before,
            req.enabled
        )
        .fetch_optional(pool)
        .await
    }

    /// Enable a rule.
    pub async fn enable(
        pool: &PgPool,
        tenant_id: Uuid,
        id: LicenseReclamationRuleId,
    ) -> Result<Option<Self>, sqlx::Error> {
        Self::update(
            pool,
            tenant_id,
            id,
            &UpdateGovLicenseReclamationRule {
                enabled: Some(true),
                ..Default::default()
            },
        )
        .await
    }

    /// Disable a rule.
    pub async fn disable(
        pool: &PgPool,
        tenant_id: Uuid,
        id: LicenseReclamationRuleId,
    ) -> Result<Option<Self>, sqlx::Error> {
        Self::update(
            pool,
            tenant_id,
            id,
            &UpdateGovLicenseReclamationRule {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
    }

    /// Delete a rule.
    pub async fn delete(
        pool: &PgPool,
        tenant_id: Uuid,
        id: LicenseReclamationRuleId,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query!(
            r#"
            DELETE FROM gov_license_reclamation_rules
            WHERE tenant_id = $1 AND id = $2
            "#,
            tenant_id,
            id.inner()
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete all rules for a pool.
    pub async fn delete_by_pool(
        pool: &PgPool,
        tenant_id: Uuid,
        license_pool_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query!(
            r#"
            DELETE FROM gov_license_reclamation_rules
            WHERE tenant_id = $1 AND license_pool_id = $2
            "#,
            tenant_id,
            license_pool_id
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }
}

impl GovLicenseReclamationRule {
    /// Validate that the rule is properly configured.
    pub fn validate(&self) -> Result<(), &'static str> {
        match self.trigger_type {
            LicenseReclamationTrigger::Inactivity => {
                if self.threshold_days.is_none() {
                    return Err("Inactivity rules require threshold_days");
                }
                if let Some(days) = self.threshold_days {
                    if days < 1 {
                        return Err("threshold_days must be at least 1");
                    }
                }
            }
            LicenseReclamationTrigger::LifecycleState => {
                if self.lifecycle_state.is_none() {
                    return Err("Lifecycle state rules require lifecycle_state");
                }
                if let Some(ref state) = self.lifecycle_state {
                    if state.is_empty() {
                        return Err("lifecycle_state cannot be empty");
                    }
                }
            }
        }

        if self.notification_days_before < 0 {
            return Err("notification_days_before cannot be negative");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_inactivity_rule() {
        let req = CreateGovLicenseReclamationRule {
            license_pool_id: Uuid::new_v4(),
            trigger_type: LicenseReclamationTrigger::Inactivity,
            threshold_days: Some(90),
            lifecycle_state: None,
            notification_days_before: Some(14),
            enabled: Some(true),
            created_by: Uuid::new_v4(),
        };

        assert_eq!(req.threshold_days, Some(90));
        assert!(req.lifecycle_state.is_none());
    }

    #[test]
    fn test_create_lifecycle_rule() {
        let req = CreateGovLicenseReclamationRule {
            license_pool_id: Uuid::new_v4(),
            trigger_type: LicenseReclamationTrigger::LifecycleState,
            threshold_days: None,
            lifecycle_state: Some("terminated".to_string()),
            notification_days_before: None,
            enabled: None,
            created_by: Uuid::new_v4(),
        };

        assert!(req.threshold_days.is_none());
        assert_eq!(req.lifecycle_state.as_deref(), Some("terminated"));
    }

    #[test]
    fn test_filter_default() {
        let filter = LicenseReclamationRuleFilter::default();
        assert!(filter.license_pool_id.is_none());
        assert!(filter.trigger_type.is_none());
        assert!(filter.enabled.is_none());
    }
}
