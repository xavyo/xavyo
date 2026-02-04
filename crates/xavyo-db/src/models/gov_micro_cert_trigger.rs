//! Governance Micro-certification Trigger Rule model (F055).
//!
//! Represents rules for when micro-certifications should be automatically created.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::{MicroCertReviewerType, MicroCertScopeType, MicroCertTriggerType};

/// Trigger rule for creating micro-certifications.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovMicroCertTrigger {
    /// Unique identifier for the trigger rule.
    pub id: Uuid,

    /// The tenant this rule belongs to.
    pub tenant_id: Uuid,

    /// Human-readable rule name.
    pub name: String,

    /// Type of event that triggers certification.
    pub trigger_type: MicroCertTriggerType,

    /// Level at which rule applies.
    pub scope_type: MicroCertScopeType,

    /// Target application/entitlement ID (NULL for tenant scope).
    pub scope_id: Option<Uuid>,

    /// How to determine the reviewer.
    pub reviewer_type: MicroCertReviewerType,

    /// User ID when `reviewer_type` = `specific_user`.
    pub specific_reviewer_id: Option<Uuid>,

    /// Backup reviewer if primary cannot be resolved.
    pub fallback_reviewer_id: Option<Uuid>,

    /// Deadline in seconds (default 24h).
    pub timeout_secs: i32,

    /// Send reminder at this % of deadline.
    pub reminder_threshold_percent: i32,

    /// Revoke access on timeout.
    pub auto_revoke: bool,

    /// For `SoD`: revoke newer assignment.
    pub revoke_triggering_assignment: bool,

    /// Rule enabled/disabled.
    pub is_active: bool,

    /// Tenant-wide default for `trigger_type`.
    pub is_default: bool,

    /// Higher priority wins when multiple rules match.
    pub priority: i32,

    /// Extensible metadata.
    pub metadata: Option<serde_json::Value>,

    /// When the rule was created.
    pub created_at: DateTime<Utc>,

    /// When the rule was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new trigger rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateMicroCertTrigger {
    pub name: String,
    pub trigger_type: MicroCertTriggerType,
    #[serde(default)]
    pub scope_type: Option<MicroCertScopeType>,
    pub scope_id: Option<Uuid>,
    #[serde(default)]
    pub reviewer_type: Option<MicroCertReviewerType>,
    pub specific_reviewer_id: Option<Uuid>,
    pub fallback_reviewer_id: Option<Uuid>,
    #[serde(default)]
    pub timeout_secs: Option<i32>,
    #[serde(default)]
    pub reminder_threshold_percent: Option<i32>,
    #[serde(default)]
    pub auto_revoke: Option<bool>,
    #[serde(default)]
    pub revoke_triggering_assignment: Option<bool>,
    #[serde(default)]
    pub is_default: Option<bool>,
    #[serde(default)]
    pub priority: Option<i32>,
    pub metadata: Option<serde_json::Value>,
}

/// Request to update a trigger rule.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateMicroCertTrigger {
    pub name: Option<String>,
    pub scope_type: Option<MicroCertScopeType>,
    pub scope_id: Option<Uuid>,
    pub reviewer_type: Option<MicroCertReviewerType>,
    pub specific_reviewer_id: Option<Uuid>,
    pub fallback_reviewer_id: Option<Uuid>,
    pub timeout_secs: Option<i32>,
    pub reminder_threshold_percent: Option<i32>,
    pub auto_revoke: Option<bool>,
    pub revoke_triggering_assignment: Option<bool>,
    pub is_active: Option<bool>,
    pub is_default: Option<bool>,
    pub priority: Option<i32>,
    pub metadata: Option<serde_json::Value>,
}

/// Filter options for listing trigger rules.
#[derive(Debug, Clone, Default)]
pub struct MicroCertTriggerFilter {
    pub trigger_type: Option<MicroCertTriggerType>,
    pub scope_type: Option<MicroCertScopeType>,
    pub scope_id: Option<Uuid>,
    pub is_active: Option<bool>,
    pub is_default: Option<bool>,
}

/// Default timeout in seconds (24 hours).
pub const DEFAULT_TIMEOUT_SECS: i32 = 86400;

/// Default reminder threshold percent.
pub const DEFAULT_REMINDER_THRESHOLD: i32 = 75;

impl GovMicroCertTrigger {
    /// Find a trigger rule by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_micro_cert_triggers
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a trigger rule by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        trigger_type: MicroCertTriggerType,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_micro_cert_triggers
            WHERE tenant_id = $1 AND trigger_type = $2 AND name = $3
            ",
        )
        .bind(tenant_id)
        .bind(trigger_type)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// Find the active default rule for a tenant and trigger type.
    pub async fn find_default(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        trigger_type: MicroCertTriggerType,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_micro_cert_triggers
            WHERE tenant_id = $1 AND trigger_type = $2 AND is_default = true AND is_active = true
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .bind(trigger_type)
        .fetch_optional(pool)
        .await
    }

    /// Find the best matching rule for a trigger event.
    /// Priority: entitlement-specific > application-specific > tenant-wide default
    pub async fn find_matching_rule(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        trigger_type: MicroCertTriggerType,
        entitlement_id: Option<Uuid>,
        application_id: Option<Uuid>,
    ) -> Result<Option<Self>, sqlx::Error> {
        // Try entitlement-specific first
        if let Some(ent_id) = entitlement_id {
            let rule: Option<Self> = sqlx::query_as(
                r"
                SELECT * FROM gov_micro_cert_triggers
                WHERE tenant_id = $1 AND trigger_type = $2
                  AND scope_type = 'entitlement' AND scope_id = $3
                  AND is_active = true
                ORDER BY priority DESC
                LIMIT 1
                ",
            )
            .bind(tenant_id)
            .bind(trigger_type)
            .bind(ent_id)
            .fetch_optional(pool)
            .await?;

            if rule.is_some() {
                return Ok(rule);
            }
        }

        // Try application-specific
        if let Some(app_id) = application_id {
            let rule: Option<Self> = sqlx::query_as(
                r"
                SELECT * FROM gov_micro_cert_triggers
                WHERE tenant_id = $1 AND trigger_type = $2
                  AND scope_type = 'application' AND scope_id = $3
                  AND is_active = true
                ORDER BY priority DESC
                LIMIT 1
                ",
            )
            .bind(tenant_id)
            .bind(trigger_type)
            .bind(app_id)
            .fetch_optional(pool)
            .await?;

            if rule.is_some() {
                return Ok(rule);
            }
        }

        // Fall back to tenant-wide default
        Self::find_default(pool, tenant_id, trigger_type).await
    }

    /// List rules for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &MicroCertTriggerFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from("SELECT * FROM gov_micro_cert_triggers WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.trigger_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND trigger_type = ${param_count}"));
        }
        if filter.scope_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND scope_type = ${param_count}"));
        }
        if filter.scope_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND scope_id = ${param_count}"));
        }
        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${param_count}"));
        }
        if filter.is_default.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_default = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY trigger_type, priority DESC, name LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(trigger_type) = filter.trigger_type {
            q = q.bind(trigger_type);
        }
        if let Some(scope_type) = filter.scope_type {
            q = q.bind(scope_type);
        }
        if let Some(scope_id) = filter.scope_id {
            q = q.bind(scope_id);
        }
        if let Some(is_active) = filter.is_active {
            q = q.bind(is_active);
        }
        if let Some(is_default) = filter.is_default {
            q = q.bind(is_default);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count rules in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &MicroCertTriggerFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query =
            String::from("SELECT COUNT(*) FROM gov_micro_cert_triggers WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.trigger_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND trigger_type = ${param_count}"));
        }
        if filter.scope_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND scope_type = ${param_count}"));
        }
        if filter.scope_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND scope_id = ${param_count}"));
        }
        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${param_count}"));
        }
        if filter.is_default.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_default = ${param_count}"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(trigger_type) = filter.trigger_type {
            q = q.bind(trigger_type);
        }
        if let Some(scope_type) = filter.scope_type {
            q = q.bind(scope_type);
        }
        if let Some(scope_id) = filter.scope_id {
            q = q.bind(scope_id);
        }
        if let Some(is_active) = filter.is_active {
            q = q.bind(is_active);
        }
        if let Some(is_default) = filter.is_default {
            q = q.bind(is_default);
        }

        q.fetch_one(pool).await
    }

    /// Create a new trigger rule.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateMicroCertTrigger,
    ) -> Result<Self, sqlx::Error> {
        let scope_type = input.scope_type.unwrap_or(MicroCertScopeType::Tenant);
        let reviewer_type = input
            .reviewer_type
            .unwrap_or(MicroCertReviewerType::UserManager);
        let timeout_secs = input.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
        let reminder_threshold = input
            .reminder_threshold_percent
            .unwrap_or(DEFAULT_REMINDER_THRESHOLD);
        let auto_revoke = input.auto_revoke.unwrap_or(true);
        let revoke_triggering = input.revoke_triggering_assignment.unwrap_or(true);
        let is_default = input.is_default.unwrap_or(false);
        let priority = input.priority.unwrap_or(0);

        sqlx::query_as(
            r"
            INSERT INTO gov_micro_cert_triggers (
                tenant_id, name, trigger_type, scope_type, scope_id,
                reviewer_type, specific_reviewer_id, fallback_reviewer_id,
                timeout_secs, reminder_threshold_percent, auto_revoke,
                revoke_triggering_assignment, is_default, priority, metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(input.trigger_type)
        .bind(scope_type)
        .bind(input.scope_id)
        .bind(reviewer_type)
        .bind(input.specific_reviewer_id)
        .bind(input.fallback_reviewer_id)
        .bind(timeout_secs)
        .bind(reminder_threshold)
        .bind(auto_revoke)
        .bind(revoke_triggering)
        .bind(is_default)
        .bind(priority)
        .bind(&input.metadata)
        .fetch_one(pool)
        .await
    }

    /// Update a trigger rule.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateMicroCertTrigger,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if input.name.is_some() {
            updates.push(format!("name = ${param_idx}"));
            param_idx += 1;
        }
        if input.scope_type.is_some() {
            updates.push(format!("scope_type = ${param_idx}"));
            param_idx += 1;
        }
        if input.scope_id.is_some() {
            updates.push(format!("scope_id = ${param_idx}"));
            param_idx += 1;
        }
        if input.reviewer_type.is_some() {
            updates.push(format!("reviewer_type = ${param_idx}"));
            param_idx += 1;
        }
        if input.specific_reviewer_id.is_some() {
            updates.push(format!("specific_reviewer_id = ${param_idx}"));
            param_idx += 1;
        }
        if input.fallback_reviewer_id.is_some() {
            updates.push(format!("fallback_reviewer_id = ${param_idx}"));
            param_idx += 1;
        }
        if input.timeout_secs.is_some() {
            updates.push(format!("timeout_secs = ${param_idx}"));
            param_idx += 1;
        }
        if input.reminder_threshold_percent.is_some() {
            updates.push(format!("reminder_threshold_percent = ${param_idx}"));
            param_idx += 1;
        }
        if input.auto_revoke.is_some() {
            updates.push(format!("auto_revoke = ${param_idx}"));
            param_idx += 1;
        }
        if input.revoke_triggering_assignment.is_some() {
            updates.push(format!("revoke_triggering_assignment = ${param_idx}"));
            param_idx += 1;
        }
        if input.is_active.is_some() {
            updates.push(format!("is_active = ${param_idx}"));
            param_idx += 1;
        }
        if input.is_default.is_some() {
            updates.push(format!("is_default = ${param_idx}"));
            param_idx += 1;
        }
        if input.priority.is_some() {
            updates.push(format!("priority = ${param_idx}"));
            param_idx += 1;
        }
        if input.metadata.is_some() {
            updates.push(format!("metadata = ${param_idx}"));
            // param_idx += 1;
        }

        let query = format!(
            "UPDATE gov_micro_cert_triggers SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, Self>(&query).bind(id).bind(tenant_id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(scope_type) = input.scope_type {
            q = q.bind(scope_type);
        }
        if let Some(scope_id) = input.scope_id {
            q = q.bind(scope_id);
        }
        if let Some(reviewer_type) = input.reviewer_type {
            q = q.bind(reviewer_type);
        }
        if let Some(specific_reviewer_id) = input.specific_reviewer_id {
            q = q.bind(specific_reviewer_id);
        }
        if let Some(fallback_reviewer_id) = input.fallback_reviewer_id {
            q = q.bind(fallback_reviewer_id);
        }
        if let Some(timeout_secs) = input.timeout_secs {
            q = q.bind(timeout_secs);
        }
        if let Some(reminder_threshold) = input.reminder_threshold_percent {
            q = q.bind(reminder_threshold);
        }
        if let Some(auto_revoke) = input.auto_revoke {
            q = q.bind(auto_revoke);
        }
        if let Some(revoke_triggering) = input.revoke_triggering_assignment {
            q = q.bind(revoke_triggering);
        }
        if let Some(is_active) = input.is_active {
            q = q.bind(is_active);
        }
        if let Some(is_default) = input.is_default {
            q = q.bind(is_default);
        }
        if let Some(priority) = input.priority {
            q = q.bind(priority);
        }
        if let Some(ref metadata) = input.metadata {
            q = q.bind(metadata);
        }

        q.fetch_optional(pool).await
    }

    /// Delete a trigger rule.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_micro_cert_triggers
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Deactivate all default rules for this trigger type except the specified one.
    pub async fn deactivate_other_defaults(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        trigger_type: MicroCertTriggerType,
        except_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_micro_cert_triggers
            SET is_default = false, updated_at = NOW()
            WHERE tenant_id = $1 AND trigger_type = $2 AND id != $3 AND is_default = true
            ",
        )
        .bind(tenant_id)
        .bind(trigger_type)
        .bind(except_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Validate the trigger rule configuration.
    pub fn validate(&self) -> Result<(), String> {
        // Check scope_id requirement
        if self.scope_type.requires_scope_id() && self.scope_id.is_none() {
            return Err(format!(
                "scope_id is required for {:?} scope type",
                self.scope_type
            ));
        }
        if !self.scope_type.requires_scope_id() && self.scope_id.is_some() {
            return Err("scope_id must be NULL for tenant scope".to_string());
        }

        // Check specific_reviewer_id requirement
        if self.reviewer_type.requires_specific_reviewer() && self.specific_reviewer_id.is_none() {
            return Err(
                "specific_reviewer_id is required for specific_user reviewer type".to_string(),
            );
        }

        // Check timeout bounds
        if self.timeout_secs <= 0 {
            return Err("timeout_secs must be positive".to_string());
        }

        // Check reminder threshold bounds
        if self.reminder_threshold_percent < 1 || self.reminder_threshold_percent > 99 {
            return Err("reminder_threshold_percent must be between 1 and 99".to_string());
        }

        Ok(())
    }

    /// Calculate the deadline timestamp from now.
    #[must_use] 
    pub fn calculate_deadline(&self) -> DateTime<Utc> {
        Utc::now() + chrono::Duration::seconds(i64::from(self.timeout_secs))
    }

    /// Calculate the reminder time based on threshold.
    #[must_use] 
    pub fn calculate_reminder_time(&self) -> DateTime<Utc> {
        let threshold_secs =
            (f64::from(self.timeout_secs) * (f64::from(self.reminder_threshold_percent) / 100.0)) as i64;
        Utc::now() + chrono::Duration::seconds(threshold_secs)
    }

    /// Calculate escalation deadline (75% of timeout by default, or 50% if specified).
    #[must_use] 
    pub fn calculate_escalation_deadline(&self) -> Option<DateTime<Utc>> {
        if self.fallback_reviewer_id.is_some() {
            // Escalate at 50% of timeout
            let escalation_secs = self.timeout_secs / 2;
            Some(Utc::now() + chrono::Duration::seconds(i64::from(escalation_secs)))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_micro_cert_trigger() {
        let input = CreateMicroCertTrigger {
            name: "High-Risk Entitlement Review".to_string(),
            trigger_type: MicroCertTriggerType::HighRiskAssignment,
            scope_type: Some(MicroCertScopeType::Tenant),
            scope_id: None,
            reviewer_type: Some(MicroCertReviewerType::UserManager),
            specific_reviewer_id: None,
            fallback_reviewer_id: None,
            timeout_secs: Some(86400),
            reminder_threshold_percent: Some(75),
            auto_revoke: Some(true),
            revoke_triggering_assignment: Some(true),
            is_default: Some(true),
            priority: Some(0),
            metadata: None,
        };

        assert_eq!(input.name, "High-Risk Entitlement Review");
        assert_eq!(input.trigger_type, MicroCertTriggerType::HighRiskAssignment);
    }

    #[test]
    fn test_validation_scope_id_required() {
        let trigger = GovMicroCertTrigger {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test".to_string(),
            trigger_type: MicroCertTriggerType::HighRiskAssignment,
            scope_type: MicroCertScopeType::Application,
            scope_id: None, // Invalid: required for application scope
            reviewer_type: MicroCertReviewerType::UserManager,
            specific_reviewer_id: None,
            fallback_reviewer_id: None,
            timeout_secs: 86400,
            reminder_threshold_percent: 75,
            auto_revoke: true,
            revoke_triggering_assignment: true,
            is_active: true,
            is_default: false,
            priority: 0,
            metadata: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(trigger.validate().is_err());
    }

    #[test]
    fn test_validation_specific_reviewer_required() {
        let trigger = GovMicroCertTrigger {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test".to_string(),
            trigger_type: MicroCertTriggerType::Manual,
            scope_type: MicroCertScopeType::Tenant,
            scope_id: None,
            reviewer_type: MicroCertReviewerType::SpecificUser,
            specific_reviewer_id: None, // Invalid: required for specific_user
            fallback_reviewer_id: None,
            timeout_secs: 86400,
            reminder_threshold_percent: 75,
            auto_revoke: true,
            revoke_triggering_assignment: true,
            is_active: true,
            is_default: false,
            priority: 0,
            metadata: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(trigger.validate().is_err());
    }

    #[test]
    fn test_validation_valid_trigger() {
        let trigger = GovMicroCertTrigger {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test".to_string(),
            trigger_type: MicroCertTriggerType::HighRiskAssignment,
            scope_type: MicroCertScopeType::Tenant,
            scope_id: None,
            reviewer_type: MicroCertReviewerType::UserManager,
            specific_reviewer_id: None,
            fallback_reviewer_id: None,
            timeout_secs: 86400,
            reminder_threshold_percent: 75,
            auto_revoke: true,
            revoke_triggering_assignment: true,
            is_active: true,
            is_default: true,
            priority: 0,
            metadata: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(trigger.validate().is_ok());
    }

    #[test]
    fn test_calculate_deadline() {
        let trigger = GovMicroCertTrigger {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test".to_string(),
            trigger_type: MicroCertTriggerType::HighRiskAssignment,
            scope_type: MicroCertScopeType::Tenant,
            scope_id: None,
            reviewer_type: MicroCertReviewerType::UserManager,
            specific_reviewer_id: None,
            fallback_reviewer_id: None,
            timeout_secs: 3600, // 1 hour
            reminder_threshold_percent: 75,
            auto_revoke: true,
            revoke_triggering_assignment: true,
            is_active: true,
            is_default: true,
            priority: 0,
            metadata: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let now = Utc::now();
        let deadline = trigger.calculate_deadline();
        let diff = (deadline - now).num_seconds();

        // Should be approximately 3600 seconds
        assert!((3599..=3601).contains(&diff));
    }

    #[test]
    fn test_filter_default() {
        let filter = MicroCertTriggerFilter::default();
        assert!(filter.trigger_type.is_none());
        assert!(filter.is_active.is_none());
    }
}
