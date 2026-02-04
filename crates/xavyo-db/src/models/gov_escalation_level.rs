//! Governance Escalation Level model (F054).
//!
//! Represents an individual escalation level within a policy or rule.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::EscalationTargetType;

/// An individual escalation level.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovEscalationLevel {
    /// Unique identifier for the level.
    pub id: Uuid,

    /// The tenant this level belongs to.
    pub tenant_id: Uuid,

    /// Reference to escalation policy (if policy-level).
    pub policy_id: Option<Uuid>,

    /// Reference to escalation rule (if rule-level).
    pub rule_id: Option<Uuid>,

    /// Order within the escalation chain (1, 2, 3...).
    pub level_order: i32,

    /// Display name for this level (e.g., "Backup Approver").
    pub level_name: Option<String>,

    /// Type of escalation target.
    pub target_type: EscalationTargetType,

    /// Target ID for `specific_user` or `approval_group`.
    pub target_id: Option<Uuid>,

    /// Depth for `manager_chain` type.
    pub manager_chain_depth: Option<i32>,

    /// Timeout for this escalation level.
    /// Note: `PgInterval` doesn't implement Serialize/Deserialize, use `timeout_secs()` accessor.
    #[serde(skip)]
    pub timeout: sqlx::postgres::types::PgInterval,

    /// When the level was created.
    pub created_at: DateTime<Utc>,
}

/// Request to create a new escalation level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateEscalationLevel {
    pub level_order: i32,
    pub level_name: Option<String>,
    pub target_type: EscalationTargetType,
    pub target_id: Option<Uuid>,
    pub manager_chain_depth: Option<i32>,
    /// Timeout in seconds.
    pub timeout_secs: i64,
}

/// Request to update an escalation level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateEscalationLevel {
    pub level_name: Option<String>,
    pub target_type: Option<EscalationTargetType>,
    pub target_id: Option<Uuid>,
    pub manager_chain_depth: Option<i32>,
    /// Timeout in seconds.
    pub timeout_secs: Option<i64>,
}

impl GovEscalationLevel {
    /// Find a level by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_escalation_levels
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find all levels for a policy, ordered by `level_order`.
    pub async fn find_by_policy(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        policy_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_escalation_levels
            WHERE tenant_id = $1 AND policy_id = $2
            ORDER BY level_order ASC
            ",
        )
        .bind(tenant_id)
        .bind(policy_id)
        .fetch_all(pool)
        .await
    }

    /// Find all levels for a rule, ordered by `level_order`.
    pub async fn find_by_rule(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        rule_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_escalation_levels
            WHERE tenant_id = $1 AND rule_id = $2
            ORDER BY level_order ASC
            ",
        )
        .bind(tenant_id)
        .bind(rule_id)
        .fetch_all(pool)
        .await
    }

    /// Count levels for a policy.
    pub async fn count_by_policy(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        policy_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_escalation_levels
            WHERE tenant_id = $1 AND policy_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(policy_id)
        .fetch_one(pool)
        .await
    }

    /// Count levels for a rule.
    pub async fn count_by_rule(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        rule_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r"
            SELECT COUNT(*) FROM gov_escalation_levels
            WHERE tenant_id = $1 AND rule_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(rule_id)
        .fetch_one(pool)
        .await
    }

    /// Create a new level for a policy.
    pub async fn create_for_policy(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        policy_id: Uuid,
        input: CreateEscalationLevel,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_escalation_levels (
                tenant_id, policy_id, level_order, level_name,
                target_type, target_id, manager_chain_depth, timeout
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, make_interval(secs => $8))
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(policy_id)
        .bind(input.level_order)
        .bind(&input.level_name)
        .bind(input.target_type)
        .bind(input.target_id)
        .bind(input.manager_chain_depth)
        .bind(input.timeout_secs as f64)
        .fetch_one(pool)
        .await
    }

    /// Create a new level for a rule.
    pub async fn create_for_rule(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        rule_id: Uuid,
        input: CreateEscalationLevel,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO gov_escalation_levels (
                tenant_id, rule_id, level_order, level_name,
                target_type, target_id, manager_chain_depth, timeout
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, make_interval(secs => $8))
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(rule_id)
        .bind(input.level_order)
        .bind(&input.level_name)
        .bind(input.target_type)
        .bind(input.target_id)
        .bind(input.manager_chain_depth)
        .bind(input.timeout_secs as f64)
        .fetch_one(pool)
        .await
    }

    /// Create multiple levels in a batch for a policy.
    pub async fn create_batch_for_policy(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        policy_id: Uuid,
        levels: Vec<CreateEscalationLevel>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut results = Vec::with_capacity(levels.len());
        for (idx, mut level) in levels.into_iter().enumerate() {
            // Auto-assign level_order if not set
            if level.level_order == 0 {
                level.level_order = (idx + 1) as i32;
            }
            let created = Self::create_for_policy(pool, tenant_id, policy_id, level).await?;
            results.push(created);
        }
        Ok(results)
    }

    /// Create multiple levels in a batch for a rule.
    pub async fn create_batch_for_rule(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        rule_id: Uuid,
        levels: Vec<CreateEscalationLevel>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut results = Vec::with_capacity(levels.len());
        for (idx, mut level) in levels.into_iter().enumerate() {
            if level.level_order == 0 {
                level.level_order = (idx + 1) as i32;
            }
            let created = Self::create_for_rule(pool, tenant_id, rule_id, level).await?;
            results.push(created);
        }
        Ok(results)
    }

    /// Update a level.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateEscalationLevel,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = Vec::new();
        let mut param_idx = 3;

        if input.level_name.is_some() {
            updates.push(format!("level_name = ${param_idx}"));
            param_idx += 1;
        }
        if input.target_type.is_some() {
            updates.push(format!("target_type = ${param_idx}"));
            param_idx += 1;
        }
        if input.target_id.is_some() {
            updates.push(format!("target_id = ${param_idx}"));
            param_idx += 1;
        }
        if input.manager_chain_depth.is_some() {
            updates.push(format!("manager_chain_depth = ${param_idx}"));
            param_idx += 1;
        }
        if input.timeout_secs.is_some() {
            updates.push(format!("timeout = make_interval(secs => ${param_idx})"));
            // param_idx += 1;
        }

        if updates.is_empty() {
            return Self::find_by_id(pool, tenant_id, id).await;
        }

        let query = format!(
            "UPDATE gov_escalation_levels SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, Self>(&query).bind(id).bind(tenant_id);

        if let Some(ref level_name) = input.level_name {
            q = q.bind(level_name);
        }
        if let Some(target_type) = input.target_type {
            q = q.bind(target_type);
        }
        if let Some(target_id) = input.target_id {
            q = q.bind(target_id);
        }
        if let Some(depth) = input.manager_chain_depth {
            q = q.bind(depth);
        }
        if let Some(timeout_secs) = input.timeout_secs {
            q = q.bind(timeout_secs as f64);
        }

        q.fetch_optional(pool).await
    }

    /// Delete a level.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_escalation_levels
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete all levels for a policy.
    pub async fn delete_by_policy(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        policy_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_escalation_levels
            WHERE tenant_id = $1 AND policy_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(policy_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Delete all levels for a rule.
    pub async fn delete_by_rule(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        rule_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM gov_escalation_levels
            WHERE tenant_id = $1 AND rule_id = $2
            ",
        )
        .bind(tenant_id)
        .bind(rule_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Get timeout as Duration.
    #[must_use] 
    pub fn timeout_duration(&self) -> chrono::Duration {
        let microseconds = self.timeout.microseconds;
        let days = i64::from(self.timeout.days);
        let months = i64::from(self.timeout.months);
        let total_days = days + (months * 30);
        let total_microseconds = microseconds + (total_days * 24 * 60 * 60 * 1_000_000);
        chrono::Duration::microseconds(total_microseconds)
    }

    /// Get timeout in seconds (for serialization).
    #[must_use] 
    pub fn timeout_secs(&self) -> i64 {
        let microseconds = self.timeout.microseconds;
        let days = i64::from(self.timeout.days);
        let months = i64::from(self.timeout.months);
        let total_days = days + (months * 30);
        (microseconds / 1_000_000) + (total_days * 24 * 60 * 60)
    }

    /// Validate the level configuration.
    pub fn validate(&self) -> Result<(), String> {
        // Must belong to exactly one of policy or rule
        if self.policy_id.is_some() && self.rule_id.is_some() {
            return Err("Level cannot belong to both policy and rule".to_string());
        }
        if self.policy_id.is_none() && self.rule_id.is_none() {
            return Err("Level must belong to either policy or rule".to_string());
        }

        // target_id required for specific_user and approval_group
        if self.target_type.requires_target_id() && self.target_id.is_none() {
            return Err(format!(
                "target_id is required for {:?} target type",
                self.target_type
            ));
        }

        // manager_chain_depth only for manager_chain
        if self.target_type == EscalationTargetType::ManagerChain {
            match self.manager_chain_depth {
                Some(depth) if (1..=10).contains(&depth) => {}
                Some(depth) => {
                    return Err(format!(
                        "manager_chain_depth must be between 1 and 10, got {depth}"
                    ))
                }
                None => {
                    return Err("manager_chain_depth is required for manager_chain type".to_string())
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_escalation_level() {
        let input = CreateEscalationLevel {
            level_order: 1,
            level_name: Some("Backup Approver".to_string()),
            target_type: EscalationTargetType::ApprovalGroup,
            target_id: Some(Uuid::new_v4()),
            manager_chain_depth: None,
            timeout_secs: 86400, // 24 hours
        };

        assert_eq!(input.level_order, 1);
        assert_eq!(input.timeout_secs, 86400);
    }

    #[test]
    fn test_level_validation_policy_and_rule() {
        let level = GovEscalationLevel {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            policy_id: Some(Uuid::new_v4()),
            rule_id: Some(Uuid::new_v4()), // Invalid: both set
            level_order: 1,
            level_name: None,
            target_type: EscalationTargetType::Manager,
            target_id: None,
            manager_chain_depth: None,
            timeout: sqlx::postgres::types::PgInterval {
                months: 0,
                days: 0,
                microseconds: 86400 * 1_000_000,
            },
            created_at: Utc::now(),
        };

        assert!(level.validate().is_err());
    }

    #[test]
    fn test_level_validation_missing_target_id() {
        let level = GovEscalationLevel {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            policy_id: Some(Uuid::new_v4()),
            rule_id: None,
            level_order: 1,
            level_name: None,
            target_type: EscalationTargetType::SpecificUser,
            target_id: None, // Invalid: required for SpecificUser
            manager_chain_depth: None,
            timeout: sqlx::postgres::types::PgInterval {
                months: 0,
                days: 0,
                microseconds: 86400 * 1_000_000,
            },
            created_at: Utc::now(),
        };

        assert!(level.validate().is_err());
    }
}
