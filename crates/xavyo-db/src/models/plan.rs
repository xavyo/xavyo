//! Plan management models for tenant subscription tiers.
//!
//! F-PLAN-MGMT: Defines plan tiers, limits, and change tracking.

use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::error::DbError;

/// Available plan tiers in order from lowest to highest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlanTier {
    Free,
    Starter,
    Professional,
    Enterprise,
}

impl PlanTier {
    /// Get the numeric order of this tier (0 = lowest, 3 = highest).
    #[must_use]
    pub fn tier_order(&self) -> i32 {
        match self {
            PlanTier::Free => 0,
            PlanTier::Starter => 1,
            PlanTier::Professional => 2,
            PlanTier::Enterprise => 3,
        }
    }

    /// Check if this tier is higher than another.
    #[must_use]
    pub fn is_higher_than(&self, other: &PlanTier) -> bool {
        self.tier_order() > other.tier_order()
    }

    /// Check if this tier is lower than another.
    #[must_use]
    pub fn is_lower_than(&self, other: &PlanTier) -> bool {
        self.tier_order() < other.tier_order()
    }

    /// Get the plan name as a string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            PlanTier::Free => "free",
            PlanTier::Starter => "starter",
            PlanTier::Professional => "professional",
            PlanTier::Enterprise => "enterprise",
        }
    }

    /// Get all available tiers in order.
    #[must_use]
    pub fn all() -> Vec<PlanTier> {
        vec![
            PlanTier::Free,
            PlanTier::Starter,
            PlanTier::Professional,
            PlanTier::Enterprise,
        ]
    }
}

impl std::fmt::Display for PlanTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for PlanTier {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "free" => Ok(PlanTier::Free),
            "starter" => Ok(PlanTier::Starter),
            "professional" => Ok(PlanTier::Professional),
            "enterprise" => Ok(PlanTier::Enterprise),
            _ => Err(format!("Invalid plan tier: {s}")),
        }
    }
}

/// Plan definition with limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanDefinition {
    /// Plan tier.
    pub tier: PlanTier,
    /// Display name.
    pub display_name: String,
    /// Maximum monthly active users.
    pub max_mau: i64,
    /// Maximum API calls per month.
    pub max_api_calls: i64,
    /// Maximum agent invocations per month.
    pub max_agent_invocations: i64,
}

impl PlanDefinition {
    /// Get the definition for a plan tier.
    #[must_use]
    pub fn for_tier(tier: PlanTier) -> Self {
        match tier {
            PlanTier::Free => Self {
                tier,
                display_name: "Free".to_string(),
                max_mau: 1_000,
                max_api_calls: 10_000,
                max_agent_invocations: 100,
            },
            PlanTier::Starter => Self {
                tier,
                display_name: "Starter".to_string(),
                max_mau: 5_000,
                max_api_calls: 100_000,
                max_agent_invocations: 1_000,
            },
            PlanTier::Professional => Self {
                tier,
                display_name: "Professional".to_string(),
                max_mau: 25_000,
                max_api_calls: 500_000,
                max_agent_invocations: 10_000,
            },
            PlanTier::Enterprise => Self {
                tier,
                display_name: "Enterprise".to_string(),
                max_mau: 100_000,
                max_api_calls: 2_000_000,
                max_agent_invocations: 100_000,
            },
        }
    }

    /// Get all plan definitions.
    pub fn all() -> Vec<Self> {
        PlanTier::all()
            .into_iter()
            .map(PlanDefinition::for_tier)
            .collect()
    }

    /// Convert to settings JSON for tenant.
    #[must_use]
    pub fn to_settings_json(&self) -> serde_json::Value {
        serde_json::json!({
            "plan": self.tier.as_str(),
            "limits": {
                "max_mau": self.max_mau,
                "max_api_calls": self.max_api_calls,
                "max_agent_invocations": self.max_agent_invocations
            }
        })
    }
}

/// Status of a plan change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlanChangeStatus {
    Pending,
    Applied,
    Cancelled,
}

impl std::fmt::Display for PlanChangeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanChangeStatus::Pending => write!(f, "pending"),
            PlanChangeStatus::Applied => write!(f, "applied"),
            PlanChangeStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::str::FromStr for PlanChangeStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(PlanChangeStatus::Pending),
            "applied" => Ok(PlanChangeStatus::Applied),
            "cancelled" => Ok(PlanChangeStatus::Cancelled),
            _ => Err(format!("Invalid plan change status: {s}")),
        }
    }
}

/// Type of plan change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlanChangeType {
    Upgrade,
    Downgrade,
}

impl std::fmt::Display for PlanChangeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanChangeType::Upgrade => write!(f, "upgrade"),
            PlanChangeType::Downgrade => write!(f, "downgrade"),
        }
    }
}

/// A record of a tenant plan change.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct TenantPlanChange {
    /// Unique identifier.
    pub id: Uuid,
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// Type of change (upgrade/downgrade).
    pub change_type: String,
    /// Previous plan name.
    pub old_plan: String,
    /// New plan name.
    pub new_plan: String,
    /// When the change takes effect.
    pub effective_at: DateTime<Utc>,
    /// Status of the change.
    pub status: String,
    /// Admin who made the change.
    pub admin_user_id: Uuid,
    /// Reason for the change (optional).
    pub reason: Option<String>,
    /// When the change was created.
    pub created_at: DateTime<Utc>,
}

impl TenantPlanChange {
    /// Get the change type as enum.
    #[must_use]
    pub fn change_type_enum(&self) -> Option<PlanChangeType> {
        match self.change_type.as_str() {
            "upgrade" => Some(PlanChangeType::Upgrade),
            "downgrade" => Some(PlanChangeType::Downgrade),
            _ => None,
        }
    }

    /// Get the status as enum.
    #[must_use]
    pub fn status_enum(&self) -> Option<PlanChangeStatus> {
        self.status.parse().ok()
    }

    /// Create a new plan change record.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        change_type: PlanChangeType,
        old_plan: &str,
        new_plan: &str,
        effective_at: DateTime<Utc>,
        admin_user_id: Uuid,
        reason: Option<&str>,
    ) -> Result<Self, DbError> {
        sqlx::query_as::<_, Self>(
            r"
            INSERT INTO tenant_plan_changes
                (tenant_id, change_type, old_plan, new_plan, effective_at, admin_user_id, reason)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, tenant_id, change_type, old_plan, new_plan, effective_at, status, admin_user_id, reason, created_at
            ",
        )
        .bind(tenant_id)
        .bind(change_type.to_string())
        .bind(old_plan)
        .bind(new_plan)
        .bind(effective_at)
        .bind(admin_user_id)
        .bind(reason)
        .fetch_one(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// Mark a plan change as applied.
    pub async fn mark_applied(pool: &PgPool, id: Uuid) -> Result<Self, DbError> {
        sqlx::query_as::<_, Self>(
            r"
            UPDATE tenant_plan_changes
            SET status = 'applied'
            WHERE id = $1
            RETURNING id, tenant_id, change_type, old_plan, new_plan, effective_at, status, admin_user_id, reason, created_at
            ",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// Mark a plan change as cancelled.
    pub async fn mark_cancelled(pool: &PgPool, id: Uuid) -> Result<Self, DbError> {
        sqlx::query_as::<_, Self>(
            r"
            UPDATE tenant_plan_changes
            SET status = 'cancelled'
            WHERE id = $1
            RETURNING id, tenant_id, change_type, old_plan, new_plan, effective_at, status, admin_user_id, reason, created_at
            ",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// Get plan change history for a tenant.
    pub async fn get_history(
        pool: &PgPool,
        tenant_id: Uuid,
        limit: i32,
    ) -> Result<Vec<Self>, DbError> {
        sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, change_type, old_plan, new_plan, effective_at, status, admin_user_id, reason, created_at
            FROM tenant_plan_changes
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            ",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// Get pending downgrade for a tenant.
    pub async fn get_pending_downgrade(
        pool: &PgPool,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, DbError> {
        sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, change_type, old_plan, new_plan, effective_at, status, admin_user_id, reason, created_at
            FROM tenant_plan_changes
            WHERE tenant_id = $1
              AND change_type = 'downgrade'
              AND status = 'pending'
            ORDER BY effective_at ASC
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// Get all pending changes that should be applied (`effective_at` <= now).
    pub async fn get_due_pending_changes(pool: &PgPool) -> Result<Vec<Self>, DbError> {
        sqlx::query_as::<_, Self>(
            r"
            SELECT id, tenant_id, change_type, old_plan, new_plan, effective_at, status, admin_user_id, reason, created_at
            FROM tenant_plan_changes
            WHERE status = 'pending'
              AND effective_at <= NOW()
            ORDER BY effective_at ASC
            ",
        )
        .fetch_all(pool)
        .await
        .map_err(DbError::QueryFailed)
    }
}

/// Calculate the first day of the next month.
#[must_use]
pub fn next_billing_cycle_date() -> DateTime<Utc> {
    let now = Utc::now();
    let next_month = if now.month() == 12 {
        NaiveDate::from_ymd_opt(now.year() + 1, 1, 1)
    } else {
        NaiveDate::from_ymd_opt(now.year(), now.month() + 1, 1)
    };

    next_month
        .expect("Invalid date calculation")
        .and_hms_opt(0, 0, 0)
        .expect("Invalid time")
        .and_utc()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Timelike;

    #[test]
    fn test_plan_tier_ordering() {
        assert!(PlanTier::Starter.is_higher_than(&PlanTier::Free));
        assert!(PlanTier::Professional.is_higher_than(&PlanTier::Starter));
        assert!(PlanTier::Enterprise.is_higher_than(&PlanTier::Professional));

        assert!(PlanTier::Free.is_lower_than(&PlanTier::Starter));
        assert!(PlanTier::Starter.is_lower_than(&PlanTier::Professional));
        assert!(PlanTier::Professional.is_lower_than(&PlanTier::Enterprise));

        assert!(!PlanTier::Free.is_higher_than(&PlanTier::Free));
        assert!(!PlanTier::Free.is_lower_than(&PlanTier::Free));
    }

    #[test]
    fn test_plan_tier_from_str() {
        assert_eq!("free".parse::<PlanTier>().unwrap(), PlanTier::Free);
        assert_eq!("STARTER".parse::<PlanTier>().unwrap(), PlanTier::Starter);
        assert_eq!(
            "Professional".parse::<PlanTier>().unwrap(),
            PlanTier::Professional
        );
        assert_eq!(
            "ENTERPRISE".parse::<PlanTier>().unwrap(),
            PlanTier::Enterprise
        );
        assert!("invalid".parse::<PlanTier>().is_err());
    }

    #[test]
    fn test_plan_tier_display() {
        assert_eq!(PlanTier::Free.to_string(), "free");
        assert_eq!(PlanTier::Starter.to_string(), "starter");
        assert_eq!(PlanTier::Professional.to_string(), "professional");
        assert_eq!(PlanTier::Enterprise.to_string(), "enterprise");
    }

    #[test]
    fn test_plan_definition_for_tier() {
        let free = PlanDefinition::for_tier(PlanTier::Free);
        assert_eq!(free.max_mau, 1_000);
        assert_eq!(free.max_api_calls, 10_000);

        let enterprise = PlanDefinition::for_tier(PlanTier::Enterprise);
        assert_eq!(enterprise.max_mau, 100_000);
        assert_eq!(enterprise.max_api_calls, 2_000_000);
    }

    #[test]
    fn test_plan_definition_to_settings_json() {
        let starter = PlanDefinition::for_tier(PlanTier::Starter);
        let json = starter.to_settings_json();

        assert_eq!(json["plan"], "starter");
        assert_eq!(json["limits"]["max_mau"], 5_000);
        assert_eq!(json["limits"]["max_api_calls"], 100_000);
        assert_eq!(json["limits"]["max_agent_invocations"], 1_000);
    }

    #[test]
    fn test_plan_definition_all() {
        let all = PlanDefinition::all();
        assert_eq!(all.len(), 4);
        assert_eq!(all[0].tier, PlanTier::Free);
        assert_eq!(all[3].tier, PlanTier::Enterprise);
    }

    #[test]
    fn test_plan_change_status_display() {
        assert_eq!(PlanChangeStatus::Pending.to_string(), "pending");
        assert_eq!(PlanChangeStatus::Applied.to_string(), "applied");
        assert_eq!(PlanChangeStatus::Cancelled.to_string(), "cancelled");
    }

    #[test]
    fn test_plan_change_type_display() {
        assert_eq!(PlanChangeType::Upgrade.to_string(), "upgrade");
        assert_eq!(PlanChangeType::Downgrade.to_string(), "downgrade");
    }

    #[test]
    fn test_next_billing_cycle_date() {
        let next = next_billing_cycle_date();
        let now = Utc::now();

        // Should be in the future
        assert!(next > now);

        // Should be the first day of a month
        assert_eq!(next.day(), 1);

        // Should be at midnight
        assert_eq!(next.hour(), 0);
        assert_eq!(next.minute(), 0);
        assert_eq!(next.second(), 0);
    }
}
