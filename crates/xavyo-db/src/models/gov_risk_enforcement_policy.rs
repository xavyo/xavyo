//! Risk enforcement policy model for adaptive authentication (F073).
//!
//! Per-tenant configuration for risk-based authentication enforcement.
//! Controls whether login-time risk evaluation is disabled, monitored, or enforced.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// Enforcement mode for risk-based authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "enforcement_mode", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum EnforcementMode {
    /// No risk evaluation during login. Existing behavior preserved.
    Disabled,
    /// Risk evaluation runs and alerts are generated, but no enforcement actions applied.
    Monitor,
    /// Risk evaluation runs and enforcement actions are applied (RequireMfa or Block).
    Enforce,
}

impl EnforcementMode {
    /// Returns true if risk evaluation should run.
    pub fn is_active(&self) -> bool {
        !matches!(self, Self::Disabled)
    }

    /// Returns true if enforcement actions should be applied.
    pub fn is_enforcing(&self) -> bool {
        matches!(self, Self::Enforce)
    }
}

/// Per-tenant risk enforcement policy.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GovRiskEnforcementPolicy {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub enforcement_mode: EnforcementMode,
    pub fail_open: bool,
    pub impossible_travel_speed_kmh: i32,
    pub impossible_travel_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Input for creating or updating an enforcement policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertEnforcementPolicy {
    pub enforcement_mode: Option<EnforcementMode>,
    pub fail_open: Option<bool>,
    pub impossible_travel_speed_kmh: Option<i32>,
    pub impossible_travel_enabled: Option<bool>,
}

impl GovRiskEnforcementPolicy {
    /// Get the enforcement policy for a tenant. Returns None if no policy exists.
    pub async fn get_by_tenant(
        pool: &PgPool,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as::<_, Self>(
            "SELECT id, tenant_id, enforcement_mode, fail_open, \
             impossible_travel_speed_kmh, impossible_travel_enabled, \
             created_at, updated_at \
             FROM gov_risk_enforcement_policies \
             WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Get the enforcement policy for a tenant, or return a default policy if none exists.
    /// The default policy has enforcement disabled, fail-open enabled, and standard travel speed.
    pub async fn get_or_default(pool: &PgPool, tenant_id: Uuid) -> Result<Self, sqlx::Error> {
        match Self::get_by_tenant(pool, tenant_id).await? {
            Some(policy) => Ok(policy),
            None => Ok(Self::default_for_tenant(tenant_id)),
        }
    }

    /// Create or update the enforcement policy for a tenant.
    /// If a policy already exists, updates only the provided fields.
    /// Returns the full policy after upsert.
    pub async fn upsert(
        pool: &PgPool,
        tenant_id: Uuid,
        input: &UpsertEnforcementPolicy,
    ) -> Result<Self, sqlx::Error> {
        let mode = input.enforcement_mode.unwrap_or(EnforcementMode::Disabled);
        let fail_open = input.fail_open.unwrap_or(true);
        let speed = input.impossible_travel_speed_kmh.unwrap_or(900);
        let travel_enabled = input.impossible_travel_enabled.unwrap_or(true);

        sqlx::query_as::<_, Self>(
            "INSERT INTO gov_risk_enforcement_policies \
             (tenant_id, enforcement_mode, fail_open, impossible_travel_speed_kmh, impossible_travel_enabled) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (tenant_id) DO UPDATE SET \
                enforcement_mode = COALESCE($2, gov_risk_enforcement_policies.enforcement_mode), \
                fail_open = COALESCE($3, gov_risk_enforcement_policies.fail_open), \
                impossible_travel_speed_kmh = COALESCE($4, gov_risk_enforcement_policies.impossible_travel_speed_kmh), \
                impossible_travel_enabled = COALESCE($5, gov_risk_enforcement_policies.impossible_travel_enabled), \
                updated_at = NOW() \
             RETURNING id, tenant_id, enforcement_mode, fail_open, \
                       impossible_travel_speed_kmh, impossible_travel_enabled, \
                       created_at, updated_at",
        )
        .bind(tenant_id)
        .bind(mode)
        .bind(fail_open)
        .bind(speed)
        .bind(travel_enabled)
        .fetch_one(pool)
        .await
    }

    /// Returns a default policy for a tenant (not persisted).
    fn default_for_tenant(tenant_id: Uuid) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::nil(),
            tenant_id,
            enforcement_mode: EnforcementMode::Disabled,
            fail_open: true,
            impossible_travel_speed_kmh: 900,
            impossible_travel_enabled: true,
            created_at: now,
            updated_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enforcement_mode_is_active() {
        assert!(!EnforcementMode::Disabled.is_active());
        assert!(EnforcementMode::Monitor.is_active());
        assert!(EnforcementMode::Enforce.is_active());
    }

    #[test]
    fn test_enforcement_mode_is_enforcing() {
        assert!(!EnforcementMode::Disabled.is_enforcing());
        assert!(!EnforcementMode::Monitor.is_enforcing());
        assert!(EnforcementMode::Enforce.is_enforcing());
    }

    #[test]
    fn test_default_policy() {
        let tenant_id = Uuid::new_v4();
        let policy = GovRiskEnforcementPolicy::default_for_tenant(tenant_id);
        assert_eq!(policy.tenant_id, tenant_id);
        assert_eq!(policy.enforcement_mode, EnforcementMode::Disabled);
        assert!(policy.fail_open);
        assert_eq!(policy.impossible_travel_speed_kmh, 900);
        assert!(policy.impossible_travel_enabled);
    }
}
