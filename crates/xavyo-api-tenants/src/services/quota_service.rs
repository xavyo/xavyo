//! Quota enforcement service.
//!
//! F-QUOTA-ENFORCE: Checks tenant usage against plan limits.

use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::TenantError;

/// Type of quota being checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuotaType {
    /// Monthly Active Users limit.
    Mau,
    /// API calls per month limit.
    ApiCalls,
    /// Agent invocations per month limit.
    AgentInvocations,
}

impl std::fmt::Display for QuotaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuotaType::Mau => write!(f, "mau"),
            QuotaType::ApiCalls => write!(f, "api_calls"),
            QuotaType::AgentInvocations => write!(f, "agent_invocations"),
        }
    }
}

/// Result of a quota check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaCheck {
    /// Whether the quota has been exceeded.
    pub exceeded: bool,

    /// Type of quota checked.
    pub quota_type: QuotaType,

    /// Current usage value.
    pub current: i64,

    /// Limit value (None = unlimited).
    pub limit: Option<i64>,

    /// When the quota resets (start of next billing period).
    pub reset_at: DateTime<Utc>,
}

/// Tenant limits extracted from settings.
#[derive(Debug, Clone, Default)]
pub struct TenantLimits {
    /// Maximum Monthly Active Users (None = unlimited).
    pub max_mau: Option<i64>,

    /// Maximum API calls per month (None = unlimited).
    pub max_api_calls: Option<i64>,

    /// Maximum agent invocations per month (None = unlimited).
    pub max_agent_invocations: Option<i64>,
}

/// Service for checking tenant quotas.
#[derive(Clone)]
pub struct QuotaService {
    pool: PgPool,
}

impl QuotaService {
    /// Create a new quota service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Check if API call quota is exceeded.
    pub async fn check_api_calls(&self, tenant_id: Uuid) -> Result<QuotaCheck, TenantError> {
        let (limits, usage) = self.get_limits_and_usage(tenant_id).await?;
        let reset_at = Self::next_period_start();

        let exceeded = limits
            .max_api_calls
            .is_some_and(|limit| usage.api_calls >= limit);

        Ok(QuotaCheck {
            exceeded,
            quota_type: QuotaType::ApiCalls,
            current: usage.api_calls,
            limit: limits.max_api_calls,
            reset_at,
        })
    }

    /// Check if MAU quota is exceeded.
    pub async fn check_mau(&self, tenant_id: Uuid) -> Result<QuotaCheck, TenantError> {
        let (limits, usage) = self.get_limits_and_usage(tenant_id).await?;
        let reset_at = Self::next_period_start();

        let exceeded = limits.max_mau.is_some_and(|limit| usage.mau_count >= limit);

        Ok(QuotaCheck {
            exceeded,
            quota_type: QuotaType::Mau,
            current: usage.mau_count,
            limit: limits.max_mau,
            reset_at,
        })
    }

    /// Check if agent invocation quota is exceeded.
    pub async fn check_agent_invocations(
        &self,
        tenant_id: Uuid,
    ) -> Result<QuotaCheck, TenantError> {
        let (limits, usage) = self.get_limits_and_usage(tenant_id).await?;
        let reset_at = Self::next_period_start();

        let exceeded = limits
            .max_agent_invocations
            .is_some_and(|limit| usage.agent_invocations >= limit);

        Ok(QuotaCheck {
            exceeded,
            quota_type: QuotaType::AgentInvocations,
            current: usage.agent_invocations,
            limit: limits.max_agent_invocations,
            reset_at,
        })
    }

    /// Get tenant limits and current usage.
    async fn get_limits_and_usage(
        &self,
        tenant_id: Uuid,
    ) -> Result<(TenantLimits, CurrentUsage), TenantError> {
        // Get tenant settings
        let tenant = xavyo_db::models::Tenant::find_by_id(&self.pool, tenant_id)
            .await
            .map_err(|e| TenantError::Database(e.to_string()))?
            .ok_or_else(|| {
                TenantError::NotFoundWithMessage(format!("Tenant {} not found", tenant_id))
            })?;

        let limits = Self::extract_limits(&tenant.settings);

        // Get current usage
        let usage = self.get_current_usage(tenant_id).await?;

        Ok((limits, usage))
    }

    /// Extract limits from tenant settings JSON.
    fn extract_limits(settings: &serde_json::Value) -> TenantLimits {
        let limits_obj = settings.get("limits").cloned().unwrap_or_default();

        TenantLimits {
            max_mau: limits_obj.get("max_mau").and_then(|v| v.as_i64()),
            max_api_calls: limits_obj.get("max_api_calls").and_then(|v| v.as_i64()),
            max_agent_invocations: limits_obj
                .get("max_agent_invocations")
                .and_then(|v| v.as_i64()),
        }
    }

    /// Get current usage from database.
    async fn get_current_usage(&self, tenant_id: Uuid) -> Result<CurrentUsage, TenantError> {
        let today = Utc::now().date_naive();
        let period_start = Self::period_start_for(today);

        let result: Option<(i32, i64, i64, i64)> = sqlx::query_as(
            r#"
            SELECT mau_count, api_calls, auth_events, agent_invocations
            FROM tenant_usage_metrics
            WHERE tenant_id = $1 AND period_start = $2
            "#,
        )
        .bind(tenant_id)
        .bind(period_start)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| TenantError::Database(e.to_string()))?;

        Ok(
            result.map_or(CurrentUsage::default(), |(mau, api, auth, agent)| {
                CurrentUsage {
                    mau_count: mau as i64,
                    api_calls: api,
                    auth_events: auth,
                    agent_invocations: agent,
                }
            }),
        )
    }

    /// Calculate the period start for a given date (first day of month).
    fn period_start_for(date: NaiveDate) -> NaiveDate {
        NaiveDate::from_ymd_opt(date.year(), date.month(), 1).unwrap()
    }

    /// Calculate the start of the next billing period.
    fn next_period_start() -> DateTime<Utc> {
        let today = Utc::now().date_naive();
        let next_month = if today.month() == 12 {
            NaiveDate::from_ymd_opt(today.year() + 1, 1, 1).unwrap()
        } else {
            NaiveDate::from_ymd_opt(today.year(), today.month() + 1, 1).unwrap()
        };
        next_month.and_hms_opt(0, 0, 0).unwrap().and_utc()
    }
}

/// Current usage values.
#[derive(Debug, Clone, Default)]
struct CurrentUsage {
    mau_count: i64,
    api_calls: i64,
    #[allow(dead_code)] // Reserved for future auth event rate limiting
    auth_events: i64,
    agent_invocations: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Timelike;

    #[test]
    fn test_quota_type_display() {
        assert_eq!(QuotaType::Mau.to_string(), "mau");
        assert_eq!(QuotaType::ApiCalls.to_string(), "api_calls");
        assert_eq!(QuotaType::AgentInvocations.to_string(), "agent_invocations");
    }

    #[test]
    fn test_quota_type_serialization() {
        let quota = QuotaType::ApiCalls;
        let json = serde_json::to_string(&quota).unwrap();
        assert_eq!(json, "\"api_calls\"");
    }

    #[test]
    fn test_extract_limits_full() {
        let settings = serde_json::json!({
            "limits": {
                "max_mau": 500,
                "max_api_calls": 100000,
                "max_agent_invocations": 10000
            }
        });

        let limits = QuotaService::extract_limits(&settings);
        assert_eq!(limits.max_mau, Some(500));
        assert_eq!(limits.max_api_calls, Some(100000));
        assert_eq!(limits.max_agent_invocations, Some(10000));
    }

    #[test]
    fn test_extract_limits_empty() {
        let settings = serde_json::json!({});

        let limits = QuotaService::extract_limits(&settings);
        assert_eq!(limits.max_mau, None);
        assert_eq!(limits.max_api_calls, None);
        assert_eq!(limits.max_agent_invocations, None);
    }

    #[test]
    fn test_extract_limits_partial() {
        let settings = serde_json::json!({
            "limits": {
                "max_mau": 100
            }
        });

        let limits = QuotaService::extract_limits(&settings);
        assert_eq!(limits.max_mau, Some(100));
        assert_eq!(limits.max_api_calls, None);
        assert_eq!(limits.max_agent_invocations, None);
    }

    #[test]
    fn test_period_start_calculation() {
        let date = NaiveDate::from_ymd_opt(2024, 3, 15).unwrap();
        let period_start = QuotaService::period_start_for(date);
        assert_eq!(period_start, NaiveDate::from_ymd_opt(2024, 3, 1).unwrap());
    }

    #[test]
    fn test_next_period_start_calculation() {
        let next = QuotaService::next_period_start();
        let today = Utc::now().date_naive();

        // Should be first day of next month
        assert_eq!(next.day(), 1);
        assert_eq!(next.hour(), 0);
        assert_eq!(next.minute(), 0);

        // Should be in the future
        assert!(next > Utc::now());
    }

    #[test]
    fn test_quota_check_serialization() {
        let check = QuotaCheck {
            exceeded: true,
            quota_type: QuotaType::ApiCalls,
            current: 100500,
            limit: Some(100000),
            reset_at: Utc::now(),
        };

        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("\"exceeded\":true"));
        assert!(json.contains("\"quota_type\":\"api_calls\""));
        assert!(json.contains("\"current\":100500"));
        assert!(json.contains("\"limit\":100000"));
    }

    #[test]
    fn test_tenant_limits_default() {
        let limits = TenantLimits::default();
        assert!(limits.max_mau.is_none());
        assert!(limits.max_api_calls.is_none());
        assert!(limits.max_agent_invocations.is_none());
    }
}
