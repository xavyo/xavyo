//! Request and response models for tenant usage tracking API.
//!
//! F-USAGE-TRACK: Provides usage metrics for billing and quota enforcement.

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Usage metrics for the current billing period.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UsageMetrics {
    /// Monthly Active Users count.
    pub mau_count: i32,

    /// Total API calls during the period.
    pub api_calls: i64,

    /// Authentication events (logins, token refreshes).
    pub auth_events: i64,

    /// AI agent API invocations.
    pub agent_invocations: i64,
}

/// Usage limits from tenant plan settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct UsageLimits {
    /// Maximum Monthly Active Users (null = unlimited).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_mau: Option<i32>,

    /// Maximum API calls per month (null = unlimited).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_api_calls: Option<i64>,

    /// Maximum agent invocations per month (null = unlimited).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_agent_invocations: Option<i64>,
}

/// Response for current usage metrics.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UsageResponse {
    /// Tenant ID.
    #[schema(value_type = String, format = "uuid")]
    pub tenant_id: Uuid,

    /// Start of the billing period.
    #[schema(value_type = String, format = "date")]
    pub period_start: NaiveDate,

    /// End of the billing period.
    #[schema(value_type = String, format = "date")]
    pub period_end: NaiveDate,

    /// Current usage metrics.
    pub metrics: UsageMetrics,

    /// Plan limits.
    pub limits: UsageLimits,
}

/// Single usage period for history.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UsagePeriod {
    /// Start of the billing period.
    #[schema(value_type = String, format = "date")]
    pub period_start: NaiveDate,

    /// End of the billing period.
    #[schema(value_type = String, format = "date")]
    pub period_end: NaiveDate,

    /// Monthly Active Users count.
    pub mau_count: i32,

    /// Total API calls during the period.
    pub api_calls: i64,

    /// Authentication events.
    pub auth_events: i64,

    /// AI agent invocations.
    pub agent_invocations: i64,
}

/// Response for usage history.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UsageHistoryResponse {
    /// Tenant ID.
    #[schema(value_type = String, format = "uuid")]
    pub tenant_id: Uuid,

    /// Historical usage periods (most recent first).
    pub periods: Vec<UsagePeriod>,
}

/// Query parameters for usage history.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UsageHistoryQuery {
    /// Number of periods to retrieve (default: 6, max: 24).
    #[serde(default = "default_periods")]
    pub periods: usize,
}

fn default_periods() -> usize {
    6
}

impl UsageHistoryQuery {
    /// Validate the query parameters.
    #[must_use] 
    pub fn validate(&self) -> Option<String> {
        if self.periods == 0 {
            return Some("periods must be at least 1".to_string());
        }
        if self.periods > 24 {
            return Some("periods must be at most 24".to_string());
        }
        None
    }
}

impl Default for UsageHistoryQuery {
    fn default() -> Self {
        Self {
            periods: default_periods(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_usage_metrics_serialization() {
        let metrics = UsageMetrics {
            mau_count: 150,
            api_calls: 45230,
            auth_events: 3200,
            agent_invocations: 500,
        };

        let json = serde_json::to_string(&metrics).unwrap();
        assert!(json.contains("\"mau_count\":150"));
        assert!(json.contains("\"api_calls\":45230"));
        assert!(json.contains("\"auth_events\":3200"));
        assert!(json.contains("\"agent_invocations\":500"));
    }

    #[test]
    fn test_usage_limits_serialization_with_values() {
        let limits = UsageLimits {
            max_mau: Some(500),
            max_api_calls: None,
            max_agent_invocations: Some(10000),
        };

        let json = serde_json::to_string(&limits).unwrap();
        assert!(json.contains("\"max_mau\":500"));
        assert!(!json.contains("max_api_calls")); // skipped when None
        assert!(json.contains("\"max_agent_invocations\":10000"));
    }

    #[test]
    fn test_usage_limits_default() {
        let limits = UsageLimits::default();
        assert!(limits.max_mau.is_none());
        assert!(limits.max_api_calls.is_none());
        assert!(limits.max_agent_invocations.is_none());
    }

    #[test]
    fn test_usage_response_serialization() {
        let response = UsageResponse {
            tenant_id: Uuid::new_v4(),
            period_start: NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
            period_end: NaiveDate::from_ymd_opt(2024, 1, 31).unwrap(),
            metrics: UsageMetrics {
                mau_count: 100,
                api_calls: 5000,
                auth_events: 200,
                agent_invocations: 50,
            },
            limits: UsageLimits::default(),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("tenant_id"));
        assert!(json.contains("period_start"));
        assert!(json.contains("metrics"));
        assert!(json.contains("limits"));
    }

    #[test]
    fn test_usage_period_serialization() {
        let period = UsagePeriod {
            period_start: NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
            period_end: NaiveDate::from_ymd_opt(2024, 1, 31).unwrap(),
            mau_count: 100,
            api_calls: 5000,
            auth_events: 200,
            agent_invocations: 50,
        };

        let json = serde_json::to_string(&period).unwrap();
        assert!(json.contains("period_start"));
        assert!(json.contains("mau_count"));
    }

    #[test]
    fn test_usage_history_response_serialization() {
        let response = UsageHistoryResponse {
            tenant_id: Uuid::new_v4(),
            periods: vec![UsagePeriod {
                period_start: NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
                period_end: NaiveDate::from_ymd_opt(2024, 1, 31).unwrap(),
                mau_count: 100,
                api_calls: 5000,
                auth_events: 200,
                agent_invocations: 50,
            }],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("tenant_id"));
        assert!(json.contains("periods"));
    }

    #[test]
    fn test_usage_history_query_validation() {
        let query = UsageHistoryQuery { periods: 0 };
        assert!(query.validate().is_some());

        let query = UsageHistoryQuery { periods: 25 };
        assert!(query.validate().is_some());

        let query = UsageHistoryQuery { periods: 6 };
        assert!(query.validate().is_none());
    }

    #[test]
    fn test_usage_history_query_default() {
        let query = UsageHistoryQuery::default();
        assert_eq!(query.periods, 6);
    }
}
