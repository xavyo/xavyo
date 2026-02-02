//! Service for unified NHI risk summary.
//!
//! This service provides aggregated risk statistics across all
//! non-human identities (service accounts and AI agents).

use sqlx::PgPool;
use uuid::Uuid;
use xavyo_db::models::{NhiRiskSummary, NonHumanIdentityView};

/// Service for calculating unified risk summaries.
#[derive(Clone)]
pub struct UnifiedRiskService {
    pool: PgPool,
}

impl UnifiedRiskService {
    /// Creates a new UnifiedRiskService.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Gets risk summary statistics for a tenant.
    ///
    /// Aggregates risk data across all NHI types:
    /// - Total count by type (service_account, ai_agent)
    /// - Count by risk level (critical, high, medium, low)
    /// - NHIs pending certification
    /// - Inactive NHIs (no activity in 30 days)
    /// - NHIs expiring soon (within 7 days)
    pub async fn get_risk_summary(&self, tenant_id: Uuid) -> Result<NhiRiskSummary, sqlx::Error> {
        NonHumanIdentityView::get_risk_summary(&self.pool, tenant_id).await
    }
}

#[cfg(test)]
mod tests {
    use xavyo_db::models::{NhiCountByRiskLevel, NhiCountByType};

    use super::*;

    #[test]
    fn test_risk_summary_structure() {
        // Verify the NhiRiskSummary struct has expected fields
        let summary = NhiRiskSummary {
            total_count: 100,
            by_type: NhiCountByType {
                service_account: 60,
                ai_agent: 40,
            },
            by_risk_level: NhiCountByRiskLevel {
                critical: 5,
                high: 15,
                medium: 30,
                low: 50,
            },
            pending_certification: 10,
            inactive_30_days: 8,
            expiring_7_days: 3,
        };

        assert_eq!(summary.total_count, 100);
        assert_eq!(summary.by_type.service_account, 60);
        assert_eq!(summary.by_type.ai_agent, 40);
        assert_eq!(summary.by_risk_level.critical, 5);
        assert_eq!(summary.by_risk_level.high, 15);
        assert_eq!(summary.by_risk_level.medium, 30);
        assert_eq!(summary.by_risk_level.low, 50);
        assert_eq!(summary.pending_certification, 10);
        assert_eq!(summary.inactive_30_days, 8);
        assert_eq!(summary.expiring_7_days, 3);
    }

    #[test]
    fn test_risk_level_totals() {
        let summary = NhiRiskSummary {
            total_count: 100,
            by_type: NhiCountByType {
                service_account: 60,
                ai_agent: 40,
            },
            by_risk_level: NhiCountByRiskLevel {
                critical: 5,
                high: 15,
                medium: 30,
                low: 50,
            },
            pending_certification: 10,
            inactive_30_days: 8,
            expiring_7_days: 3,
        };

        // Risk level counts should sum to total
        let risk_total = summary.by_risk_level.critical
            + summary.by_risk_level.high
            + summary.by_risk_level.medium
            + summary.by_risk_level.low;
        assert_eq!(risk_total, summary.total_count);

        // Type counts should sum to total
        let type_total = summary.by_type.service_account + summary.by_type.ai_agent;
        assert_eq!(type_total, summary.total_count);
    }
}
