//! License Analytics Service (F065).
//!
//! Provides dashboard analytics, cost optimization recommendations,
//! and usage trend reporting for license management.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    GovLicensePool, LicensePoolFilter, LicensePoolStatus, HIGH_UTILIZATION_THRESHOLD,
    UNDERUTILIZATION_THRESHOLD,
};
use xavyo_governance::error::Result;

use super::license_audit_service::LicenseAuditService;
use crate::models::license::{
    LicenseAuditEntry, LicenseDashboardResponse, LicensePoolStats, LicenseRecommendation,
    LicenseSummary, RecommendationType, VendorCost,
};

/// A single point in a pool's usage trend history.
#[derive(Debug, Clone, Serialize)]
pub struct PoolTrendPoint {
    /// The date/time of the snapshot.
    pub date: DateTime<Utc>,
    /// Number of licenses allocated at this point.
    pub allocated_count: i32,
    /// Total pool capacity at this point.
    pub total_capacity: i32,
    /// Utilization as a percentage (0.0 - 100.0).
    pub utilization_percent: f64,
}

/// Service for license usage analytics, dashboard aggregation,
/// cost optimization recommendations, and trend reporting.
pub struct LicenseAnalyticsService {
    pool: PgPool,
}

impl LicenseAnalyticsService {
    /// Create a new license analytics service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Build the license management dashboard.
    ///
    /// Aggregates all active license pools into summary statistics, per-pool
    /// breakdowns, vendor cost groupings, and recent audit events.
    pub async fn get_dashboard(&self, tenant_id: Uuid) -> Result<LicenseDashboardResponse> {
        // Fetch all active pools
        let filter = LicensePoolFilter {
            status: Some(LicensePoolStatus::Active),
            ..Default::default()
        };
        let active_pools =
            GovLicensePool::list_by_tenant(&self.pool, tenant_id, &filter, i64::MAX, 0).await?;

        // Build summary by aggregating pool data
        let total_pools = active_pools.len() as i64;
        let total_capacity: i64 = active_pools.iter().map(|p| i64::from(p.total_capacity)).sum();
        let total_allocated: i64 = active_pools.iter().map(|p| i64::from(p.allocated_count)).sum();
        let total_available = total_capacity - total_allocated;

        let overall_utilization = if total_capacity > 0 {
            (total_allocated as f64 / total_capacity as f64) * 100.0
        } else {
            0.0
        };

        let total_monthly_cost: Decimal = active_pools
            .iter()
            .filter_map(xavyo_db::models::GovLicensePool::monthly_allocated_cost)
            .sum();

        let expiring_soon_count = active_pools
            .iter()
            .filter(|p| p.should_show_expiration_warning())
            .count() as i64;

        let summary = LicenseSummary {
            total_pools,
            total_capacity,
            total_allocated,
            total_available,
            overall_utilization,
            total_monthly_cost,
            expiring_soon_count,
        };

        // Build per-pool stats
        let pools: Vec<LicensePoolStats> = active_pools.iter().map(pool_to_stats).collect();

        // Group by (vendor, currency) for vendor cost breakdown
        let cost_by_vendor = build_vendor_costs(&active_pools);

        // Fetch recent audit events
        let audit_service = LicenseAuditService::new(self.pool.clone());
        let service_entries = audit_service.get_recent(tenant_id, 10).await?;

        // Convert from service LicenseAuditEntry to model LicenseAuditEntry
        let recent_events: Vec<LicenseAuditEntry> = service_entries
            .into_iter()
            .map(convert_audit_entry)
            .collect();

        Ok(LicenseDashboardResponse {
            summary,
            pools,
            cost_by_vendor,
            recent_events,
        })
    }

    /// Generate cost optimization and capacity planning recommendations.
    ///
    /// Analyzes all active license pools and produces actionable recommendations:
    /// - Underutilized pools (< 60% utilization) with potential savings
    /// - High utilization pools (> 90%) that may need expansion
    /// - Pools that are expiring soon
    pub async fn get_recommendations(&self, tenant_id: Uuid) -> Result<Vec<LicenseRecommendation>> {
        let filter = LicensePoolFilter {
            status: Some(LicensePoolStatus::Active),
            ..Default::default()
        };
        let active_pools =
            GovLicensePool::list_by_tenant(&self.pool, tenant_id, &filter, i64::MAX, 0).await?;

        let mut recommendations = Vec::new();

        for pool in &active_pools {
            // Skip pools with zero capacity (no meaningful utilization)
            if pool.total_capacity == 0 {
                continue;
            }

            let utilization = pool.utilization_percent() / 100.0;

            // Underutilization check
            if utilization < UNDERUTILIZATION_THRESHOLD {
                let unused_count = pool.available_count();
                let potential_savings = pool.cost_per_license.map(|cost| {
                    let unused = Decimal::from(unused_count);
                    match pool.billing_period {
                        xavyo_db::models::LicenseBillingPeriod::Monthly => cost * unused,
                        xavyo_db::models::LicenseBillingPeriod::Annual => {
                            (cost * unused) / Decimal::from(12)
                        }
                        xavyo_db::models::LicenseBillingPeriod::Perpetual => Decimal::ZERO,
                    }
                });

                recommendations.push(LicenseRecommendation {
                    recommendation_type: RecommendationType::Underutilized,
                    pool_id: pool.id,
                    pool_name: pool.name.clone(),
                    description: format!(
                        "Pool \"{}\" is at {:.1}% utilization ({} of {} licenses used). \
                         Consider reducing capacity to optimize costs.",
                        pool.name,
                        pool.utilization_percent(),
                        pool.allocated_count,
                        pool.total_capacity,
                    ),
                    potential_savings,
                    currency: if potential_savings.is_some() {
                        Some(pool.currency.clone())
                    } else {
                        None
                    },
                });
            }

            // High utilization check
            if utilization > HIGH_UTILIZATION_THRESHOLD {
                recommendations.push(LicenseRecommendation {
                    recommendation_type: RecommendationType::HighUtilization,
                    pool_id: pool.id,
                    pool_name: pool.name.clone(),
                    description: format!(
                        "Pool \"{}\" is at {:.1}% utilization ({} of {} licenses used). \
                         Consider expanding capacity to avoid assignment failures.",
                        pool.name,
                        pool.utilization_percent(),
                        pool.allocated_count,
                        pool.total_capacity,
                    ),
                    potential_savings: None,
                    currency: None,
                });
            }

            // Expiring soon check
            if pool.should_show_expiration_warning() {
                let days_remaining = pool
                    .expiration_date
                    .map_or(0, |exp| {
                        let diff = exp - Utc::now();
                        diff.num_days()
                    });

                recommendations.push(LicenseRecommendation {
                    recommendation_type: RecommendationType::ExpiringSoon,
                    pool_id: pool.id,
                    pool_name: pool.name.clone(),
                    description: format!(
                        "Pool \"{}\" expires in {} days with {} active assignments. \
                         Review renewal options.",
                        pool.name, days_remaining, pool.allocated_count,
                    ),
                    potential_savings: None,
                    currency: None,
                });
            }
        }

        // Sort by priority: ExpiringSoon > HighUtilization > Underutilized > ReclaimOpportunity
        recommendations.sort_by_key(|r| recommendation_priority(&r.recommendation_type));

        Ok(recommendations)
    }

    /// Get usage trend data for a specific license pool.
    ///
    /// Returns historical utilization snapshots. Currently returns the pool's
    /// current state as a single data point; future versions will aggregate
    /// from audit event history to provide month-over-month trends.
    pub async fn get_pool_trends(
        &self,
        tenant_id: Uuid,
        pool_id: Uuid,
    ) -> Result<Vec<PoolTrendPoint>> {
        let pool_record = GovLicensePool::find_by_id(&self.pool, tenant_id, pool_id).await?;

        match pool_record {
            Some(p) => {
                let point = PoolTrendPoint {
                    date: Utc::now(),
                    allocated_count: p.allocated_count,
                    total_capacity: p.total_capacity,
                    utilization_percent: p.utilization_percent(),
                };
                Ok(vec![point])
            }
            None => Ok(vec![]),
        }
    }

    /// Get the underlying database pool reference.
    #[must_use] 
    pub fn db_pool(&self) -> &PgPool {
        &self.pool
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert a `GovLicensePool` into `LicensePoolStats`.
fn pool_to_stats(pool: &GovLicensePool) -> LicensePoolStats {
    LicensePoolStats {
        id: pool.id,
        name: pool.name.clone(),
        vendor: pool.vendor.clone(),
        total_capacity: pool.total_capacity,
        allocated_count: pool.allocated_count,
        utilization_percent: pool.utilization_percent(),
        monthly_cost: pool.monthly_allocated_cost(),
        status: pool.status,
        expiration_date: pool.expiration_date,
    }
}

/// Group pools by (vendor, currency) and aggregate costs.
fn build_vendor_costs(pools: &[GovLicensePool]) -> Vec<VendorCost> {
    let mut groups: HashMap<(String, String), VendorCostAccumulator> = HashMap::new();

    for pool in pools {
        let key = (pool.vendor.clone(), pool.currency.clone());
        let entry = groups.entry(key).or_insert_with(VendorCostAccumulator::new);
        entry.pool_count += 1;
        entry.total_capacity += i64::from(pool.total_capacity);
        entry.allocated_count += i64::from(pool.allocated_count);
        entry.monthly_cost += pool.monthly_allocated_cost().unwrap_or(Decimal::ZERO);
    }

    let mut results: Vec<VendorCost> = groups
        .into_iter()
        .map(|((vendor, currency), acc)| VendorCost {
            vendor,
            pool_count: acc.pool_count,
            total_capacity: acc.total_capacity,
            allocated_count: acc.allocated_count,
            monthly_cost: acc.monthly_cost,
            currency,
        })
        .collect();

    // Sort by vendor name for deterministic output
    results.sort_by(|a, b| a.vendor.cmp(&b.vendor).then(a.currency.cmp(&b.currency)));
    results
}

/// Accumulator for grouping vendor cost data.
struct VendorCostAccumulator {
    pool_count: i64,
    total_capacity: i64,
    allocated_count: i64,
    monthly_cost: Decimal,
}

impl VendorCostAccumulator {
    fn new() -> Self {
        Self {
            pool_count: 0,
            total_capacity: 0,
            allocated_count: 0,
            monthly_cost: Decimal::ZERO,
        }
    }
}

/// Map recommendation type to a sort priority (lower = higher priority).
fn recommendation_priority(rt: &RecommendationType) -> u8 {
    match rt {
        RecommendationType::ExpiringSoon => 0,
        RecommendationType::HighUtilization => 1,
        RecommendationType::Underutilized => 2,
        RecommendationType::ReclaimOpportunity => 3,
    }
}

/// Convert the service-layer `LicenseAuditEntry` to the model-layer `LicenseAuditEntry`.
///
/// Both types have identical fields but exist in different modules. The dashboard
/// response uses the model-layer type, while the audit service returns its own type.
fn convert_audit_entry(
    entry: super::license_audit_service::LicenseAuditEntry,
) -> LicenseAuditEntry {
    LicenseAuditEntry {
        id: entry.id,
        pool_id: entry.pool_id,
        pool_name: entry.pool_name,
        assignment_id: entry.assignment_id,
        user_id: entry.user_id,
        user_email: entry.user_email,
        action: entry.action,
        actor_id: entry.actor_id,
        actor_email: entry.actor_email,
        details: entry.details,
        created_at: entry.created_at,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use rust_decimal::Decimal;
    use std::str::FromStr;
    use xavyo_db::models::{
        LicenseBillingPeriod, LicenseExpirationPolicy, LicensePoolStatus, LicenseType,
    };

    // ========================================================================
    // Test Helpers
    // ========================================================================

    /// Create a test `GovLicensePool` with configurable fields.
    fn make_pool(
        name: &str,
        vendor: &str,
        capacity: i32,
        allocated: i32,
        cost: Option<Decimal>,
        currency: &str,
        billing: LicenseBillingPeriod,
        expiration: Option<DateTime<Utc>>,
        warning_days: i32,
        status: LicensePoolStatus,
    ) -> GovLicensePool {
        GovLicensePool {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: name.to_string(),
            vendor: vendor.to_string(),
            description: None,
            total_capacity: capacity,
            allocated_count: allocated,
            cost_per_license: cost,
            currency: currency.to_string(),
            billing_period: billing,
            license_type: LicenseType::Named,
            expiration_date: expiration,
            expiration_policy: LicenseExpirationPolicy::BlockNew,
            warning_days,
            status,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: Uuid::new_v4(),
        }
    }

    /// Create a simple active pool with monthly billing and USD cost.
    fn make_active_pool(
        name: &str,
        vendor: &str,
        capacity: i32,
        allocated: i32,
        cost_per_license: Option<Decimal>,
    ) -> GovLicensePool {
        make_pool(
            name,
            vendor,
            capacity,
            allocated,
            cost_per_license,
            "USD",
            LicenseBillingPeriod::Monthly,
            None,
            60,
            LicensePoolStatus::Active,
        )
    }

    // ========================================================================
    // LicenseSummary Tests
    // ========================================================================

    #[test]
    fn test_license_summary_construction() {
        let summary = LicenseSummary {
            total_pools: 5,
            total_capacity: 1000,
            total_allocated: 750,
            total_available: 250,
            overall_utilization: 75.0,
            total_monthly_cost: Decimal::from(27000),
            expiring_soon_count: 2,
        };

        assert_eq!(summary.total_pools, 5);
        assert_eq!(summary.total_capacity, 1000);
        assert_eq!(summary.total_allocated, 750);
        assert_eq!(summary.total_available, 250);
        assert!((summary.overall_utilization - 75.0).abs() < f64::EPSILON);
        assert_eq!(summary.total_monthly_cost, Decimal::from(27000));
        assert_eq!(summary.expiring_soon_count, 2);
    }

    #[test]
    fn test_license_summary_serialization() {
        let summary = LicenseSummary {
            total_pools: 3,
            total_capacity: 500,
            total_allocated: 200,
            total_available: 300,
            overall_utilization: 40.0,
            total_monthly_cost: Decimal::from(7200),
            expiring_soon_count: 0,
        };

        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"total_pools\":3"));
        assert!(json.contains("\"total_capacity\":500"));
        assert!(json.contains("\"total_allocated\":200"));
        assert!(json.contains("\"total_available\":300"));
        assert!(json.contains("\"expiring_soon_count\":0"));
    }

    #[test]
    fn test_license_summary_empty_pools() {
        let summary = LicenseSummary {
            total_pools: 0,
            total_capacity: 0,
            total_allocated: 0,
            total_available: 0,
            overall_utilization: 0.0,
            total_monthly_cost: Decimal::ZERO,
            expiring_soon_count: 0,
        };

        assert_eq!(summary.total_pools, 0);
        assert!((summary.overall_utilization - 0.0).abs() < f64::EPSILON);
        assert_eq!(summary.total_monthly_cost, Decimal::ZERO);
    }

    // ========================================================================
    // LicensePoolStats Tests
    // ========================================================================

    #[test]
    fn test_pool_stats_from_pool_data() {
        let pool = make_active_pool(
            "Office 365 E3",
            "Microsoft",
            500,
            350,
            Some(Decimal::from(36)),
        );
        let stats = pool_to_stats(&pool);

        assert_eq!(stats.id, pool.id);
        assert_eq!(stats.name, "Office 365 E3");
        assert_eq!(stats.vendor, "Microsoft");
        assert_eq!(stats.total_capacity, 500);
        assert_eq!(stats.allocated_count, 350);
        assert!((stats.utilization_percent - 70.0).abs() < f64::EPSILON);
        assert!(stats.monthly_cost.is_some());
        assert_eq!(stats.status, LicensePoolStatus::Active);
        assert!(stats.expiration_date.is_none());
    }

    #[test]
    fn test_pool_stats_with_zero_capacity() {
        let pool = make_active_pool("Empty Pool", "Vendor", 0, 0, Some(Decimal::from(10)));
        let stats = pool_to_stats(&pool);

        assert_eq!(stats.total_capacity, 0);
        assert_eq!(stats.allocated_count, 0);
        assert!((stats.utilization_percent - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_pool_stats_fully_utilized() {
        let pool = make_active_pool("Full Pool", "Vendor", 100, 100, Some(Decimal::from(50)));
        let stats = pool_to_stats(&pool);

        assert!((stats.utilization_percent - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_pool_stats_no_cost() {
        let pool = make_active_pool("Free Pool", "Vendor", 100, 50, None);
        let stats = pool_to_stats(&pool);

        assert!(stats.monthly_cost.is_none());
    }

    #[test]
    fn test_pool_stats_with_expiration() {
        let expiration = Utc::now() + Duration::days(30);
        let pool = make_pool(
            "Expiring Pool",
            "Vendor",
            200,
            150,
            Some(Decimal::from(25)),
            "EUR",
            LicenseBillingPeriod::Annual,
            Some(expiration),
            60,
            LicensePoolStatus::Active,
        );
        let stats = pool_to_stats(&pool);

        assert!(stats.expiration_date.is_some());
        assert!(
            (stats.expiration_date.unwrap() - expiration)
                .num_seconds()
                .abs()
                < 1
        );
    }

    #[test]
    fn test_pool_stats_serialization() {
        let pool = make_active_pool(
            "Serialized Pool",
            "Vendor",
            100,
            75,
            Some(Decimal::from(10)),
        );
        let stats = pool_to_stats(&pool);

        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.contains("\"name\":\"Serialized Pool\""));
        assert!(json.contains("\"vendor\":\"Vendor\""));
        assert!(json.contains("\"total_capacity\":100"));
        assert!(json.contains("\"allocated_count\":75"));
    }

    // ========================================================================
    // VendorCost Grouping Tests
    // ========================================================================

    #[test]
    fn test_vendor_cost_single_vendor() {
        let pools = vec![
            make_active_pool("Pool A", "Microsoft", 100, 50, Some(Decimal::from(36))),
            make_active_pool("Pool B", "Microsoft", 200, 150, Some(Decimal::from(22))),
        ];

        let costs = build_vendor_costs(&pools);

        assert_eq!(costs.len(), 1);
        let microsoft = &costs[0];
        assert_eq!(microsoft.vendor, "Microsoft");
        assert_eq!(microsoft.pool_count, 2);
        assert_eq!(microsoft.total_capacity, 300);
        assert_eq!(microsoft.allocated_count, 200);
        assert_eq!(microsoft.currency, "USD");
        // Monthly cost: 50*36 + 150*22 = 1800 + 3300 = 5100
        assert_eq!(microsoft.monthly_cost, Decimal::from(5100));
    }

    #[test]
    fn test_vendor_cost_multiple_vendors() {
        let pools = vec![
            make_active_pool("Office 365", "Microsoft", 500, 400, Some(Decimal::from(36))),
            make_active_pool(
                "Salesforce CRM",
                "Salesforce",
                100,
                80,
                Some(Decimal::from(75)),
            ),
            make_active_pool(
                "Azure DevOps",
                "Microsoft",
                200,
                100,
                Some(Decimal::from(52)),
            ),
        ];

        let costs = build_vendor_costs(&pools);

        assert_eq!(costs.len(), 2);

        // Sorted by vendor name
        assert_eq!(costs[0].vendor, "Microsoft");
        assert_eq!(costs[0].pool_count, 2);
        assert_eq!(costs[0].total_capacity, 700);
        assert_eq!(costs[0].allocated_count, 500);

        assert_eq!(costs[1].vendor, "Salesforce");
        assert_eq!(costs[1].pool_count, 1);
        assert_eq!(costs[1].total_capacity, 100);
        assert_eq!(costs[1].allocated_count, 80);
    }

    #[test]
    fn test_vendor_cost_empty_pools() {
        let pools: Vec<GovLicensePool> = vec![];
        let costs = build_vendor_costs(&pools);
        assert!(costs.is_empty());
    }

    #[test]
    fn test_vendor_cost_no_cost_per_license() {
        let pools = vec![make_active_pool("Free Pool", "FreeVendor", 100, 50, None)];

        let costs = build_vendor_costs(&pools);

        assert_eq!(costs.len(), 1);
        assert_eq!(costs[0].monthly_cost, Decimal::ZERO);
    }

    #[test]
    fn test_vendor_cost_mixed_currencies() {
        let pool_usd = make_active_pool("US Pool", "Acme", 100, 80, Some(Decimal::from(50)));
        let pool_eur = make_pool(
            "EU Pool",
            "Acme",
            200,
            150,
            Some(Decimal::from(45)),
            "EUR",
            LicenseBillingPeriod::Monthly,
            None,
            60,
            LicensePoolStatus::Active,
        );

        let costs = build_vendor_costs(&[pool_usd, pool_eur]);

        // Same vendor but different currencies => separate entries
        assert_eq!(costs.len(), 2);

        let usd_entry = costs.iter().find(|c| c.currency == "USD").unwrap();
        let eur_entry = costs.iter().find(|c| c.currency == "EUR").unwrap();

        assert_eq!(usd_entry.pool_count, 1);
        assert_eq!(usd_entry.total_capacity, 100);
        // 80 * 50 = 4000
        assert_eq!(usd_entry.monthly_cost, Decimal::from(4000));

        assert_eq!(eur_entry.pool_count, 1);
        assert_eq!(eur_entry.total_capacity, 200);
        // 150 * 45 = 6750
        assert_eq!(eur_entry.monthly_cost, Decimal::from(6750));
    }

    #[test]
    fn test_vendor_cost_annual_billing() {
        let pool = make_pool(
            "Annual Pool",
            "AnnualVendor",
            100,
            60,
            Some(Decimal::from(120)),
            "USD",
            LicenseBillingPeriod::Annual,
            None,
            60,
            LicensePoolStatus::Active,
        );

        let costs = build_vendor_costs(&[pool]);

        assert_eq!(costs.len(), 1);
        // Annual cost: 60 * 120 = 7200, monthly = 7200 / 12 = 600
        assert_eq!(costs[0].monthly_cost, Decimal::from(600));
    }

    #[test]
    fn test_vendor_cost_perpetual_billing() {
        let pool = make_pool(
            "Perpetual Pool",
            "PerpVendor",
            100,
            80,
            Some(Decimal::from(500)),
            "USD",
            LicenseBillingPeriod::Perpetual,
            None,
            60,
            LicensePoolStatus::Active,
        );

        let costs = build_vendor_costs(&[pool]);

        assert_eq!(costs.len(), 1);
        // Perpetual = no monthly cost
        assert_eq!(costs[0].monthly_cost, Decimal::ZERO);
    }

    // ========================================================================
    // Recommendation Generation Tests
    // ========================================================================

    #[test]
    fn test_recommendation_underutilized() {
        // 30% utilization (well below 60% threshold)
        let pool = make_active_pool("Low Usage", "Vendor", 100, 30, Some(Decimal::from(50)));

        let utilization = pool.utilization_percent() / 100.0;
        assert!(utilization < UNDERUTILIZATION_THRESHOLD);

        let unused = pool.available_count();
        assert_eq!(unused, 70);

        // Verify potential savings calculation
        let savings = pool.cost_per_license.map(|c| c * Decimal::from(unused));
        assert_eq!(savings, Some(Decimal::from(3500)));
    }

    #[test]
    fn test_recommendation_high_utilization() {
        // 95% utilization (above 90% threshold)
        let pool = make_active_pool("Nearly Full", "Vendor", 100, 95, None);

        let utilization = pool.utilization_percent() / 100.0;
        assert!(utilization > HIGH_UTILIZATION_THRESHOLD);
    }

    #[test]
    fn test_recommendation_expiring_soon() {
        // Expiration within warning window
        let warning_days = 60;
        let expiration = Utc::now() + Duration::days(30);
        let pool = make_pool(
            "Expiring",
            "Vendor",
            100,
            80,
            Some(Decimal::from(25)),
            "USD",
            LicenseBillingPeriod::Monthly,
            Some(expiration),
            warning_days,
            LicensePoolStatus::Active,
        );

        assert!(pool.should_show_expiration_warning());
    }

    #[test]
    fn test_recommendation_not_expiring_far_away() {
        // Expiration far in the future (beyond warning window)
        let warning_days = 60;
        let expiration = Utc::now() + Duration::days(365);
        let pool = make_pool(
            "Not Expiring",
            "Vendor",
            100,
            80,
            Some(Decimal::from(25)),
            "USD",
            LicenseBillingPeriod::Monthly,
            Some(expiration),
            warning_days,
            LicensePoolStatus::Active,
        );

        assert!(!pool.should_show_expiration_warning());
    }

    #[test]
    fn test_recommendation_no_expiration_date() {
        // Pool without expiration date should not trigger expiring warning
        let pool = make_active_pool("No Expiry", "Vendor", 100, 50, Some(Decimal::from(10)));
        assert!(!pool.should_show_expiration_warning());
    }

    #[test]
    fn test_recommendation_borderline_underutilized() {
        // Exactly 60% utilization should NOT be underutilized
        let pool = make_active_pool("Borderline", "Vendor", 100, 60, Some(Decimal::from(10)));
        let utilization = pool.utilization_percent() / 100.0;
        assert!((utilization - UNDERUTILIZATION_THRESHOLD).abs() < f64::EPSILON);
        // Not strictly less than threshold
        assert!(!(utilization < UNDERUTILIZATION_THRESHOLD));
    }

    #[test]
    fn test_recommendation_borderline_high_utilization() {
        // Exactly 90% should NOT be high utilization (need > 90%)
        let pool = make_active_pool("Borderline High", "Vendor", 100, 90, None);
        let utilization = pool.utilization_percent() / 100.0;
        assert!((utilization - HIGH_UTILIZATION_THRESHOLD).abs() < f64::EPSILON);
        // Not strictly greater than threshold
        assert!(!(utilization > HIGH_UTILIZATION_THRESHOLD));
    }

    #[test]
    fn test_recommendation_priority_ordering() {
        assert!(
            recommendation_priority(&RecommendationType::ExpiringSoon)
                < recommendation_priority(&RecommendationType::HighUtilization)
        );
        assert!(
            recommendation_priority(&RecommendationType::HighUtilization)
                < recommendation_priority(&RecommendationType::Underutilized)
        );
        assert!(
            recommendation_priority(&RecommendationType::Underutilized)
                < recommendation_priority(&RecommendationType::ReclaimOpportunity)
        );
    }

    #[test]
    fn test_recommendation_underutilized_annual_savings() {
        // Annual billing: savings should be monthly equivalent
        let pool = make_pool(
            "Annual Low",
            "Vendor",
            100,
            20,
            Some(Decimal::from(120)),
            "USD",
            LicenseBillingPeriod::Annual,
            None,
            60,
            LicensePoolStatus::Active,
        );

        let unused = pool.available_count();
        assert_eq!(unused, 80);

        let savings = pool.cost_per_license.map(|cost| {
            let unused_dec = Decimal::from(unused);
            match pool.billing_period {
                LicenseBillingPeriod::Monthly => cost * unused_dec,
                LicenseBillingPeriod::Annual => (cost * unused_dec) / Decimal::from(12),
                LicenseBillingPeriod::Perpetual => Decimal::ZERO,
            }
        });

        // 80 * 120 / 12 = 800
        assert_eq!(savings, Some(Decimal::from(800)));
    }

    #[test]
    fn test_recommendation_underutilized_perpetual_no_savings() {
        let pool = make_pool(
            "Perpetual Low",
            "Vendor",
            100,
            10,
            Some(Decimal::from(500)),
            "USD",
            LicenseBillingPeriod::Perpetual,
            None,
            60,
            LicensePoolStatus::Active,
        );

        let savings = pool.cost_per_license.map(|cost| {
            let unused_dec = Decimal::from(pool.available_count());
            match pool.billing_period {
                LicenseBillingPeriod::Monthly => cost * unused_dec,
                LicenseBillingPeriod::Annual => (cost * unused_dec) / Decimal::from(12),
                LicenseBillingPeriod::Perpetual => Decimal::ZERO,
            }
        });

        assert_eq!(savings, Some(Decimal::ZERO));
    }

    // ========================================================================
    // RecommendationType Serialization Tests
    // ========================================================================

    #[test]
    fn test_recommendation_type_serialization() {
        assert_eq!(
            serde_json::to_string(&RecommendationType::Underutilized).unwrap(),
            "\"underutilized\""
        );
        assert_eq!(
            serde_json::to_string(&RecommendationType::HighUtilization).unwrap(),
            "\"high_utilization\""
        );
        assert_eq!(
            serde_json::to_string(&RecommendationType::ExpiringSoon).unwrap(),
            "\"expiring_soon\""
        );
        assert_eq!(
            serde_json::to_string(&RecommendationType::ReclaimOpportunity).unwrap(),
            "\"reclaim_opportunity\""
        );
    }

    #[test]
    fn test_recommendation_type_deserialization() {
        let r: RecommendationType = serde_json::from_str("\"underutilized\"").unwrap();
        assert_eq!(r, RecommendationType::Underutilized);

        let r: RecommendationType = serde_json::from_str("\"high_utilization\"").unwrap();
        assert_eq!(r, RecommendationType::HighUtilization);

        let r: RecommendationType = serde_json::from_str("\"expiring_soon\"").unwrap();
        assert_eq!(r, RecommendationType::ExpiringSoon);

        let r: RecommendationType = serde_json::from_str("\"reclaim_opportunity\"").unwrap();
        assert_eq!(r, RecommendationType::ReclaimOpportunity);
    }

    // ========================================================================
    // PoolTrendPoint Tests
    // ========================================================================

    #[test]
    fn test_pool_trend_point_construction() {
        let now = Utc::now();
        let point = PoolTrendPoint {
            date: now,
            allocated_count: 75,
            total_capacity: 100,
            utilization_percent: 75.0,
        };

        assert_eq!(point.allocated_count, 75);
        assert_eq!(point.total_capacity, 100);
        assert!((point.utilization_percent - 75.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_pool_trend_point_serialization() {
        let now = Utc::now();
        let point = PoolTrendPoint {
            date: now,
            allocated_count: 50,
            total_capacity: 200,
            utilization_percent: 25.0,
        };

        let json = serde_json::to_string(&point).unwrap();
        assert!(json.contains("\"allocated_count\":50"));
        assert!(json.contains("\"total_capacity\":200"));
        assert!(json.contains("\"utilization_percent\":25.0"));
        assert!(json.contains("\"date\":"));
    }

    #[test]
    fn test_pool_trend_point_zero_capacity() {
        let point = PoolTrendPoint {
            date: Utc::now(),
            allocated_count: 0,
            total_capacity: 0,
            utilization_percent: 0.0,
        };

        assert_eq!(point.allocated_count, 0);
        assert_eq!(point.total_capacity, 0);
        assert!((point.utilization_percent - 0.0).abs() < f64::EPSILON);
    }

    // ========================================================================
    // Dashboard Response Structure Tests
    // ========================================================================

    #[test]
    fn test_dashboard_response_serialization() {
        let dashboard = LicenseDashboardResponse {
            summary: LicenseSummary {
                total_pools: 2,
                total_capacity: 300,
                total_allocated: 200,
                total_available: 100,
                overall_utilization: 66.67,
                total_monthly_cost: Decimal::from(9200),
                expiring_soon_count: 1,
            },
            pools: vec![LicensePoolStats {
                id: Uuid::new_v4(),
                name: "Test Pool".to_string(),
                vendor: "Vendor".to_string(),
                total_capacity: 100,
                allocated_count: 80,
                utilization_percent: 80.0,
                monthly_cost: Some(Decimal::from(4000)),
                status: LicensePoolStatus::Active,
                expiration_date: None,
            }],
            cost_by_vendor: vec![VendorCost {
                vendor: "Vendor".to_string(),
                pool_count: 1,
                total_capacity: 100,
                allocated_count: 80,
                monthly_cost: Decimal::from(4000),
                currency: "USD".to_string(),
            }],
            recent_events: vec![],
        };

        let json = serde_json::to_string(&dashboard).unwrap();
        assert!(json.contains("\"summary\""));
        assert!(json.contains("\"pools\""));
        assert!(json.contains("\"cost_by_vendor\""));
        assert!(json.contains("\"recent_events\""));
        assert!(json.contains("\"total_pools\":2"));
    }

    #[test]
    fn test_dashboard_response_empty() {
        let dashboard = LicenseDashboardResponse {
            summary: LicenseSummary {
                total_pools: 0,
                total_capacity: 0,
                total_allocated: 0,
                total_available: 0,
                overall_utilization: 0.0,
                total_monthly_cost: Decimal::ZERO,
                expiring_soon_count: 0,
            },
            pools: vec![],
            cost_by_vendor: vec![],
            recent_events: vec![],
        };

        let json = serde_json::to_string(&dashboard).unwrap();
        assert!(json.contains("\"pools\":[]"));
        assert!(json.contains("\"cost_by_vendor\":[]"));
        assert!(json.contains("\"recent_events\":[]"));
    }

    // ========================================================================
    // Empty Pools Scenario Tests
    // ========================================================================

    #[test]
    fn test_build_summary_from_empty_pools() {
        let pools: Vec<GovLicensePool> = vec![];
        let stats: Vec<LicensePoolStats> = pools.iter().map(pool_to_stats).collect();
        let costs = build_vendor_costs(&pools);

        assert!(stats.is_empty());
        assert!(costs.is_empty());
    }

    #[test]
    fn test_build_summary_from_single_pool() {
        let pools = vec![make_active_pool(
            "Single Pool",
            "Solo",
            100,
            65,
            Some(Decimal::from(30)),
        )];

        let stats: Vec<LicensePoolStats> = pools.iter().map(pool_to_stats).collect();
        let costs = build_vendor_costs(&pools);

        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].name, "Single Pool");

        assert_eq!(costs.len(), 1);
        assert_eq!(costs[0].vendor, "Solo");
        assert_eq!(costs[0].pool_count, 1);
        // 65 * 30 = 1950
        assert_eq!(costs[0].monthly_cost, Decimal::from(1950));
    }

    // ========================================================================
    // Mixed Currencies in Vendor Costs Tests
    // ========================================================================

    #[test]
    fn test_vendor_costs_same_vendor_different_currencies() {
        let pool_usd =
            make_active_pool("US Office", "Microsoft", 200, 150, Some(Decimal::from(36)));
        let pool_eur = make_pool(
            "EU Office",
            "Microsoft",
            300,
            250,
            Some(Decimal::from(32)),
            "EUR",
            LicenseBillingPeriod::Monthly,
            None,
            60,
            LicensePoolStatus::Active,
        );
        let pool_gbp = make_pool(
            "UK Office",
            "Microsoft",
            100,
            75,
            Some(Decimal::from(28)),
            "GBP",
            LicenseBillingPeriod::Monthly,
            None,
            60,
            LicensePoolStatus::Active,
        );

        let costs = build_vendor_costs(&[pool_usd, pool_eur, pool_gbp]);

        // Three separate entries for Microsoft (USD, EUR, GBP)
        assert_eq!(costs.len(), 3);

        for cost in &costs {
            assert_eq!(cost.vendor, "Microsoft");
            assert_eq!(cost.pool_count, 1);
        }

        let usd = costs.iter().find(|c| c.currency == "USD").unwrap();
        let eur = costs.iter().find(|c| c.currency == "EUR").unwrap();
        let gbp = costs.iter().find(|c| c.currency == "GBP").unwrap();

        assert_eq!(usd.total_capacity, 200);
        assert_eq!(usd.allocated_count, 150);
        assert_eq!(usd.monthly_cost, Decimal::from(5400)); // 150 * 36

        assert_eq!(eur.total_capacity, 300);
        assert_eq!(eur.allocated_count, 250);
        assert_eq!(eur.monthly_cost, Decimal::from(8000)); // 250 * 32

        assert_eq!(gbp.total_capacity, 100);
        assert_eq!(gbp.allocated_count, 75);
        assert_eq!(gbp.monthly_cost, Decimal::from(2100)); // 75 * 28
    }

    #[test]
    fn test_vendor_costs_multiple_vendors_multiple_currencies() {
        let ms_usd = make_active_pool("MS USD", "Microsoft", 100, 80, Some(Decimal::from(36)));
        let ms_eur = make_pool(
            "MS EUR",
            "Microsoft",
            50,
            40,
            Some(Decimal::from(32)),
            "EUR",
            LicenseBillingPeriod::Monthly,
            None,
            60,
            LicensePoolStatus::Active,
        );
        let sf_usd = make_active_pool("SF USD", "Salesforce", 200, 150, Some(Decimal::from(75)));

        let costs = build_vendor_costs(&[ms_usd, ms_eur, sf_usd]);

        assert_eq!(costs.len(), 3);

        // Sorted by vendor then currency
        assert_eq!(costs[0].vendor, "Microsoft");
        assert_eq!(costs[1].vendor, "Microsoft");
        assert_eq!(costs[2].vendor, "Salesforce");

        // Microsoft EUR should come before Microsoft USD alphabetically
        assert_eq!(costs[0].currency, "EUR");
        assert_eq!(costs[1].currency, "USD");
        assert_eq!(costs[2].currency, "USD");
    }

    // ========================================================================
    // LicenseRecommendation Serialization Tests
    // ========================================================================

    #[test]
    fn test_recommendation_serialization() {
        let rec = LicenseRecommendation {
            recommendation_type: RecommendationType::Underutilized,
            pool_id: Uuid::new_v4(),
            pool_name: "Low Usage Pool".to_string(),
            description: "Pool is at 25% utilization.".to_string(),
            potential_savings: Some(Decimal::from_str("3750.00").unwrap()),
            currency: Some("USD".to_string()),
        };

        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"recommendation_type\":\"underutilized\""));
        assert!(json.contains("\"pool_name\":\"Low Usage Pool\""));
        assert!(json.contains("\"potential_savings\""));
        assert!(json.contains("\"currency\":\"USD\""));
    }

    #[test]
    fn test_recommendation_high_utilization_no_savings() {
        let rec = LicenseRecommendation {
            recommendation_type: RecommendationType::HighUtilization,
            pool_id: Uuid::new_v4(),
            pool_name: "Full Pool".to_string(),
            description: "Pool is at 95% utilization.".to_string(),
            potential_savings: None,
            currency: None,
        };

        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"recommendation_type\":\"high_utilization\""));
        // null for optional fields when None
        assert!(json.contains("\"potential_savings\":null"));
    }

    #[test]
    fn test_recommendation_expiring_soon_fields() {
        let rec = LicenseRecommendation {
            recommendation_type: RecommendationType::ExpiringSoon,
            pool_id: Uuid::new_v4(),
            pool_name: "Expiring Pool".to_string(),
            description: "Pool expires in 15 days with 80 active assignments.".to_string(),
            potential_savings: None,
            currency: None,
        };

        assert_eq!(rec.recommendation_type, RecommendationType::ExpiringSoon);
        assert!(rec.description.contains("15 days"));
    }

    // ========================================================================
    // Audit Entry Conversion Tests
    // ========================================================================

    #[test]
    fn test_convert_audit_entry() {
        let service_entry = super::super::license_audit_service::LicenseAuditEntry {
            id: Uuid::new_v4(),
            pool_id: Some(Uuid::new_v4()),
            pool_name: Some("Test Pool".to_string()),
            assignment_id: None,
            user_id: None,
            user_email: None,
            action: "pool_created".to_string(),
            actor_id: Uuid::new_v4(),
            actor_email: None,
            details: serde_json::json!({"test": true}),
            created_at: Utc::now(),
        };

        let model_entry = convert_audit_entry(service_entry.clone());

        assert_eq!(model_entry.id, service_entry.id);
        assert_eq!(model_entry.pool_id, service_entry.pool_id);
        assert_eq!(model_entry.pool_name, service_entry.pool_name);
        assert_eq!(model_entry.action, service_entry.action);
        assert_eq!(model_entry.actor_id, service_entry.actor_id);
        assert_eq!(model_entry.details, service_entry.details);
    }

    // ========================================================================
    // Overall Utilization Calculation Tests
    // ========================================================================

    #[test]
    fn test_overall_utilization_calculation() {
        let total_capacity: i64 = 500;
        let total_allocated: i64 = 350;

        let utilization = if total_capacity > 0 {
            (total_allocated as f64 / total_capacity as f64) * 100.0
        } else {
            0.0
        };

        assert!((utilization - 70.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_overall_utilization_zero_capacity() {
        let total_capacity: i64 = 0;
        let total_allocated: i64 = 0;

        let utilization = if total_capacity > 0 {
            (total_allocated as f64 / total_capacity as f64) * 100.0
        } else {
            0.0
        };

        assert!((utilization - 0.0).abs() < f64::EPSILON);
    }
}
