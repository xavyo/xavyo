//! License Report Service (F065).
//!
//! Generates compliance reports, audit trails, and CSV exports
//! for software license management auditing.

use std::fmt::Write;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    GovLicenseAssignment, GovLicensePool, LicenseAssignmentFilter, LicenseAssignmentStatus,
    LicensePoolFilter, LicensePoolStatus, LicenseType,
};
use xavyo_governance::error::Result;

use crate::services::license_audit_service::{
    LicenseAuditEntry as ServiceAuditEntry, LicenseAuditService, ListAuditParams,
};

// ============================================================================
// Parameter Types
// ============================================================================

/// Parameters for generating a compliance report.
#[derive(Debug, Clone)]
pub struct ComplianceReportParams {
    /// Filter to specific pools. `None` means all pools.
    pub pool_ids: Option<Vec<Uuid>>,
    /// Filter by vendor name.
    pub vendor: Option<String>,
    /// Filter audit data from this date.
    pub from_date: Option<DateTime<Utc>>,
    /// Filter audit data to this date.
    pub to_date: Option<DateTime<Utc>>,
}

/// Parameters for querying the audit trail.
#[derive(Debug, Clone, Default)]
pub struct AuditTrailParams {
    pub pool_id: Option<Uuid>,
    pub user_id: Option<Uuid>,
    pub action: Option<String>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
    pub limit: i64,
    pub offset: i64,
}

// ============================================================================
// Report Types
// ============================================================================

/// Full compliance report for license auditing.
#[derive(Debug, Clone, Serialize)]
pub struct ComplianceReport {
    /// When the report was generated.
    pub generated_at: DateTime<Utc>,
    /// The tenant this report covers.
    pub tenant_id: Uuid,
    /// Filters that were applied to generate this report.
    pub filters_applied: ComplianceReportFilters,
    /// Per-pool compliance summaries.
    pub pool_summaries: Vec<PoolComplianceSummary>,
    /// Total number of pools included in the report.
    pub total_pools: usize,
    /// Sum of `total_capacity` across all pools.
    pub total_licenses: i64,
    /// Sum of `allocated_count` across all pools.
    pub total_assigned: i64,
    /// Overall compliance score (0-100 percentage).
    pub overall_compliance_score: f64,
}

/// Filters applied when generating the report.
#[derive(Debug, Clone, Serialize)]
pub struct ComplianceReportFilters {
    pub pool_ids: Option<Vec<Uuid>>,
    pub vendor: Option<String>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
}

/// Compliance summary for a single license pool.
#[derive(Debug, Clone, Serialize)]
pub struct PoolComplianceSummary {
    pub pool_id: Uuid,
    pub pool_name: String,
    pub vendor: String,
    pub total_capacity: i32,
    pub allocated_count: i32,
    pub utilization_percent: f64,
    pub status: LicensePoolStatus,
    pub license_type: LicenseType,
    pub expiration_date: Option<DateTime<Utc>>,
    /// Whether `allocated_count` exceeds `total_capacity`.
    pub is_over_allocated: bool,
    /// Count of active assignments for this pool.
    pub assignment_count: i64,
}

/// A single entry in the audit trail.
#[derive(Debug, Clone, Serialize)]
pub struct AuditTrailEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub action: String,
    pub pool_id: Option<Uuid>,
    pub pool_name: Option<String>,
    pub user_id: Option<Uuid>,
    pub user_email: Option<String>,
    pub actor_id: Uuid,
    pub actor_email: Option<String>,
    pub details: serde_json::Value,
}

// ============================================================================
// Service
// ============================================================================

/// Service for generating compliance reports, audit trails, and CSV exports.
pub struct LicenseReportService {
    pool: PgPool,
}

impl LicenseReportService {
    /// Create a new license report service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Generate a compliance report for software license auditing.
    ///
    /// Fetches pools (optionally filtered), counts active assignments per pool,
    /// and calculates an overall compliance score based on over-allocation and
    /// expiration status.
    pub async fn generate_compliance_report(
        &self,
        tenant_id: Uuid,
        params: ComplianceReportParams,
    ) -> Result<ComplianceReport> {
        // 1. Fetch pools with optional vendor filter
        let filter = LicensePoolFilter {
            vendor: params.vendor.clone(),
            ..Default::default()
        };

        let all_pools =
            GovLicensePool::list_by_tenant(&self.pool, tenant_id, &filter, i64::MAX, 0).await?;

        // 2. Apply pool_ids filter if specified
        let pools: Vec<GovLicensePool> = if let Some(ref pool_ids) = params.pool_ids {
            all_pools
                .into_iter()
                .filter(|p| pool_ids.contains(&p.id))
                .collect()
        } else {
            all_pools
        };

        // 3. Build per-pool summaries
        let mut pool_summaries = Vec::with_capacity(pools.len());
        let mut total_licenses: i64 = 0;
        let mut total_assigned: i64 = 0;
        let mut over_allocated_count: usize = 0;
        let mut expired_count: usize = 0;

        for pool_record in &pools {
            // Count active assignments for this pool
            let assignment_filter = LicenseAssignmentFilter {
                license_pool_id: Some(pool_record.id),
                status: Some(LicenseAssignmentStatus::Active),
                ..Default::default()
            };
            let assignment_count =
                GovLicenseAssignment::count_by_tenant(&self.pool, tenant_id, &assignment_filter)
                    .await?;

            let is_over_allocated = pool_record.allocated_count > pool_record.total_capacity;
            if is_over_allocated {
                over_allocated_count += 1;
            }
            if matches!(pool_record.status, LicensePoolStatus::Expired) {
                expired_count += 1;
            }

            total_licenses += i64::from(pool_record.total_capacity);
            total_assigned += i64::from(pool_record.allocated_count);

            pool_summaries.push(PoolComplianceSummary {
                pool_id: pool_record.id,
                pool_name: pool_record.name.clone(),
                vendor: pool_record.vendor.clone(),
                total_capacity: pool_record.total_capacity,
                allocated_count: pool_record.allocated_count,
                utilization_percent: pool_record.utilization_percent(),
                status: pool_record.status,
                license_type: pool_record.license_type,
                expiration_date: pool_record.expiration_date,
                is_over_allocated,
                assignment_count,
            });
        }

        // 4. Calculate compliance score
        let compliance_score = calculate_compliance_score(over_allocated_count, expired_count);

        Ok(ComplianceReport {
            generated_at: Utc::now(),
            tenant_id,
            filters_applied: ComplianceReportFilters {
                pool_ids: params.pool_ids,
                vendor: params.vendor,
                from_date: params.from_date,
                to_date: params.to_date,
            },
            pool_summaries,
            total_pools: pools.len(),
            total_licenses,
            total_assigned,
            overall_compliance_score: compliance_score,
        })
    }

    /// Get an enriched audit trail by wrapping the audit service.
    ///
    /// Converts service-level audit entries into `AuditTrailEntry` structs
    /// with richer field naming for report consumers.
    pub async fn get_audit_trail(
        &self,
        tenant_id: Uuid,
        params: AuditTrailParams,
    ) -> Result<(Vec<AuditTrailEntry>, i64)> {
        let audit_service = LicenseAuditService::new(self.pool.clone());

        // Convert the action string to a LicenseAuditAction if provided
        let action = params
            .action
            .as_deref()
            .and_then(xavyo_db::models::LicenseAuditAction::parse);

        let list_params = ListAuditParams {
            pool_id: params.pool_id,
            user_id: params.user_id,
            action,
            from_date: params.from_date,
            to_date: params.to_date,
            limit: params.limit,
            offset: params.offset,
        };

        let (entries, total) = audit_service
            .list_audit_events(tenant_id, list_params)
            .await?;

        let trail_entries = entries.into_iter().map(convert_to_audit_trail).collect();

        Ok((trail_entries, total))
    }

    /// Export a compliance report as a CSV string.
    ///
    /// Produces a header row followed by one data row per pool. Returns the
    /// CSV content as a `String` so the handler can set the appropriate
    /// content-type header.
    pub fn export_csv(report: &ComplianceReport) -> Result<String> {
        let mut csv = String::new();

        // Header row
        writeln!(
            csv,
            "Pool ID,Pool Name,Vendor,License Type,Total Capacity,Allocated,Utilization %,Status,Over-Allocated,Expiration Date"
        )
        .expect("write to String cannot fail");

        // Data rows
        for summary in &report.pool_summaries {
            let license_type = format!("{:?}", summary.license_type).to_lowercase();
            let status = format!("{:?}", summary.status).to_lowercase();
            let expiration = summary
                .expiration_date
                .map(|d| d.to_rfc3339())
                .unwrap_or_default();
            let pool_name = escape_csv_field(&summary.pool_name);
            let vendor = escape_csv_field(&summary.vendor);

            writeln!(
                csv,
                "{},{},{},{},{},{},{:.2},{},{},{}",
                summary.pool_id,
                pool_name,
                vendor,
                license_type,
                summary.total_capacity,
                summary.allocated_count,
                summary.utilization_percent,
                status,
                summary.is_over_allocated,
                expiration,
            )
            .expect("write to String cannot fail");
        }

        Ok(csv)
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

/// Calculate the compliance score.
///
/// Starts at 100.0 and deducts:
/// - 10 points per over-allocated pool
/// - 5 points per expired pool
///
/// The result is clamped to the range `[0.0, 100.0]`.
fn calculate_compliance_score(over_allocated_pools: usize, expired_pools: usize) -> f64 {
    let score = 100.0 - (over_allocated_pools as f64 * 10.0) - (expired_pools as f64 * 5.0);
    score.clamp(0.0, 100.0)
}

/// Convert a service-level audit entry to the report-level audit trail entry.
fn convert_to_audit_trail(entry: ServiceAuditEntry) -> AuditTrailEntry {
    AuditTrailEntry {
        id: entry.id,
        timestamp: entry.created_at,
        action: entry.action,
        pool_id: entry.pool_id,
        pool_name: entry.pool_name,
        user_id: entry.user_id,
        user_email: entry.user_email,
        actor_id: entry.actor_id,
        actor_email: entry.actor_email,
        details: entry.details,
    }
}

/// Escape a field for CSV output.
///
/// If the field contains a comma, double-quote, or newline, it is wrapped in
/// double-quotes and any internal double-quotes are doubled.
fn escape_csv_field(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        let escaped = field.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        field.to_string()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    // ========================================================================
    // ComplianceReport Construction and Serialization
    // ========================================================================

    #[test]
    fn test_compliance_report_construction() {
        let tenant_id = Uuid::new_v4();
        let report = ComplianceReport {
            generated_at: Utc::now(),
            tenant_id,
            filters_applied: ComplianceReportFilters {
                pool_ids: None,
                vendor: None,
                from_date: None,
                to_date: None,
            },
            pool_summaries: vec![],
            total_pools: 0,
            total_licenses: 0,
            total_assigned: 0,
            overall_compliance_score: 100.0,
        };

        assert_eq!(report.tenant_id, tenant_id);
        assert_eq!(report.total_pools, 0);
        assert_eq!(report.total_licenses, 0);
        assert_eq!(report.total_assigned, 0);
        assert!((report.overall_compliance_score - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compliance_report_serialization() {
        let report = ComplianceReport {
            generated_at: Utc::now(),
            tenant_id: Uuid::new_v4(),
            filters_applied: ComplianceReportFilters {
                pool_ids: None,
                vendor: Some("Microsoft".to_string()),
                from_date: None,
                to_date: None,
            },
            pool_summaries: vec![],
            total_pools: 5,
            total_licenses: 1000,
            total_assigned: 750,
            overall_compliance_score: 85.0,
        };

        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"total_pools\":5"));
        assert!(json.contains("\"total_licenses\":1000"));
        assert!(json.contains("\"total_assigned\":750"));
        assert!(json.contains("\"overall_compliance_score\":85.0"));
        assert!(json.contains("\"vendor\":\"Microsoft\""));
    }

    // ========================================================================
    // ComplianceReportParams Default
    // ========================================================================

    #[test]
    fn test_compliance_report_params_all_none() {
        let params = ComplianceReportParams {
            pool_ids: None,
            vendor: None,
            from_date: None,
            to_date: None,
        };

        assert!(params.pool_ids.is_none());
        assert!(params.vendor.is_none());
        assert!(params.from_date.is_none());
        assert!(params.to_date.is_none());
    }

    #[test]
    fn test_compliance_report_params_with_values() {
        let pool_id = Uuid::new_v4();
        let now = Utc::now();
        let params = ComplianceReportParams {
            pool_ids: Some(vec![pool_id]),
            vendor: Some("Acme".to_string()),
            from_date: Some(now - Duration::days(30)),
            to_date: Some(now),
        };

        assert_eq!(params.pool_ids.as_ref().unwrap().len(), 1);
        assert_eq!(params.vendor.as_deref(), Some("Acme"));
        assert!(params.from_date.is_some());
        assert!(params.to_date.is_some());
    }

    // ========================================================================
    // PoolComplianceSummary Scenarios
    // ========================================================================

    #[test]
    fn test_pool_compliance_summary_normal() {
        let summary = PoolComplianceSummary {
            pool_id: Uuid::new_v4(),
            pool_name: "Office 365 E3".to_string(),
            vendor: "Microsoft".to_string(),
            total_capacity: 500,
            allocated_count: 350,
            utilization_percent: 70.0,
            status: LicensePoolStatus::Active,
            license_type: LicenseType::Named,
            expiration_date: None,
            is_over_allocated: false,
            assignment_count: 350,
        };

        assert!(!summary.is_over_allocated);
        assert_eq!(summary.status, LicensePoolStatus::Active);
        assert!((summary.utilization_percent - 70.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_pool_compliance_summary_over_allocated() {
        let summary = PoolComplianceSummary {
            pool_id: Uuid::new_v4(),
            pool_name: "Over-sold License".to_string(),
            vendor: "Vendor X".to_string(),
            total_capacity: 100,
            allocated_count: 120,
            utilization_percent: 120.0,
            status: LicensePoolStatus::Active,
            license_type: LicenseType::Concurrent,
            expiration_date: None,
            is_over_allocated: true,
            assignment_count: 120,
        };

        assert!(summary.is_over_allocated);
        assert!((summary.utilization_percent - 120.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_pool_compliance_summary_expired() {
        let summary = PoolComplianceSummary {
            pool_id: Uuid::new_v4(),
            pool_name: "Expired Pool".to_string(),
            vendor: "Old Vendor".to_string(),
            total_capacity: 200,
            allocated_count: 50,
            utilization_percent: 25.0,
            status: LicensePoolStatus::Expired,
            license_type: LicenseType::Named,
            expiration_date: Some(Utc::now() - Duration::days(10)),
            is_over_allocated: false,
            assignment_count: 50,
        };

        assert_eq!(summary.status, LicensePoolStatus::Expired);
        assert!(summary.expiration_date.is_some());
    }

    #[test]
    fn test_pool_compliance_summary_serialization() {
        let summary = PoolComplianceSummary {
            pool_id: Uuid::new_v4(),
            pool_name: "Test Pool".to_string(),
            vendor: "Test".to_string(),
            total_capacity: 100,
            allocated_count: 50,
            utilization_percent: 50.0,
            status: LicensePoolStatus::Active,
            license_type: LicenseType::Named,
            expiration_date: None,
            is_over_allocated: false,
            assignment_count: 50,
        };

        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"pool_name\":\"Test Pool\""));
        assert!(json.contains("\"is_over_allocated\":false"));
        assert!(json.contains("\"assignment_count\":50"));
    }

    // ========================================================================
    // Compliance Score Calculation
    // ========================================================================

    #[test]
    fn test_compliance_score_perfect() {
        let score = calculate_compliance_score(0, 0);
        assert!((score - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compliance_score_with_over_allocation() {
        // 2 over-allocated pools: 100 - (2 * 10) = 80
        let score = calculate_compliance_score(2, 0);
        assert!((score - 80.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compliance_score_with_expired_pools() {
        // 3 expired pools: 100 - (3 * 5) = 85
        let score = calculate_compliance_score(0, 3);
        assert!((score - 85.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compliance_score_with_both() {
        // 1 over-allocated + 2 expired: 100 - 10 - 10 = 80
        let score = calculate_compliance_score(1, 2);
        assert!((score - 80.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compliance_score_worst_case() {
        // Many issues, should clamp to 0
        let score = calculate_compliance_score(10, 10);
        assert!((score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compliance_score_clamp_to_zero() {
        // 15 over-allocated: 100 - 150 = -50, clamped to 0
        let score = calculate_compliance_score(15, 0);
        assert!((score - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compliance_score_exact_zero() {
        // 10 over-allocated: 100 - 100 = 0
        let score = calculate_compliance_score(10, 0);
        assert!((score - 0.0).abs() < f64::EPSILON);
    }

    // ========================================================================
    // AuditTrailEntry Construction
    // ========================================================================

    #[test]
    fn test_audit_trail_entry_construction() {
        let entry = AuditTrailEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            action: "pool_created".to_string(),
            pool_id: Some(Uuid::new_v4()),
            pool_name: Some("Test Pool".to_string()),
            user_id: None,
            user_email: None,
            actor_id: Uuid::new_v4(),
            actor_email: Some("admin@example.com".to_string()),
            details: serde_json::json!({"pool_name": "Test Pool"}),
        };

        assert_eq!(entry.action, "pool_created");
        assert!(entry.pool_id.is_some());
        assert!(entry.pool_name.is_some());
        assert!(entry.user_id.is_none());
        assert_eq!(entry.actor_email.as_deref(), Some("admin@example.com"));
    }

    #[test]
    fn test_audit_trail_entry_serialization() {
        let entry = AuditTrailEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            action: "license_assigned".to_string(),
            pool_id: Some(Uuid::new_v4()),
            pool_name: Some("Pool A".to_string()),
            user_id: Some(Uuid::new_v4()),
            user_email: Some("user@example.com".to_string()),
            actor_id: Uuid::new_v4(),
            actor_email: Some("admin@example.com".to_string()),
            details: serde_json::json!({"source": "manual"}),
        };

        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"action\":\"license_assigned\""));
        assert!(json.contains("\"pool_name\":\"Pool A\""));
        assert!(json.contains("\"user_email\":\"user@example.com\""));
    }

    // ========================================================================
    // AuditTrailParams Defaults
    // ========================================================================

    #[test]
    fn test_audit_trail_params_default() {
        let params = AuditTrailParams::default();
        assert!(params.pool_id.is_none());
        assert!(params.user_id.is_none());
        assert!(params.action.is_none());
        assert!(params.from_date.is_none());
        assert!(params.to_date.is_none());
        assert_eq!(params.limit, 0);
        assert_eq!(params.offset, 0);
    }

    #[test]
    fn test_audit_trail_params_with_values() {
        let pool_id = Uuid::new_v4();
        let params = AuditTrailParams {
            pool_id: Some(pool_id),
            user_id: None,
            action: Some("pool_created".to_string()),
            from_date: Some(Utc::now() - Duration::days(7)),
            to_date: Some(Utc::now()),
            limit: 50,
            offset: 10,
        };

        assert_eq!(params.pool_id, Some(pool_id));
        assert_eq!(params.action.as_deref(), Some("pool_created"));
        assert_eq!(params.limit, 50);
        assert_eq!(params.offset, 10);
    }

    // ========================================================================
    // CSV Export Tests
    // ========================================================================

    #[test]
    fn test_csv_export_header_row() {
        let report = ComplianceReport {
            generated_at: Utc::now(),
            tenant_id: Uuid::new_v4(),
            filters_applied: ComplianceReportFilters {
                pool_ids: None,
                vendor: None,
                from_date: None,
                to_date: None,
            },
            pool_summaries: vec![],
            total_pools: 0,
            total_licenses: 0,
            total_assigned: 0,
            overall_compliance_score: 100.0,
        };

        let csv = LicenseReportService::export_csv(&report).unwrap();
        let first_line = csv.lines().next().unwrap();
        assert_eq!(
            first_line,
            "Pool ID,Pool Name,Vendor,License Type,Total Capacity,Allocated,Utilization %,Status,Over-Allocated,Expiration Date"
        );
    }

    #[test]
    fn test_csv_export_data_row() {
        let pool_id = Uuid::new_v4();
        let report = ComplianceReport {
            generated_at: Utc::now(),
            tenant_id: Uuid::new_v4(),
            filters_applied: ComplianceReportFilters {
                pool_ids: None,
                vendor: None,
                from_date: None,
                to_date: None,
            },
            pool_summaries: vec![PoolComplianceSummary {
                pool_id,
                pool_name: "Office 365 E3".to_string(),
                vendor: "Microsoft".to_string(),
                total_capacity: 500,
                allocated_count: 350,
                utilization_percent: 70.0,
                status: LicensePoolStatus::Active,
                license_type: LicenseType::Named,
                expiration_date: None,
                is_over_allocated: false,
                assignment_count: 350,
            }],
            total_pools: 1,
            total_licenses: 500,
            total_assigned: 350,
            overall_compliance_score: 100.0,
        };

        let csv = LicenseReportService::export_csv(&report).unwrap();
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2); // header + 1 data row

        let data_row = lines[1];
        assert!(data_row.contains(&pool_id.to_string()));
        assert!(data_row.contains("Office 365 E3"));
        assert!(data_row.contains("Microsoft"));
        assert!(data_row.contains("named"));
        assert!(data_row.contains("500"));
        assert!(data_row.contains("350"));
        assert!(data_row.contains("70.00"));
        assert!(data_row.contains("active"));
        assert!(data_row.contains("false"));
    }

    #[test]
    fn test_csv_export_empty_report() {
        let report = ComplianceReport {
            generated_at: Utc::now(),
            tenant_id: Uuid::new_v4(),
            filters_applied: ComplianceReportFilters {
                pool_ids: None,
                vendor: None,
                from_date: None,
                to_date: None,
            },
            pool_summaries: vec![],
            total_pools: 0,
            total_licenses: 0,
            total_assigned: 0,
            overall_compliance_score: 100.0,
        };

        let csv = LicenseReportService::export_csv(&report).unwrap();
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 1); // header only
    }

    #[test]
    fn test_csv_export_special_characters_in_pool_name() {
        let report = ComplianceReport {
            generated_at: Utc::now(),
            tenant_id: Uuid::new_v4(),
            filters_applied: ComplianceReportFilters {
                pool_ids: None,
                vendor: None,
                from_date: None,
                to_date: None,
            },
            pool_summaries: vec![PoolComplianceSummary {
                pool_id: Uuid::new_v4(),
                pool_name: "Pool with, comma".to_string(),
                vendor: "Vendor \"Quoted\"".to_string(),
                total_capacity: 100,
                allocated_count: 50,
                utilization_percent: 50.0,
                status: LicensePoolStatus::Active,
                license_type: LicenseType::Named,
                expiration_date: None,
                is_over_allocated: false,
                assignment_count: 50,
            }],
            total_pools: 1,
            total_licenses: 100,
            total_assigned: 50,
            overall_compliance_score: 100.0,
        };

        let csv = LicenseReportService::export_csv(&report).unwrap();
        let data_row = csv.lines().nth(1).unwrap();
        // Pool name with comma should be quoted
        assert!(data_row.contains("\"Pool with, comma\""));
        // Vendor with quotes should be double-quoted
        assert!(data_row.contains("\"Vendor \"\"Quoted\"\"\""));
    }

    #[test]
    fn test_csv_export_with_expiration_date() {
        let expiration = Utc::now() + Duration::days(30);
        let report = ComplianceReport {
            generated_at: Utc::now(),
            tenant_id: Uuid::new_v4(),
            filters_applied: ComplianceReportFilters {
                pool_ids: None,
                vendor: None,
                from_date: None,
                to_date: None,
            },
            pool_summaries: vec![PoolComplianceSummary {
                pool_id: Uuid::new_v4(),
                pool_name: "Expiring Pool".to_string(),
                vendor: "Vendor".to_string(),
                total_capacity: 100,
                allocated_count: 80,
                utilization_percent: 80.0,
                status: LicensePoolStatus::Active,
                license_type: LicenseType::Named,
                expiration_date: Some(expiration),
                is_over_allocated: false,
                assignment_count: 80,
            }],
            total_pools: 1,
            total_licenses: 100,
            total_assigned: 80,
            overall_compliance_score: 100.0,
        };

        let csv = LicenseReportService::export_csv(&report).unwrap();
        let data_row = csv.lines().nth(1).unwrap();
        // Expiration date should be present in RFC 3339 format
        let rfc3339 = expiration.to_rfc3339();
        assert!(data_row.contains(&rfc3339));
    }

    #[test]
    fn test_csv_export_multiple_rows() {
        let report = ComplianceReport {
            generated_at: Utc::now(),
            tenant_id: Uuid::new_v4(),
            filters_applied: ComplianceReportFilters {
                pool_ids: None,
                vendor: None,
                from_date: None,
                to_date: None,
            },
            pool_summaries: vec![
                PoolComplianceSummary {
                    pool_id: Uuid::new_v4(),
                    pool_name: "Pool A".to_string(),
                    vendor: "Vendor A".to_string(),
                    total_capacity: 100,
                    allocated_count: 50,
                    utilization_percent: 50.0,
                    status: LicensePoolStatus::Active,
                    license_type: LicenseType::Named,
                    expiration_date: None,
                    is_over_allocated: false,
                    assignment_count: 50,
                },
                PoolComplianceSummary {
                    pool_id: Uuid::new_v4(),
                    pool_name: "Pool B".to_string(),
                    vendor: "Vendor B".to_string(),
                    total_capacity: 200,
                    allocated_count: 180,
                    utilization_percent: 90.0,
                    status: LicensePoolStatus::Active,
                    license_type: LicenseType::Concurrent,
                    expiration_date: None,
                    is_over_allocated: false,
                    assignment_count: 180,
                },
            ],
            total_pools: 2,
            total_licenses: 300,
            total_assigned: 230,
            overall_compliance_score: 100.0,
        };

        let csv = LicenseReportService::export_csv(&report).unwrap();
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 3); // header + 2 data rows
        assert!(lines[1].contains("Pool A"));
        assert!(lines[2].contains("Pool B"));
        assert!(lines[2].contains("concurrent"));
    }

    // ========================================================================
    // Filters Applied Serialization
    // ========================================================================

    #[test]
    fn test_filters_applied_serialization_empty() {
        let filters = ComplianceReportFilters {
            pool_ids: None,
            vendor: None,
            from_date: None,
            to_date: None,
        };

        let json = serde_json::to_string(&filters).unwrap();
        assert!(json.contains("\"pool_ids\":null"));
        assert!(json.contains("\"vendor\":null"));
        assert!(json.contains("\"from_date\":null"));
        assert!(json.contains("\"to_date\":null"));
    }

    #[test]
    fn test_filters_applied_serialization_with_values() {
        let pool_id = Uuid::new_v4();
        let now = Utc::now();
        let filters = ComplianceReportFilters {
            pool_ids: Some(vec![pool_id]),
            vendor: Some("Microsoft".to_string()),
            from_date: Some(now),
            to_date: Some(now),
        };

        let json = serde_json::to_string(&filters).unwrap();
        assert!(json.contains(&pool_id.to_string()));
        assert!(json.contains("\"vendor\":\"Microsoft\""));
    }

    // ========================================================================
    // Conversion from ServiceAuditEntry to AuditTrailEntry
    // ========================================================================

    #[test]
    fn test_convert_service_audit_entry_to_trail_entry() {
        let id = Uuid::new_v4();
        let pool_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let now = Utc::now();

        let service_entry = ServiceAuditEntry {
            id,
            pool_id: Some(pool_id),
            pool_name: Some("Test Pool".to_string()),
            assignment_id: None,
            user_id: None,
            user_email: None,
            action: "pool_created".to_string(),
            actor_id,
            actor_email: Some("admin@test.com".to_string()),
            details: serde_json::json!({"test": true}),
            created_at: now,
        };

        let trail_entry = convert_to_audit_trail(service_entry);

        assert_eq!(trail_entry.id, id);
        assert_eq!(trail_entry.timestamp, now);
        assert_eq!(trail_entry.action, "pool_created");
        assert_eq!(trail_entry.pool_id, Some(pool_id));
        assert_eq!(trail_entry.pool_name.as_deref(), Some("Test Pool"));
        assert!(trail_entry.user_id.is_none());
        assert!(trail_entry.user_email.is_none());
        assert_eq!(trail_entry.actor_id, actor_id);
        assert_eq!(trail_entry.actor_email.as_deref(), Some("admin@test.com"));
        assert_eq!(trail_entry.details, serde_json::json!({"test": true}));
    }

    #[test]
    fn test_convert_service_audit_entry_with_user_info() {
        let user_id = Uuid::new_v4();

        let service_entry = ServiceAuditEntry {
            id: Uuid::new_v4(),
            pool_id: Some(Uuid::new_v4()),
            pool_name: Some("License Pool".to_string()),
            assignment_id: Some(Uuid::new_v4()),
            user_id: Some(user_id),
            user_email: Some("user@example.com".to_string()),
            action: "license_assigned".to_string(),
            actor_id: Uuid::new_v4(),
            actor_email: None,
            details: serde_json::json!({"source": "manual"}),
            created_at: Utc::now(),
        };

        let trail_entry = convert_to_audit_trail(service_entry);

        assert_eq!(trail_entry.user_id, Some(user_id));
        assert_eq!(trail_entry.user_email.as_deref(), Some("user@example.com"));
        assert_eq!(trail_entry.action, "license_assigned");
        assert!(trail_entry.actor_email.is_none());
    }

    #[test]
    fn test_convert_service_audit_entry_minimal() {
        let service_entry = ServiceAuditEntry {
            id: Uuid::new_v4(),
            pool_id: None,
            pool_name: None,
            assignment_id: None,
            user_id: None,
            user_email: None,
            action: "bulk_assign".to_string(),
            actor_id: Uuid::new_v4(),
            actor_email: None,
            details: serde_json::json!({}),
            created_at: Utc::now(),
        };

        let trail_entry = convert_to_audit_trail(service_entry);

        assert!(trail_entry.pool_id.is_none());
        assert!(trail_entry.pool_name.is_none());
        assert!(trail_entry.user_id.is_none());
        assert!(trail_entry.user_email.is_none());
        assert!(trail_entry.actor_email.is_none());
        assert_eq!(trail_entry.details, serde_json::json!({}));
    }

    // ========================================================================
    // CSV Field Escaping
    // ========================================================================

    #[test]
    fn test_escape_csv_field_plain() {
        assert_eq!(escape_csv_field("Hello"), "Hello");
    }

    #[test]
    fn test_escape_csv_field_with_comma() {
        assert_eq!(escape_csv_field("Hello, World"), "\"Hello, World\"");
    }

    #[test]
    fn test_escape_csv_field_with_quotes() {
        assert_eq!(escape_csv_field("Say \"Hello\""), "\"Say \"\"Hello\"\"\"");
    }

    #[test]
    fn test_escape_csv_field_with_newline() {
        assert_eq!(escape_csv_field("Line1\nLine2"), "\"Line1\nLine2\"");
    }

    #[test]
    fn test_escape_csv_field_empty() {
        assert_eq!(escape_csv_field(""), "");
    }
}
