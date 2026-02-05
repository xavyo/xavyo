//! GDPR report service for governance API (F-067).

use chrono::Utc;
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

use xavyo_db::models::{DataProtectionClassification, GdprLegalBasis, GovEntitlement};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{
    ClassifiedEntitlementDetail, EntitlementResponse, GdprReport, UserDataProtectionSummary,
};

/// Row returned by the classification summary query.
#[derive(sqlx::FromRow)]
struct ClassificationCountRow {
    classification: DataProtectionClassification,
    count: i64,
}

/// Row returned by the legal basis summary query.
#[derive(sqlx::FromRow)]
struct LegalBasisCountRow {
    legal_basis: GdprLegalBasis,
    count: i64,
}

/// Row returned by the classified entitlement detail query.
#[derive(sqlx::FromRow)]
struct ClassifiedDetailRow {
    id: Uuid,
    name: String,
    application_name: String,
    data_protection_classification: DataProtectionClassification,
    legal_basis: Option<GdprLegalBasis>,
    retention_period_days: Option<i32>,
    data_controller: Option<String>,
    data_processor: Option<String>,
    purposes: Option<Vec<String>>,
    active_assignment_count: i64,
}

/// Service for generating GDPR compliance reports.
pub struct GdprReportService {
    pool: PgPool,
}

impl GdprReportService {
    /// Create a new GDPR report service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Generate a tenant-wide GDPR compliance report.
    pub async fn generate_report(&self, tenant_id: Uuid) -> Result<GdprReport> {
        // Total entitlements
        let total_entitlements: i64 =
            sqlx::query_scalar(r"SELECT COUNT(*) FROM gov_entitlements WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&self.pool)
                .await
                .map_err(GovernanceError::Database)?;

        // Classification summary
        let classification_rows: Vec<ClassificationCountRow> = sqlx::query_as(
            r"
            SELECT data_protection_classification AS classification, COUNT(*) AS count
            FROM gov_entitlements
            WHERE tenant_id = $1
            GROUP BY data_protection_classification
            ",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        let mut classification_summary = HashMap::new();
        let mut classified_count = 0i64;
        for row in &classification_rows {
            let key = serde_json::to_value(row.classification)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_else(|| format!("{:?}", row.classification));
            if row.classification != DataProtectionClassification::None {
                classified_count += row.count;
            }
            classification_summary.insert(key, row.count);
        }

        // Legal basis summary
        let legal_basis_rows: Vec<LegalBasisCountRow> = sqlx::query_as(
            r"
            SELECT legal_basis, COUNT(*) AS count
            FROM gov_entitlements
            WHERE tenant_id = $1 AND legal_basis IS NOT NULL
            GROUP BY legal_basis
            ",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        let mut legal_basis_summary = HashMap::new();
        for row in &legal_basis_rows {
            let key = serde_json::to_value(row.legal_basis)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_else(|| format!("{:?}", row.legal_basis));
            legal_basis_summary.insert(key, row.count);
        }

        // Classified entitlements with details
        let detail_rows: Vec<ClassifiedDetailRow> = sqlx::query_as(
            r"
            SELECT
                e.id,
                e.name,
                COALESCE(a.name, 'Unknown') AS application_name,
                e.data_protection_classification,
                e.legal_basis,
                e.retention_period_days,
                e.data_controller,
                e.data_processor,
                e.purposes,
                COALESCE(
                    (SELECT COUNT(*) FROM gov_entitlement_assignments ea
                     WHERE ea.entitlement_id = e.id AND ea.tenant_id = e.tenant_id
                       AND ea.status = 'active'),
                    0
                ) AS active_assignment_count
            FROM gov_entitlements e
            LEFT JOIN gov_applications a ON a.id = e.application_id AND a.tenant_id = e.tenant_id
            WHERE e.tenant_id = $1
              AND e.data_protection_classification != 'none'
            ORDER BY e.name
            ",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        let classified_entitlements_detail: Vec<ClassifiedEntitlementDetail> = detail_rows
            .iter()
            .map(|r| ClassifiedEntitlementDetail {
                entitlement_id: r.id,
                entitlement_name: r.name.clone(),
                application_name: r.application_name.clone(),
                classification: r.data_protection_classification,
                legal_basis: r.legal_basis,
                retention_period_days: r.retention_period_days,
                data_controller: r.data_controller.clone(),
                data_processor: r.data_processor.clone(),
                purposes: r.purposes.clone(),
                active_assignment_count: r.active_assignment_count,
            })
            .collect();

        let entitlements_with_retention: Vec<ClassifiedEntitlementDetail> = detail_rows
            .into_iter()
            .filter(|r| r.retention_period_days.is_some())
            .map(|r| ClassifiedEntitlementDetail {
                entitlement_id: r.id,
                entitlement_name: r.name,
                application_name: r.application_name,
                classification: r.data_protection_classification,
                legal_basis: r.legal_basis,
                retention_period_days: r.retention_period_days,
                data_controller: r.data_controller,
                data_processor: r.data_processor,
                purposes: r.purposes,
                active_assignment_count: r.active_assignment_count,
            })
            .collect();

        Ok(GdprReport {
            tenant_id,
            generated_at: Utc::now(),
            total_entitlements,
            classified_entitlements: classified_count,
            classification_summary,
            legal_basis_summary,
            classified_entitlements_detail,
            entitlements_with_retention,
        })
    }

    /// Get a per-user data protection summary (T025).
    pub async fn get_user_data_protection_summary(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<UserDataProtectionSummary> {
        // Query entitlements assigned to user where classification != none
        let entitlements: Vec<GovEntitlement> = sqlx::query_as(
            r"
            SELECT e.*
            FROM gov_entitlements e
            INNER JOIN gov_entitlement_assignments ea
                ON ea.entitlement_id = e.id AND ea.tenant_id = e.tenant_id
            WHERE e.tenant_id = $1
              AND ea.user_id = $2
              AND ea.status = 'active'
              AND e.data_protection_classification != 'none'
            ORDER BY e.name
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        let total_classified = entitlements.len() as i64;

        let mut classifications = HashMap::new();
        for ent in &entitlements {
            let key = serde_json::to_value(ent.data_protection_classification)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_else(|| format!("{:?}", ent.data_protection_classification));
            *classifications.entry(key).or_insert(0i64) += 1;
        }

        let entitlement_responses: Vec<EntitlementResponse> =
            entitlements.into_iter().map(Into::into).collect();

        Ok(UserDataProtectionSummary {
            user_id,
            entitlements: entitlement_responses,
            total_classified,
            classifications,
        })
    }
}
