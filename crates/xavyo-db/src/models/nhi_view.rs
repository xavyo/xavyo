//! Unified Non-Human Identity view model.
//!
//! This model represents rows from the `v_non_human_identities` view,
//! which provides a unified representation of service accounts and AI agents.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A row from the unified `v_non_human_identities` view.
///
/// This struct normalizes service accounts and AI agents into a common
/// structure for unified listing, risk reporting, and certification.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NonHumanIdentityView {
    /// Unique identifier (from source table)
    pub id: Uuid,

    /// Tenant this identity belongs to
    pub tenant_id: Uuid,

    /// Display name
    pub name: String,

    /// Description or purpose statement
    pub description: Option<String>,

    /// Type discriminator: "`service_account`" or "`ai_agent`"
    pub nhi_type: String,

    /// Primary owner user ID
    pub owner_id: Uuid,

    /// Backup owner for succession planning
    pub backup_owner_id: Option<Uuid>,

    /// Current status (active, suspended, expired, etc.)
    pub status: String,

    /// When the identity was created
    pub created_at: DateTime<Utc>,

    /// When the identity expires
    pub expires_at: Option<DateTime<Utc>>,

    /// Last time the identity was used
    pub last_activity_at: Option<DateTime<Utc>>,

    /// Unified risk score (0-100)
    pub risk_score: i32,

    /// When next certification is due
    pub next_certification_at: Option<DateTime<Utc>>,

    /// When last certified
    pub last_certified_at: Option<DateTime<Utc>>,
}

impl NonHumanIdentityView {
    /// Check if this is a service account.
    #[must_use] 
    pub fn is_service_account(&self) -> bool {
        self.nhi_type == "service_account"
    }

    /// Check if this is an AI agent.
    #[must_use] 
    pub fn is_ai_agent(&self) -> bool {
        self.nhi_type == "ai_agent"
    }

    /// Check if the identity is active.
    #[must_use] 
    pub fn is_active(&self) -> bool {
        self.status == "active" || self.status == "Active"
    }

    /// Check if the identity has expired.
    #[must_use] 
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            expires < Utc::now()
        } else {
            self.status == "expired" || self.status == "Expired"
        }
    }

    /// Check if certification is due within the given days.
    #[must_use] 
    pub fn certification_due_within_days(&self, days: i64) -> bool {
        if let Some(next_cert) = self.next_certification_at {
            let threshold = Utc::now() + chrono::Duration::days(days);
            next_cert <= threshold
        } else {
            false
        }
    }

    /// Get the risk level category.
    #[must_use] 
    pub fn risk_level(&self) -> &'static str {
        match self.risk_score {
            0..=25 => "low",
            26..=50 => "medium",
            51..=75 => "high",
            _ => "critical",
        }
    }

    /// Check if the identity has been inactive for the given days.
    #[must_use] 
    pub fn inactive_for_days(&self, days: i64) -> bool {
        if let Some(last_activity) = self.last_activity_at {
            let threshold = Utc::now() - chrono::Duration::days(days);
            last_activity < threshold
        } else {
            true // No activity recorded = considered inactive
        }
    }

    /// List all NHIs for a tenant with optional filtering.
    pub async fn list(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &NhiViewFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT id, tenant_id, name, description, nhi_type, owner_id, backup_owner_id,
                   status, created_at, expires_at, last_activity_at, risk_score,
                   next_certification_at, last_certified_at
            FROM v_non_human_identities
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.nhi_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND nhi_type = ${param_count}"));
        }

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }

        if filter.owner_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND owner_id = ${param_count}"));
        }

        if let Some(risk_min) = filter.risk_min {
            param_count += 1;
            query.push_str(&format!(" AND risk_score >= ${param_count}"));
            let _ = risk_min; // Used below
        }

        if filter.certification_due {
            query.push_str(" AND next_certification_at <= NOW() + INTERVAL '30 days'");
        }

        query.push_str(&format!(
            " ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, NonHumanIdentityView>(&query).bind(tenant_id);

        if let Some(ref nhi_type) = filter.nhi_type {
            q = q.bind(nhi_type);
        }
        if let Some(ref status) = filter.status {
            q = q.bind(status);
        }
        if let Some(owner_id) = filter.owner_id {
            q = q.bind(owner_id);
        }
        if let Some(risk_min) = filter.risk_min {
            q = q.bind(risk_min);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count NHIs for a tenant with optional filtering.
    pub async fn count(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &NhiViewFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*)
            FROM v_non_human_identities
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.nhi_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND nhi_type = ${param_count}"));
        }

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }

        if filter.owner_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND owner_id = ${param_count}"));
        }

        if let Some(risk_min) = filter.risk_min {
            param_count += 1;
            query.push_str(&format!(" AND risk_score >= ${param_count}"));
            let _ = risk_min;
        }

        if filter.certification_due {
            query.push_str(" AND next_certification_at <= NOW() + INTERVAL '30 days'");
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(ref nhi_type) = filter.nhi_type {
            q = q.bind(nhi_type);
        }
        if let Some(ref status) = filter.status {
            q = q.bind(status);
        }
        if let Some(owner_id) = filter.owner_id {
            q = q.bind(owner_id);
        }
        if let Some(risk_min) = filter.risk_min {
            q = q.bind(risk_min);
        }

        q.fetch_one(pool).await
    }

    /// Find a specific NHI by ID.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT id, tenant_id, name, description, nhi_type, owner_id, backup_owner_id,
                   status, created_at, expires_at, last_activity_at, risk_score,
                   next_certification_at, last_certified_at
            FROM v_non_human_identities
            WHERE tenant_id = $1 AND id = $2
            ",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(pool)
        .await
    }

    /// Get risk summary statistics for a tenant.
    pub async fn get_risk_summary(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<NhiRiskSummary, sqlx::Error> {
        let row = sqlx::query_as::<_, RiskSummaryRow>(
            r"
            SELECT
                COUNT(*)::integer AS total_count,
                COUNT(*) FILTER (WHERE nhi_type = 'service_account')::integer AS service_account_count,
                COUNT(*) FILTER (WHERE nhi_type = 'ai_agent')::integer AS ai_agent_count,
                COUNT(*) FILTER (WHERE risk_score >= 76)::integer AS critical_count,
                COUNT(*) FILTER (WHERE risk_score >= 51 AND risk_score <= 75)::integer AS high_count,
                COUNT(*) FILTER (WHERE risk_score >= 26 AND risk_score <= 50)::integer AS medium_count,
                COUNT(*) FILTER (WHERE risk_score <= 25)::integer AS low_count,
                COUNT(*) FILTER (WHERE next_certification_at <= NOW() + INTERVAL '30 days')::integer AS pending_certification,
                COUNT(*) FILTER (WHERE last_activity_at < NOW() - INTERVAL '30 days')::integer AS inactive_30_days,
                COUNT(*) FILTER (WHERE expires_at <= NOW() + INTERVAL '7 days')::integer AS expiring_7_days
            FROM v_non_human_identities
            WHERE tenant_id = $1
            ",
        )
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

        Ok(NhiRiskSummary {
            total_count: row.total_count,
            by_type: NhiCountByType {
                service_account: row.service_account_count,
                ai_agent: row.ai_agent_count,
            },
            by_risk_level: NhiCountByRiskLevel {
                critical: row.critical_count,
                high: row.high_count,
                medium: row.medium_count,
                low: row.low_count,
            },
            pending_certification: row.pending_certification,
            inactive_30_days: row.inactive_30_days,
            expiring_7_days: row.expiring_7_days,
        })
    }
}

/// Helper struct for raw risk summary query.
#[derive(Debug, FromRow)]
struct RiskSummaryRow {
    total_count: i32,
    service_account_count: i32,
    ai_agent_count: i32,
    critical_count: i32,
    high_count: i32,
    medium_count: i32,
    low_count: i32,
    pending_certification: i32,
    inactive_30_days: i32,
    expiring_7_days: i32,
}

/// Filter options for listing NHIs from the unified view.
#[derive(Debug, Clone, Default)]
pub struct NhiViewFilter {
    /// Filter by NHI type ("`service_account`", "`ai_agent`", or None for all)
    pub nhi_type: Option<String>,

    /// Filter by status
    pub status: Option<String>,

    /// Filter by owner
    pub owner_id: Option<Uuid>,

    /// Filter by minimum risk score
    pub risk_min: Option<i32>,

    /// Filter for certification due within 30 days
    pub certification_due: bool,
}

/// Aggregated risk summary across all NHI types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NhiRiskSummary {
    /// Total count of all NHIs
    pub total_count: i32,

    /// Counts by NHI type
    pub by_type: NhiCountByType,

    /// Counts by risk level
    pub by_risk_level: NhiCountByRiskLevel,

    /// NHIs with certification due within 30 days
    pub pending_certification: i32,

    /// NHIs with no activity in 30 days
    pub inactive_30_days: i32,

    /// NHIs expiring within 7 days
    pub expiring_7_days: i32,
}

/// Count of NHIs by type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NhiCountByType {
    pub service_account: i32,
    pub ai_agent: i32,
}

/// Count of NHIs by risk level.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NhiCountByRiskLevel {
    pub critical: i32,
    pub high: i32,
    pub medium: i32,
    pub low: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_nhi() -> NonHumanIdentityView {
        NonHumanIdentityView {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "test-nhi".to_string(),
            description: Some("Test NHI".to_string()),
            nhi_type: "service_account".to_string(),
            owner_id: Uuid::new_v4(),
            backup_owner_id: None,
            status: "active".to_string(),
            created_at: Utc::now(),
            expires_at: None,
            last_activity_at: Some(Utc::now()),
            risk_score: 25,
            next_certification_at: None,
            last_certified_at: None,
        }
    }

    #[test]
    fn test_is_service_account() {
        let nhi = create_test_nhi();
        assert!(nhi.is_service_account());
        assert!(!nhi.is_ai_agent());
    }

    #[test]
    fn test_is_ai_agent() {
        let mut nhi = create_test_nhi();
        nhi.nhi_type = "ai_agent".to_string();
        assert!(nhi.is_ai_agent());
        assert!(!nhi.is_service_account());
    }

    #[test]
    fn test_is_active() {
        let nhi = create_test_nhi();
        assert!(nhi.is_active());

        let mut suspended = create_test_nhi();
        suspended.status = "suspended".to_string();
        assert!(!suspended.is_active());
    }

    #[test]
    fn test_is_expired() {
        let nhi = create_test_nhi();
        assert!(!nhi.is_expired());

        let mut expired = create_test_nhi();
        expired.expires_at = Some(Utc::now() - chrono::Duration::days(1));
        assert!(expired.is_expired());
    }

    #[test]
    fn test_risk_level() {
        let mut nhi = create_test_nhi();

        nhi.risk_score = 10;
        assert_eq!(nhi.risk_level(), "low");

        nhi.risk_score = 40;
        assert_eq!(nhi.risk_level(), "medium");

        nhi.risk_score = 60;
        assert_eq!(nhi.risk_level(), "high");

        nhi.risk_score = 90;
        assert_eq!(nhi.risk_level(), "critical");
    }

    #[test]
    fn test_inactive_for_days() {
        let mut nhi = create_test_nhi();
        nhi.last_activity_at = Some(Utc::now() - chrono::Duration::days(10));

        assert!(!nhi.inactive_for_days(30));
        assert!(nhi.inactive_for_days(5));
    }

    #[test]
    fn test_certification_due_within_days() {
        let mut nhi = create_test_nhi();
        nhi.next_certification_at = Some(Utc::now() + chrono::Duration::days(15));

        assert!(nhi.certification_due_within_days(30));
        assert!(!nhi.certification_due_within_days(10));
    }

    #[test]
    fn test_nhi_view_filter_default() {
        let filter = NhiViewFilter::default();
        assert!(filter.nhi_type.is_none());
        assert!(filter.status.is_none());
        assert!(filter.owner_id.is_none());
        assert!(filter.risk_min.is_none());
        assert!(!filter.certification_due);
    }
}
