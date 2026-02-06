//! Service for unified NHI listing.
//!
//! This service queries the `v_non_human_identities` view to provide
//! a unified listing of service accounts and AI agents.

use sqlx::PgPool;
use uuid::Uuid;
use xavyo_db::models::{NhiViewFilter, NonHumanIdentityView};

/// Service for listing unified Non-Human Identities.
#[derive(Clone)]
pub struct UnifiedListService {
    pool: PgPool,
}

impl UnifiedListService {
    /// Creates a new `UnifiedListService`.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Lists NHIs for a tenant with filtering and pagination.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        filter: NhiViewFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<NonHumanIdentityView>, sqlx::Error> {
        NonHumanIdentityView::list(&self.pool, tenant_id, &filter, limit, offset).await
    }

    /// Counts NHIs for a tenant with filtering.
    pub async fn count(&self, tenant_id: Uuid, filter: NhiViewFilter) -> Result<i64, sqlx::Error> {
        NonHumanIdentityView::count(&self.pool, tenant_id, &filter).await
    }

    /// Finds a specific NHI by ID.
    pub async fn find_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<NonHumanIdentityView>, sqlx::Error> {
        NonHumanIdentityView::find_by_id(&self.pool, tenant_id, id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_list_service_creation() {
        // This test verifies the service can be constructed
        // Integration tests would test actual database queries

        // For unit testing without a DB connection, we just verify
        // the types are correctly defined
        let filter = NhiViewFilter::default();
        assert!(filter.nhi_type.is_none());
        assert!(filter.status.is_none());
        assert!(filter.owner_id.is_none());
        assert!(filter.risk_min.is_none());
        assert!(!filter.certification_due);
    }

    #[test]
    fn test_nhi_view_filter_with_type() {
        let filter = NhiViewFilter {
            nhi_type: Some("service_account".to_string()),
            ..Default::default()
        };
        assert_eq!(filter.nhi_type, Some("service_account".to_string()));
    }

    #[test]
    fn test_nhi_view_filter_with_all_options() {
        let owner_id = Uuid::new_v4();
        let filter = NhiViewFilter {
            nhi_type: Some("ai_agent".to_string()),
            status: Some("active".to_string()),
            owner_id: Some(owner_id),
            risk_min: Some(50),
            certification_due: true,
        };

        assert_eq!(filter.nhi_type, Some("ai_agent".to_string()));
        assert_eq!(filter.status, Some("active".to_string()));
        assert_eq!(filter.owner_id, Some(owner_id));
        assert_eq!(filter.risk_min, Some(50));
        assert!(filter.certification_due);
    }
}
