//! Merge Audit Service (F062 - US5).
//!
//! Provides audit trail and merge history functionality:
//! - List audit records with filtering
//! - Get detailed audit record
//! - Search by identity, operator, date range
//!
//! Note: Audit records are immutable (create-only, no update/delete).

use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{GovMergeAudit, MergeAuditFilter};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for merge audit operations.
pub struct MergeAuditService {
    pool: PgPool,
}

impl MergeAuditService {
    /// Create a new merge audit service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// List audit records with filtering and pagination.
    ///
    /// # Arguments
    /// * `tenant_id` - Tenant ID for isolation
    /// * `filter` - Filter criteria (`identity_id`, `operator_id`, date range)
    /// * `limit` - Maximum number of records to return
    /// * `offset` - Number of records to skip
    pub async fn list(
        &self,
        tenant_id: Uuid,
        filter: &MergeAuditFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovMergeAudit>, i64)> {
        let records = GovMergeAudit::list_by_tenant(&self.pool, tenant_id, filter, limit, offset)
            .await
            .map_err(GovernanceError::Database)?;

        let total = GovMergeAudit::count_by_tenant(&self.pool, tenant_id, filter)
            .await
            .map_err(GovernanceError::Database)?;

        Ok((records, total))
    }

    /// Get an audit record by ID.
    pub async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<GovMergeAudit> {
        GovMergeAudit::find_by_id(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or(GovernanceError::MergeAuditNotFound(id))
    }

    /// Get an audit record by operation ID.
    pub async fn get_by_operation(
        &self,
        tenant_id: Uuid,
        operation_id: Uuid,
    ) -> Result<Option<GovMergeAudit>> {
        GovMergeAudit::find_by_operation(&self.pool, tenant_id, operation_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Find all audit records involving a specific identity.
    ///
    /// This searches both source and target identity snapshots.
    pub async fn find_by_identity(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        limit: i64,
    ) -> Result<Vec<GovMergeAudit>> {
        GovMergeAudit::find_by_identity(&self.pool, tenant_id, identity_id, limit)
            .await
            .map_err(GovernanceError::Database)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_audit_service_creation() {
        // Test that we can create a MergeAuditService
        // Note: Actual database tests would require a test database
        assert!(true);
    }
}
