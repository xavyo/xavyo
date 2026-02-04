//! Delegation Audit Service for governance API (F053).
//!
//! Provides business logic for querying and recording audit records
//! of actions taken by deputies on behalf of delegators.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovDelegationAudit, DelegationActionType, DelegationAuditFilter, GovApprovalDelegation,
    GovDelegationAudit, WorkItemType,
};
use xavyo_governance::error::Result;

use crate::models::DelegationAuditEntry;

/// Service for delegation audit operations.
pub struct DelegationAuditService {
    pool: PgPool,
}

/// Parameters for recording a delegation action.
#[derive(Debug, Clone)]
pub struct RecordActionParams {
    pub delegation_id: Uuid,
    pub deputy_id: Uuid,
    pub delegator_id: Uuid,
    pub action_type: DelegationActionType,
    pub work_item_id: Uuid,
    pub work_item_type: WorkItemType,
    pub metadata: Option<serde_json::Value>,
}

/// Parameters for listing delegation audit records.
#[derive(Debug, Clone, Default)]
pub struct ListAuditParams {
    pub delegation_id: Option<Uuid>,
    pub deputy_id: Option<Uuid>,
    pub delegator_id: Option<Uuid>,
    pub action_type: Option<String>,
    pub work_item_type: Option<String>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
    pub limit: i64,
    pub offset: i64,
}

impl DelegationAuditService {
    /// Create a new delegation audit service.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Record a delegation action in the audit trail.
    ///
    /// This method validates that the delegation exists before creating
    /// the audit record.
    pub async fn record_delegation_action(
        &self,
        tenant_id: Uuid,
        params: RecordActionParams,
    ) -> Result<GovDelegationAudit> {
        // Verify the delegation exists
        let _delegation =
            GovApprovalDelegation::find_by_id(&self.pool, tenant_id, params.delegation_id)
                .await?
                .ok_or_else(|| {
                    xavyo_governance::error::GovernanceError::DelegationNotFound(
                        params.delegation_id,
                    )
                })?;

        let input = CreateGovDelegationAudit {
            delegation_id: params.delegation_id,
            deputy_id: params.deputy_id,
            delegator_id: params.delegator_id,
            action_type: params.action_type,
            work_item_id: params.work_item_id,
            work_item_type: params.work_item_type,
            metadata: params.metadata,
        };

        let audit = GovDelegationAudit::create(&self.pool, tenant_id, input).await?;
        Ok(audit)
    }

    /// List delegation audit records with filtering.
    ///
    /// Supports filtering by `delegation_id`, `deputy_id`, `delegator_id`,
    /// `action_type`, `work_item_type`, and date range.
    pub async fn list_delegation_audit(
        &self,
        tenant_id: Uuid,
        params: ListAuditParams,
    ) -> Result<(Vec<DelegationAuditEntry>, i64)> {
        let filter = DelegationAuditFilter {
            delegation_id: params.delegation_id,
            deputy_id: params.deputy_id,
            delegator_id: params.delegator_id,
            action_type: params.action_type.and_then(|s| parse_action_type(&s)),
            work_item_type: params.work_item_type.and_then(|s| parse_work_item_type(&s)),
            from_date: params.from_date,
            to_date: params.to_date,
        };

        let records = GovDelegationAudit::list_by_tenant(
            &self.pool,
            tenant_id,
            &filter,
            params.limit,
            params.offset,
        )
        .await?;

        let total = GovDelegationAudit::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        // Convert to DTOs with enriched data
        let entries = self.enrich_audit_entries(tenant_id, records).await?;

        Ok((entries, total))
    }

    /// Get a single audit record by ID.
    pub async fn get_audit_record(
        &self,
        tenant_id: Uuid,
        audit_id: Uuid,
    ) -> Result<Option<DelegationAuditEntry>> {
        let record = GovDelegationAudit::find_by_id(&self.pool, tenant_id, audit_id).await?;

        match record {
            Some(r) => {
                let entries = self.enrich_audit_entries(tenant_id, vec![r]).await?;
                Ok(entries.into_iter().next())
            }
            None => Ok(None),
        }
    }

    /// List audit records for a specific delegation.
    pub async fn list_by_delegation(
        &self,
        tenant_id: Uuid,
        delegation_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<DelegationAuditEntry>, i64)> {
        let filter = DelegationAuditFilter {
            delegation_id: Some(delegation_id),
            ..Default::default()
        };

        let records =
            GovDelegationAudit::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;

        let total = GovDelegationAudit::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        let entries = self.enrich_audit_entries(tenant_id, records).await?;

        Ok((entries, total))
    }

    /// Enrich audit records with display names.
    async fn enrich_audit_entries(
        &self,
        _tenant_id: Uuid,
        records: Vec<GovDelegationAudit>,
    ) -> Result<Vec<DelegationAuditEntry>> {
        // Note: In a full implementation, we would lookup user display names
        // from the users table. For now, we return the entries without
        // display name enrichment.
        let entries = records
            .into_iter()
            .map(|r| DelegationAuditEntry {
                id: r.id,
                delegation_id: r.delegation_id,
                deputy_id: r.deputy_id,
                deputy_display: None, // TODO: Lookup from users table
                delegator_id: r.delegator_id,
                delegator_display: None, // TODO: Lookup from users table
                action_type: r.action_type.to_string(),
                work_item_id: r.work_item_id,
                work_item_type: r.work_item_type.to_string(),
                metadata: r.metadata,
                created_at: r.created_at,
            })
            .collect();

        Ok(entries)
    }

    /// Get database pool reference.
    #[must_use] 
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

/// Parse action type string to enum.
fn parse_action_type(s: &str) -> Option<DelegationActionType> {
    match s.to_lowercase().as_str() {
        "approve_request" => Some(DelegationActionType::ApproveRequest),
        "reject_request" => Some(DelegationActionType::RejectRequest),
        "certify_access" => Some(DelegationActionType::CertifyAccess),
        "revoke_access" => Some(DelegationActionType::RevokeAccess),
        "approve_transition" => Some(DelegationActionType::ApproveTransition),
        "reject_transition" => Some(DelegationActionType::RejectTransition),
        _ => None,
    }
}

/// Parse work item type string to enum.
fn parse_work_item_type(s: &str) -> Option<WorkItemType> {
    match s.to_lowercase().as_str() {
        "access_request" => Some(WorkItemType::AccessRequest),
        "certification" => Some(WorkItemType::Certification),
        "state_transition" => Some(WorkItemType::StateTransition),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_action_type() {
        assert_eq!(
            parse_action_type("approve_request"),
            Some(DelegationActionType::ApproveRequest)
        );
        assert_eq!(
            parse_action_type("REJECT_REQUEST"),
            Some(DelegationActionType::RejectRequest)
        );
        assert_eq!(
            parse_action_type("certify_access"),
            Some(DelegationActionType::CertifyAccess)
        );
        assert_eq!(parse_action_type("invalid"), None);
    }

    #[test]
    fn test_parse_work_item_type() {
        assert_eq!(
            parse_work_item_type("access_request"),
            Some(WorkItemType::AccessRequest)
        );
        assert_eq!(
            parse_work_item_type("CERTIFICATION"),
            Some(WorkItemType::Certification)
        );
        assert_eq!(
            parse_work_item_type("state_transition"),
            Some(WorkItemType::StateTransition)
        );
        assert_eq!(parse_work_item_type("invalid"), None);
    }

    #[test]
    fn test_list_audit_params_default() {
        let params = ListAuditParams::default();
        assert!(params.delegation_id.is_none());
        assert!(params.deputy_id.is_none());
        assert!(params.delegator_id.is_none());
        assert_eq!(params.limit, 0);
        assert_eq!(params.offset, 0);
    }

    #[test]
    fn test_record_action_params() {
        let params = RecordActionParams {
            delegation_id: Uuid::new_v4(),
            deputy_id: Uuid::new_v4(),
            delegator_id: Uuid::new_v4(),
            action_type: DelegationActionType::ApproveRequest,
            work_item_id: Uuid::new_v4(),
            work_item_type: WorkItemType::AccessRequest,
            metadata: Some(serde_json::json!({"test": true})),
        };

        assert_eq!(params.action_type, DelegationActionType::ApproveRequest);
        assert!(params.metadata.is_some());
    }
}
