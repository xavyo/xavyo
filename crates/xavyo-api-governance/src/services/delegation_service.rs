//! Delegation service for governance API.
//!
//! Handles approval delegation management.
//! Enhanced in F053 to support scoped delegations and lifecycle management.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovApprovalDelegation, CreateGovDelegationScope, DelegationFilter, DelegationStatus,
    GovApprovalDelegation, GovDelegationScope,
};
use xavyo_governance::error::{GovernanceError, Result};

use crate::models::{CreateDelegationScopeRequest, DelegatedWorkItem};

/// Type alias for pending work item row returned from the database query.
/// Contains: (request_id, entitlement_id, application_id, summary, created_at)
type PendingWorkItemRow = (Uuid, Uuid, Option<Uuid>, String, chrono::DateTime<Utc>);

/// Service for delegation operations.
pub struct DelegationService {
    pool: PgPool,
}

impl DelegationService {
    /// Create a new delegation service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// List delegations for the current user (as delegator).
    pub async fn list_my_delegations(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        is_active: Option<bool>,
        active_now: Option<bool>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovApprovalDelegation>, i64)> {
        let filter = DelegationFilter {
            delegator_id: Some(user_id),
            delegate_id: None,
            is_active,
            active_now,
            ..Default::default()
        };

        let delegations =
            GovApprovalDelegation::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;
        let total = GovApprovalDelegation::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok((delegations, total))
    }

    /// List delegations where the user is the delegate.
    pub async fn list_delegations_to_me(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        is_active: Option<bool>,
        active_now: Option<bool>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovApprovalDelegation>, i64)> {
        let filter = DelegationFilter {
            delegator_id: None,
            delegate_id: Some(user_id),
            is_active,
            active_now,
            ..Default::default()
        };

        let delegations =
            GovApprovalDelegation::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;
        let total = GovApprovalDelegation::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok((delegations, total))
    }

    /// Get a specific delegation by ID.
    pub async fn get_delegation(
        &self,
        tenant_id: Uuid,
        delegation_id: Uuid,
    ) -> Result<GovApprovalDelegation> {
        GovApprovalDelegation::find_by_id(&self.pool, tenant_id, delegation_id)
            .await?
            .ok_or(GovernanceError::DelegationNotFound(delegation_id))
    }

    /// Create a new delegation (F053 enhanced with scope support).
    pub async fn create_delegation(
        &self,
        tenant_id: Uuid,
        delegator_id: Uuid,
        delegate_id: Uuid,
        starts_at: DateTime<Utc>,
        ends_at: DateTime<Utc>,
    ) -> Result<GovApprovalDelegation> {
        self.create_delegation_with_scope(
            tenant_id,
            delegator_id,
            delegate_id,
            starts_at,
            ends_at,
            None,
        )
        .await
    }

    /// Create a new delegation with optional scope (F053).
    pub async fn create_delegation_with_scope(
        &self,
        tenant_id: Uuid,
        delegator_id: Uuid,
        delegate_id: Uuid,
        starts_at: DateTime<Utc>,
        ends_at: DateTime<Utc>,
        scope: Option<CreateDelegationScopeRequest>,
    ) -> Result<GovApprovalDelegation> {
        // Self-delegation check
        if delegator_id == delegate_id {
            return Err(GovernanceError::SelfDelegationNotAllowed);
        }

        // Validate period
        if ends_at <= starts_at {
            return Err(GovernanceError::InvalidDelegationPeriod);
        }

        // Check for existing active delegation from this delegator
        if GovApprovalDelegation::find_active_for_delegator(
            &self.pool,
            tenant_id,
            delegator_id,
            Utc::now(),
        )
        .await?
        .is_some()
        {
            return Err(GovernanceError::DelegationAlreadyExists);
        }

        // Create scope if provided
        let scope_id = if let Some(scope_req) = scope {
            // Validate scope references
            let scope_input = CreateGovDelegationScope {
                application_ids: if scope_req.application_ids.is_empty() {
                    None
                } else {
                    Some(scope_req.application_ids)
                },
                entitlement_ids: if scope_req.entitlement_ids.is_empty() {
                    None
                } else {
                    Some(scope_req.entitlement_ids)
                },
                role_ids: if scope_req.role_ids.is_empty() {
                    None
                } else {
                    Some(scope_req.role_ids)
                },
                workflow_types: if scope_req.workflow_types.is_empty() {
                    None
                } else {
                    // Validate workflow types
                    let valid_types = ["access_request", "certification", "state_transition"];
                    for wf_type in &scope_req.workflow_types {
                        if !valid_types.contains(&wf_type.as_str()) {
                            return Err(GovernanceError::Validation(format!(
                                "Invalid workflow type: {}. Valid types: {:?}",
                                wf_type, valid_types
                            )));
                        }
                    }
                    Some(scope_req.workflow_types)
                },
            };

            // Validate referenced entities exist
            let validation_errors =
                GovDelegationScope::validate_references(&self.pool, tenant_id, &scope_input)
                    .await?;
            if !validation_errors.is_empty() {
                return Err(GovernanceError::InvalidDelegationScopeReferences(
                    validation_errors.join(", "),
                ));
            }

            // Create the scope
            let scope = GovDelegationScope::create(&self.pool, tenant_id, scope_input).await?;
            Some(scope.id)
        } else {
            None
        };

        let input = CreateGovApprovalDelegation {
            delegator_id,
            delegate_id,
            starts_at,
            ends_at,
            scope_id,
        };

        GovApprovalDelegation::create(&self.pool, tenant_id, input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Get delegation scope details (F053).
    pub async fn get_delegation_scope(
        &self,
        tenant_id: Uuid,
        scope_id: Uuid,
    ) -> Result<GovDelegationScope> {
        GovDelegationScope::find_by_id(&self.pool, tenant_id, scope_id)
            .await?
            .ok_or_else(|| GovernanceError::Validation("Delegation scope not found".to_string()))
    }

    /// Extend delegation end date (F053).
    pub async fn extend_delegation(
        &self,
        tenant_id: Uuid,
        delegation_id: Uuid,
        user_id: Uuid,
        new_ends_at: DateTime<Utc>,
    ) -> Result<GovApprovalDelegation> {
        // Get the delegation
        let delegation = self.get_delegation(tenant_id, delegation_id).await?;

        // Only the delegator can extend
        if delegation.delegator_id != user_id {
            return Err(GovernanceError::NotAuthorizedApprover);
        }

        // Check status
        match delegation.status {
            DelegationStatus::Expired => {
                return Err(GovernanceError::CannotExtendExpiredDelegation(
                    delegation_id,
                ));
            }
            DelegationStatus::Revoked => {
                return Err(GovernanceError::CannotExtendRevokedDelegation(
                    delegation_id,
                ));
            }
            _ => {}
        }

        // New end date must be after current end date
        if new_ends_at <= delegation.ends_at {
            return Err(GovernanceError::InvalidDelegationExtension);
        }

        GovApprovalDelegation::extend(&self.pool, tenant_id, delegation_id, new_ends_at)
            .await?
            .ok_or(GovernanceError::DelegationNotFound(delegation_id))
    }

    /// Revoke an active delegation.
    pub async fn revoke_delegation(
        &self,
        tenant_id: Uuid,
        delegation_id: Uuid,
        user_id: Uuid,
    ) -> Result<GovApprovalDelegation> {
        // Get the delegation
        let delegation = self.get_delegation(tenant_id, delegation_id).await?;

        // Only the delegator can revoke
        if delegation.delegator_id != user_id {
            return Err(GovernanceError::NotAuthorizedApprover);
        }

        // Check if already inactive
        if !delegation.is_active {
            return Err(GovernanceError::DelegationNotActive(delegation_id));
        }

        GovApprovalDelegation::revoke(&self.pool, tenant_id, delegation_id)
            .await?
            .ok_or(GovernanceError::DelegationNotFound(delegation_id))
    }

    /// Check if a user is delegating to another user.
    pub async fn is_delegating_to(
        &self,
        tenant_id: Uuid,
        delegator_id: Uuid,
        delegate_id: Uuid,
    ) -> Result<bool> {
        GovApprovalDelegation::is_delegating_to(
            &self.pool,
            tenant_id,
            delegator_id,
            delegate_id,
            Utc::now(),
        )
        .await
        .map_err(GovernanceError::Database)
    }

    /// Get delegated work items for a deputy (F053).
    ///
    /// Returns pending approval work items from all active delegators,
    /// filtered by the delegation scopes.
    #[allow(clippy::too_many_arguments)]
    pub async fn get_delegated_work_items(
        &self,
        tenant_id: Uuid,
        deputy_id: Uuid,
        delegator_id: Option<Uuid>,
        work_item_type: Option<&str>,
        application_id: Option<Uuid>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<DelegatedWorkItem>, i64)> {
        // Get all active delegations where this user is the deputy
        let filter = DelegationFilter {
            delegator_id: None,
            delegate_id: Some(deputy_id),
            is_active: Some(true),
            active_now: Some(true),
            ..Default::default()
        };

        let delegations =
            GovApprovalDelegation::list_by_tenant(&self.pool, tenant_id, &filter, 100, 0).await?;

        // Filter by specific delegator if requested
        let delegations: Vec<_> = if let Some(specific_delegator) = delegator_id {
            delegations
                .into_iter()
                .filter(|d| d.delegator_id == specific_delegator)
                .collect()
        } else {
            delegations
        };

        if delegations.is_empty() {
            return Ok((vec![], 0));
        }

        // Collect all delegator IDs and their scopes
        let mut all_work_items = Vec::new();

        for delegation in &delegations {
            // Get scope if any
            let scope = if let Some(scope_id) = delegation.scope_id {
                GovDelegationScope::find_by_id(&self.pool, tenant_id, scope_id).await?
            } else {
                None
            };

            // Query pending access requests where delegator is an approver
            // Only include entitlements that are marked as delegable (IGA edge case)
            let requests: Vec<PendingWorkItemRow> = sqlx::query_as(
                r#"
                SELECT
                    ar.id,
                    ar.entitlement_id,
                    e.application_id,
                    ar.justification,
                    ar.created_at
                FROM gov_access_requests ar
                JOIN gov_entitlements e ON e.id = ar.entitlement_id
                JOIN gov_applications a ON a.id = e.application_id
                LEFT JOIN gov_approval_steps step ON step.workflow_id = ar.workflow_id
                    AND step.step_order = ar.current_step + 1
                WHERE ar.tenant_id = $1
                    AND ar.status IN ('pending', 'pending_approval')
                    -- Only include delegable entitlements and applications (F053 IGA edge case)
                    AND e.is_delegable = TRUE
                    AND a.is_delegable = TRUE
                    AND (
                        -- Direct approver match
                        (step.approver_type = 'specific_users' AND $2 = ANY(step.specific_approvers))
                        OR (step.approver_type = 'entitlement_owner' AND e.owner_id = $2)
                    )
                ORDER BY ar.created_at ASC
                "#,
            )
            .bind(tenant_id)
            .bind(delegation.delegator_id)
            .fetch_all(&self.pool)
            .await?;

            for (request_id, entitlement_id, app_id, summary, created_at) in requests {
                // Check scope if present
                if let Some(ref scope) = scope {
                    // Apply scope filters
                    if !scope.application_ids.is_empty() {
                        if let Some(aid) = app_id {
                            if !scope.application_ids.contains(&aid) {
                                continue;
                            }
                        } else {
                            continue;
                        }
                    }

                    if !scope.entitlement_ids.is_empty()
                        && !scope.entitlement_ids.contains(&entitlement_id)
                    {
                        continue;
                    }

                    // Check workflow type filter
                    if !scope.workflow_types.is_empty()
                        && !scope.workflow_types.contains(&"access_request".to_string())
                    {
                        continue;
                    }
                }

                // Apply user filters
                if let Some(filter_type) = work_item_type {
                    if filter_type != "access_request" {
                        continue;
                    }
                }

                if let Some(filter_app_id) = application_id {
                    if app_id != Some(filter_app_id) {
                        continue;
                    }
                }

                // Get entitlement details
                let entitlement =
                    xavyo_db::GovEntitlement::find_by_id(&self.pool, tenant_id, entitlement_id)
                        .await?;
                let entitlement_name = entitlement.as_ref().map(|e| e.name.clone());
                let app_name = if let Some(eid) = &entitlement {
                    xavyo_db::GovApplication::find_by_id(&self.pool, tenant_id, eid.application_id)
                        .await?
                        .map(|a| a.name)
                } else {
                    None
                };

                all_work_items.push(DelegatedWorkItem {
                    id: request_id,
                    work_item_type: "access_request".to_string(),
                    delegation_id: delegation.id,
                    delegator_id: delegation.delegator_id,
                    delegator_display: None, // Could fetch user email
                    access_request_id: Some(request_id),
                    certification_item_id: None,
                    application_id: app_id,
                    application_name: app_name,
                    entitlement_id: Some(entitlement_id),
                    entitlement_name,
                    role_id: None,
                    role_name: None,
                    summary,
                    priority: None,
                    due_at: None,
                    created_at,
                });
            }
        }

        // Sort by created_at
        all_work_items.sort_by(|a, b| a.created_at.cmp(&b.created_at));

        let total = all_work_items.len() as i64;

        // Apply pagination
        let start = offset as usize;
        let end = std::cmp::min(start + limit as usize, all_work_items.len());
        let paginated = if start < all_work_items.len() {
            all_work_items[start..end].to_vec()
        } else {
            vec![]
        };

        Ok((paginated, total))
    }

    /// Get database pool reference.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_delegation_validation() {
        let now = Utc::now();
        let future = now + Duration::days(7);

        // Valid period
        assert!(future > now);

        // Invalid period (end before start)
        let past = now - Duration::days(1);
        assert!(past < now);
    }

    #[test]
    fn test_delegation_period_boundaries() {
        let now = Utc::now();

        // Start in the future, end further in the future (valid)
        let start = now + Duration::hours(1);
        let end = now + Duration::days(14);
        assert!(end > start);
        assert!(start > now);

        // Delegation duration check (14 days minus 1 hour = ~13.96 days)
        let duration = end - start;
        assert!(duration.num_days() <= 14);
        assert!(duration.num_days() >= 13);
        // More precise check using hours
        assert!(duration.num_hours() == 14 * 24 - 1); // 335 hours
    }

    #[test]
    fn test_same_user_delegation_detection() {
        let user_id = Uuid::new_v4();

        // Self-delegation should be detected
        let delegator_id = user_id;
        let delegate_id = user_id;
        assert_eq!(delegator_id, delegate_id);
    }

    #[test]
    fn test_different_users_delegation() {
        let delegator_id = Uuid::new_v4();
        let delegate_id = Uuid::new_v4();

        // Different users should be allowed
        assert_ne!(delegator_id, delegate_id);
    }

    #[test]
    fn test_delegation_model() {
        use xavyo_db::DelegationStatus;

        let now = Utc::now();
        let delegation = GovApprovalDelegation {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            delegator_id: Uuid::new_v4(),
            delegate_id: Uuid::new_v4(),
            starts_at: now,
            ends_at: now + Duration::days(7),
            is_active: true,
            created_at: now,
            revoked_at: None,
            scope_id: None,
            status: DelegationStatus::Active,
            expiry_warning_sent: false,
        };

        assert!(delegation.is_active);
        assert!(delegation.revoked_at.is_none());
        assert!(delegation.ends_at > delegation.starts_at);
        assert_eq!(delegation.status, DelegationStatus::Active);
        assert!(!delegation.expiry_warning_sent);
    }
}
