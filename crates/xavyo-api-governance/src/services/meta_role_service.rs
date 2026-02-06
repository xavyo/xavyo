//! Meta-role service for governance API (F056).
//!
//! Handles meta-role CRUD operations, criteria management, entitlement/constraint
//! inheritance, and audit trail.

#[cfg(feature = "kafka")]
use std::sync::Arc;

use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use xavyo_db::{
    CreateGovMetaRole, CreateGovMetaRoleConstraint, CreateGovMetaRoleCriteria,
    CreateGovMetaRoleEntitlement, CreateGovMetaRoleEvent, GovMetaRole, GovMetaRoleConstraint,
    GovMetaRoleCriteria, GovMetaRoleEntitlement, GovMetaRoleEvent, GovMetaRoleInheritance,
    MetaRoleEventStats, MetaRoleEventType, MetaRoleFilter, MetaRoleStatus, UpdateGovMetaRole,
    SUPPORTED_CONSTRAINT_TYPES, SUPPORTED_CRITERIA_FIELDS,
};
use xavyo_governance::error::{GovernanceError, Result};

#[cfg(feature = "kafka")]
use xavyo_events::EventProducer;

/// Service for meta-role operations.
pub struct MetaRoleService {
    pool: PgPool,
    #[cfg(feature = "kafka")]
    event_producer: Option<Arc<EventProducer>>,
}

impl MetaRoleService {
    /// Create a new meta-role service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            #[cfg(feature = "kafka")]
            event_producer: None,
        }
    }

    /// Create a new meta-role service with event producer.
    #[cfg(feature = "kafka")]
    pub fn with_event_producer(pool: PgPool, event_producer: Arc<EventProducer>) -> Self {
        Self {
            pool,
            event_producer: Some(event_producer),
        }
    }

    /// Set the event producer for publishing events.
    #[cfg(feature = "kafka")]
    pub fn set_event_producer(&mut self, producer: Arc<EventProducer>) {
        self.event_producer = Some(producer);
    }

    // =========================================================================
    // Meta-role CRUD operations
    // =========================================================================

    /// Get a meta-role by ID.
    pub async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<GovMetaRole> {
        GovMetaRole::find_by_id(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::MetaRoleNotFound(id))
    }

    /// List meta-roles with filtering and pagination.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        filter: &MetaRoleFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovMetaRole>, i64)> {
        let items = GovMetaRole::list_by_tenant(&self.pool, tenant_id, filter, limit, offset)
            .await
            .map_err(GovernanceError::Database)?;

        let total = GovMetaRole::count_by_tenant(&self.pool, tenant_id, filter)
            .await
            .map_err(GovernanceError::Database)?;

        Ok((items, total))
    }

    /// List all active meta-roles ordered by priority.
    pub async fn list_active(&self, tenant_id: Uuid) -> Result<Vec<GovMetaRole>> {
        GovMetaRole::list_active(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Create a new meta-role with criteria.
    pub async fn create(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        input: CreateGovMetaRole,
        criteria: Vec<CreateGovMetaRoleCriteria>,
    ) -> Result<GovMetaRole> {
        // Validate name uniqueness
        if let Some(_existing) =
            GovMetaRole::find_by_name(&self.pool, tenant_id, &input.name).await?
        {
            return Err(GovernanceError::MetaRoleNameExists(input.name));
        }

        // Validate criteria fields
        for criterion in &criteria {
            self.validate_criteria(&criterion.field, &criterion.operator, &criterion.value)?;
        }

        // Create meta-role
        let meta_role = GovMetaRole::create(&self.pool, tenant_id, actor_id, input)
            .await
            .map_err(GovernanceError::Database)?;

        // Create criteria
        for criterion in criteria {
            GovMetaRoleCriteria::create(&self.pool, tenant_id, meta_role.id, criterion)
                .await
                .map_err(GovernanceError::Database)?;
        }

        // Record audit event
        let meta_role_json = serde_json::to_value(&meta_role).unwrap_or_default();
        GovMetaRoleEvent::record_created(
            &self.pool,
            tenant_id,
            meta_role.id,
            actor_id,
            meta_role_json,
        )
        .await
        .map_err(GovernanceError::Database)?;

        info!(
            tenant_id = %tenant_id,
            meta_role_id = %meta_role.id,
            meta_role_name = %meta_role.name,
            actor_id = %actor_id,
            "Meta-role created"
        );

        Ok(meta_role)
    }

    /// Update a meta-role.
    pub async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        actor_id: Uuid,
        input: UpdateGovMetaRole,
    ) -> Result<GovMetaRole> {
        let before = self.get(tenant_id, id).await?;

        // Check name uniqueness if name is being changed
        if let Some(ref new_name) = input.name {
            if new_name != &before.name {
                if let Some(_existing) =
                    GovMetaRole::find_by_name(&self.pool, tenant_id, new_name).await?
                {
                    return Err(GovernanceError::MetaRoleNameExists(new_name.clone()));
                }
            }
        }

        let after = GovMetaRole::update(&self.pool, tenant_id, id, input)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::MetaRoleNotFound(id))?;

        // Record audit event
        let before_json = serde_json::to_value(&before).unwrap_or_default();
        let after_json = serde_json::to_value(&after).unwrap_or_default();
        GovMetaRoleEvent::record_updated(
            &self.pool,
            tenant_id,
            id,
            actor_id,
            before_json,
            after_json,
        )
        .await
        .map_err(GovernanceError::Database)?;

        info!(
            tenant_id = %tenant_id,
            meta_role_id = %id,
            actor_id = %actor_id,
            "Meta-role updated"
        );

        Ok(after)
    }

    /// Disable a meta-role.
    pub async fn disable(&self, tenant_id: Uuid, id: Uuid, actor_id: Uuid) -> Result<GovMetaRole> {
        let meta_role = self.get(tenant_id, id).await?;

        if meta_role.status == MetaRoleStatus::Disabled {
            return Err(GovernanceError::MetaRoleAlreadyDisabled(id));
        }

        let disabled = GovMetaRole::disable(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::MetaRoleNotFound(id))?;

        // Suspend all inheritances
        let suspended_count =
            GovMetaRoleInheritance::suspend_by_meta_role(&self.pool, tenant_id, id)
                .await
                .map_err(GovernanceError::Database)?;

        // Record audit event
        GovMetaRoleEvent::create(
            &self.pool,
            tenant_id,
            CreateGovMetaRoleEvent {
                meta_role_id: Some(id),
                event_type: MetaRoleEventType::Disabled,
                actor_id: Some(actor_id),
                changes: None,
                affected_roles: None,
                metadata: Some(serde_json::json!({ "suspended_inheritances": suspended_count })),
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        info!(
            tenant_id = %tenant_id,
            meta_role_id = %id,
            actor_id = %actor_id,
            suspended_count = suspended_count,
            "Meta-role disabled"
        );

        Ok(disabled)
    }

    /// Enable a meta-role.
    pub async fn enable(&self, tenant_id: Uuid, id: Uuid, actor_id: Uuid) -> Result<GovMetaRole> {
        let meta_role = self.get(tenant_id, id).await?;

        if meta_role.status == MetaRoleStatus::Active {
            return Err(GovernanceError::MetaRoleAlreadyActive(id));
        }

        let enabled = GovMetaRole::enable(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::MetaRoleNotFound(id))?;

        // Reactivate suspended inheritances
        let reactivated_count =
            GovMetaRoleInheritance::reactivate_by_meta_role(&self.pool, tenant_id, id)
                .await
                .map_err(GovernanceError::Database)?;

        // Record audit event
        GovMetaRoleEvent::create(
            &self.pool,
            tenant_id,
            CreateGovMetaRoleEvent {
                meta_role_id: Some(id),
                event_type: MetaRoleEventType::Enabled,
                actor_id: Some(actor_id),
                changes: None,
                affected_roles: None,
                metadata: Some(
                    serde_json::json!({ "reactivated_inheritances": reactivated_count }),
                ),
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        info!(
            tenant_id = %tenant_id,
            meta_role_id = %id,
            actor_id = %actor_id,
            reactivated_count = reactivated_count,
            "Meta-role enabled"
        );

        Ok(enabled)
    }

    /// Delete a meta-role.
    pub async fn delete(&self, tenant_id: Uuid, id: Uuid, actor_id: Uuid) -> Result<()> {
        let meta_role = self.get(tenant_id, id).await?;

        // Check for active inheritances
        let active_count =
            GovMetaRoleInheritance::count_active_by_meta_role(&self.pool, tenant_id, id)
                .await
                .map_err(GovernanceError::Database)?;

        if active_count > 0 {
            return Err(GovernanceError::MetaRoleHasActiveInheritances(active_count));
        }

        // Get affected role IDs for audit
        let inheritances =
            GovMetaRoleInheritance::list_by_meta_role(&self.pool, tenant_id, id, None, 1000, 0)
                .await
                .map_err(GovernanceError::Database)?;
        let affected_role_ids: Vec<Uuid> = inheritances.iter().map(|i| i.child_role_id).collect();

        // Delete related data
        GovMetaRoleCriteria::delete_by_meta_role(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?;
        GovMetaRoleEntitlement::delete_by_meta_role(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?;
        GovMetaRoleConstraint::delete_by_meta_role(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?;

        // Record audit event before deletion
        let meta_role_json = serde_json::to_value(&meta_role).unwrap_or_default();
        GovMetaRoleEvent::record_deleted(
            &self.pool,
            tenant_id,
            id,
            actor_id,
            meta_role_json,
            affected_role_ids,
        )
        .await
        .map_err(GovernanceError::Database)?;

        // Delete meta-role
        let deleted = GovMetaRole::delete(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?;

        if !deleted {
            return Err(GovernanceError::MetaRoleNotFound(id));
        }

        info!(
            tenant_id = %tenant_id,
            meta_role_id = %id,
            actor_id = %actor_id,
            "Meta-role deleted"
        );

        Ok(())
    }

    // =========================================================================
    // Criteria operations
    // =========================================================================

    /// List criteria for a meta-role.
    pub async fn list_criteria(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
    ) -> Result<Vec<GovMetaRoleCriteria>> {
        // Verify meta-role exists
        self.get(tenant_id, meta_role_id).await?;

        GovMetaRoleCriteria::list_by_meta_role(&self.pool, tenant_id, meta_role_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Add a criterion to a meta-role.
    pub async fn add_criterion(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        input: CreateGovMetaRoleCriteria,
    ) -> Result<GovMetaRoleCriteria> {
        // Verify meta-role exists
        self.get(tenant_id, meta_role_id).await?;

        // Validate criterion
        self.validate_criteria(&input.field, &input.operator, &input.value)?;

        GovMetaRoleCriteria::create(&self.pool, tenant_id, meta_role_id, input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Remove a criterion from a meta-role.
    pub async fn remove_criterion(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        criterion_id: Uuid,
    ) -> Result<()> {
        // Verify meta-role exists
        self.get(tenant_id, meta_role_id).await?;

        let deleted = GovMetaRoleCriteria::delete(&self.pool, tenant_id, criterion_id)
            .await
            .map_err(GovernanceError::Database)?;

        if !deleted {
            return Err(GovernanceError::MetaRoleCriteriaNotFound(criterion_id));
        }

        Ok(())
    }

    /// Validate a criterion field, operator, and value combination.
    fn validate_criteria(
        &self,
        field: &str,
        operator: &xavyo_db::CriteriaOperator,
        value: &serde_json::Value,
    ) -> Result<()> {
        // Check field is supported
        if !SUPPORTED_CRITERIA_FIELDS.contains(&field) {
            return Err(GovernanceError::InvalidMetaRoleCriteriaField(
                field.to_string(),
            ));
        }

        // Validate operator-value compatibility
        if operator.requires_list() && !value.is_array() {
            return Err(GovernanceError::InvalidMetaRoleCriteriaValue {
                field: field.to_string(),
                operator: format!("{operator:?}"),
                reason: "Operator requires array value".to_string(),
            });
        }

        if operator.is_numeric() && !value.is_number() {
            return Err(GovernanceError::InvalidMetaRoleCriteriaValue {
                field: field.to_string(),
                operator: format!("{operator:?}"),
                reason: "Operator requires numeric value".to_string(),
            });
        }

        if operator.is_string_match() && !value.is_string() {
            return Err(GovernanceError::InvalidMetaRoleCriteriaValue {
                field: field.to_string(),
                operator: format!("{operator:?}"),
                reason: "Operator requires string value".to_string(),
            });
        }

        Ok(())
    }

    // =========================================================================
    // Entitlement operations
    // =========================================================================

    /// List entitlements for a meta-role.
    pub async fn list_entitlements(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
    ) -> Result<Vec<GovMetaRoleEntitlement>> {
        // Verify meta-role exists
        self.get(tenant_id, meta_role_id).await?;

        GovMetaRoleEntitlement::list_by_meta_role(&self.pool, tenant_id, meta_role_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Add an entitlement to a meta-role.
    pub async fn add_entitlement(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        input: CreateGovMetaRoleEntitlement,
    ) -> Result<GovMetaRoleEntitlement> {
        // Verify meta-role exists
        self.get(tenant_id, meta_role_id).await?;

        // Check if already exists
        if let Some(_existing) = GovMetaRoleEntitlement::find_by_meta_role_and_entitlement(
            &self.pool,
            tenant_id,
            meta_role_id,
            input.entitlement_id,
        )
        .await
        .map_err(GovernanceError::Database)?
        {
            return Err(GovernanceError::MetaRoleEntitlementAlreadyExists);
        }

        GovMetaRoleEntitlement::create(&self.pool, tenant_id, meta_role_id, input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Remove an entitlement from a meta-role.
    pub async fn remove_entitlement(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        entitlement_id: Uuid,
    ) -> Result<()> {
        // Verify meta-role exists
        self.get(tenant_id, meta_role_id).await?;

        let deleted = GovMetaRoleEntitlement::delete(&self.pool, tenant_id, entitlement_id)
            .await
            .map_err(GovernanceError::Database)?;

        if !deleted {
            return Err(GovernanceError::MetaRoleEntitlementNotFound(entitlement_id));
        }

        Ok(())
    }

    // =========================================================================
    // Constraint operations
    // =========================================================================

    /// List constraints for a meta-role.
    pub async fn list_constraints(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
    ) -> Result<Vec<GovMetaRoleConstraint>> {
        // Verify meta-role exists
        self.get(tenant_id, meta_role_id).await?;

        GovMetaRoleConstraint::list_by_meta_role(&self.pool, tenant_id, meta_role_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Add a constraint to a meta-role.
    pub async fn add_constraint(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        input: CreateGovMetaRoleConstraint,
    ) -> Result<GovMetaRoleConstraint> {
        // Verify meta-role exists
        self.get(tenant_id, meta_role_id).await?;

        // Validate constraint type
        if !SUPPORTED_CONSTRAINT_TYPES.contains(&input.constraint_type.as_str()) {
            return Err(GovernanceError::InvalidMetaRoleConstraintType(
                input.constraint_type.clone(),
            ));
        }

        // Check if already exists
        if let Some(_existing) = GovMetaRoleConstraint::find_by_meta_role_and_type(
            &self.pool,
            tenant_id,
            meta_role_id,
            &input.constraint_type,
        )
        .await
        .map_err(GovernanceError::Database)?
        {
            return Err(GovernanceError::MetaRoleConstraintAlreadyExists(
                input.constraint_type,
            ));
        }

        GovMetaRoleConstraint::create(&self.pool, tenant_id, meta_role_id, input)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Update a constraint value.
    pub async fn update_constraint(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        constraint_id: Uuid,
        constraint_value: serde_json::Value,
    ) -> Result<GovMetaRoleConstraint> {
        // Verify meta-role exists
        self.get(tenant_id, meta_role_id).await?;

        GovMetaRoleConstraint::update_value(&self.pool, tenant_id, constraint_id, constraint_value)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::MetaRoleConstraintNotFound(constraint_id))
    }

    /// Remove a constraint from a meta-role.
    pub async fn remove_constraint(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        constraint_id: Uuid,
    ) -> Result<()> {
        // Verify meta-role exists
        self.get(tenant_id, meta_role_id).await?;

        let deleted = GovMetaRoleConstraint::delete(&self.pool, tenant_id, constraint_id)
            .await
            .map_err(GovernanceError::Database)?;

        if !deleted {
            return Err(GovernanceError::MetaRoleConstraintNotFound(constraint_id));
        }

        Ok(())
    }

    // =========================================================================
    // Audit trail
    // =========================================================================

    /// Get event statistics for a tenant.
    pub async fn get_event_stats(&self, tenant_id: Uuid) -> Result<MetaRoleEventStats> {
        GovMetaRoleEvent::get_stats(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)
    }

    /// List events for a meta-role.
    pub async fn list_events(
        &self,
        tenant_id: Uuid,
        meta_role_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<GovMetaRoleEvent>> {
        GovMetaRoleEvent::list_by_meta_role(&self.pool, tenant_id, meta_role_id, limit, offset)
            .await
            .map_err(GovernanceError::Database)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xavyo_db::CriteriaLogic;

    #[test]
    fn test_criteria_validation() {
        // Test valid fields (without needing a service instance)
        assert!(SUPPORTED_CRITERIA_FIELDS.contains(&"risk_level"));
        assert!(SUPPORTED_CRITERIA_FIELDS.contains(&"application_id"));
        assert!(SUPPORTED_CRITERIA_FIELDS.contains(&"owner_id"));
        assert!(SUPPORTED_CRITERIA_FIELDS.contains(&"status"));
        assert!(SUPPORTED_CRITERIA_FIELDS.contains(&"name"));
        assert!(SUPPORTED_CRITERIA_FIELDS.contains(&"is_delegable"));
        assert!(SUPPORTED_CRITERIA_FIELDS.contains(&"metadata"));

        // Test invalid field detection would work
        assert!(!SUPPORTED_CRITERIA_FIELDS.contains(&"invalid_field"));
    }

    #[test]
    fn test_constraint_type_validation() {
        assert!(SUPPORTED_CONSTRAINT_TYPES.contains(&"max_session_duration"));
        assert!(SUPPORTED_CONSTRAINT_TYPES.contains(&"require_mfa"));
        assert!(!SUPPORTED_CONSTRAINT_TYPES.contains(&"invalid_constraint"));
    }

    #[test]
    fn test_all_supported_criteria_fields() {
        // Verify full list of supported criteria fields
        let expected_fields = [
            "risk_level",
            "application_id",
            "owner_id",
            "status",
            "name",
            "is_delegable",
            "metadata",
        ];

        for field in &expected_fields {
            assert!(
                SUPPORTED_CRITERIA_FIELDS.contains(field),
                "Missing field: {}",
                field
            );
        }
    }

    #[test]
    fn test_all_supported_constraint_types() {
        // Verify constraint types are available
        assert!(SUPPORTED_CONSTRAINT_TYPES.contains(&"max_session_duration"));
        assert!(SUPPORTED_CONSTRAINT_TYPES.contains(&"require_mfa"));
        assert!(SUPPORTED_CONSTRAINT_TYPES.contains(&"ip_whitelist"));
        assert!(SUPPORTED_CONSTRAINT_TYPES.contains(&"approval_required"));
        // Verify total count
        assert_eq!(SUPPORTED_CONSTRAINT_TYPES.len(), 4);
    }

    #[test]
    fn test_meta_role_status_values() {
        // Verify all meta-role statuses
        let statuses = [MetaRoleStatus::Active, MetaRoleStatus::Disabled];

        assert_eq!(statuses.len(), 2);
        assert_ne!(MetaRoleStatus::Active, MetaRoleStatus::Disabled);
    }

    #[test]
    fn test_meta_role_event_types() {
        // Verify all event types for audit trail
        let event_types = [
            MetaRoleEventType::Created,
            MetaRoleEventType::Updated,
            MetaRoleEventType::Deleted,
            MetaRoleEventType::Disabled,
            MetaRoleEventType::Enabled,
            MetaRoleEventType::InheritanceApplied,
            MetaRoleEventType::InheritanceRemoved,
            MetaRoleEventType::ConflictDetected,
            MetaRoleEventType::ConflictResolved,
            MetaRoleEventType::CascadeStarted,
            MetaRoleEventType::CascadeCompleted,
            MetaRoleEventType::CascadeFailed,
        ];

        assert_eq!(event_types.len(), 12);
    }

    #[test]
    fn test_meta_role_filter_default() {
        let filter = MetaRoleFilter::default();

        // Default filter should have no restrictions
        assert!(filter.status.is_none());
        assert!(filter.name_contains.is_none());
        assert!(filter.priority_min.is_none());
        assert!(filter.priority_max.is_none());
    }

    #[test]
    fn test_criteria_logic_default() {
        // Default criteria logic should be AND
        assert_eq!(CriteriaLogic::default(), CriteriaLogic::And);
    }

    #[test]
    fn test_create_gov_meta_role_structure() {
        let create = CreateGovMetaRole {
            name: "High Risk Policy".to_string(),
            description: Some("Policy for high-risk roles".to_string()),
            priority: Some(10),
            criteria_logic: Some(CriteriaLogic::And),
        };

        assert_eq!(create.name, "High Risk Policy");
        assert_eq!(create.priority, Some(10));
        assert_eq!(create.criteria_logic, Some(CriteriaLogic::And));
    }

    #[test]
    fn test_update_gov_meta_role_partial() {
        let update = UpdateGovMetaRole {
            name: Some("Updated Name".to_string()),
            description: None,
            priority: Some(5),
            criteria_logic: None,
        };

        assert!(update.name.is_some());
        assert!(update.description.is_none());
        assert!(update.priority.is_some());
        assert!(update.criteria_logic.is_none());
    }

    #[test]
    fn test_meta_role_event_stats_structure() {
        let stats = MetaRoleEventStats {
            total: 100,
            created: 10,
            updated: 20,
            deleted: 5,
            disabled: 3,
            enabled: 2,
            inheritance_applied: 30,
            inheritance_removed: 10,
            conflict_detected: 5,
            conflict_resolved: 4,
            cascade_started: 8,
            cascade_completed: 7,
            cascade_failed: 1,
        };

        assert_eq!(stats.total, 100);
        assert_eq!(stats.created, 10);
        assert_eq!(stats.cascade_failed, 1);
    }

    #[test]
    fn test_priority_ordering() {
        // Lower priority number = higher precedence
        let high_priority = 1;
        let medium_priority = 50;
        let low_priority = 100;

        assert!(high_priority < medium_priority);
        assert!(medium_priority < low_priority);
    }

    #[test]
    fn test_meta_role_filter_with_status() {
        let filter = MetaRoleFilter {
            status: Some(MetaRoleStatus::Active),
            name_contains: None,
            priority_min: None,
            priority_max: None,
        };

        assert_eq!(filter.status, Some(MetaRoleStatus::Active));
    }

    #[test]
    fn test_meta_role_filter_with_name_search() {
        let filter = MetaRoleFilter {
            status: None,
            name_contains: Some("finance".to_string()),
            priority_min: None,
            priority_max: None,
        };

        assert_eq!(filter.name_contains.as_deref(), Some("finance"));
    }

    #[test]
    fn test_meta_role_filter_with_priority_range() {
        let filter = MetaRoleFilter {
            status: None,
            name_contains: None,
            priority_min: Some(1),
            priority_max: Some(50),
        };

        assert_eq!(filter.priority_min, Some(1));
        assert_eq!(filter.priority_max, Some(50));
    }
}
