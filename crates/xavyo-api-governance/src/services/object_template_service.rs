//! Object template service for governance API (F058).
//!
//! Handles object template CRUD operations, status management, inheritance,
//! versioning, and audit trail.

use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use xavyo_db::models::{
    CreateGovObjectTemplate, CreateGovTemplateEvent, GovObjectTemplate, GovTemplateMergePolicy,
    GovTemplateRule, GovTemplateScope, GovTemplateVersion, ObjectTemplateFilter,
    ObjectTemplateStatus, TemplateEventType, TemplateObjectType, UpdateGovObjectTemplate,
};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for object template operations.
pub struct ObjectTemplateService {
    pool: PgPool,
}

impl ObjectTemplateService {
    /// Create a new object template service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // =========================================================================
    // Object Template CRUD operations
    // =========================================================================

    /// Get an object template by ID.
    pub async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<GovObjectTemplate> {
        GovObjectTemplate::find_by_id(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::ObjectTemplateNotFound(id))
    }

    /// Get a template with all its details (rules, scopes, merge policies, parent).
    pub async fn get_detail(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<(
        GovObjectTemplate,
        Vec<GovTemplateRule>,
        Vec<GovTemplateScope>,
        Vec<GovTemplateMergePolicy>,
        Option<GovObjectTemplate>,
        Option<i32>,
    )> {
        let template = self.get(tenant_id, id).await?;

        let rules = GovTemplateRule::list_by_template(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?;

        let scopes = GovTemplateScope::list_by_template(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?;

        let merge_policies = GovTemplateMergePolicy::list_by_template(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?;

        // Load parent if exists
        let parent = if let Some(parent_id) = template.parent_template_id {
            GovObjectTemplate::find_by_id(&self.pool, tenant_id, parent_id)
                .await
                .map_err(GovernanceError::Database)?
        } else {
            None
        };

        // Get current version number
        let current_version = GovTemplateVersion::find_latest(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .map(|v| v.version_number);

        Ok((
            template,
            rules,
            scopes,
            merge_policies,
            parent,
            current_version,
        ))
    }

    /// List object templates with filtering and pagination.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        filter: &ObjectTemplateFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovObjectTemplate>, i64)> {
        let items = GovObjectTemplate::list_by_tenant(&self.pool, tenant_id, filter, limit, offset)
            .await
            .map_err(GovernanceError::Database)?;

        let total = GovObjectTemplate::count_by_tenant(&self.pool, tenant_id, filter)
            .await
            .map_err(GovernanceError::Database)?;

        Ok((items, total))
    }

    /// List active templates for a given object type ordered by priority.
    pub async fn list_active_for_type(
        &self,
        tenant_id: Uuid,
        object_type: TemplateObjectType,
    ) -> Result<Vec<GovObjectTemplate>> {
        GovObjectTemplate::list_active_by_type(&self.pool, tenant_id, object_type)
            .await
            .map_err(GovernanceError::Database)
    }

    /// Create a new object template.
    pub async fn create(
        &self,
        tenant_id: Uuid,
        actor_id: Uuid,
        input: CreateGovObjectTemplate,
    ) -> Result<GovObjectTemplate> {
        // Validate name uniqueness within tenant
        if let Some(_existing) =
            GovObjectTemplate::find_by_name(&self.pool, tenant_id, &input.name).await?
        {
            return Err(GovernanceError::ObjectTemplateNameExists(input.name));
        }

        // Validate parent template if specified
        if let Some(parent_id) = input.parent_template_id {
            let parent = GovObjectTemplate::find_by_id(&self.pool, tenant_id, parent_id)
                .await
                .map_err(GovernanceError::Database)?
                .ok_or_else(|| GovernanceError::ObjectTemplateParentNotFound(parent_id))?;

            // Parent must be same object type
            if parent.object_type != input.object_type {
                return Err(GovernanceError::ObjectTemplateParentTypeMismatch);
            }
        }

        // Create template
        let template = GovObjectTemplate::create(&self.pool, tenant_id, actor_id, input)
            .await
            .map_err(GovernanceError::Database)?;

        // Record audit event
        self.record_event(
            tenant_id,
            template.id,
            TemplateEventType::Created,
            Some(actor_id),
            Some(serde_json::to_value(&template).unwrap_or_default()),
        )
        .await?;

        info!(
            tenant_id = %tenant_id,
            template_id = %template.id,
            template_name = %template.name,
            actor_id = %actor_id,
            "Object template created"
        );

        Ok(template)
    }

    /// Update an object template.
    pub async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        actor_id: Uuid,
        input: UpdateGovObjectTemplate,
    ) -> Result<GovObjectTemplate> {
        let before = self.get(tenant_id, id).await?;

        // Check name uniqueness if name is being changed
        if let Some(ref new_name) = input.name {
            if new_name != &before.name {
                if let Some(_existing) =
                    GovObjectTemplate::find_by_name(&self.pool, tenant_id, new_name).await?
                {
                    return Err(GovernanceError::ObjectTemplateNameExists(new_name.clone()));
                }
            }
        }

        let after = GovObjectTemplate::update(&self.pool, tenant_id, id, input)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::ObjectTemplateNotFound(id))?;

        // Record audit event
        let changes = serde_json::json!({
            "before": before,
            "after": after
        });
        self.record_event(
            tenant_id,
            id,
            TemplateEventType::Updated,
            Some(actor_id),
            Some(changes),
        )
        .await?;

        info!(
            tenant_id = %tenant_id,
            template_id = %id,
            actor_id = %actor_id,
            "Object template updated"
        );

        Ok(after)
    }

    /// Activate an object template (draft -> active).
    pub async fn activate(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        actor_id: Uuid,
    ) -> Result<GovObjectTemplate> {
        let template = self.get(tenant_id, id).await?;

        // Must be in draft status
        if template.status != ObjectTemplateStatus::Draft {
            return Err(GovernanceError::ObjectTemplateNotDraft(id));
        }

        // Template must have at least one scope
        let scopes = GovTemplateScope::list_by_template(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?;

        if scopes.is_empty() {
            return Err(GovernanceError::ObjectTemplateNoScopes);
        }

        // Activate
        let activated = GovObjectTemplate::activate(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::ObjectTemplateNotFound(id))?;

        // Create a version snapshot
        self.create_version(tenant_id, id, actor_id).await?;

        // Record audit event
        self.record_event(
            tenant_id,
            id,
            TemplateEventType::Activated,
            Some(actor_id),
            None,
        )
        .await?;

        info!(
            tenant_id = %tenant_id,
            template_id = %id,
            actor_id = %actor_id,
            "Object template activated"
        );

        Ok(activated)
    }

    /// Disable an active object template.
    pub async fn disable(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        actor_id: Uuid,
    ) -> Result<GovObjectTemplate> {
        let template = self.get(tenant_id, id).await?;

        // Must be active
        if template.status != ObjectTemplateStatus::Active {
            return Err(GovernanceError::ObjectTemplateNotActive(id));
        }

        let disabled = GovObjectTemplate::disable(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::ObjectTemplateNotFound(id))?;

        // Record audit event
        self.record_event(
            tenant_id,
            id,
            TemplateEventType::Disabled,
            Some(actor_id),
            None,
        )
        .await?;

        info!(
            tenant_id = %tenant_id,
            template_id = %id,
            actor_id = %actor_id,
            "Object template disabled"
        );

        Ok(disabled)
    }

    /// Delete an object template.
    pub async fn delete(&self, tenant_id: Uuid, id: Uuid, actor_id: Uuid) -> Result<()> {
        let template = self.get(tenant_id, id).await?;

        // Check for child templates
        let children = GovObjectTemplate::find_children(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?;

        if !children.is_empty() {
            // Don't allow deletion if there are active child templates
            let active_children: Vec<_> = children
                .iter()
                .filter(|c| c.status == ObjectTemplateStatus::Active)
                .collect();

            if !active_children.is_empty() {
                return Err(GovernanceError::ObjectTemplateHasActiveChildren(
                    active_children.len(),
                ));
            }
        }

        // Delete related data
        GovTemplateRule::delete_by_template(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?;

        GovTemplateScope::delete_by_template(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?;

        GovTemplateMergePolicy::delete_by_template(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?;

        // Record audit event before deletion
        let template_json = serde_json::to_value(&template).unwrap_or_default();
        self.record_event(
            tenant_id,
            id,
            TemplateEventType::Deleted,
            Some(actor_id),
            Some(template_json),
        )
        .await?;

        // Delete template
        let deleted = GovObjectTemplate::delete(&self.pool, tenant_id, id)
            .await
            .map_err(GovernanceError::Database)?;

        if !deleted {
            return Err(GovernanceError::ObjectTemplateNotFound(id));
        }

        info!(
            tenant_id = %tenant_id,
            template_id = %id,
            actor_id = %actor_id,
            "Object template deleted"
        );

        Ok(())
    }

    // =========================================================================
    // Template Versioning
    // =========================================================================

    /// Create a new version snapshot of the template.
    pub async fn create_version(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        actor_id: Uuid,
    ) -> Result<GovTemplateVersion> {
        // Get current rules and scopes
        let rules = GovTemplateRule::list_by_template(&self.pool, tenant_id, template_id)
            .await
            .map_err(GovernanceError::Database)?;

        let scopes = GovTemplateScope::list_by_template(&self.pool, tenant_id, template_id)
            .await
            .map_err(GovernanceError::Database)?;

        let rules_snapshot = serde_json::to_value(&rules).unwrap_or_default();
        let scopes_snapshot = serde_json::to_value(&scopes).unwrap_or_default();

        let version = GovTemplateVersion::create_next_version(
            &self.pool,
            tenant_id,
            template_id,
            actor_id,
            rules_snapshot,
            scopes_snapshot,
        )
        .await
        .map_err(GovernanceError::Database)?;

        // Record audit event
        self.record_event(
            tenant_id,
            template_id,
            TemplateEventType::VersionCreated,
            Some(actor_id),
            Some(serde_json::json!({ "version_number": version.version_number })),
        )
        .await?;

        info!(
            tenant_id = %tenant_id,
            template_id = %template_id,
            version_number = version.version_number,
            "Template version created"
        );

        Ok(version)
    }

    /// List versions for a template.
    pub async fn list_versions(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovTemplateVersion>, i64)> {
        // Verify template exists
        self.get(tenant_id, template_id).await?;

        let items = GovTemplateVersion::list_by_template_paginated(
            &self.pool,
            tenant_id,
            template_id,
            limit,
            offset,
        )
        .await
        .map_err(GovernanceError::Database)?;

        let total = GovTemplateVersion::count_by_template(&self.pool, tenant_id, template_id)
            .await
            .map_err(GovernanceError::Database)?;

        Ok((items, total))
    }

    /// Get a specific version by ID.
    pub async fn get_version(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        version_id: Uuid,
    ) -> Result<GovTemplateVersion> {
        // Verify template exists
        self.get(tenant_id, template_id).await?;

        GovTemplateVersion::find_by_id(&self.pool, tenant_id, version_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::TemplateVersionNotFound(version_id))
    }

    // =========================================================================
    // Inheritance
    // =========================================================================

    /// Get the inheritance chain for a template (from child to root).
    pub async fn get_inheritance_chain(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<Vec<GovObjectTemplate>> {
        let mut chain = Vec::new();
        let mut current_id = Some(template_id);
        let mut visited = std::collections::HashSet::new();

        while let Some(id) = current_id {
            // Circular inheritance check
            if visited.contains(&id) {
                return Err(GovernanceError::ObjectTemplateCircularInheritance);
            }
            visited.insert(id);

            let template = self.get(tenant_id, id).await?;
            current_id = template.parent_template_id;
            chain.push(template);
        }

        Ok(chain)
    }

    /// Get all rules for a template including inherited rules.
    pub async fn get_effective_rules(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
    ) -> Result<Vec<GovTemplateRule>> {
        let chain = self.get_inheritance_chain(tenant_id, template_id).await?;

        // Collect rules from root to child (parent rules first, child can override)
        let mut all_rules = Vec::new();

        // Reverse to start from root
        for template in chain.into_iter().rev() {
            let rules = GovTemplateRule::list_by_template(&self.pool, tenant_id, template.id)
                .await
                .map_err(GovernanceError::Database)?;

            for rule in rules {
                // Remove any existing rule with same target_attribute (child overrides parent)
                all_rules.retain(|r: &GovTemplateRule| {
                    r.target_attribute != rule.target_attribute || r.rule_type != rule.rule_type
                });
                all_rules.push(rule);
            }
        }

        // Sort by priority
        all_rules.sort_by_key(|r| r.priority);

        Ok(all_rules)
    }

    // =========================================================================
    // Audit Trail
    // =========================================================================

    /// Record a template event.
    async fn record_event(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        event_type: TemplateEventType,
        actor_id: Option<Uuid>,
        changes: Option<serde_json::Value>,
    ) -> Result<()> {
        use xavyo_db::models::GovTemplateEvent;

        GovTemplateEvent::create(
            &self.pool,
            tenant_id,
            CreateGovTemplateEvent {
                template_id: Some(template_id),
                event_type,
                actor_id,
                changes,
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        Ok(())
    }

    /// List events for a template.
    pub async fn list_events(
        &self,
        tenant_id: Uuid,
        template_id: Uuid,
        event_type: Option<TemplateEventType>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<xavyo_db::models::GovTemplateEvent>, i64)> {
        use xavyo_db::models::{GovTemplateEvent, TemplateChangeEventFilter};

        // Verify template exists
        self.get(tenant_id, template_id).await?;

        let filter = TemplateChangeEventFilter {
            template_id: Some(template_id),
            event_type,
            actor_id: None,
            from_date: None,
            to_date: None,
        };

        let items =
            GovTemplateEvent::list_with_filter(&self.pool, tenant_id, &filter, limit, offset)
                .await
                .map_err(GovernanceError::Database)?;

        let total = GovTemplateEvent::count_by_template(&self.pool, tenant_id, template_id)
            .await
            .map_err(GovernanceError::Database)?;

        Ok((items, total))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_construction() {
        // Just verify the struct and impl are correctly defined
        // Database tests would require a test database
        let _ = std::mem::size_of::<ObjectTemplateService>();
    }
}
