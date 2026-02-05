//! Persona service for governance API (F063).
//!
//! Handles persona lifecycle management including creation from archetypes,
//! attribute inheritance, name generation, and status transitions.
//!
//! Implements IGA-compatible edge case handling:
//! - Authorization checks for persona creation (execution-phase)
//! - Archetype conflict detection
//! - Approval workflow compatibility validation

use chrono::{Duration, Utc};
use handlebars::Handlebars;
use serde_json::json;
use sqlx::PgPool;
use std::collections::HashMap;
use tracing::{info, warn};
use uuid::Uuid;

use xavyo_db::models::{
    CreatePersona, CreatePersonaLink, GovPersona, GovPersonaArchetype, GovPersonaLink,
    PersonaAttributes, PersonaFilter, PersonaLinkType, PersonaStatus, UpdatePersona, User,
};
use xavyo_governance::error::{GovernanceError, Result};

use super::persona_authorization_service::PersonaAuthorizationService;
use super::persona_validation_service::PersonaValidationService;
use super::PersonaArchetypeService;

/// Service for persona operations.
pub struct PersonaService {
    pool: PgPool,
    archetype_service: PersonaArchetypeService,
    authorization_service: PersonaAuthorizationService,
    validation_service: PersonaValidationService,
    #[allow(dead_code)] // Reserved for template rendering
    handlebars: Handlebars<'static>,
}

impl PersonaService {
    /// Create a new persona service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        let handlebars = Handlebars::new();
        Self {
            archetype_service: PersonaArchetypeService::new(pool.clone()),
            authorization_service: PersonaAuthorizationService::new(pool.clone()),
            validation_service: PersonaValidationService::new(pool.clone()),
            pool,
            handlebars,
        }
    }

    /// Get reference to authorization service.
    #[must_use]
    pub fn authorization_service(&self) -> &PersonaAuthorizationService {
        &self.authorization_service
    }

    /// Get reference to validation service.
    #[must_use]
    pub fn validation_service(&self) -> &PersonaValidationService {
        &self.validation_service
    }

    // =========================================================================
    // T017: Core persona operations
    // =========================================================================

    /// Create a new persona from an archetype for a physical user.
    ///
    /// Steps (IGA-compatible with edge case handling):
    /// 1. Validate archetype exists and is active
    /// 2. Validate physical user exists
    /// 3. **Authorization check** (IGA execution-phase)
    /// 4. **Archetype conflict check** (IGA construction merging)
    /// 5. **Approval workflow compatibility check**
    /// 6. Check for duplicate (one persona per archetype per user)
    /// 7. Generate persona name from archetype naming pattern
    /// 8. Compute initial attributes (inherited + computed)
    /// 9. Create persona in draft status
    /// 10. Create owner link to physical user
    pub async fn create(
        &self,
        tenant_id: Uuid,
        archetype_id: Uuid,
        physical_user_id: Uuid,
        attribute_overrides: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<GovPersona> {
        self.create_with_actor(
            tenant_id,
            archetype_id,
            physical_user_id,
            physical_user_id,
            attribute_overrides,
        )
        .await
    }

    /// Create a new persona with explicit actor (for admin operations).
    ///
    /// This method allows specifying the actor performing the operation,
    /// enabling proper authorization checks for admin-initiated persona creation.
    pub async fn create_with_actor(
        &self,
        tenant_id: Uuid,
        archetype_id: Uuid,
        physical_user_id: Uuid,
        actor_id: Uuid,
        attribute_overrides: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<GovPersona> {
        // 1. Get and validate archetype
        let archetype = self.archetype_service.get(tenant_id, archetype_id).await?;
        if !archetype.is_active {
            return Err(GovernanceError::PersonaArchetypeNotActive(archetype_id));
        }

        // 2. Validate physical user exists (include tenant_id for defense-in-depth)
        let user = User::find_by_id_in_tenant(&self.pool, tenant_id, physical_user_id)
            .await?
            .ok_or(GovernanceError::UserNotFound(physical_user_id))?;

        // 3. Authorization check (IGA execution-phase)
        // "Assignment of a new persona means that a new user needs to be created.
        // The authorization for this operation is evaluated in the usual way."
        let auth_result = self
            .authorization_service
            .can_create_persona(tenant_id, actor_id, archetype_id, physical_user_id)
            .await?;

        if !auth_result.authorized {
            if auth_result.requires_approval {
                warn!(
                    tenant_id = %tenant_id,
                    actor_id = %actor_id,
                    archetype_id = %archetype_id,
                    "Persona creation would require approval"
                );
                return Err(GovernanceError::PersonaOperationRequiresApproval(
                    auth_result
                        .reason
                        .unwrap_or_else(|| "Approval required".to_string()),
                ));
            }
            warn!(
                tenant_id = %tenant_id,
                actor_id = %actor_id,
                archetype_id = %archetype_id,
                reason = ?auth_result.reason,
                "Persona creation not authorized"
            );
            return Err(GovernanceError::PersonaCreationNotAuthorized);
        }

        // 4. Archetype conflict check (IGA construction merging)
        // "Currently only one persona construction is supported for each persona.
        // IGA cannot currently merge two persona constructions."
        let conflict_result = self
            .validation_service
            .check_archetype_conflicts(tenant_id, physical_user_id, archetype_id)
            .await?;

        if conflict_result.has_conflict {
            warn!(
                tenant_id = %tenant_id,
                physical_user_id = %physical_user_id,
                archetype_id = %archetype_id,
                conflicts = ?conflict_result.conflict_details,
                "Archetype conflict detected"
            );
            return Err(GovernanceError::PersonaArchetypeConflict(archetype_id));
        }

        // 5. Approval workflow compatibility check
        // "The operation that automatically provisions, deprovisions or updates
        // a persona must not be subject to approvals."
        self.validation_service
            .validate_no_approval_conflict(tenant_id, archetype_id)
            .await?;

        // 6. Check for duplicate (T020)
        let existing = GovPersona::find_by_user_and_archetype(
            &self.pool,
            tenant_id,
            physical_user_id,
            archetype_id,
        )
        .await?;
        if existing.is_some() {
            return Err(GovernanceError::PersonaArchetypeDuplicate);
        }

        // 7. Generate persona name (T018)
        let persona_name = self.generate_persona_name(&archetype, &user)?;

        // Check name uniqueness
        let name_exists = GovPersona::find_by_name(&self.pool, tenant_id, &persona_name).await?;
        if name_exists.is_some() {
            return Err(GovernanceError::PersonaNameExists(persona_name));
        }

        // 8. Compute attributes (T019)
        let (attributes, display_name) =
            self.compute_initial_attributes(&archetype, &user, attribute_overrides)?;

        // 9. Calculate validity period from lifecycle policy
        let lifecycle_policy = archetype
            .parse_lifecycle_policy()
            .map_err(|e| GovernanceError::Validation(format!("Invalid lifecycle policy: {e}")))?;

        let valid_from = Utc::now();
        let valid_until =
            valid_from + Duration::days(i64::from(lifecycle_policy.default_validity_days));

        // Create persona
        let input = CreatePersona {
            archetype_id,
            physical_user_id,
            persona_name: persona_name.clone(),
            display_name,
            attributes: serde_json::to_value(&attributes).unwrap_or(json!({})),
            valid_from: Some(valid_from),
            valid_until: Some(valid_until),
        };

        let persona = GovPersona::create(&self.pool, tenant_id, input).await?;

        // 10. Create owner link (T021)
        let link_input = CreatePersonaLink {
            persona_id: persona.id,
            physical_user_id,
            link_type: PersonaLinkType::Owner,
        };
        GovPersonaLink::create(&self.pool, tenant_id, physical_user_id, link_input).await?;

        info!(
            persona_id = %persona.id,
            persona_name = %persona.persona_name,
            archetype_id = %archetype_id,
            physical_user_id = %physical_user_id,
            actor_id = %actor_id,
            "Persona created"
        );

        Ok(persona)
    }

    /// Get a persona by ID.
    pub async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<GovPersona> {
        GovPersona::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(GovernanceError::PersonaNotFound(id))
    }

    /// Update a persona.
    pub async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdatePersona,
    ) -> Result<GovPersona> {
        // Get existing persona
        let existing = self.get(tenant_id, id).await?;

        // Cannot update archived persona
        if existing.status.is_terminal() {
            return Err(GovernanceError::PersonaAlreadyArchived(id));
        }

        // Update persona
        let updated = GovPersona::update(&self.pool, tenant_id, id, input)
            .await?
            .ok_or(GovernanceError::PersonaNotFound(id))?;

        info!(
            persona_id = %updated.id,
            persona_name = %updated.persona_name,
            "Persona updated"
        );

        Ok(updated)
    }

    /// List personas with filtering and pagination.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        filter: &PersonaFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovPersona>, i64)> {
        let items =
            GovPersona::list_by_tenant(&self.pool, tenant_id, filter, limit, offset).await?;
        let total = GovPersona::count_by_tenant(&self.pool, tenant_id, filter).await?;
        Ok((items, total))
    }

    /// Get personas for a physical user.
    pub async fn list_for_user(
        &self,
        tenant_id: Uuid,
        physical_user_id: Uuid,
        include_archived: bool,
    ) -> Result<Vec<GovPersona>> {
        // Validate user exists (include tenant_id for defense-in-depth)
        let _user = User::find_by_id_in_tenant(&self.pool, tenant_id, physical_user_id)
            .await?
            .ok_or(GovernanceError::UserNotFound(physical_user_id))?;

        let personas = GovPersona::find_by_physical_user(
            &self.pool,
            tenant_id,
            physical_user_id,
            include_archived,
        )
        .await?;

        Ok(personas)
    }

    // =========================================================================
    // Persona status transitions
    // =========================================================================

    /// Activate a persona (draft/suspended/expired → active).
    pub async fn activate(&self, tenant_id: Uuid, id: Uuid) -> Result<GovPersona> {
        let persona = self.get(tenant_id, id).await?;

        if !persona.status.can_activate() {
            if persona.status == PersonaStatus::Active {
                return Err(GovernanceError::PersonaAlreadyActive(id));
            }
            if persona.status == PersonaStatus::Archived {
                return Err(GovernanceError::PersonaAlreadyArchived(id));
            }
            return Err(GovernanceError::Validation(format!(
                "Cannot activate persona in status: {:?}",
                persona.status
            )));
        }

        let activated = GovPersona::activate(&self.pool, tenant_id, id)
            .await?
            .ok_or(GovernanceError::PersonaNotFound(id))?;

        info!(
            persona_id = %id,
            persona_name = %activated.persona_name,
            "Persona activated"
        );

        Ok(activated)
    }

    /// Deactivate (suspend) a persona.
    pub async fn deactivate(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        actor_id: Uuid,
        reason: &str,
    ) -> Result<GovPersona> {
        let persona = self.get(tenant_id, id).await?;

        // Validate reason
        if reason.len() < 5 {
            return Err(GovernanceError::Validation(
                "Deactivation reason must be at least 5 characters".to_string(),
            ));
        }

        // Cannot deactivate archived persona
        if persona.status == PersonaStatus::Archived {
            return Err(GovernanceError::PersonaAlreadyArchived(id));
        }

        let deactivated = GovPersona::deactivate(
            &self.pool,
            tenant_id,
            id,
            actor_id,
            Some(reason.to_string()),
        )
        .await?
        .ok_or(GovernanceError::PersonaNotFound(id))?;

        info!(
            persona_id = %id,
            persona_name = %deactivated.persona_name,
            reason = %reason,
            "Persona deactivated"
        );

        Ok(deactivated)
    }

    /// Archive a persona (terminal state).
    pub async fn archive(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        actor_id: Uuid,
        reason: &str,
    ) -> Result<GovPersona> {
        let persona = self.get(tenant_id, id).await?;

        // Already archived
        if persona.status == PersonaStatus::Archived {
            return Err(GovernanceError::PersonaAlreadyArchived(id));
        }

        // Validate reason
        if reason.len() < 5 {
            return Err(GovernanceError::Validation(
                "Archive reason must be at least 5 characters".to_string(),
            ));
        }

        let archived = GovPersona::archive(
            &self.pool,
            tenant_id,
            id,
            actor_id,
            Some(reason.to_string()),
        )
        .await?
        .ok_or(GovernanceError::PersonaNotFound(id))?;

        // Clean up persona links
        GovPersonaLink::delete_by_persona(&self.pool, tenant_id, id).await?;

        info!(
            persona_id = %id,
            persona_name = %archived.persona_name,
            reason = %reason,
            "Persona archived"
        );

        Ok(archived)
    }

    // =========================================================================
    // T018: Persona name generation
    // =========================================================================

    /// Generate persona name from archetype naming pattern.
    fn generate_persona_name(
        &self,
        archetype: &GovPersonaArchetype,
        user: &User,
    ) -> Result<String> {
        let pattern = &archetype.naming_pattern;

        // Build context for template
        let mut context = HashMap::new();

        // Add username (from user's email before @)
        let username = user.email.split('@').next().unwrap_or("user");
        context.insert("username", json!(username));

        // Add user attributes from direct fields
        if let Some(ref given_name) = user.first_name {
            context.insert("given_name", json!(given_name.to_lowercase()));
        }
        if let Some(ref surname) = user.last_name {
            context.insert("surname", json!(surname.to_lowercase()));
        }

        // Simple template replacement (not using handlebars for simple patterns)
        let mut result = pattern.clone();
        for (key, value) in &context {
            let placeholder = format!("{{{key}}}");
            if let Some(s) = value.as_str() {
                result = result.replace(&placeholder, s);
            }
        }

        // Check if any unreplaced placeholders remain
        if result.contains('{') && result.contains('}') {
            return Err(GovernanceError::Validation(format!(
                "Unable to replace all placeholders in naming pattern: {result}"
            )));
        }

        Ok(result)
    }

    // =========================================================================
    // T019: Attribute inheritance and propagation
    // =========================================================================

    /// Compute initial attributes for a new persona.
    fn compute_initial_attributes(
        &self,
        archetype: &GovPersonaArchetype,
        user: &User,
        overrides: Option<serde_json::Map<String, serde_json::Value>>,
    ) -> Result<(PersonaAttributes, String)> {
        let mappings = archetype
            .parse_attribute_mappings()
            .map_err(|e| GovernanceError::Validation(format!("Invalid attribute mappings: {e}")))?;

        // Build user attributes map from User struct fields
        let mut user_attrs = serde_json::Map::new();
        user_attrs.insert("email".to_string(), json!(user.email.clone()));
        if let Some(ref first_name) = user.first_name {
            user_attrs.insert("given_name".to_string(), json!(first_name.clone()));
        }
        if let Some(ref last_name) = user.last_name {
            user_attrs.insert("surname".to_string(), json!(last_name.clone()));
        }
        if let Some(ref display_name) = user.display_name {
            user_attrs.insert("display_name".to_string(), json!(display_name.clone()));
        }

        // Build inherited attributes from propagate mappings
        let mut inherited = serde_json::Map::new();
        for mapping in &mappings.propagate {
            if let Some(value) = user_attrs.get(&mapping.source) {
                inherited.insert(mapping.target.clone(), value.clone());
            }
        }

        // Apply overrides
        let overrides = overrides.unwrap_or_default();

        // Initialize persona-specific (empty for now)
        let persona_specific = serde_json::Map::new();

        // Compute display_name from computed mappings
        let mut display_name = String::new();
        for mapping in &mappings.computed {
            if mapping.target == "display_name" {
                display_name = self.render_template(&mapping.template, &inherited, &overrides)?;
                break;
            }
        }

        // Default display_name if not computed
        if display_name.is_empty() {
            let given = inherited
                .get("given_name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let surname = inherited
                .get("surname")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            display_name = format!("{given} {surname}").trim().to_string();
            if display_name.is_empty() {
                display_name = "Persona".to_string();
            }
        }

        let attrs = PersonaAttributes {
            inherited,
            overrides,
            persona_specific,
            last_propagation_at: Some(Utc::now()),
        };

        Ok((attrs, display_name))
    }

    /// Render a template with context.
    fn render_template(
        &self,
        template: &str,
        inherited: &serde_json::Map<String, serde_json::Value>,
        overrides: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<String> {
        render_persona_template(template, inherited, overrides)
    }

    /// Propagate attributes from physical user to persona.
    pub async fn propagate_attributes(
        &self,
        tenant_id: Uuid,
        persona_id: Uuid,
    ) -> Result<GovPersona> {
        let persona = self.get(tenant_id, persona_id).await?;

        // Get archetype
        let archetype = self
            .archetype_service
            .get(tenant_id, persona.archetype_id)
            .await?;

        // Get physical user (include tenant_id for defense-in-depth)
        let user = User::find_by_id_in_tenant(&self.pool, tenant_id, persona.physical_user_id)
            .await?
            .ok_or(GovernanceError::UserNotFound(persona.physical_user_id))?;

        // Parse mappings
        let mappings = archetype
            .parse_attribute_mappings()
            .map_err(|e| GovernanceError::Validation(format!("Invalid attribute mappings: {e}")))?;

        // Build user attributes map from User struct fields
        let mut user_attrs = serde_json::Map::new();
        user_attrs.insert("email".to_string(), json!(user.email.clone()));
        if let Some(ref first_name) = user.first_name {
            user_attrs.insert("given_name".to_string(), json!(first_name.clone()));
        }
        if let Some(ref last_name) = user.last_name {
            user_attrs.insert("surname".to_string(), json!(last_name.clone()));
        }
        if let Some(ref display_name) = user.display_name {
            user_attrs.insert("display_name".to_string(), json!(display_name.clone()));
        }

        // Build new inherited attributes
        let mut inherited = serde_json::Map::new();
        for mapping in &mappings.propagate {
            if let Some(value) = user_attrs.get(&mapping.source) {
                inherited.insert(mapping.target.clone(), value.clone());
            }
        }

        // Update persona with new inherited attributes
        let updated =
            GovPersona::update_inherited_attributes(&self.pool, tenant_id, persona_id, inherited)
                .await?
                .ok_or(GovernanceError::PersonaNotFound(persona_id))?;

        info!(
            persona_id = %persona_id,
            "Persona attributes propagated"
        );

        Ok(updated)
    }

    // =========================================================================
    // T022: Physical user deactivation cascade
    // =========================================================================

    /// Handle physical user deactivation - cascade to all their personas.
    pub async fn cascade_user_deactivation(
        &self,
        tenant_id: Uuid,
        physical_user_id: Uuid,
        action: &str,
    ) -> Result<u64> {
        match action {
            "cascade_deactivate" | "suspend" => {
                let affected = GovPersona::deactivate_all_for_user(
                    &self.pool,
                    tenant_id,
                    physical_user_id,
                    "Physical user deactivated",
                )
                .await?;

                info!(
                    physical_user_id = %physical_user_id,
                    affected_personas = %affected,
                    action = %action,
                    "Persona cascade deactivation completed"
                );

                Ok(affected)
            }
            "no_action" => {
                // Do nothing
                Ok(0)
            }
            _ => Err(GovernanceError::Validation(format!(
                "Invalid deactivation action: {action}"
            ))),
        }
    }

    // =========================================================================
    // Batch operations with validation (IGA multi-persona atomicity)
    // =========================================================================

    /// Validate that multiple personas can be created without conflicts.
    ///
    /// In IGA pattern: "If more than one persona is provisioned at the same time
    /// then an error in one persona may cause the other persona not to be provisioned."
    ///
    /// This method validates upfront before any creation to avoid partial failures.
    pub async fn validate_batch_creation(
        &self,
        tenant_id: Uuid,
        physical_user_id: Uuid,
        archetype_ids: &[Uuid],
    ) -> Result<super::persona_validation_service::ConflictCheckResult> {
        self.validation_service
            .validate_batch_creation(tenant_id, physical_user_id, archetype_ids)
            .await
    }

    /// Create multiple personas with pre-validation.
    ///
    /// This method validates all archetypes upfront to minimize the chance of
    /// partial failure. If validation passes, it creates personas sequentially.
    ///
    /// NOTE: True atomic batch creation would require transaction-aware variants
    /// of all underlying methods. This implementation validates upfront but
    /// creates sequentially - if a late creation fails, earlier ones remain.
    /// For critical atomicity requirements, use compensation logic externally.
    pub async fn create_batch(
        &self,
        tenant_id: Uuid,
        physical_user_id: Uuid,
        actor_id: Uuid,
        archetype_ids: &[Uuid],
    ) -> Result<Vec<GovPersona>> {
        // Validate all archetypes upfront to minimize partial failure risk
        let conflict_check = self
            .validate_batch_creation(tenant_id, physical_user_id, archetype_ids)
            .await?;

        if conflict_check.has_conflict {
            return Err(GovernanceError::PersonaMultiOperationPartialFailure {
                succeeded: 0,
                failed: archetype_ids.len() as i32,
                details: conflict_check.conflict_details.join("; "),
            });
        }

        let mut created_personas = Vec::new();
        let mut failed_at: Option<(Uuid, String)> = None;

        for archetype_id in archetype_ids {
            match self
                .create_with_actor(tenant_id, *archetype_id, physical_user_id, actor_id, None)
                .await
            {
                Ok(persona) => {
                    created_personas.push(persona);
                }
                Err(e) => {
                    warn!(
                        tenant_id = %tenant_id,
                        archetype_id = %archetype_id,
                        error = %e,
                        succeeded_count = created_personas.len(),
                        "Batch persona creation partial failure"
                    );
                    failed_at = Some((*archetype_id, e.to_string()));
                    break;
                }
            }
        }

        if let Some((archetype_id, error)) = failed_at {
            // Return partial failure info - caller may implement compensation
            return Err(GovernanceError::PersonaMultiOperationPartialFailure {
                succeeded: created_personas.len() as i32,
                failed: (archetype_ids.len() - created_personas.len()) as i32,
                details: format!(
                    "Failed on archetype {}: {}. {} personas were created before failure.",
                    archetype_id,
                    error,
                    created_personas.len()
                ),
            });
        }

        info!(
            tenant_id = %tenant_id,
            physical_user_id = %physical_user_id,
            count = created_personas.len(),
            "Batch persona creation completed"
        );

        Ok(created_personas)
    }

    /// Get reference to the database pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Get reference to archetype service.
    #[must_use]
    pub fn archetype_service(&self) -> &PersonaArchetypeService {
        &self.archetype_service
    }
}

/// Render a template with context (standalone function for testing).
pub fn render_persona_template(
    template: &str,
    inherited: &serde_json::Map<String, serde_json::Value>,
    overrides: &serde_json::Map<String, serde_json::Value>,
) -> Result<String> {
    // Build context with overrides taking precedence
    let mut context = HashMap::new();
    for (k, v) in inherited {
        if let Some(s) = v.as_str() {
            context.insert(k.clone(), s.to_string());
        }
    }
    for (k, v) in overrides {
        if let Some(s) = v.as_str() {
            context.insert(k.clone(), s.to_string());
        }
    }

    // Simple placeholder replacement
    let mut result = template.to_string();
    for (key, value) in &context {
        let placeholder = format!("{{{key}}}");
        result = result.replace(&placeholder, value);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_template() {
        let mut inherited = serde_json::Map::new();
        inherited.insert("given_name".to_string(), json!("John"));
        inherited.insert("surname".to_string(), json!("Doe"));

        let overrides = serde_json::Map::new();

        let result =
            render_persona_template("Admin {given_name} {surname}", &inherited, &overrides)
                .unwrap();
        assert_eq!(result, "Admin John Doe");
    }

    #[test]
    fn test_render_template_with_overrides() {
        let mut inherited = serde_json::Map::new();
        inherited.insert("given_name".to_string(), json!("John"));
        inherited.insert("surname".to_string(), json!("Doe"));

        let mut overrides = serde_json::Map::new();
        overrides.insert("surname".to_string(), json!("Smith"));

        let result =
            render_persona_template("{given_name} {surname}", &inherited, &overrides).unwrap();
        assert_eq!(result, "John Smith");
    }
}
