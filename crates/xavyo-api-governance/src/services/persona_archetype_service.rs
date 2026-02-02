//! Persona archetype service for governance API (F063).
//!
//! Handles CRUD operations for persona archetypes including validation
//! of naming patterns, attribute mappings, and lifecycle policies.

use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use xavyo_db::models::{
    AttributeMappings, CreatePersonaArchetype, GovPersonaArchetype, LifecyclePolicy,
    PersonaArchetypeFilter, UpdatePersonaArchetype,
};
use xavyo_governance::error::{GovernanceError, Result};

/// Service for persona archetype operations.
pub struct PersonaArchetypeService {
    pool: PgPool,
}

impl PersonaArchetypeService {
    /// Create a new archetype service.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // =========================================================================
    // T015: CRUD methods
    // =========================================================================

    /// Create a new persona archetype.
    ///
    /// Validates:
    /// - Name uniqueness within tenant
    /// - Naming pattern contains at least one placeholder
    /// - Attribute mappings structure is valid
    /// - Lifecycle policy values are within bounds
    pub async fn create(
        &self,
        tenant_id: Uuid,
        input: CreatePersonaArchetype,
    ) -> Result<GovPersonaArchetype> {
        // Check name uniqueness
        let existing =
            GovPersonaArchetype::find_by_name(&self.pool, tenant_id, &input.name).await?;
        if existing.is_some() {
            return Err(GovernanceError::PersonaArchetypeNameExists(input.name));
        }

        // Validate naming pattern (T016)
        validate_naming_pattern(&input.naming_pattern)?;

        // Validate attribute mappings (T016)
        validate_attribute_mappings(&input.attribute_mappings)?;

        // Validate lifecycle policy (T016)
        validate_lifecycle_policy(&input.lifecycle_policy)?;

        // Create the archetype
        let archetype = GovPersonaArchetype::create(&self.pool, tenant_id, input).await?;

        info!(
            archetype_id = %archetype.id,
            name = %archetype.name,
            "Persona archetype created"
        );

        Ok(archetype)
    }

    /// Get an archetype by ID.
    pub async fn get(&self, tenant_id: Uuid, id: Uuid) -> Result<GovPersonaArchetype> {
        GovPersonaArchetype::find_by_id(&self.pool, tenant_id, id)
            .await?
            .ok_or(GovernanceError::PersonaArchetypeNotFound(id))
    }

    /// Update an archetype.
    pub async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdatePersonaArchetype,
    ) -> Result<GovPersonaArchetype> {
        // Get existing archetype
        let existing = self.get(tenant_id, id).await?;

        // Validate name uniqueness if changed
        if let Some(ref name) = input.name {
            if name != &existing.name {
                let duplicate =
                    GovPersonaArchetype::find_by_name(&self.pool, tenant_id, name).await?;
                if duplicate.is_some() {
                    return Err(GovernanceError::PersonaArchetypeNameExists(name.clone()));
                }
            }
        }

        // Validate naming pattern if changed (T016)
        if let Some(ref naming_pattern) = input.naming_pattern {
            validate_naming_pattern(naming_pattern)?;
        }

        // Validate attribute mappings if changed (T016)
        if let Some(ref attribute_mappings) = input.attribute_mappings {
            validate_attribute_mappings(attribute_mappings)?;
        }

        // Validate lifecycle policy if changed (T016)
        if let Some(ref lifecycle_policy) = input.lifecycle_policy {
            validate_lifecycle_policy(lifecycle_policy)?;
        }

        // Update the archetype
        let updated = GovPersonaArchetype::update(&self.pool, tenant_id, id, input)
            .await?
            .ok_or(GovernanceError::PersonaArchetypeNotFound(id))?;

        info!(
            archetype_id = %updated.id,
            name = %updated.name,
            "Persona archetype updated"
        );

        Ok(updated)
    }

    /// Delete an archetype.
    ///
    /// Deletion is prevented if active personas exist for this archetype.
    pub async fn delete(&self, tenant_id: Uuid, id: Uuid) -> Result<()> {
        // Check archetype exists
        let archetype = self.get(tenant_id, id).await?;

        // Check for active personas (T054 - edge case)
        let active_count =
            GovPersonaArchetype::count_active_personas(&self.pool, tenant_id, id).await?;
        if active_count > 0 {
            return Err(GovernanceError::PersonaArchetypeHasActivePersonas(
                active_count,
            ));
        }

        // Delete the archetype
        let deleted = GovPersonaArchetype::delete(&self.pool, tenant_id, id).await?;

        if !deleted {
            return Err(GovernanceError::PersonaArchetypeNotFound(id));
        }

        info!(
            archetype_id = %id,
            name = %archetype.name,
            "Persona archetype deleted"
        );

        Ok(())
    }

    /// List archetypes with filtering and pagination.
    pub async fn list(
        &self,
        tenant_id: Uuid,
        filter: &PersonaArchetypeFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovPersonaArchetype>, i64)> {
        let items =
            GovPersonaArchetype::list_by_tenant(&self.pool, tenant_id, filter, limit, offset)
                .await?;
        let total = GovPersonaArchetype::count_by_tenant(&self.pool, tenant_id, filter).await?;
        Ok((items, total))
    }

    // =========================================================================
    // Archetype status management
    // =========================================================================

    /// Activate an archetype.
    pub async fn activate(&self, tenant_id: Uuid, id: Uuid) -> Result<GovPersonaArchetype> {
        let input = UpdatePersonaArchetype {
            is_active: Some(true),
            ..Default::default()
        };

        let updated = GovPersonaArchetype::update(&self.pool, tenant_id, id, input)
            .await?
            .ok_or(GovernanceError::PersonaArchetypeNotFound(id))?;

        info!(archetype_id = %id, "Persona archetype activated");

        Ok(updated)
    }

    /// Deactivate an archetype.
    ///
    /// Note: This does not affect existing personas, but prevents new
    /// persona creation from this archetype.
    pub async fn deactivate(&self, tenant_id: Uuid, id: Uuid) -> Result<GovPersonaArchetype> {
        let updated = GovPersonaArchetype::deactivate(&self.pool, tenant_id, id)
            .await?
            .ok_or(GovernanceError::PersonaArchetypeNotFound(id))?;

        info!(archetype_id = %id, "Persona archetype deactivated");

        Ok(updated)
    }

    /// Get count of active personas for an archetype.
    pub async fn count_active_personas(&self, tenant_id: Uuid, id: Uuid) -> Result<i64> {
        // Verify archetype exists
        let _ = self.get(tenant_id, id).await?;

        let count = GovPersonaArchetype::count_active_personas(&self.pool, tenant_id, id).await?;
        Ok(count)
    }

    /// Get reference to the database pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

// =========================================================================
// Standalone validation functions for testing
// =========================================================================

/// Validate a naming pattern (standalone function for testing).
pub fn validate_naming_pattern(pattern: &str) -> Result<()> {
    if pattern.is_empty() {
        return Err(GovernanceError::Validation(
            "Naming pattern cannot be empty".to_string(),
        ));
    }

    // Check for at least one placeholder
    if !pattern.contains('{') || !pattern.contains('}') {
        return Err(GovernanceError::Validation(
            "Naming pattern must contain at least one placeholder (e.g., {username})".to_string(),
        ));
    }

    // Validate placeholder syntax (matching braces)
    let open_count = pattern.matches('{').count();
    let close_count = pattern.matches('}').count();
    if open_count != close_count {
        return Err(GovernanceError::Validation(
            "Naming pattern has unmatched braces".to_string(),
        ));
    }

    // Extract and validate placeholders
    let mut in_placeholder = false;
    let mut placeholder_start = 0;
    for (i, c) in pattern.chars().enumerate() {
        match c {
            '{' => {
                if in_placeholder {
                    return Err(GovernanceError::Validation(
                        "Nested placeholders are not allowed".to_string(),
                    ));
                }
                in_placeholder = true;
                placeholder_start = i + 1;
            }
            '}' => {
                if !in_placeholder {
                    return Err(GovernanceError::Validation(
                        "Unmatched closing brace in naming pattern".to_string(),
                    ));
                }
                let placeholder_len = i - placeholder_start;
                if placeholder_len == 0 {
                    return Err(GovernanceError::Validation(
                        "Empty placeholder in naming pattern".to_string(),
                    ));
                }
                in_placeholder = false;
            }
            _ => {}
        }
    }

    Ok(())
}

/// Validate attribute mappings JSON structure (standalone function for testing).
pub fn validate_attribute_mappings(mappings: &serde_json::Value) -> Result<()> {
    // Try to parse as AttributeMappings struct
    let parsed: AttributeMappings = serde_json::from_value(mappings.clone()).map_err(|e| {
        GovernanceError::Validation(format!("Invalid attribute_mappings structure: {}", e))
    })?;

    // Validate propagate mappings
    for mapping in &parsed.propagate {
        if mapping.source.is_empty() {
            return Err(GovernanceError::Validation(
                "Propagate mapping source cannot be empty".to_string(),
            ));
        }
        if mapping.target.is_empty() {
            return Err(GovernanceError::Validation(
                "Propagate mapping target cannot be empty".to_string(),
            ));
        }
        if mapping.mode != "always" && mapping.mode != "default" {
            return Err(GovernanceError::Validation(format!(
                "Invalid propagate mode '{}': must be 'always' or 'default'",
                mapping.mode
            )));
        }
    }

    // Validate computed mappings
    for mapping in &parsed.computed {
        if mapping.target.is_empty() {
            return Err(GovernanceError::Validation(
                "Computed mapping target cannot be empty".to_string(),
            ));
        }
        if mapping.template.is_empty() {
            return Err(GovernanceError::Validation(
                "Computed mapping template cannot be empty".to_string(),
            ));
        }
    }

    // Validate persona_only attributes (just non-empty strings)
    for attr in &parsed.persona_only {
        if attr.is_empty() {
            return Err(GovernanceError::Validation(
                "Persona-only attribute name cannot be empty".to_string(),
            ));
        }
    }

    Ok(())
}

/// Validate lifecycle policy values (standalone function for testing).
pub fn validate_lifecycle_policy(policy: &serde_json::Value) -> Result<()> {
    // Try to parse as LifecyclePolicy struct
    let parsed: LifecyclePolicy = serde_json::from_value(policy.clone()).map_err(|e| {
        GovernanceError::Validation(format!("Invalid lifecycle_policy structure: {}", e))
    })?;

    // Validate validity days
    if parsed.default_validity_days <= 0 {
        return Err(GovernanceError::Validation(
            "default_validity_days must be positive".to_string(),
        ));
    }
    if parsed.max_validity_days <= 0 {
        return Err(GovernanceError::Validation(
            "max_validity_days must be positive".to_string(),
        ));
    }
    if parsed.max_validity_days < parsed.default_validity_days {
        return Err(GovernanceError::Validation(
            "max_validity_days must be >= default_validity_days".to_string(),
        ));
    }

    // Validate notification days
    if parsed.notification_before_expiry_days < 0 {
        return Err(GovernanceError::Validation(
            "notification_before_expiry_days cannot be negative".to_string(),
        ));
    }
    if parsed.notification_before_expiry_days > parsed.default_validity_days {
        return Err(GovernanceError::Validation(
            "notification_before_expiry_days cannot exceed default_validity_days".to_string(),
        ));
    }

    // Validate deactivation action
    let valid_actions = ["cascade_deactivate", "suspend", "no_action"];
    if !valid_actions.contains(&parsed.on_physical_user_deactivation.as_str()) {
        return Err(GovernanceError::Validation(format!(
            "Invalid on_physical_user_deactivation '{}': must be one of {:?}",
            parsed.on_physical_user_deactivation, valid_actions
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_naming_pattern_valid() {
        // Valid patterns
        assert!(validate_naming_pattern("admin.{username}").is_ok());
        assert!(validate_naming_pattern("{prefix}.{given_name}.{surname}").is_ok());
        assert!(validate_naming_pattern("svc-{username}").is_ok());
    }

    #[test]
    fn test_validate_naming_pattern_invalid() {
        // Empty pattern
        assert!(validate_naming_pattern("").is_err());

        // No placeholders
        assert!(validate_naming_pattern("admin").is_err());

        // Unmatched braces
        assert!(validate_naming_pattern("admin.{username").is_err());
        assert!(validate_naming_pattern("admin.username}").is_err());

        // Empty placeholder
        assert!(validate_naming_pattern("admin.{}").is_err());
    }

    #[test]
    fn test_validate_attribute_mappings_valid() {
        let valid_mappings = serde_json::json!({
            "propagate": [
                {"source": "surname", "target": "surname", "mode": "always", "allow_override": false}
            ],
            "computed": [
                {"target": "display_name", "template": "Admin {given_name} {surname}", "variables": {}}
            ],
            "persona_only": ["admin_level"]
        });

        assert!(validate_attribute_mappings(&valid_mappings).is_ok());
    }

    #[test]
    fn test_validate_attribute_mappings_invalid_mode() {
        let invalid_mappings = serde_json::json!({
            "propagate": [
                {"source": "surname", "target": "surname", "mode": "invalid_mode"}
            ],
            "computed": [],
            "persona_only": []
        });

        assert!(validate_attribute_mappings(&invalid_mappings).is_err());
    }

    #[test]
    fn test_validate_lifecycle_policy_valid() {
        let valid_policy = serde_json::json!({
            "default_validity_days": 365,
            "max_validity_days": 730,
            "notification_before_expiry_days": 7,
            "auto_extension_allowed": false,
            "extension_requires_approval": true,
            "on_physical_user_deactivation": "cascade_deactivate"
        });

        assert!(validate_lifecycle_policy(&valid_policy).is_ok());
    }

    #[test]
    fn test_validate_lifecycle_policy_invalid_validity() {
        // max < default
        let invalid_policy = serde_json::json!({
            "default_validity_days": 730,
            "max_validity_days": 365,
            "notification_before_expiry_days": 7,
            "auto_extension_allowed": false,
            "extension_requires_approval": true,
            "on_physical_user_deactivation": "cascade_deactivate"
        });

        assert!(validate_lifecycle_policy(&invalid_policy).is_err());
    }

    #[test]
    fn test_validate_lifecycle_policy_invalid_action() {
        let invalid_policy = serde_json::json!({
            "default_validity_days": 365,
            "max_validity_days": 730,
            "notification_before_expiry_days": 7,
            "auto_extension_allowed": false,
            "extension_requires_approval": true,
            "on_physical_user_deactivation": "delete_everything"
        });

        assert!(validate_lifecycle_policy(&invalid_policy).is_err());
    }
}
