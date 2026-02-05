//! Archetype lifecycle service (F-193).
//!
//! Resolves effective lifecycle models for identities based on their archetype
//! and archetype inheritance chain.

use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use xavyo_db::{GovLifecycleConfig, IdentityArchetype};
use xavyo_governance::GovernanceError;

/// Information about an effective lifecycle model assignment.
#[derive(Debug, Clone)]
pub struct EffectiveLifecycleModel {
    /// The lifecycle model ID.
    pub model_id: Uuid,
    /// The lifecycle model name.
    pub model_name: String,
    /// The archetype that provided this lifecycle model.
    pub source_archetype_id: Option<Uuid>,
    /// The archetype name that provided this lifecycle model.
    pub source_archetype_name: Option<String>,
    /// Whether this is directly assigned or inherited.
    pub is_inherited: bool,
    /// The inheritance depth (0 = direct assignment, 1+ = inherited).
    pub inheritance_depth: usize,
}

/// Service for resolving lifecycle models based on archetypes.
pub struct ArchetypeLifecycleService {
    pool: Arc<PgPool>,
}

impl ArchetypeLifecycleService {
    /// Create a new archetype lifecycle service.
    #[must_use]
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }

    /// Resolve the effective lifecycle model for an identity based on its archetype.
    ///
    /// This traverses the archetype inheritance chain to find the first archetype
    /// with a lifecycle model assigned. Returns `None` if no archetype in the chain
    /// has a lifecycle model.
    pub async fn resolve_effective_lifecycle(
        &self,
        tenant_id: Uuid,
        archetype_id: Uuid,
    ) -> Result<Option<EffectiveLifecycleModel>, GovernanceError> {
        // Track visited archetypes to prevent infinite loops
        let mut visited: Vec<Uuid> = Vec::new();
        let mut current_archetype_id = Some(archetype_id);
        let mut depth: usize = 0;

        while let Some(arch_id) = current_archetype_id {
            // Check for cycles
            if visited.contains(&arch_id) {
                return Err(GovernanceError::ActionExecutionFailed(format!(
                    "Circular archetype inheritance detected at archetype {}",
                    arch_id
                )));
            }
            visited.push(arch_id);

            // Get the archetype
            let archetype = IdentityArchetype::find_by_id(&self.pool, tenant_id, arch_id)
                .await?
                .ok_or_else(|| {
                    GovernanceError::ActionExecutionFailed(format!(
                        "Archetype {} not found",
                        arch_id
                    ))
                })?;

            // Check if this archetype has a lifecycle model assigned
            if let Some(lifecycle_model_id) = archetype.lifecycle_model_id {
                // Get the lifecycle model details
                let lifecycle_model =
                    GovLifecycleConfig::find_by_id(&self.pool, tenant_id, lifecycle_model_id)
                        .await?
                        .ok_or_else(|| {
                            GovernanceError::LifecycleConfigNotFound(lifecycle_model_id)
                        })?;

                return Ok(Some(EffectiveLifecycleModel {
                    model_id: lifecycle_model.id,
                    model_name: lifecycle_model.name,
                    source_archetype_id: Some(archetype.id),
                    source_archetype_name: Some(archetype.name),
                    is_inherited: depth > 0,
                    inheritance_depth: depth,
                }));
            }

            // Move to parent archetype
            current_archetype_id = archetype.parent_archetype_id;
            depth += 1;
        }

        // No lifecycle model found in inheritance chain
        Ok(None)
    }

    /// Resolve the effective lifecycle model for a user.
    ///
    /// First checks if the user has a direct lifecycle assignment, then falls back
    /// to the archetype-based resolution.
    pub async fn resolve_effective_lifecycle_for_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<EffectiveLifecycleModel>, GovernanceError> {
        // Get the user to find their archetype
        let user: Option<(Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
            r"
            SELECT archetype_id, lifecycle_config_id FROM users
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_optional(self.pool.as_ref())
        .await
        .map_err(GovernanceError::Database)?;

        let Some((archetype_id, lifecycle_config_id)) = user else {
            return Err(GovernanceError::ActionExecutionFailed(format!(
                "User {} not found",
                user_id
            )));
        };

        // Check for direct lifecycle assignment on user
        if let Some(lifecycle_id) = lifecycle_config_id {
            let lifecycle_model =
                GovLifecycleConfig::find_by_id(&self.pool, tenant_id, lifecycle_id)
                    .await?
                    .ok_or_else(|| GovernanceError::LifecycleConfigNotFound(lifecycle_id))?;

            return Ok(Some(EffectiveLifecycleModel {
                model_id: lifecycle_model.id,
                model_name: lifecycle_model.name,
                source_archetype_id: None,
                source_archetype_name: None,
                is_inherited: false,
                inheritance_depth: 0,
            }));
        }

        // Fall back to archetype-based resolution
        if let Some(arch_id) = archetype_id {
            return self.resolve_effective_lifecycle(tenant_id, arch_id).await;
        }

        Ok(None)
    }

    /// Get the lifecycle model assigned to an archetype.
    ///
    /// Returns the lifecycle model directly assigned to the archetype,
    /// not considering inheritance.
    pub async fn get_archetype_lifecycle(
        &self,
        tenant_id: Uuid,
        archetype_id: Uuid,
    ) -> Result<Option<GovLifecycleConfig>, GovernanceError> {
        let archetype = IdentityArchetype::find_by_id(&self.pool, tenant_id, archetype_id)
            .await?
            .ok_or_else(|| {
                GovernanceError::ActionExecutionFailed(format!(
                    "Archetype {} not found",
                    archetype_id
                ))
            })?;

        if let Some(lifecycle_model_id) = archetype.lifecycle_model_id {
            let lifecycle_model =
                GovLifecycleConfig::find_by_id(&self.pool, tenant_id, lifecycle_model_id).await?;
            return Ok(lifecycle_model);
        }

        Ok(None)
    }

    /// Assign a lifecycle model to an archetype.
    pub async fn assign_archetype_lifecycle(
        &self,
        tenant_id: Uuid,
        archetype_id: Uuid,
        lifecycle_model_id: Uuid,
    ) -> Result<IdentityArchetype, GovernanceError> {
        // Verify lifecycle model exists
        let _lifecycle_model =
            GovLifecycleConfig::find_by_id(&self.pool, tenant_id, lifecycle_model_id)
                .await?
                .ok_or_else(|| GovernanceError::LifecycleConfigNotFound(lifecycle_model_id))?;

        // Update archetype with lifecycle model
        let update = xavyo_db::UpdateIdentityArchetype {
            lifecycle_model_id: Some(Some(lifecycle_model_id)),
            ..Default::default()
        };

        let updated_archetype =
            IdentityArchetype::update(&self.pool, tenant_id, archetype_id, update)
                .await?
                .ok_or_else(|| {
                    GovernanceError::ActionExecutionFailed(format!(
                        "Archetype {} not found",
                        archetype_id
                    ))
                })?;

        Ok(updated_archetype)
    }

    /// Remove lifecycle model assignment from an archetype.
    pub async fn remove_archetype_lifecycle(
        &self,
        tenant_id: Uuid,
        archetype_id: Uuid,
    ) -> Result<IdentityArchetype, GovernanceError> {
        // Update archetype to remove lifecycle model
        let update = xavyo_db::UpdateIdentityArchetype {
            lifecycle_model_id: Some(None), // Set to None to clear
            ..Default::default()
        };

        let updated_archetype =
            IdentityArchetype::update(&self.pool, tenant_id, archetype_id, update)
                .await?
                .ok_or_else(|| {
                    GovernanceError::ActionExecutionFailed(format!(
                        "Archetype {} not found",
                        archetype_id
                    ))
                })?;

        Ok(updated_archetype)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // T044: Unit tests for archetype lifecycle resolution
    // =========================================================================

    #[test]
    fn test_effective_lifecycle_model_creation() {
        let model = EffectiveLifecycleModel {
            model_id: Uuid::new_v4(),
            model_name: "Employee Lifecycle".to_string(),
            source_archetype_id: Some(Uuid::new_v4()),
            source_archetype_name: Some("Employee".to_string()),
            is_inherited: false,
            inheritance_depth: 0,
        };
        assert!(!model.is_inherited);
        assert_eq!(model.inheritance_depth, 0);
    }

    #[test]
    fn test_effective_lifecycle_model_inherited() {
        let model = EffectiveLifecycleModel {
            model_id: Uuid::new_v4(),
            model_name: "Person Lifecycle".to_string(),
            source_archetype_id: Some(Uuid::new_v4()),
            source_archetype_name: Some("Person".to_string()),
            is_inherited: true,
            inheritance_depth: 2,
        };
        assert!(model.is_inherited);
        assert_eq!(model.inheritance_depth, 2);
    }

    #[test]
    fn test_effective_lifecycle_model_direct_assignment() {
        let model = EffectiveLifecycleModel {
            model_id: Uuid::new_v4(),
            model_name: "Custom Lifecycle".to_string(),
            source_archetype_id: None,
            source_archetype_name: None,
            is_inherited: false,
            inheritance_depth: 0,
        };
        assert!(model.source_archetype_id.is_none());
        assert!(model.source_archetype_name.is_none());
    }

    #[test]
    fn test_effective_lifecycle_model_fields() {
        let model_id = Uuid::new_v4();
        let archetype_id = Uuid::new_v4();
        let model = EffectiveLifecycleModel {
            model_id,
            model_name: "Contractor Lifecycle".to_string(),
            source_archetype_id: Some(archetype_id),
            source_archetype_name: Some("Contractor".to_string()),
            is_inherited: true,
            inheritance_depth: 1,
        };
        assert_eq!(model.model_id, model_id);
        assert_eq!(model.model_name, "Contractor Lifecycle");
        assert_eq!(model.source_archetype_id, Some(archetype_id));
    }
}
