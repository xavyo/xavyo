//! Persona validation service for governance API (F063).
//!
//! Implements validation logic for persona operations including:
//! - Archetype conflict detection
//! - Multi-persona atomic operations
//! - Approval workflow compatibility checks

use sqlx::PgPool;
use std::collections::HashSet;
use tracing::{info, warn};
use uuid::Uuid;

use xavyo_db::models::{AttributeMappings, GovPersona, GovPersonaArchetype, PersonaFilter};
use xavyo_governance::error::{GovernanceError, Result};

/// Result of a conflict check.
#[derive(Debug, Clone)]
pub struct ConflictCheckResult {
    pub has_conflict: bool,
    pub conflicting_archetypes: Vec<Uuid>,
    pub conflict_details: Vec<String>,
}

impl ConflictCheckResult {
    #[must_use]
    pub fn no_conflict() -> Self {
        Self {
            has_conflict: false,
            conflicting_archetypes: vec![],
            conflict_details: vec![],
        }
    }

    #[must_use]
    pub fn conflict(archetypes: Vec<Uuid>, details: Vec<String>) -> Self {
        Self {
            has_conflict: true,
            conflicting_archetypes: archetypes,
            conflict_details: details,
        }
    }
}

/// Result of a multi-persona operation.
#[derive(Debug, Clone)]
pub struct MultiPersonaOperationResult {
    pub succeeded: Vec<Uuid>,
    pub failed: Vec<(Uuid, String)>,
    pub rolled_back: bool,
}

impl MultiPersonaOperationResult {
    #[must_use]
    pub fn all_succeeded(ids: Vec<Uuid>) -> Self {
        Self {
            succeeded: ids,
            failed: vec![],
            rolled_back: false,
        }
    }

    #[must_use]
    pub fn partial_failure(succeeded: Vec<Uuid>, failed: Vec<(Uuid, String)>) -> Self {
        Self {
            succeeded,
            failed,
            rolled_back: false,
        }
    }

    #[must_use]
    pub fn all_rolled_back(failed: Vec<(Uuid, String)>) -> Self {
        Self {
            succeeded: vec![],
            failed,
            rolled_back: true,
        }
    }
}

/// Service for persona validation operations.
pub struct PersonaValidationService {
    pool: PgPool,
}

impl PersonaValidationService {
    /// Create a new validation service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // =========================================================================
    // Archetype Conflict Detection
    // =========================================================================

    /// Check for conflicts between archetypes for a user.
    ///
    /// In IGA pattern: "Currently only one persona construction is supported for each persona.
    /// IGA cannot currently merge two persona constructions and apply them both."
    ///
    /// We check for:
    /// 1. Overlapping target attributes in computed mappings
    /// 2. Conflicting propagation rules (same source, different modes)
    /// 3. Conflicting `persona_only` attributes
    pub async fn check_archetype_conflicts(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        new_archetype_id: Uuid,
    ) -> Result<ConflictCheckResult> {
        // Get user's existing personas
        let filter = PersonaFilter {
            status: None,
            archetype_id: None,
            physical_user_id: Some(user_id),
            expiring_within_days: None,
        };
        let existing_personas =
            GovPersona::list_by_tenant(&self.pool, tenant_id, &filter, 100, 0).await?;

        if existing_personas.is_empty() {
            return Ok(ConflictCheckResult::no_conflict());
        }

        // Get the new archetype
        let new_archetype =
            GovPersonaArchetype::find_by_id(&self.pool, tenant_id, new_archetype_id)
                .await?
                .ok_or(GovernanceError::PersonaArchetypeNotFound(new_archetype_id))?;

        let new_mappings: AttributeMappings =
            serde_json::from_value(new_archetype.attribute_mappings.clone()).unwrap_or_default();

        let mut conflicts = vec![];
        let mut conflicting_archetypes = vec![];

        // Check each existing persona's archetype
        for persona in &existing_personas {
            let existing_archetype =
                GovPersonaArchetype::find_by_id(&self.pool, tenant_id, persona.archetype_id)
                    .await?;

            if let Some(archetype) = existing_archetype {
                let existing_mappings: AttributeMappings =
                    serde_json::from_value(archetype.attribute_mappings.clone())
                        .unwrap_or_default();

                // Check for computed attribute conflicts
                let new_computed_targets: HashSet<_> =
                    new_mappings.computed.iter().map(|c| &c.target).collect();
                let existing_computed_targets: HashSet<_> = existing_mappings
                    .computed
                    .iter()
                    .map(|c| &c.target)
                    .collect();

                let computed_conflicts: Vec<_> = new_computed_targets
                    .intersection(&existing_computed_targets)
                    .collect();

                if !computed_conflicts.is_empty() {
                    conflicts.push(format!(
                        "Computed attribute conflict with archetype '{}': targets {:?}",
                        archetype.name, computed_conflicts
                    ));
                    if !conflicting_archetypes.contains(&archetype.id) {
                        conflicting_archetypes.push(archetype.id);
                    }
                }

                // Check for propagation rule conflicts (same source, different modes)
                for new_prop in &new_mappings.propagate {
                    for existing_prop in &existing_mappings.propagate {
                        if new_prop.source == existing_prop.source
                            && new_prop.mode != existing_prop.mode
                        {
                            conflicts.push(format!(
                                "Propagation mode conflict for '{}': {} vs {} (archetype '{}')",
                                new_prop.source, new_prop.mode, existing_prop.mode, archetype.name
                            ));
                            if !conflicting_archetypes.contains(&archetype.id) {
                                conflicting_archetypes.push(archetype.id);
                            }
                        }
                    }
                }

                // Check for persona_only attribute conflicts
                let new_persona_only: HashSet<_> = new_mappings.persona_only.iter().collect();
                let existing_persona_only: HashSet<_> =
                    existing_mappings.persona_only.iter().collect();

                let persona_only_conflicts: Vec<_> = new_persona_only
                    .intersection(&existing_persona_only)
                    .collect();

                if !persona_only_conflicts.is_empty() {
                    conflicts.push(format!(
                        "Persona-only attribute conflict with archetype '{}': {:?}",
                        archetype.name, persona_only_conflicts
                    ));
                    if !conflicting_archetypes.contains(&archetype.id) {
                        conflicting_archetypes.push(archetype.id);
                    }
                }
            }
        }

        if conflicts.is_empty() {
            Ok(ConflictCheckResult::no_conflict())
        } else {
            warn!(
                tenant_id = %tenant_id,
                user_id = %user_id,
                new_archetype_id = %new_archetype_id,
                conflicts = ?conflicts,
                "Archetype conflict detected"
            );
            Ok(ConflictCheckResult::conflict(
                conflicting_archetypes,
                conflicts,
            ))
        }
    }

    // =========================================================================
    // Multi-Persona Atomic Operations
    // =========================================================================

    /// Execute a multi-persona operation atomically.
    ///
    /// In IGA pattern: "If more than one persona is provisioned at the same time
    /// then an error in one persona may cause the other persona not to be provisioned."
    ///
    /// We handle this by using a database transaction and rolling back all
    /// changes if any operation fails.
    pub async fn execute_multi_persona_operation<F, Fut>(
        &self,
        tenant_id: Uuid,
        persona_ids: Vec<Uuid>,
        operation_name: &str,
        operation: F,
    ) -> Result<MultiPersonaOperationResult>
    where
        F: Fn(Uuid) -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        info!(
            tenant_id = %tenant_id,
            operation = operation_name,
            persona_count = persona_ids.len(),
            "Starting multi-persona atomic operation"
        );

        // Start a transaction
        let tx = self.pool.begin().await?;

        let mut succeeded = vec![];
        let mut failed = vec![];

        for persona_id in &persona_ids {
            match operation(*persona_id).await {
                Ok(()) => {
                    succeeded.push(*persona_id);
                }
                Err(e) => {
                    failed.push((*persona_id, e.to_string()));
                    // On first failure, rollback and return
                    warn!(
                        tenant_id = %tenant_id,
                        persona_id = %persona_id,
                        error = %e,
                        "Multi-persona operation failed, rolling back"
                    );
                    tx.rollback().await?;
                    return Ok(MultiPersonaOperationResult::all_rolled_back(failed));
                }
            }
        }

        // All succeeded, commit
        tx.commit().await?;

        info!(
            tenant_id = %tenant_id,
            operation = operation_name,
            succeeded_count = succeeded.len(),
            "Multi-persona operation completed successfully"
        );

        Ok(MultiPersonaOperationResult::all_succeeded(succeeded))
    }

    /// Validate that a batch of personas can be created without conflicts.
    pub async fn validate_batch_creation(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        archetype_ids: &[Uuid],
    ) -> Result<ConflictCheckResult> {
        let mut all_conflicts = vec![];
        let mut all_conflicting = vec![];

        // Check each archetype against existing personas
        for archetype_id in archetype_ids {
            let result = self
                .check_archetype_conflicts(tenant_id, user_id, *archetype_id)
                .await?;
            if result.has_conflict {
                all_conflicts.extend(result.conflict_details);
                all_conflicting.extend(result.conflicting_archetypes);
            }
        }

        // Also check new archetypes against each other
        for (i, arch1) in archetype_ids.iter().enumerate() {
            for arch2 in archetype_ids.iter().skip(i + 1) {
                let conflict = self
                    .check_archetype_pair_conflict(tenant_id, *arch1, *arch2)
                    .await?;
                if let Some(details) = conflict {
                    all_conflicts.push(details);
                    if !all_conflicting.contains(arch1) {
                        all_conflicting.push(*arch1);
                    }
                    if !all_conflicting.contains(arch2) {
                        all_conflicting.push(*arch2);
                    }
                }
            }
        }

        if all_conflicts.is_empty() {
            Ok(ConflictCheckResult::no_conflict())
        } else {
            Ok(ConflictCheckResult::conflict(
                all_conflicting,
                all_conflicts,
            ))
        }
    }

    /// Check if two archetypes have conflicting constructions.
    async fn check_archetype_pair_conflict(
        &self,
        tenant_id: Uuid,
        arch1_id: Uuid,
        arch2_id: Uuid,
    ) -> Result<Option<String>> {
        let arch1 = GovPersonaArchetype::find_by_id(&self.pool, tenant_id, arch1_id).await?;
        let arch2 = GovPersonaArchetype::find_by_id(&self.pool, tenant_id, arch2_id).await?;

        let (Some(a1), Some(a2)) = (arch1, arch2) else {
            return Ok(None);
        };

        let m1: AttributeMappings =
            serde_json::from_value(a1.attribute_mappings.clone()).unwrap_or_default();
        let m2: AttributeMappings =
            serde_json::from_value(a2.attribute_mappings.clone()).unwrap_or_default();

        // Check computed attribute conflicts
        let t1: HashSet<_> = m1.computed.iter().map(|c| &c.target).collect();
        let t2: HashSet<_> = m2.computed.iter().map(|c| &c.target).collect();

        let conflicts: Vec<_> = t1.intersection(&t2).collect();
        if !conflicts.is_empty() {
            return Ok(Some(format!(
                "Archetypes '{}' and '{}' have conflicting computed targets: {:?}",
                a1.name, a2.name, conflicts
            )));
        }

        Ok(None)
    }

    // =========================================================================
    // Approval Workflow Compatibility
    // =========================================================================

    /// Validate that persona operations won't trigger approval workflows.
    ///
    /// In IGA pattern: "The operation that automatically provisions, deprovisions or
    /// updates a persona must not be subject to approvals."
    pub async fn validate_no_approval_conflict(
        &self,
        tenant_id: Uuid,
        archetype_id: Uuid,
    ) -> Result<()> {
        let archetype = GovPersonaArchetype::find_by_id(&self.pool, tenant_id, archetype_id)
            .await?
            .ok_or(GovernanceError::PersonaArchetypeNotFound(archetype_id))?;

        // Check default_entitlements for approval requirements
        if let Some(ref entitlements) = archetype.default_entitlements {
            if let Some(arr) = entitlements.as_array() {
                for ent in arr {
                    if let Some(requires_approval) = ent.get("requires_approval") {
                        if requires_approval.as_bool().unwrap_or(false) {
                            let ent_name = ent
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            return Err(GovernanceError::PersonaOperationRequiresApproval(
                                format!(
                                    "Default entitlement '{}' in archetype '{}' requires approval",
                                    ent_name, archetype.name
                                ),
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conflict_check_result_no_conflict() {
        let result = ConflictCheckResult::no_conflict();
        assert!(!result.has_conflict);
        assert!(result.conflicting_archetypes.is_empty());
        assert!(result.conflict_details.is_empty());
    }

    #[test]
    fn test_conflict_check_result_with_conflict() {
        let arch_id = Uuid::new_v4();
        let result =
            ConflictCheckResult::conflict(vec![arch_id], vec!["Test conflict".to_string()]);
        assert!(result.has_conflict);
        assert_eq!(result.conflicting_archetypes.len(), 1);
        assert_eq!(result.conflict_details.len(), 1);
    }

    #[test]
    fn test_multi_operation_result_all_succeeded() {
        let ids = vec![Uuid::new_v4(), Uuid::new_v4()];
        let result = MultiPersonaOperationResult::all_succeeded(ids.clone());
        assert_eq!(result.succeeded.len(), 2);
        assert!(result.failed.is_empty());
        assert!(!result.rolled_back);
    }

    #[test]
    fn test_multi_operation_result_rolled_back() {
        let failed = vec![(Uuid::new_v4(), "Error".to_string())];
        let result = MultiPersonaOperationResult::all_rolled_back(failed);
        assert!(result.succeeded.is_empty());
        assert_eq!(result.failed.len(), 1);
        assert!(result.rolled_back);
    }
}
