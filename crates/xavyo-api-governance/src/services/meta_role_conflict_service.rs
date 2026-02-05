//! Meta-role conflict service for governance API (F056 - US3).
//!
//! Handles detection and resolution of conflicts when multiple meta-roles
//! apply contradicting policies to the same role.

use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

use xavyo_db::{
    CreateGovMetaRoleEvent, GovMetaRole, GovMetaRoleConflict, GovMetaRoleConstraint,
    GovMetaRoleEntitlement, GovMetaRoleInheritance, InheritanceStatus, MetaRoleConflictType,
    MetaRoleEventType, PermissionType, ResolutionStatus, ResolveGovMetaRoleConflict,
};
use xavyo_governance::error::{GovernanceError, Result};

/// Conflict detection result.
#[derive(Debug, Clone)]
pub struct ConflictInfo {
    /// First meta-role in conflict.
    pub meta_role_a_id: Uuid,
    /// Second meta-role in conflict.
    pub meta_role_b_id: Uuid,
    /// Role affected by the conflict.
    pub affected_role_id: Uuid,
    /// Type of conflict.
    pub conflict_type: MetaRoleConflictType,
    /// Details of conflicting items.
    pub conflicting_items: serde_json::Value,
}

/// Service for meta-role conflict detection and resolution.
pub struct MetaRoleConflictService {
    pool: PgPool,
}

impl MetaRoleConflictService {
    /// Create a new conflict service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // =========================================================================
    // Conflict Detection
    // =========================================================================

    /// Detect all conflicts for a specific role (T057).
    ///
    /// Checks for entitlement, constraint, and policy conflicts from all
    /// meta-roles that apply to this role.
    pub async fn detect_conflicts_for_role(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
    ) -> Result<Vec<ConflictInfo>> {
        let mut conflicts = Vec::new();

        // Get all active inheritances for this role
        let active_inheritances = GovMetaRoleInheritance::list_by_child_role(
            &self.pool,
            tenant_id,
            role_id,
            Some(InheritanceStatus::Active),
        )
        .await
        .map_err(GovernanceError::Database)?;

        if active_inheritances.len() < 2 {
            // No conflicts possible with fewer than 2 meta-roles
            return Ok(conflicts);
        }

        // Get meta-role IDs
        let meta_role_ids: Vec<Uuid> = active_inheritances.iter().map(|i| i.meta_role_id).collect();

        // Check entitlement conflicts
        let entitlement_conflicts = self
            .detect_entitlement_conflicts(tenant_id, role_id, &meta_role_ids)
            .await?;
        conflicts.extend(entitlement_conflicts);

        // Check constraint conflicts
        let constraint_conflicts = self
            .detect_constraint_conflicts(tenant_id, role_id, &meta_role_ids)
            .await?;
        conflicts.extend(constraint_conflicts);

        // Check policy conflicts (boolean constraints)
        let policy_conflicts = self
            .detect_policy_conflicts(tenant_id, role_id, &meta_role_ids)
            .await?;
        conflicts.extend(policy_conflicts);

        Ok(conflicts)
    }

    /// Detect entitlement conflicts (grant vs deny for same entitlement) (T054).
    pub async fn detect_entitlement_conflicts(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        meta_role_ids: &[Uuid],
    ) -> Result<Vec<ConflictInfo>> {
        let mut conflicts = Vec::new();

        // Get all entitlements from all meta-roles
        let mut entitlement_map: std::collections::HashMap<Uuid, Vec<(Uuid, PermissionType)>> =
            std::collections::HashMap::new();

        for &meta_role_id in meta_role_ids {
            let entitlements =
                GovMetaRoleEntitlement::list_by_meta_role(&self.pool, tenant_id, meta_role_id)
                    .await
                    .map_err(GovernanceError::Database)?;

            for ent in entitlements {
                entitlement_map
                    .entry(ent.entitlement_id)
                    .or_default()
                    .push((meta_role_id, ent.permission_type));
            }
        }

        // Check for conflicts (same entitlement with different permission types)
        for (entitlement_id, entries) in entitlement_map {
            if entries.len() < 2 {
                continue;
            }

            // Check if there's both grant and deny
            let has_grant = entries
                .iter()
                .any(|(_, perm)| *perm == PermissionType::Grant);
            let has_deny = entries
                .iter()
                .any(|(_, perm)| *perm == PermissionType::Deny);

            if has_grant && has_deny {
                // Find the conflicting meta-roles
                let grant_mr = entries
                    .iter()
                    .find(|(_, perm)| *perm == PermissionType::Grant)
                    .map(|(id, _)| *id)
                    .unwrap();
                let deny_mr = entries
                    .iter()
                    .find(|(_, perm)| *perm == PermissionType::Deny)
                    .map(|(id, _)| *id)
                    .unwrap();

                // Ensure meta_role_a_id < meta_role_b_id
                let (mr_a, mr_b) = if grant_mr < deny_mr {
                    (grant_mr, deny_mr)
                } else {
                    (deny_mr, grant_mr)
                };

                conflicts.push(ConflictInfo {
                    meta_role_a_id: mr_a,
                    meta_role_b_id: mr_b,
                    affected_role_id: role_id,
                    conflict_type: MetaRoleConflictType::EntitlementConflict,
                    conflicting_items: serde_json::json!({
                        "entitlement_id": entitlement_id,
                        "grant_meta_role": grant_mr,
                        "deny_meta_role": deny_mr
                    }),
                });
            }
        }

        Ok(conflicts)
    }

    /// Detect constraint conflicts (different values for same constraint type) (T055).
    pub async fn detect_constraint_conflicts(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        meta_role_ids: &[Uuid],
    ) -> Result<Vec<ConflictInfo>> {
        let mut conflicts = Vec::new();

        // Get all constraints from all meta-roles, grouped by type
        let mut constraint_map: std::collections::HashMap<String, Vec<(Uuid, serde_json::Value)>> =
            std::collections::HashMap::new();

        for &meta_role_id in meta_role_ids {
            let constraints =
                GovMetaRoleConstraint::list_by_meta_role(&self.pool, tenant_id, meta_role_id)
                    .await
                    .map_err(GovernanceError::Database)?;

            for c in constraints {
                constraint_map
                    .entry(c.constraint_type.clone())
                    .or_default()
                    .push((meta_role_id, c.constraint_value.clone()));
            }
        }

        // Check for conflicts (same constraint type with different values)
        // Exclude boolean constraints (handled by detect_policy_conflicts)
        for (constraint_type, entries) in constraint_map {
            if entries.len() < 2 {
                continue;
            }

            // Skip boolean types (they're policy conflicts)
            if entries.iter().any(|(_, v)| v.is_boolean()) {
                continue;
            }

            // Check if values differ
            let first_value = &entries[0].1;
            let has_conflict = entries.iter().skip(1).any(|(_, v)| v != first_value);

            if has_conflict {
                // Find first two conflicting entries
                for i in 0..entries.len() {
                    for j in (i + 1)..entries.len() {
                        if entries[i].1 != entries[j].1 {
                            let (mr_a, mr_b) = if entries[i].0 < entries[j].0 {
                                (entries[i].0, entries[j].0)
                            } else {
                                (entries[j].0, entries[i].0)
                            };

                            conflicts.push(ConflictInfo {
                                meta_role_a_id: mr_a,
                                meta_role_b_id: mr_b,
                                affected_role_id: role_id,
                                conflict_type: MetaRoleConflictType::ConstraintConflict,
                                conflicting_items: serde_json::json!({
                                    "constraint_type": constraint_type,
                                    "value_a": entries[i].1,
                                    "value_b": entries[j].1,
                                    "meta_role_a": mr_a,
                                    "meta_role_b": mr_b
                                }),
                            });
                            break;
                        }
                    }
                }
            }
        }

        Ok(conflicts)
    }

    /// Detect policy conflicts (contradicting boolean policies) (T056).
    pub async fn detect_policy_conflicts(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        meta_role_ids: &[Uuid],
    ) -> Result<Vec<ConflictInfo>> {
        let mut conflicts = Vec::new();

        // Get all boolean constraints from all meta-roles
        let mut bool_constraint_map: std::collections::HashMap<String, Vec<(Uuid, bool)>> =
            std::collections::HashMap::new();

        for &meta_role_id in meta_role_ids {
            let constraints =
                GovMetaRoleConstraint::list_by_meta_role(&self.pool, tenant_id, meta_role_id)
                    .await
                    .map_err(GovernanceError::Database)?;

            for c in constraints {
                if let Some(b) = c.constraint_value.as_bool() {
                    bool_constraint_map
                        .entry(c.constraint_type.clone())
                        .or_default()
                        .push((meta_role_id, b));
                }
            }
        }

        // Check for conflicts (same policy with true vs false)
        for (policy_name, entries) in bool_constraint_map {
            if entries.len() < 2 {
                continue;
            }

            let has_true = entries.iter().any(|(_, v)| *v);
            let has_false = entries.iter().any(|(_, v)| !*v);

            if has_true && has_false {
                let true_mr = entries.iter().find(|(_, v)| *v).map(|(id, _)| *id).unwrap();
                let false_mr = entries
                    .iter()
                    .find(|(_, v)| !*v)
                    .map(|(id, _)| *id)
                    .unwrap();

                let (mr_a, mr_b) = if true_mr < false_mr {
                    (true_mr, false_mr)
                } else {
                    (false_mr, true_mr)
                };

                conflicts.push(ConflictInfo {
                    meta_role_a_id: mr_a,
                    meta_role_b_id: mr_b,
                    affected_role_id: role_id,
                    conflict_type: MetaRoleConflictType::PolicyConflict,
                    conflicting_items: serde_json::json!({
                        "policy": policy_name,
                        "true_meta_role": true_mr,
                        "false_meta_role": false_mr
                    }),
                });
            }
        }

        Ok(conflicts)
    }

    /// Record detected conflicts in the database.
    pub async fn record_conflicts(
        &self,
        tenant_id: Uuid,
        conflicts: &[ConflictInfo],
    ) -> Result<Vec<Uuid>> {
        let mut conflict_ids = Vec::new();

        for conflict in conflicts {
            // Check if conflict already exists
            let existing = GovMetaRoleConflict::find_existing(
                &self.pool,
                tenant_id,
                conflict.meta_role_a_id,
                conflict.meta_role_b_id,
                conflict.affected_role_id,
            )
            .await
            .map_err(GovernanceError::Database)?;

            if existing.is_some() {
                // Skip already recorded conflict
                continue;
            }

            // Create new conflict record
            let created_conflict = GovMetaRoleConflict::create(
                &self.pool,
                tenant_id,
                xavyo_db::CreateGovMetaRoleConflict {
                    meta_role_a_id: conflict.meta_role_a_id,
                    meta_role_b_id: conflict.meta_role_b_id,
                    affected_role_id: conflict.affected_role_id,
                    conflict_type: conflict.conflict_type,
                    conflicting_items: conflict.conflicting_items.clone(),
                },
            )
            .await
            .map_err(GovernanceError::Database)?;

            let conflict_id = created_conflict.id;
            conflict_ids.push(conflict_id);

            info!(
                tenant_id = %tenant_id,
                conflict_id = %conflict_id,
                conflict_type = ?conflict.conflict_type,
                "Conflict detected and recorded"
            );
        }

        Ok(conflict_ids)
    }

    // =========================================================================
    // Conflict Resolution
    // =========================================================================

    /// Resolve conflict by priority (lower priority number wins) (T058).
    pub async fn resolve_conflict_by_priority(
        &self,
        tenant_id: Uuid,
        conflict_id: Uuid,
        actor_id: Uuid,
    ) -> Result<GovMetaRoleConflict> {
        // Get the conflict
        let conflict = GovMetaRoleConflict::find_by_id(&self.pool, tenant_id, conflict_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::MetaRoleConflictNotFound(conflict_id))?;

        if conflict.resolution_status != ResolutionStatus::Unresolved {
            return Err(GovernanceError::MetaRoleConflictAlreadyResolved(
                conflict_id,
            ));
        }

        // Get both meta-roles to compare priorities
        let meta_role_a = GovMetaRole::find_by_id(&self.pool, tenant_id, conflict.meta_role_a_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::MetaRoleNotFound(conflict.meta_role_a_id))?;

        let meta_role_b = GovMetaRole::find_by_id(&self.pool, tenant_id, conflict.meta_role_b_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::MetaRoleNotFound(conflict.meta_role_b_id))?;

        // Determine winner (lower priority wins, then earlier created_at)
        let winning_meta_role = if meta_role_a.priority < meta_role_b.priority {
            meta_role_a
        } else if meta_role_b.priority < meta_role_a.priority {
            meta_role_b
        } else {
            // Equal priority - first created wins
            if meta_role_a.created_at <= meta_role_b.created_at {
                meta_role_a
            } else {
                meta_role_b
            }
        };

        // Update conflict with resolution
        let resolution_choice = serde_json::json!({
            "winning_meta_role_id": winning_meta_role.id,
            "winning_meta_role_name": winning_meta_role.name,
            "resolution_reason": "priority"
        });

        let updated_conflict = GovMetaRoleConflict::resolve(
            &self.pool,
            tenant_id,
            conflict_id,
            actor_id,
            ResolveGovMetaRoleConflict {
                resolution_status: ResolutionStatus::ResolvedPriority,
                resolution_choice: Some(resolution_choice),
            },
        )
        .await
        .map_err(GovernanceError::Database)?
        .ok_or_else(|| GovernanceError::MetaRoleConflictNotFound(conflict_id))?;

        // Record event
        self.record_conflict_event(
            tenant_id,
            conflict_id,
            actor_id,
            MetaRoleEventType::ConflictResolved,
            serde_json::json!({
                "resolution_type": "priority",
                "winning_meta_role_id": winning_meta_role.id
            }),
        )
        .await?;

        info!(
            tenant_id = %tenant_id,
            conflict_id = %conflict_id,
            winning_meta_role = %winning_meta_role.id,
            "Conflict resolved by priority"
        );

        Ok(updated_conflict)
    }

    /// Resolve conflict manually with admin choice (T059).
    pub async fn resolve_conflict_manually(
        &self,
        tenant_id: Uuid,
        conflict_id: Uuid,
        actor_id: Uuid,
        winning_meta_role_id: Uuid,
        reason: Option<String>,
    ) -> Result<GovMetaRoleConflict> {
        // Get the conflict
        let conflict = GovMetaRoleConflict::find_by_id(&self.pool, tenant_id, conflict_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::MetaRoleConflictNotFound(conflict_id))?;

        if conflict.resolution_status != ResolutionStatus::Unresolved {
            return Err(GovernanceError::MetaRoleConflictAlreadyResolved(
                conflict_id,
            ));
        }

        // Verify winning_meta_role_id is one of the conflicting meta-roles
        if winning_meta_role_id != conflict.meta_role_a_id
            && winning_meta_role_id != conflict.meta_role_b_id
        {
            return Err(GovernanceError::Validation(
                "Winning meta-role must be one of the conflicting meta-roles".to_string(),
            ));
        }

        // Get the winning meta-role
        let winning_meta_role =
            GovMetaRole::find_by_id(&self.pool, tenant_id, winning_meta_role_id)
                .await
                .map_err(GovernanceError::Database)?
                .ok_or_else(|| GovernanceError::MetaRoleNotFound(winning_meta_role_id))?;

        // Update conflict with resolution
        let resolution_choice = serde_json::json!({
            "winning_meta_role_id": winning_meta_role.id,
            "winning_meta_role_name": winning_meta_role.name,
            "resolution_reason": reason.clone().unwrap_or_else(|| "manual".to_string())
        });

        let updated_conflict = GovMetaRoleConflict::resolve(
            &self.pool,
            tenant_id,
            conflict_id,
            actor_id,
            ResolveGovMetaRoleConflict {
                resolution_status: ResolutionStatus::ResolvedManual,
                resolution_choice: Some(resolution_choice),
            },
        )
        .await
        .map_err(GovernanceError::Database)?
        .ok_or_else(|| GovernanceError::MetaRoleConflictNotFound(conflict_id))?;

        // Record event
        self.record_conflict_event(
            tenant_id,
            conflict_id,
            actor_id,
            MetaRoleEventType::ConflictResolved,
            serde_json::json!({
                "resolution_type": "manual",
                "winning_meta_role_id": winning_meta_role.id,
                "reason": reason
            }),
        )
        .await?;

        info!(
            tenant_id = %tenant_id,
            conflict_id = %conflict_id,
            winning_meta_role = %winning_meta_role.id,
            "Conflict resolved manually"
        );

        Ok(updated_conflict)
    }

    /// Ignore conflict (acknowledged but not resolved) (T060).
    pub async fn ignore_conflict(
        &self,
        tenant_id: Uuid,
        conflict_id: Uuid,
        actor_id: Uuid,
        reason: String,
    ) -> Result<GovMetaRoleConflict> {
        // Get the conflict
        let conflict = GovMetaRoleConflict::find_by_id(&self.pool, tenant_id, conflict_id)
            .await
            .map_err(GovernanceError::Database)?
            .ok_or_else(|| GovernanceError::MetaRoleConflictNotFound(conflict_id))?;

        if conflict.resolution_status != ResolutionStatus::Unresolved {
            return Err(GovernanceError::MetaRoleConflictAlreadyResolved(
                conflict_id,
            ));
        }

        // Update conflict status to ignored
        let resolution_choice = serde_json::json!({
            "reason": reason.clone()
        });

        let updated_conflict = GovMetaRoleConflict::resolve(
            &self.pool,
            tenant_id,
            conflict_id,
            actor_id,
            ResolveGovMetaRoleConflict {
                resolution_status: ResolutionStatus::Ignored,
                resolution_choice: Some(resolution_choice),
            },
        )
        .await
        .map_err(GovernanceError::Database)?
        .ok_or_else(|| GovernanceError::MetaRoleConflictNotFound(conflict_id))?;

        // Record event
        self.record_conflict_event(
            tenant_id,
            conflict_id,
            actor_id,
            MetaRoleEventType::ConflictResolved,
            serde_json::json!({
                "resolution_type": "ignored",
                "reason": reason
            }),
        )
        .await?;

        warn!(
            tenant_id = %tenant_id,
            conflict_id = %conflict_id,
            reason = %reason,
            "Conflict marked as ignored"
        );

        Ok(updated_conflict)
    }

    // =========================================================================
    // Listing and Querying
    // =========================================================================

    /// List conflicts with optional status filter.
    /// Returns (conflicts, `total_count`) for proper pagination.
    pub async fn list_conflicts(
        &self,
        tenant_id: Uuid,
        status: Option<ResolutionStatus>,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<GovMetaRoleConflict>, i64)> {
        let conflicts = GovMetaRoleConflict::list(&self.pool, tenant_id, status, limit, offset)
            .await
            .map_err(GovernanceError::Database)?;

        let total = GovMetaRoleConflict::count(&self.pool, tenant_id, status)
            .await
            .map_err(GovernanceError::Database)?;

        Ok((conflicts, total))
    }

    /// Count unresolved conflicts.
    pub async fn count_unresolved(&self, tenant_id: Uuid) -> Result<i64> {
        let count = GovMetaRoleConflict::count_unresolved(&self.pool, tenant_id)
            .await
            .map_err(GovernanceError::Database)?;

        Ok(count)
    }

    /// Check if a role has any unresolved conflicts.
    pub async fn role_has_conflicts(&self, tenant_id: Uuid, role_id: Uuid) -> Result<bool> {
        let count = GovMetaRoleConflict::count_by_role(
            &self.pool,
            tenant_id,
            role_id,
            Some(ResolutionStatus::Unresolved),
        )
        .await
        .map_err(GovernanceError::Database)?;

        Ok(count > 0)
    }

    // =========================================================================
    // Event Recording
    // =========================================================================

    /// Record a conflict-related event.
    async fn record_conflict_event(
        &self,
        tenant_id: Uuid,
        conflict_id: Uuid,
        actor_id: Uuid,
        event_type: MetaRoleEventType,
        metadata: serde_json::Value,
    ) -> Result<()> {
        use xavyo_db::GovMetaRoleEvent;

        GovMetaRoleEvent::create(
            &self.pool,
            tenant_id,
            CreateGovMetaRoleEvent {
                meta_role_id: None, // Conflict events don't have a single meta-role
                event_type,
                actor_id: Some(actor_id),
                changes: None,
                affected_roles: None,
                metadata: Some(serde_json::json!({
                    "conflict_id": conflict_id,
                    "details": metadata
                })),
            },
        )
        .await
        .map_err(GovernanceError::Database)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conflict_info_structure() {
        let conflict = ConflictInfo {
            meta_role_a_id: Uuid::new_v4(),
            meta_role_b_id: Uuid::new_v4(),
            affected_role_id: Uuid::new_v4(),
            conflict_type: MetaRoleConflictType::EntitlementConflict,
            conflicting_items: serde_json::json!({"test": true}),
        };

        assert!(conflict.meta_role_a_id != conflict.meta_role_b_id);
    }

    #[test]
    fn test_conflict_info_entitlement_conflict() {
        let meta_a = Uuid::new_v4();
        let meta_b = Uuid::new_v4();
        let role_id = Uuid::new_v4();

        let conflict = ConflictInfo {
            meta_role_a_id: meta_a,
            meta_role_b_id: meta_b,
            affected_role_id: role_id,
            conflict_type: MetaRoleConflictType::EntitlementConflict,
            conflicting_items: serde_json::json!({
                "entitlement_id": Uuid::new_v4().to_string(),
                "meta_role_a_permission": "grant",
                "meta_role_b_permission": "deny"
            }),
        };

        assert_eq!(
            conflict.conflict_type,
            MetaRoleConflictType::EntitlementConflict
        );
        assert!(conflict
            .conflicting_items
            .get("meta_role_a_permission")
            .is_some());
        assert!(conflict
            .conflicting_items
            .get("meta_role_b_permission")
            .is_some());
    }

    #[test]
    fn test_conflict_info_constraint_conflict() {
        let conflict = ConflictInfo {
            meta_role_a_id: Uuid::new_v4(),
            meta_role_b_id: Uuid::new_v4(),
            affected_role_id: Uuid::new_v4(),
            conflict_type: MetaRoleConflictType::ConstraintConflict,
            conflicting_items: serde_json::json!({
                "constraint_type": "max_session_duration",
                "meta_role_a_value": 3600,
                "meta_role_b_value": 7200
            }),
        };

        assert_eq!(
            conflict.conflict_type,
            MetaRoleConflictType::ConstraintConflict
        );
    }

    #[test]
    fn test_conflict_info_policy_conflict() {
        let conflict = ConflictInfo {
            meta_role_a_id: Uuid::new_v4(),
            meta_role_b_id: Uuid::new_v4(),
            affected_role_id: Uuid::new_v4(),
            conflict_type: MetaRoleConflictType::PolicyConflict,
            conflicting_items: serde_json::json!({
                "policy_name": "require_mfa",
                "meta_role_a_value": true,
                "meta_role_b_value": false
            }),
        };

        assert_eq!(conflict.conflict_type, MetaRoleConflictType::PolicyConflict);
    }

    #[test]
    fn test_all_conflict_types() {
        // Verify all conflict types exist
        let types = [
            MetaRoleConflictType::EntitlementConflict,
            MetaRoleConflictType::ConstraintConflict,
            MetaRoleConflictType::PolicyConflict,
        ];

        assert_eq!(types.len(), 3);
    }

    #[test]
    fn test_resolution_status_values() {
        // Verify all resolution statuses exist
        let statuses = [
            ResolutionStatus::Unresolved,
            ResolutionStatus::ResolvedPriority,
            ResolutionStatus::ResolvedManual,
            ResolutionStatus::Ignored,
        ];

        assert_eq!(statuses.len(), 4);
    }

    #[test]
    fn test_permission_type_values() {
        // Verify grant and deny permissions
        let permissions = [PermissionType::Grant, PermissionType::Deny];

        assert_eq!(permissions.len(), 2);

        // Test that they are different
        assert_ne!(PermissionType::Grant, PermissionType::Deny);
    }

    #[test]
    fn test_conflict_info_json_serializable() {
        let conflict = ConflictInfo {
            meta_role_a_id: Uuid::new_v4(),
            meta_role_b_id: Uuid::new_v4(),
            affected_role_id: Uuid::new_v4(),
            conflict_type: MetaRoleConflictType::EntitlementConflict,
            conflicting_items: serde_json::json!({
                "entitlement_name": "admin_access",
                "severity": "high"
            }),
        };

        // Test that conflicting_items is properly structured JSON
        assert!(conflict.conflicting_items.is_object());
        assert_eq!(conflict.conflicting_items.get("severity").unwrap(), "high");
    }

    #[test]
    fn test_conflict_info_clone() {
        let original = ConflictInfo {
            meta_role_a_id: Uuid::new_v4(),
            meta_role_b_id: Uuid::new_v4(),
            affected_role_id: Uuid::new_v4(),
            conflict_type: MetaRoleConflictType::ConstraintConflict,
            conflicting_items: serde_json::json!({}),
        };

        let cloned = original.clone();

        assert_eq!(original.meta_role_a_id, cloned.meta_role_a_id);
        assert_eq!(original.meta_role_b_id, cloned.meta_role_b_id);
        assert_eq!(original.affected_role_id, cloned.affected_role_id);
        assert_eq!(original.conflict_type, cloned.conflict_type);
    }

    #[test]
    fn test_conflict_with_multiple_items() {
        let conflict = ConflictInfo {
            meta_role_a_id: Uuid::new_v4(),
            meta_role_b_id: Uuid::new_v4(),
            affected_role_id: Uuid::new_v4(),
            conflict_type: MetaRoleConflictType::EntitlementConflict,
            conflicting_items: serde_json::json!({
                "conflicting_entitlements": [
                    {"id": Uuid::new_v4().to_string(), "name": "read_data"},
                    {"id": Uuid::new_v4().to_string(), "name": "write_data"}
                ],
                "count": 2
            }),
        };

        let items = conflict
            .conflicting_items
            .get("conflicting_entitlements")
            .unwrap();
        assert!(items.is_array());
        assert_eq!(items.as_array().unwrap().len(), 2);
    }
}
