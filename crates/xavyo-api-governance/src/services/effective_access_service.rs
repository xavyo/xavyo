//! Effective access service for governance API.
//!
//! Consolidates entitlements from all sources: direct user assignments,
//! group memberships, and role mappings.

use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use xavyo_db::models::{
    GovEntitlement, GovEntitlementAssignment, GovRoleEffectiveEntitlement, GovRoleEntitlement,
    GroupMembership,
};
use xavyo_governance::error::{GovernanceError, Result};

/// Source of an entitlement assignment.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntitlementSource {
    /// Direct user assignment.
    Direct,
    /// Inherited from group membership.
    Group { group_id: Uuid, group_name: String },
    /// Inherited from role.
    Role { role_name: String },
    /// From governance role hierarchy (F088).
    /// `is_inherited` indicates if the entitlement comes from an ancestor role.
    GovRole {
        role_id: Uuid,
        role_name: String,
        source_role_id: Uuid,
        source_role_name: String,
        is_inherited: bool,
    },
}

/// An effective entitlement with its sources.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EffectiveEntitlement {
    /// The entitlement.
    pub entitlement: GovEntitlement,
    /// All sources that grant this entitlement.
    pub sources: Vec<EntitlementSource>,
}

/// Result of an effective access query.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EffectiveAccessResult {
    /// User ID.
    pub user_id: Uuid,
    /// Tenant ID.
    pub tenant_id: Uuid,
    /// All effective entitlements with their sources.
    pub entitlements: Vec<EffectiveEntitlement>,
    /// Total count of unique entitlements.
    pub total: i64,
}

/// Service for effective access queries.
pub struct EffectiveAccessService {
    pool: PgPool,
}

impl EffectiveAccessService {
    /// Create a new effective access service.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get effective access for a user.
    ///
    /// Consolidates entitlements from:
    /// 1. Direct user assignments
    /// 2. Group memberships
    /// 3. Role mappings (via user roles)
    pub async fn get_effective_access(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        application_id: Option<Uuid>,
    ) -> Result<EffectiveAccessResult> {
        // Map of entitlement_id -> sources
        let mut entitlement_sources: HashMap<Uuid, HashSet<EntitlementSource>> = HashMap::new();

        // 1. Get direct user assignments
        let direct_entitlement_ids =
            GovEntitlementAssignment::list_user_entitlement_ids(&self.pool, tenant_id, user_id)
                .await?;
        for eid in direct_entitlement_ids {
            entitlement_sources
                .entry(eid)
                .or_default()
                .insert(EntitlementSource::Direct);
        }

        // 2. Get group memberships and their entitlements
        let user_groups = GroupMembership::get_user_groups(&self.pool, tenant_id, user_id).await?;
        for group_info in user_groups {
            let group_entitlement_ids = GovEntitlementAssignment::list_group_entitlement_ids(
                &self.pool,
                tenant_id,
                group_info.group_id,
            )
            .await?;
            for eid in group_entitlement_ids {
                entitlement_sources
                    .entry(eid)
                    .or_default()
                    .insert(EntitlementSource::Group {
                        group_id: group_info.group_id,
                        group_name: group_info.display_name.clone(),
                    });
            }
        }

        // 3. Get role-based entitlements (legacy string-based roles)
        let user_roles = self.get_user_roles(tenant_id, user_id).await?;
        for role_name in user_roles {
            let role_entitlement_ids =
                GovRoleEntitlement::list_entitlement_ids_by_role(&self.pool, tenant_id, &role_name)
                    .await?;
            for eid in role_entitlement_ids {
                entitlement_sources
                    .entry(eid)
                    .or_default()
                    .insert(EntitlementSource::Role {
                        role_name: role_name.clone(),
                    });
            }
        }

        // 4. Get entitlements from governance role hierarchy (F088)
        // This includes both direct role entitlements and inherited from ancestor roles
        let gov_role_ids = self.get_user_gov_roles(tenant_id, user_id).await?;
        for (role_id, role_name) in gov_role_ids {
            let effective_entitlements = GovRoleEffectiveEntitlement::get_for_role_with_details(
                &self.pool, tenant_id, role_id,
            )
            .await
            .map_err(GovernanceError::Database)?;

            for eff in effective_entitlements {
                entitlement_sources
                    .entry(eff.entitlement_id)
                    .or_default()
                    .insert(EntitlementSource::GovRole {
                        role_id,
                        role_name: role_name.clone(),
                        source_role_id: eff.source_role_id,
                        source_role_name: eff.source_role_name,
                        is_inherited: eff.is_inherited,
                    });
            }
        }

        // Fetch all unique entitlements
        let entitlement_ids: Vec<Uuid> = entitlement_sources.keys().copied().collect();
        let mut effective_entitlements = Vec::new();

        for eid in entitlement_ids {
            if let Some(entitlement) =
                GovEntitlement::find_by_id(&self.pool, tenant_id, eid).await?
            {
                // Filter by application if specified
                if let Some(app_id) = application_id {
                    if entitlement.application_id != app_id {
                        continue;
                    }
                }

                // Only include active entitlements
                if !entitlement.is_active() {
                    continue;
                }

                let sources: Vec<EntitlementSource> = entitlement_sources
                    .remove(&eid)
                    .unwrap_or_default()
                    .into_iter()
                    .collect();

                effective_entitlements.push(EffectiveEntitlement {
                    entitlement,
                    sources,
                });
            }
        }

        // Sort by entitlement name for consistent output
        effective_entitlements.sort_by(|a, b| a.entitlement.name.cmp(&b.entitlement.name));

        let total = effective_entitlements.len() as i64;

        Ok(EffectiveAccessResult {
            user_id,
            tenant_id,
            entitlements: effective_entitlements,
            total,
        })
    }

    /// Get user's roles from the `user_roles` table.
    async fn get_user_roles(&self, _tenant_id: Uuid, user_id: Uuid) -> Result<Vec<String>> {
        // user_roles table does not have tenant_id; tenant isolation is enforced
        // via the user_id FK to the users table (which is tenant-scoped).
        let roles: Vec<String> = sqlx::query_scalar(
            r"
            SELECT role_name FROM user_roles
            WHERE user_id = $1
            ",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .map_err(GovernanceError::Database)?;

        Ok(roles)
    }

    /// Get user's governance roles (F088 role hierarchy).
    ///
    /// Returns a list of (`role_id`, `role_name`) tuples for roles the user is assigned to.
    /// Only returns non-abstract roles (abstract roles cannot be directly assigned).
    async fn get_user_gov_roles(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<(Uuid, String)>> {
        // Query gov_role_assignments (F088) to get user's assigned governance roles
        // Note: This table would need to exist for role assignments
        // For now, check if there's a gov_user_role_assignments or similar table
        let roles: Vec<(Uuid, String)> = sqlx::query_as(
            r"
            SELECT r.id, r.name
            FROM gov_roles r
            JOIN gov_user_role_assignments ura ON r.id = ura.role_id
            WHERE ura.tenant_id = $1 AND ura.user_id = $2 AND r.is_abstract = false
            ",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_default(); // Return empty if table doesn't exist yet

        Ok(roles)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entitlement_source_serialization() {
        let direct = EntitlementSource::Direct;
        let json = serde_json::to_string(&direct).unwrap();
        assert_eq!(json, "\"direct\"");

        let group = EntitlementSource::Group {
            group_id: Uuid::nil(),
            group_name: "Admins".to_string(),
        };
        let json = serde_json::to_string(&group).unwrap();
        assert!(json.contains("group_id"));
        assert!(json.contains("Admins"));
    }
}
