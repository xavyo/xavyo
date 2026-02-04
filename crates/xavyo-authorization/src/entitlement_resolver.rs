//! Entitlement resolver for authorization decisions.
//!
//! Resolves all effective entitlements for a user from three sources:
//! 1. Direct user assignments
//! 2. Group-based assignments (via group membership)
//! 3. Role-based entitlements (via JWT roles)

use std::collections::HashSet;

use sqlx::PgPool;
use uuid::Uuid;

use crate::types::{EntitlementSource, ResolvedEntitlement};
use xavyo_db::models::gov_entitlement_assignment::GovEntitlementAssignment;
use xavyo_db::models::gov_role_entitlement::GovRoleEntitlement;
use xavyo_db::models::group_membership::GroupMembership;

/// Resolves effective entitlements for a user across all sources.
pub struct EntitlementResolver;

impl EntitlementResolver {
    /// Resolve all effective entitlements for a user.
    ///
    /// Gathers entitlements from three sources:
    /// 1. **Direct assignments**: Entitlements assigned directly to the user
    /// 2. **Group-based**: Entitlements assigned to groups the user belongs to
    /// 3. **Role-based**: Entitlements linked to roles the user holds
    ///
    /// Only active, non-expired assignments are included.
    /// Results are deduplicated by `entitlement_id` (first source wins).
    pub async fn resolve_entitlements(
        pool: &PgPool,
        tenant_id: Uuid,
        user_id: Uuid,
        user_roles: &[String],
    ) -> Vec<ResolvedEntitlement> {
        let mut entitlements = Vec::new();
        let mut seen_ids = HashSet::new();

        // 1. Direct user entitlements
        if let Ok(direct_ids) =
            GovEntitlementAssignment::list_user_entitlement_ids(pool, tenant_id, user_id).await
        {
            for eid in direct_ids {
                if seen_ids.insert(eid) {
                    entitlements.push(ResolvedEntitlement {
                        entitlement_id: eid,
                        source: EntitlementSource::Direct,
                    });
                }
            }
        } else {
            tracing::warn!(
                target: "authorization",
                tenant_id = %tenant_id,
                user_id = %user_id,
                "Failed to load direct entitlements"
            );
        }

        // 2. Group-based entitlements
        match GroupMembership::get_user_groups(pool, tenant_id, user_id).await {
            Ok(groups) => {
                for group_info in groups {
                    if let Ok(group_ids) = GovEntitlementAssignment::list_group_entitlement_ids(
                        pool,
                        tenant_id,
                        group_info.group_id,
                    )
                    .await
                    {
                        for eid in group_ids {
                            if seen_ids.insert(eid) {
                                entitlements.push(ResolvedEntitlement {
                                    entitlement_id: eid,
                                    source: EntitlementSource::Group {
                                        group_id: group_info.group_id,
                                    },
                                });
                            }
                        }
                    } else {
                        tracing::warn!(
                            target: "authorization",
                            tenant_id = %tenant_id,
                            group_id = %group_info.group_id,
                            "Failed to load group entitlements"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    target: "authorization",
                    tenant_id = %tenant_id,
                    user_id = %user_id,
                    error = %e,
                    "Failed to load user groups"
                );
            }
        }

        // 3. Role-based entitlements
        for role_name in user_roles {
            if let Ok(role_ids) =
                GovRoleEntitlement::list_entitlement_ids_by_role(pool, tenant_id, role_name).await
            {
                for eid in role_ids {
                    if seen_ids.insert(eid) {
                        entitlements.push(ResolvedEntitlement {
                            entitlement_id: eid,
                            source: EntitlementSource::Role {
                                role_name: role_name.clone(),
                            },
                        });
                    }
                }
            } else {
                tracing::warn!(
                    target: "authorization",
                    tenant_id = %tenant_id,
                    role_name = %role_name,
                    "Failed to load role entitlements"
                );
            }
        }

        entitlements
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolved_entitlement_dedup_logic() {
        // Test that HashSet-based dedup works correctly
        let mut seen = HashSet::new();
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        assert!(seen.insert(id1));
        assert!(!seen.insert(id1)); // duplicate
        assert!(seen.insert(id2));
    }

    #[test]
    fn test_entitlement_source_variants() {
        let direct = EntitlementSource::Direct;
        let group = EntitlementSource::Group {
            group_id: Uuid::new_v4(),
        };
        let role = EntitlementSource::Role {
            role_name: "admin".to_string(),
        };

        // Verify they are distinct
        assert_ne!(direct, group);
        assert_ne!(group, role);
        assert_ne!(direct, role);
    }

    #[test]
    fn test_resolved_entitlement_construction() {
        let eid = Uuid::new_v4();
        let ent = ResolvedEntitlement {
            entitlement_id: eid,
            source: EntitlementSource::Direct,
        };
        assert_eq!(ent.entitlement_id, eid);
        assert_eq!(ent.source, EntitlementSource::Direct);
    }
}
