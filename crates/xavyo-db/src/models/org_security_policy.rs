//! Organization-level security policy model (F-066).
//!
//! Supports per-organization security policies with inheritance from parent organizations.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Policy type discriminator for organization security policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrgPolicyType {
    /// Password requirements policy
    Password,
    /// Multi-factor authentication policy
    Mfa,
    /// Session management policy
    Session,
    /// IP-based access restriction policy
    IpRestriction,
}

impl OrgPolicyType {
    /// Convert to database string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::Mfa => "mfa",
            Self::Session => "session",
            Self::IpRestriction => "ip_restriction",
        }
    }

    /// Parse from database string representation.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "password" => Some(Self::Password),
            "mfa" => Some(Self::Mfa),
            "session" => Some(Self::Session),
            "ip_restriction" => Some(Self::IpRestriction),
            _ => None,
        }
    }
}

impl std::fmt::Display for OrgPolicyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Organization-level security policy.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct OrgSecurityPolicy {
    /// Unique identifier.
    pub id: Uuid,
    /// Tenant this policy belongs to.
    pub tenant_id: Uuid,
    /// Group/organization this policy applies to.
    pub group_id: Uuid,
    /// Type of policy (stored as varchar in DB).
    pub policy_type: String,
    /// Policy configuration as JSONB.
    pub config: serde_json::Value,
    /// Whether this policy is active.
    pub is_active: bool,
    /// When the policy was created.
    pub created_at: DateTime<Utc>,
    /// When the policy was last updated.
    pub updated_at: DateTime<Utc>,
    /// User who created the policy.
    pub created_by: Option<Uuid>,
    /// User who last updated the policy.
    pub updated_by: Option<Uuid>,
}

impl OrgSecurityPolicy {
    /// Get the policy type as enum.
    #[must_use]
    pub fn policy_type_enum(&self) -> Option<OrgPolicyType> {
        OrgPolicyType::parse(&self.policy_type)
    }
}

/// Request to create an organization security policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateOrgSecurityPolicy {
    /// Type of policy to create.
    pub policy_type: OrgPolicyType,
    /// Policy configuration (type-specific JSON).
    pub config: serde_json::Value,
    /// Whether the policy should be active (default: true).
    #[serde(default = "default_active")]
    pub is_active: bool,
}

fn default_active() -> bool {
    true
}

/// Request to update an organization security policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateOrgSecurityPolicy {
    /// Updated policy configuration.
    pub config: serde_json::Value,
    /// Updated active status.
    pub is_active: Option<bool>,
}

/// Filter for listing organization security policies.
#[derive(Debug, Clone, Default)]
pub struct OrgSecurityPolicyFilter {
    /// Filter by group ID.
    pub group_id: Option<Uuid>,
    /// Filter by policy type.
    pub policy_type: Option<OrgPolicyType>,
    /// Filter by active status.
    pub is_active: Option<bool>,
}

/// Effective policy with source attribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectiveOrgPolicy {
    /// The resolved policy configuration.
    pub config: serde_json::Value,
    /// Where this policy came from.
    pub source: PolicySource,
    /// Policy type.
    pub policy_type: OrgPolicyType,
}

/// Source attribution for an effective policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicySource {
    /// Policy is defined directly on the target organization.
    Local {
        /// The group ID where the policy is defined.
        group_id: Uuid,
        /// Display name of the group.
        group_name: String,
    },
    /// Policy is inherited from a parent organization.
    Inherited {
        /// The group ID where the policy is defined.
        group_id: Uuid,
        /// Display name of the group.
        group_name: String,
    },
    /// Policy falls back to tenant default.
    TenantDefault,
}

/// Row returned from effective policy resolution query.
#[derive(Debug, Clone, FromRow)]
pub struct EffectivePolicyRow {
    /// Policy ID (if found).
    pub id: Option<Uuid>,
    /// Group ID where policy was found.
    pub group_id: Option<Uuid>,
    /// Group name where policy was found.
    pub group_name: Option<String>,
    /// Policy configuration.
    pub config: Option<serde_json::Value>,
    /// Depth in hierarchy (0 = local, >0 = inherited).
    pub depth: i32,
}

impl OrgSecurityPolicy {
    /// Find a policy by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM org_security_policies
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a policy by group and type.
    pub async fn find_by_group_and_type(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        group_id: Uuid,
        policy_type: OrgPolicyType,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM org_security_policies
            WHERE tenant_id = $1 AND group_id = $2 AND policy_type = $3
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(policy_type.as_str())
        .fetch_optional(pool)
        .await
    }

    /// List policies for a group.
    pub async fn list_by_group(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        group_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM org_security_policies
            WHERE tenant_id = $1 AND group_id = $2
            ORDER BY policy_type
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .fetch_all(pool)
        .await
    }

    /// List all policies in a tenant with optional filters.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &OrgSecurityPolicyFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM org_security_policies
            WHERE tenant_id = $1
            ",
        );

        let mut param_count = 1;

        if filter.group_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND group_id = ${param_count}"));
        }
        if filter.policy_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND policy_type = ${param_count}"));
        }
        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${param_count}"));
        }

        query.push_str(&format!(
            " ORDER BY group_id, policy_type LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(group_id) = filter.group_id {
            q = q.bind(group_id);
        }
        if let Some(policy_type) = &filter.policy_type {
            q = q.bind(policy_type.as_str());
        }
        if let Some(is_active) = filter.is_active {
            q = q.bind(is_active);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count policies in a tenant with optional filters.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &OrgSecurityPolicyFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM org_security_policies
            WHERE tenant_id = $1
            ",
        );

        let mut param_count = 1;

        if filter.group_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND group_id = ${param_count}"));
        }
        if filter.policy_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND policy_type = ${param_count}"));
        }
        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${param_count}"));
        }

        let mut q = sqlx::query_as::<_, (i64,)>(&query).bind(tenant_id);

        if let Some(group_id) = filter.group_id {
            q = q.bind(group_id);
        }
        if let Some(policy_type) = &filter.policy_type {
            q = q.bind(policy_type.as_str());
        }
        if let Some(is_active) = filter.is_active {
            q = q.bind(is_active);
        }

        let (count,) = q.fetch_one(pool).await?;
        Ok(count)
    }

    /// Create a new organization security policy.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        group_id: Uuid,
        create: &CreateOrgSecurityPolicy,
        created_by: Option<Uuid>,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO org_security_policies
                (tenant_id, group_id, policy_type, config, is_active, created_by, updated_by)
            VALUES ($1, $2, $3, $4, $5, $6, $6)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(create.policy_type.as_str())
        .bind(&create.config)
        .bind(create.is_active)
        .bind(created_by)
        .fetch_one(pool)
        .await
    }

    /// Update an existing organization security policy.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        update: &UpdateOrgSecurityPolicy,
        updated_by: Option<Uuid>,
    ) -> Result<Option<Self>, sqlx::Error> {
        let is_active = update.is_active;

        if let Some(active) = is_active {
            sqlx::query_as(
                r"
                UPDATE org_security_policies
                SET config = $3, is_active = $4, updated_by = $5
                WHERE id = $1 AND tenant_id = $2
                RETURNING *
                ",
            )
            .bind(id)
            .bind(tenant_id)
            .bind(&update.config)
            .bind(active)
            .bind(updated_by)
            .fetch_optional(pool)
            .await
        } else {
            sqlx::query_as(
                r"
                UPDATE org_security_policies
                SET config = $3, updated_by = $4
                WHERE id = $1 AND tenant_id = $2
                RETURNING *
                ",
            )
            .bind(id)
            .bind(tenant_id)
            .bind(&update.config)
            .bind(updated_by)
            .fetch_optional(pool)
            .await
        }
    }

    /// Upsert a policy (create or update).
    pub async fn upsert(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        group_id: Uuid,
        create: &CreateOrgSecurityPolicy,
        user_id: Option<Uuid>,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO org_security_policies
                (tenant_id, group_id, policy_type, config, is_active, created_by, updated_by)
            VALUES ($1, $2, $3, $4, $5, $6, $6)
            ON CONFLICT (tenant_id, group_id, policy_type)
            DO UPDATE SET
                config = EXCLUDED.config,
                is_active = EXCLUDED.is_active,
                updated_by = EXCLUDED.created_by,
                updated_at = NOW()
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(create.policy_type.as_str())
        .bind(&create.config)
        .bind(create.is_active)
        .bind(user_id)
        .fetch_one(pool)
        .await
    }

    /// Delete a policy.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM org_security_policies
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete a policy by group and type.
    pub async fn delete_by_group_and_type(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        group_id: Uuid,
        policy_type: OrgPolicyType,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM org_security_policies
            WHERE tenant_id = $1 AND group_id = $2 AND policy_type = $3
            ",
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(policy_type.as_str())
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Get the effective policy for an organization by walking up the hierarchy.
    /// Returns the first policy found (most specific wins).
    /// Max depth limit of 10 levels to prevent infinite loops.
    pub async fn get_effective_policy(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        group_id: Uuid,
        policy_type: OrgPolicyType,
    ) -> Result<Option<EffectivePolicyRow>, sqlx::Error> {
        sqlx::query_as(
            r"
            WITH RECURSIVE org_hierarchy AS (
                -- Start with the target group
                SELECT g.id, g.parent_id, g.display_name, 0 as depth
                FROM groups g
                WHERE g.id = $1 AND g.tenant_id = $2

                UNION ALL

                -- Walk up the tree
                SELECT g.id, g.parent_id, g.display_name, h.depth + 1
                FROM groups g
                JOIN org_hierarchy h ON g.id = h.parent_id
                WHERE g.tenant_id = $2 AND h.depth < 10
            )
            SELECT
                p.id,
                h.id as group_id,
                h.display_name as group_name,
                p.config,
                h.depth
            FROM org_hierarchy h
            LEFT JOIN org_security_policies p
                ON p.group_id = h.id
                AND p.tenant_id = $2
                AND p.policy_type = $3
                AND p.is_active = true
            WHERE p.id IS NOT NULL
            ORDER BY h.depth ASC
            LIMIT 1
            ",
        )
        .bind(group_id)
        .bind(tenant_id)
        .bind(policy_type.as_str())
        .fetch_optional(pool)
        .await
    }

    /// Get all policies in the hierarchy for conflict detection.
    pub async fn get_hierarchy_policies(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        group_id: Uuid,
        policy_type: OrgPolicyType,
    ) -> Result<Vec<EffectivePolicyRow>, sqlx::Error> {
        sqlx::query_as(
            r"
            WITH RECURSIVE org_hierarchy AS (
                -- Start with the target group
                SELECT g.id, g.parent_id, g.display_name, 0 as depth
                FROM groups g
                WHERE g.id = $1 AND g.tenant_id = $2

                UNION ALL

                -- Walk up the tree
                SELECT g.id, g.parent_id, g.display_name, h.depth + 1
                FROM groups g
                JOIN org_hierarchy h ON g.id = h.parent_id
                WHERE g.tenant_id = $2 AND h.depth < 10
            )
            SELECT
                p.id,
                h.id as group_id,
                h.display_name as group_name,
                p.config,
                h.depth
            FROM org_hierarchy h
            LEFT JOIN org_security_policies p
                ON p.group_id = h.id
                AND p.tenant_id = $2
                AND p.policy_type = $3
                AND p.is_active = true
            WHERE p.id IS NOT NULL
            ORDER BY h.depth ASC
            ",
        )
        .bind(group_id)
        .bind(tenant_id)
        .bind(policy_type.as_str())
        .fetch_all(pool)
        .await
    }

    /// Get policies for child organizations (for conflict detection).
    pub async fn get_child_policies(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        group_id: Uuid,
        policy_type: OrgPolicyType,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            WITH RECURSIVE org_descendants AS (
                -- Start with direct children
                SELECT g.id, g.display_name, 1 as depth
                FROM groups g
                WHERE g.parent_id = $1 AND g.tenant_id = $2

                UNION ALL

                -- Walk down the tree
                SELECT g.id, g.display_name, d.depth + 1
                FROM groups g
                JOIN org_descendants d ON g.parent_id = d.id
                WHERE d.depth < 10
            )
            SELECT p.*
            FROM org_security_policies p
            JOIN org_descendants d ON p.group_id = d.id
            WHERE p.tenant_id = $2
                AND p.policy_type = $3
                AND p.is_active = true
            ORDER BY d.depth ASC
            ",
        )
        .bind(group_id)
        .bind(tenant_id)
        .bind(policy_type.as_str())
        .fetch_all(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_type_conversion() {
        assert_eq!(OrgPolicyType::Password.as_str(), "password");
        assert_eq!(OrgPolicyType::Mfa.as_str(), "mfa");
        assert_eq!(OrgPolicyType::Session.as_str(), "session");
        assert_eq!(OrgPolicyType::IpRestriction.as_str(), "ip_restriction");

        assert_eq!(
            OrgPolicyType::parse("password"),
            Some(OrgPolicyType::Password)
        );
        assert_eq!(OrgPolicyType::parse("mfa"), Some(OrgPolicyType::Mfa));
        assert_eq!(
            OrgPolicyType::parse("session"),
            Some(OrgPolicyType::Session)
        );
        assert_eq!(
            OrgPolicyType::parse("ip_restriction"),
            Some(OrgPolicyType::IpRestriction)
        );
        assert_eq!(OrgPolicyType::parse("unknown"), None);
    }

    #[test]
    fn test_create_policy_request() {
        let create = CreateOrgSecurityPolicy {
            policy_type: OrgPolicyType::Password,
            config: serde_json::json!({
                "min_length": 12,
                "require_uppercase": true
            }),
            is_active: true,
        };

        assert_eq!(create.policy_type, OrgPolicyType::Password);
        assert!(create.is_active);
    }

    #[test]
    fn test_policy_source_serialization() {
        let local = PolicySource::Local {
            group_id: Uuid::new_v4(),
            group_name: "Finance".to_string(),
        };
        let json = serde_json::to_string(&local).unwrap();
        assert!(json.contains("\"type\":\"local\""));

        let inherited = PolicySource::Inherited {
            group_id: Uuid::new_v4(),
            group_name: "Headquarters".to_string(),
        };
        let json = serde_json::to_string(&inherited).unwrap();
        assert!(json.contains("\"type\":\"inherited\""));

        let tenant = PolicySource::TenantDefault;
        let json = serde_json::to_string(&tenant).unwrap();
        assert!(json.contains("\"type\":\"tenant_default\""));
    }
}
