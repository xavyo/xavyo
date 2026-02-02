//! IP restriction rule model.
//!
//! Defines IP access rules for tenant IP restrictions with CIDR support.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgExecutor, Type};
use uuid::Uuid;

/// IP rule type (whitelist or blacklist).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "ip_rule_type", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum IpRuleType {
    /// Allow access from matching IPs.
    Whitelist,
    /// Block access from matching IPs.
    Blacklist,
}

impl std::fmt::Display for IpRuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Whitelist => write!(f, "whitelist"),
            Self::Blacklist => write!(f, "blacklist"),
        }
    }
}

/// An IP restriction rule.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct IpRestrictionRule {
    /// Unique identifier for this rule.
    pub id: Uuid,

    /// The tenant this rule belongs to.
    pub tenant_id: Uuid,

    /// Rule type: whitelist or blacklist.
    pub rule_type: IpRuleType,

    /// Target users: "all", "admin", or "role:<name>".
    pub scope: String,

    /// IP address or range in CIDR notation.
    /// Stored as text since SQLx doesn't have native CIDR support.
    #[sqlx(rename = "ip_cidr")]
    pub ip_cidr: String,

    /// Human-readable rule name.
    pub name: String,

    /// Optional rule description.
    pub description: Option<String>,

    /// Whether the rule is active.
    pub is_active: bool,

    /// User who created the rule.
    pub created_by: Option<Uuid>,

    /// When the rule was created.
    pub created_at: DateTime<Utc>,

    /// When the rule was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Input for creating a new IP restriction rule.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateIpRule {
    pub rule_type: IpRuleType,
    pub scope: Option<String>,
    pub ip_cidr: String,
    pub name: String,
    pub description: Option<String>,
    pub is_active: Option<bool>,
}

/// Input for updating an IP restriction rule.
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateIpRule {
    pub rule_type: Option<IpRuleType>,
    pub scope: Option<String>,
    pub ip_cidr: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub is_active: Option<bool>,
}

/// Filter options for listing rules.
#[derive(Debug, Clone, Default)]
pub struct ListRulesFilter {
    pub is_active: Option<bool>,
    pub rule_type: Option<IpRuleType>,
}

impl IpRestrictionRule {
    /// Create a new IP restriction rule.
    pub async fn create<'e, E>(
        executor: E,
        tenant_id: Uuid,
        input: CreateIpRule,
        created_by: Option<Uuid>,
    ) -> Result<Self, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let scope = input.scope.unwrap_or_else(|| "all".to_string());
        let is_active = input.is_active.unwrap_or(true);

        sqlx::query_as(
            r#"
            INSERT INTO ip_restriction_rules (
                tenant_id, rule_type, scope, ip_cidr, name, description, is_active, created_by
            )
            VALUES ($1, $2, $3, $4::cidr, $5, $6, $7, $8)
            RETURNING id, tenant_id, rule_type, scope, ip_cidr::text as ip_cidr, name, description, is_active, created_by, created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(input.rule_type)
        .bind(&scope)
        .bind(&input.ip_cidr)
        .bind(&input.name)
        .bind(&input.description)
        .bind(is_active)
        .bind(created_by)
        .fetch_one(executor)
        .await
    }

    /// Find a rule by ID.
    pub async fn find_by_id<'e, E>(
        executor: E,
        tenant_id: Uuid,
        rule_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r#"
            SELECT id, tenant_id, rule_type, scope, ip_cidr::text as ip_cidr, name, description, is_active, created_by, created_at, updated_at
            FROM ip_restriction_rules
            WHERE tenant_id = $1 AND id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(rule_id)
        .fetch_optional(executor)
        .await
    }

    /// List all rules for a tenant with optional filtering.
    pub async fn list<'e, E>(
        executor: E,
        tenant_id: Uuid,
        filter: ListRulesFilter,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r#"
            SELECT id, tenant_id, rule_type, scope, ip_cidr::text as ip_cidr, name, description, is_active, created_by, created_at, updated_at
            FROM ip_restriction_rules
            WHERE tenant_id = $1
              AND ($2::boolean IS NULL OR is_active = $2)
              AND ($3::ip_rule_type IS NULL OR rule_type = $3)
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(filter.is_active)
        .bind(filter.rule_type)
        .fetch_all(executor)
        .await
    }

    /// List all active rules for a tenant (used by middleware).
    pub async fn list_active<'e, E>(
        executor: E,
        tenant_id: Uuid,
        rule_type: IpRuleType,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r#"
            SELECT id, tenant_id, rule_type, scope, ip_cidr::text as ip_cidr, name, description, is_active, created_by, created_at, updated_at
            FROM ip_restriction_rules
            WHERE tenant_id = $1 AND is_active = TRUE AND rule_type = $2
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(rule_type)
        .fetch_all(executor)
        .await
    }

    /// Update an IP restriction rule.
    pub async fn update<'e, E>(
        executor: E,
        tenant_id: Uuid,
        rule_id: Uuid,
        input: UpdateIpRule,
    ) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as(
            r#"
            UPDATE ip_restriction_rules
            SET
                rule_type = COALESCE($3, rule_type),
                scope = COALESCE($4, scope),
                ip_cidr = COALESCE($5::cidr, ip_cidr),
                name = COALESCE($6, name),
                description = COALESCE($7, description),
                is_active = COALESCE($8, is_active),
                updated_at = NOW()
            WHERE tenant_id = $1 AND id = $2
            RETURNING id, tenant_id, rule_type, scope, ip_cidr::text as ip_cidr, name, description, is_active, created_by, created_at, updated_at
            "#,
        )
        .bind(tenant_id)
        .bind(rule_id)
        .bind(input.rule_type)
        .bind(input.scope)
        .bind(input.ip_cidr)
        .bind(input.name)
        .bind(input.description)
        .bind(input.is_active)
        .fetch_optional(executor)
        .await
    }

    /// Delete an IP restriction rule.
    pub async fn delete<'e, E>(
        executor: E,
        tenant_id: Uuid,
        rule_id: Uuid,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let result =
            sqlx::query("DELETE FROM ip_restriction_rules WHERE tenant_id = $1 AND id = $2")
                .bind(tenant_id)
                .bind(rule_id)
                .execute(executor)
                .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Check if a rule with the given name exists for the tenant.
    pub async fn name_exists<'e, E>(
        executor: E,
        tenant_id: Uuid,
        name: &str,
        exclude_id: Option<Uuid>,
    ) -> Result<bool, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let row: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM ip_restriction_rules
            WHERE tenant_id = $1 AND LOWER(name) = LOWER($2)
              AND ($3::uuid IS NULL OR id != $3)
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .bind(exclude_id)
        .fetch_one(executor)
        .await?;

        Ok(row.0 > 0)
    }

    /// Check if the scope applies to a user with the given roles.
    ///
    /// Returns true if:
    /// - scope is "all"
    /// - scope is "admin" and roles contains "admin"
    /// - scope is "role:X" and roles contains "X"
    pub fn scope_applies(&self, roles: &[String]) -> bool {
        match self.scope.as_str() {
            "all" => true,
            "admin" => roles.iter().any(|r| r == "admin"),
            scope if scope.starts_with("role:") => {
                let role = &scope[5..];
                roles.iter().any(|r| r == role)
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_type_display() {
        assert_eq!(IpRuleType::Whitelist.to_string(), "whitelist");
        assert_eq!(IpRuleType::Blacklist.to_string(), "blacklist");
    }

    #[test]
    fn test_rule_type_serialization() {
        let json = serde_json::to_string(&IpRuleType::Whitelist).unwrap();
        assert_eq!(json, "\"whitelist\"");

        let rule_type: IpRuleType = serde_json::from_str("\"blacklist\"").unwrap();
        assert_eq!(rule_type, IpRuleType::Blacklist);
    }

    #[test]
    fn test_scope_applies_all() {
        let rule = IpRestrictionRule {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            rule_type: IpRuleType::Whitelist,
            scope: "all".to_string(),
            ip_cidr: "192.168.0.0/24".to_string(),
            name: "Test".to_string(),
            description: None,
            is_active: true,
            created_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(rule.scope_applies(&[]));
        assert!(rule.scope_applies(&["user".to_string()]));
        assert!(rule.scope_applies(&["admin".to_string()]));
    }

    #[test]
    fn test_scope_applies_admin() {
        let rule = IpRestrictionRule {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            rule_type: IpRuleType::Whitelist,
            scope: "admin".to_string(),
            ip_cidr: "192.168.0.0/24".to_string(),
            name: "Test".to_string(),
            description: None,
            is_active: true,
            created_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(!rule.scope_applies(&[]));
        assert!(!rule.scope_applies(&["user".to_string()]));
        assert!(rule.scope_applies(&["admin".to_string()]));
        assert!(rule.scope_applies(&["user".to_string(), "admin".to_string()]));
    }

    #[test]
    fn test_scope_applies_role() {
        let rule = IpRestrictionRule {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            rule_type: IpRuleType::Whitelist,
            scope: "role:manager".to_string(),
            ip_cidr: "192.168.0.0/24".to_string(),
            name: "Test".to_string(),
            description: None,
            is_active: true,
            created_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(!rule.scope_applies(&[]));
        assert!(!rule.scope_applies(&["user".to_string()]));
        assert!(!rule.scope_applies(&["admin".to_string()]));
        assert!(rule.scope_applies(&["manager".to_string()]));
        assert!(rule.scope_applies(&["user".to_string(), "manager".to_string()]));
    }
}
