//! Admin permission model for delegated administration.
//!
//! Represents a single permission capability that can be assigned to role templates.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgExecutor};
use uuid::Uuid;

/// Permission category for grouping permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "VARCHAR", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum PermissionCategory {
    Users,
    Groups,
    Settings,
    Security,
    Audit,
    Branding,
}

impl std::fmt::Display for PermissionCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PermissionCategory::Users => write!(f, "users"),
            PermissionCategory::Groups => write!(f, "groups"),
            PermissionCategory::Settings => write!(f, "settings"),
            PermissionCategory::Security => write!(f, "security"),
            PermissionCategory::Audit => write!(f, "audit"),
            PermissionCategory::Branding => write!(f, "branding"),
        }
    }
}

impl std::str::FromStr for PermissionCategory {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "users" => Ok(PermissionCategory::Users),
            "groups" => Ok(PermissionCategory::Groups),
            "settings" => Ok(PermissionCategory::Settings),
            "security" => Ok(PermissionCategory::Security),
            "audit" => Ok(PermissionCategory::Audit),
            "branding" => Ok(PermissionCategory::Branding),
            _ => Err(format!("Invalid permission category: {}", s)),
        }
    }
}

/// Admin permission entity.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AdminPermission {
    /// Unique identifier.
    pub id: Uuid,
    /// Permission code in format category:action (e.g., users:read).
    pub code: String,
    /// Human-readable name.
    pub name: String,
    /// Detailed description.
    pub description: Option<String>,
    /// Permission category.
    pub category: String,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// Category summary with permission count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategorySummary {
    pub name: String,
    pub permission_count: i64,
}

impl AdminPermission {
    /// Get all permissions.
    pub async fn get_all<'e, E>(executor: E) -> Result<Vec<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT id, code, name, description, category, created_at
            FROM admin_permissions
            ORDER BY category, code
            "#,
        )
        .fetch_all(executor)
        .await
    }

    /// Get permissions by category.
    pub async fn get_by_category<'e, E>(
        executor: E,
        category: &str,
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT id, code, name, description, category, created_at
            FROM admin_permissions
            WHERE category = $1
            ORDER BY code
            "#,
        )
        .bind(category)
        .fetch_all(executor)
        .await
    }

    /// Get permission by code.
    pub async fn get_by_code<'e, E>(executor: E, code: &str) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT id, code, name, description, category, created_at
            FROM admin_permissions
            WHERE code = $1
            "#,
        )
        .bind(code)
        .fetch_optional(executor)
        .await
    }

    /// Get permission by ID.
    pub async fn get_by_id<'e, E>(executor: E, id: Uuid) -> Result<Option<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT id, code, name, description, category, created_at
            FROM admin_permissions
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(executor)
        .await
    }

    /// Get permissions by codes (for bulk lookup).
    pub async fn get_by_codes<'e, E>(
        executor: E,
        codes: &[String],
    ) -> Result<Vec<Self>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT id, code, name, description, category, created_at
            FROM admin_permissions
            WHERE code = ANY($1)
            ORDER BY category, code
            "#,
        )
        .bind(codes)
        .fetch_all(executor)
        .await
    }

    /// Get category summaries with permission counts.
    pub async fn get_category_summaries<'e, E>(
        executor: E,
    ) -> Result<Vec<CategorySummary>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            r#"
            SELECT category, COUNT(*) as count
            FROM admin_permissions
            GROUP BY category
            ORDER BY category
            "#,
        )
        .fetch_all(executor)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(name, permission_count)| CategorySummary {
                name,
                permission_count,
            })
            .collect())
    }

    /// Check if a permission code matches a wildcard pattern.
    /// e.g., "users:read" matches "users:*" or "users:read"
    pub fn matches_pattern(code: &str, pattern: &str) -> bool {
        if code == pattern {
            return true;
        }

        // Check for wildcard pattern (e.g., "users:*")
        if pattern.ends_with(":*") {
            let category = pattern.trim_end_matches(":*");
            if let Some(code_category) = code.split(':').next() {
                return code_category == category;
            }
        }

        false
    }

    /// Expand wildcard patterns to actual permission codes.
    /// Returns the input if not a wildcard, otherwise returns all matching permission codes.
    /// Note: This function fetches all permissions upfront to avoid executor borrowing issues.
    pub async fn expand_wildcards<'e, E>(
        executor: E,
        patterns: &[String],
    ) -> Result<Vec<String>, sqlx::Error>
    where
        E: PgExecutor<'e>,
    {
        // Fetch all permissions upfront
        let all_permissions = Self::get_all(executor).await?;

        let mut result = Vec::new();

        for pattern in patterns {
            if pattern.ends_with(":*") {
                let category = pattern.trim_end_matches(":*");
                // Filter from pre-fetched permissions
                let matching: Vec<String> = all_permissions
                    .iter()
                    .filter(|p| p.category == category)
                    .map(|p| p.code.clone())
                    .collect();
                result.extend(matching);
            } else {
                result.push(pattern.clone());
            }
        }

        // Remove duplicates
        result.sort();
        result.dedup();
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_category_display() {
        assert_eq!(PermissionCategory::Users.to_string(), "users");
        assert_eq!(PermissionCategory::Security.to_string(), "security");
    }

    #[test]
    fn test_permission_category_from_str() {
        assert_eq!(
            "users".parse::<PermissionCategory>().unwrap(),
            PermissionCategory::Users
        );
        assert_eq!(
            "SECURITY".parse::<PermissionCategory>().unwrap(),
            PermissionCategory::Security
        );
        assert!("invalid".parse::<PermissionCategory>().is_err());
    }

    #[test]
    fn test_matches_pattern_exact() {
        assert!(AdminPermission::matches_pattern("users:read", "users:read"));
        assert!(!AdminPermission::matches_pattern(
            "users:read",
            "users:write"
        ));
    }

    #[test]
    fn test_matches_pattern_wildcard() {
        assert!(AdminPermission::matches_pattern("users:read", "users:*"));
        assert!(AdminPermission::matches_pattern("users:create", "users:*"));
        assert!(!AdminPermission::matches_pattern("groups:read", "users:*"));
    }
}
