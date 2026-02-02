//! Governance Persona Archetype model (F063).
//!
//! Defines templates for persona types with attribute mappings and lifecycle policies.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A persona archetype - template for creating personas.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovPersonaArchetype {
    /// Unique identifier for the archetype.
    pub id: Uuid,

    /// The tenant this archetype belongs to.
    pub tenant_id: Uuid,

    /// Archetype name (e.g., "Admin Persona").
    pub name: String,

    /// Human-readable description.
    pub description: Option<String>,

    /// Template for persona names (e.g., "admin.{username}").
    pub naming_pattern: String,

    /// How attributes propagate from physical user.
    pub attribute_mappings: serde_json::Value,

    /// Entitlements auto-assigned to new personas.
    pub default_entitlements: Option<serde_json::Value>,

    /// Expiration, renewal, notification settings.
    pub lifecycle_policy: serde_json::Value,

    /// Whether archetype is available for assignment.
    pub is_active: bool,

    /// When the archetype was created.
    pub created_at: DateTime<Utc>,

    /// When the archetype was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new persona archetype.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePersonaArchetype {
    pub name: String,
    pub description: Option<String>,
    pub naming_pattern: String,
    pub attribute_mappings: serde_json::Value,
    pub default_entitlements: Option<serde_json::Value>,
    pub lifecycle_policy: serde_json::Value,
}

/// Request to update a persona archetype.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UpdatePersonaArchetype {
    pub name: Option<String>,
    pub description: Option<String>,
    pub naming_pattern: Option<String>,
    pub attribute_mappings: Option<serde_json::Value>,
    pub default_entitlements: Option<serde_json::Value>,
    pub lifecycle_policy: Option<serde_json::Value>,
    pub is_active: Option<bool>,
}

/// Filter options for listing archetypes.
#[derive(Debug, Clone, Default)]
pub struct PersonaArchetypeFilter {
    pub is_active: Option<bool>,
    pub name_contains: Option<String>,
}

/// Attribute mapping configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttributeMappings {
    /// Attributes that always propagate from physical user.
    #[serde(default)]
    pub propagate: Vec<PropagateMapping>,

    /// Computed attributes derived from templates.
    #[serde(default)]
    pub computed: Vec<ComputedMapping>,

    /// Attributes specific to persona only.
    #[serde(default)]
    pub persona_only: Vec<String>,
}

/// Propagation mapping for an attribute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagateMapping {
    /// Source attribute name on physical user.
    pub source: String,

    /// Target attribute name on persona.
    pub target: String,

    /// Propagation mode: "always" or "default".
    pub mode: String,

    /// Whether persona can override this attribute.
    #[serde(default)]
    pub allow_override: bool,
}

/// Computed attribute mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputedMapping {
    /// Target attribute name on persona.
    pub target: String,

    /// Handlebars template for computing value.
    pub template: String,

    /// Static variables for template.
    #[serde(default)]
    pub variables: serde_json::Map<String, serde_json::Value>,
}

/// Lifecycle policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecyclePolicy {
    /// Default validity in days for new personas.
    #[serde(default = "default_validity_days")]
    pub default_validity_days: i32,

    /// Maximum validity in days.
    #[serde(default = "default_max_validity_days")]
    pub max_validity_days: i32,

    /// Days before expiry to send notification.
    #[serde(default = "default_notification_days")]
    pub notification_before_expiry_days: i32,

    /// Whether auto-extension is allowed.
    #[serde(default)]
    pub auto_extension_allowed: bool,

    /// Whether extension requires approval.
    #[serde(default = "default_true")]
    pub extension_requires_approval: bool,

    /// Action on physical user deactivation.
    #[serde(default = "default_deactivation_action")]
    pub on_physical_user_deactivation: String,
}

fn default_validity_days() -> i32 {
    365
}
fn default_max_validity_days() -> i32 {
    730
}
fn default_notification_days() -> i32 {
    7
}
fn default_true() -> bool {
    true
}
fn default_deactivation_action() -> String {
    "cascade_deactivate".to_string()
}

impl Default for LifecyclePolicy {
    fn default() -> Self {
        Self {
            default_validity_days: default_validity_days(),
            max_validity_days: default_max_validity_days(),
            notification_before_expiry_days: default_notification_days(),
            auto_extension_allowed: false,
            extension_requires_approval: true,
            on_physical_user_deactivation: default_deactivation_action(),
        }
    }
}

impl GovPersonaArchetype {
    /// Find an archetype by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_persona_archetypes
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find an archetype by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT * FROM gov_persona_archetypes
            WHERE tenant_id = $1 AND name = $2
            "#,
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// List archetypes for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &PersonaArchetypeFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from("SELECT * FROM gov_persona_archetypes WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${}", param_count));
        }
        if filter.name_contains.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND name ILIKE ${}", param_count));
        }

        query.push_str(&format!(
            " ORDER BY name ASC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(is_active) = filter.is_active {
            q = q.bind(is_active);
        }
        if let Some(ref name_contains) = filter.name_contains {
            q = q.bind(format!("%{}%", name_contains));
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count archetypes for a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &PersonaArchetypeFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query =
            String::from("SELECT COUNT(*) FROM gov_persona_archetypes WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.is_active.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND is_active = ${}", param_count));
        }
        if filter.name_contains.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND name ILIKE ${}", param_count));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(is_active) = filter.is_active {
            q = q.bind(is_active);
        }
        if let Some(ref name_contains) = filter.name_contains {
            q = q.bind(format!("%{}%", name_contains));
        }

        q.fetch_one(pool).await
    }

    /// Create a new archetype.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreatePersonaArchetype,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r#"
            INSERT INTO gov_persona_archetypes (
                tenant_id, name, description, naming_pattern,
                attribute_mappings, default_entitlements, lifecycle_policy
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(tenant_id)
        .bind(&input.name)
        .bind(&input.description)
        .bind(&input.naming_pattern)
        .bind(&input.attribute_mappings)
        .bind(&input.default_entitlements)
        .bind(&input.lifecycle_policy)
        .fetch_one(pool)
        .await
    }

    /// Update an archetype.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdatePersonaArchetype,
    ) -> Result<Option<Self>, sqlx::Error> {
        let current = Self::find_by_id(pool, tenant_id, id).await?;
        let Some(current) = current else {
            return Ok(None);
        };

        let name = input.name.unwrap_or(current.name);
        let description = input.description.or(current.description);
        let naming_pattern = input.naming_pattern.unwrap_or(current.naming_pattern);
        let attribute_mappings = input
            .attribute_mappings
            .unwrap_or(current.attribute_mappings);
        let default_entitlements = input.default_entitlements.or(current.default_entitlements);
        let lifecycle_policy = input.lifecycle_policy.unwrap_or(current.lifecycle_policy);
        let is_active = input.is_active.unwrap_or(current.is_active);

        sqlx::query_as(
            r#"
            UPDATE gov_persona_archetypes
            SET name = $3,
                description = $4,
                naming_pattern = $5,
                attribute_mappings = $6,
                default_entitlements = $7,
                lifecycle_policy = $8,
                is_active = $9,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&name)
        .bind(&description)
        .bind(&naming_pattern)
        .bind(&attribute_mappings)
        .bind(&default_entitlements)
        .bind(&lifecycle_policy)
        .bind(is_active)
        .fetch_optional(pool)
        .await
    }

    /// Deactivate an archetype.
    pub async fn deactivate(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r#"
            UPDATE gov_persona_archetypes
            SET is_active = false, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Delete an archetype (only if no active personas exist).
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM gov_persona_archetypes
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Count active personas using this archetype.
    pub async fn count_active_personas(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM gov_personas
            WHERE tenant_id = $1 AND archetype_id = $2 AND status NOT IN ('archived')
            "#,
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_one(pool)
        .await
    }

    /// Parse attribute mappings from JSON.
    pub fn parse_attribute_mappings(&self) -> Result<AttributeMappings, serde_json::Error> {
        serde_json::from_value(self.attribute_mappings.clone())
    }

    /// Parse lifecycle policy from JSON.
    pub fn parse_lifecycle_policy(&self) -> Result<LifecyclePolicy, serde_json::Error> {
        serde_json::from_value(self.lifecycle_policy.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lifecycle_policy_defaults() {
        let policy = LifecyclePolicy::default();
        assert_eq!(policy.default_validity_days, 365);
        assert_eq!(policy.max_validity_days, 730);
        assert_eq!(policy.notification_before_expiry_days, 7);
        assert!(!policy.auto_extension_allowed);
        assert!(policy.extension_requires_approval);
        assert_eq!(policy.on_physical_user_deactivation, "cascade_deactivate");
    }

    #[test]
    fn test_lifecycle_policy_serialization() {
        let policy = LifecyclePolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("\"default_validity_days\":365"));
        assert!(json.contains("\"extension_requires_approval\":true"));
    }

    #[test]
    fn test_attribute_mappings_serialization() {
        let mappings = AttributeMappings {
            propagate: vec![PropagateMapping {
                source: "surname".to_string(),
                target: "surname".to_string(),
                mode: "always".to_string(),
                allow_override: false,
            }],
            computed: vec![ComputedMapping {
                target: "display_name".to_string(),
                template: "Admin {given_name} {surname}".to_string(),
                variables: serde_json::Map::new(),
            }],
            persona_only: vec!["admin_level".to_string()],
        };

        let json = serde_json::to_string(&mappings).unwrap();
        assert!(json.contains("\"source\":\"surname\""));
        assert!(json.contains("\"template\":\"Admin {given_name} {surname}\""));
        assert!(json.contains("\"admin_level\""));
    }

    #[test]
    fn test_create_archetype_request() {
        let input = CreatePersonaArchetype {
            name: "Admin Persona".to_string(),
            description: Some("Elevated privileges".to_string()),
            naming_pattern: "admin.{username}".to_string(),
            attribute_mappings: serde_json::json!({
                "propagate": [
                    {"source": "surname", "target": "surname", "mode": "always"}
                ]
            }),
            default_entitlements: None,
            lifecycle_policy: serde_json::to_value(LifecyclePolicy::default()).unwrap(),
        };

        assert_eq!(input.name, "Admin Persona");
        assert_eq!(input.naming_pattern, "admin.{username}");
    }

    #[test]
    fn test_filter_default() {
        let filter = PersonaArchetypeFilter::default();
        assert!(filter.is_active.is_none());
        assert!(filter.name_contains.is_none());
    }
}
