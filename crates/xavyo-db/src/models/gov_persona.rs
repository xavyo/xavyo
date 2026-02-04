//! Governance Persona model (F063).
//!
//! Virtual identity linked to a physical user, created from an archetype.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::PersonaStatus;

/// A persona - virtual identity for a physical user.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct GovPersona {
    /// Unique identifier for the persona.
    pub id: Uuid,

    /// The tenant this persona belongs to.
    pub tenant_id: Uuid,

    /// Source archetype.
    pub archetype_id: Uuid,

    /// Owning physical user.
    pub physical_user_id: Uuid,

    /// Generated from `naming_pattern` (e.g., "admin.john.doe").
    pub persona_name: String,

    /// Computed or overridden display name.
    pub display_name: String,

    /// Persona-specific attributes (overrides, `persona_specific`, inherited).
    pub attributes: serde_json::Value,

    /// Lifecycle status.
    pub status: PersonaStatus,

    /// When persona becomes valid.
    pub valid_from: DateTime<Utc>,

    /// Optional expiration time.
    pub valid_until: Option<DateTime<Utc>>,

    /// When the persona was created.
    pub created_at: DateTime<Utc>,

    /// When the persona was last updated.
    pub updated_at: DateTime<Utc>,

    /// When deactivated.
    pub deactivated_at: Option<DateTime<Utc>>,

    /// Who deactivated.
    pub deactivated_by: Option<Uuid>,

    /// Why deactivated.
    pub deactivation_reason: Option<String>,
}

/// Request to create a new persona.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePersona {
    pub archetype_id: Uuid,
    pub physical_user_id: Uuid,
    pub persona_name: String,
    pub display_name: String,
    pub attributes: serde_json::Value,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_until: Option<DateTime<Utc>>,
}

/// Request to update a persona.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePersona {
    pub display_name: Option<String>,
    pub attributes: Option<serde_json::Value>,
    pub valid_until: Option<DateTime<Utc>>,
}

/// Filter options for listing personas.
#[derive(Debug, Clone, Default)]
pub struct PersonaFilter {
    pub archetype_id: Option<Uuid>,
    pub physical_user_id: Option<Uuid>,
    pub status: Option<PersonaStatus>,
    pub expiring_within_days: Option<i32>,
}

/// Persona attributes structure.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersonaAttributes {
    /// Attributes inherited from physical user.
    #[serde(default)]
    pub inherited: serde_json::Map<String, serde_json::Value>,

    /// Attribute overrides (persona-specific values that override inherited).
    #[serde(default)]
    pub overrides: serde_json::Map<String, serde_json::Value>,

    /// Persona-only attributes (not derived from physical user).
    #[serde(default)]
    pub persona_specific: serde_json::Map<String, serde_json::Value>,

    /// When attributes were last propagated from physical user.
    pub last_propagation_at: Option<DateTime<Utc>>,
}

impl GovPersona {
    /// Find a persona by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_personas
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a persona by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        persona_name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_personas
            WHERE tenant_id = $1 AND persona_name = $2
            ",
        )
        .bind(tenant_id)
        .bind(persona_name)
        .fetch_optional(pool)
        .await
    }

    /// Find existing persona for user + archetype combination.
    pub async fn find_by_user_and_archetype(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        physical_user_id: Uuid,
        archetype_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_personas
            WHERE tenant_id = $1 AND physical_user_id = $2 AND archetype_id = $3
            ",
        )
        .bind(tenant_id)
        .bind(physical_user_id)
        .bind(archetype_id)
        .fetch_optional(pool)
        .await
    }

    /// List personas for a physical user.
    pub async fn find_by_physical_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        physical_user_id: Uuid,
        include_archived: bool,
    ) -> Result<Vec<Self>, sqlx::Error> {
        if include_archived {
            sqlx::query_as(
                r"
                SELECT * FROM gov_personas
                WHERE tenant_id = $1 AND physical_user_id = $2
                ORDER BY persona_name ASC
                ",
            )
            .bind(tenant_id)
            .bind(physical_user_id)
            .fetch_all(pool)
            .await
        } else {
            sqlx::query_as(
                r"
                SELECT * FROM gov_personas
                WHERE tenant_id = $1 AND physical_user_id = $2 AND status != 'archived'
                ORDER BY persona_name ASC
                ",
            )
            .bind(tenant_id)
            .bind(physical_user_id)
            .fetch_all(pool)
            .await
        }
    }

    /// List personas for a tenant with filtering and pagination.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &PersonaFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from("SELECT * FROM gov_personas WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.archetype_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND archetype_id = ${param_count}"));
        }
        if filter.physical_user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND physical_user_id = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.expiring_within_days.is_some() {
            query.push_str(
                " AND status = 'active' AND valid_until IS NOT NULL AND valid_until <= NOW() + $",
            );
            param_count += 1;
            query.push_str(&format!("{param_count}::interval"));
        }

        query.push_str(&format!(
            " ORDER BY persona_name ASC LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, Self>(&query).bind(tenant_id);

        if let Some(archetype_id) = filter.archetype_id {
            q = q.bind(archetype_id);
        }
        if let Some(physical_user_id) = filter.physical_user_id {
            q = q.bind(physical_user_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(days) = filter.expiring_within_days {
            q = q.bind(format!("{days} days"));
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count personas for a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &PersonaFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from("SELECT COUNT(*) FROM gov_personas WHERE tenant_id = $1");
        let mut param_count = 1;

        if filter.archetype_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND archetype_id = ${param_count}"));
        }
        if filter.physical_user_id.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND physical_user_id = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.expiring_within_days.is_some() {
            query.push_str(
                " AND status = 'active' AND valid_until IS NOT NULL AND valid_until <= NOW() + $",
            );
            param_count += 1;
            query.push_str(&format!("{param_count}::interval"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(archetype_id) = filter.archetype_id {
            q = q.bind(archetype_id);
        }
        if let Some(physical_user_id) = filter.physical_user_id {
            q = q.bind(physical_user_id);
        }
        if let Some(status) = filter.status {
            q = q.bind(status);
        }
        if let Some(days) = filter.expiring_within_days {
            q = q.bind(format!("{days} days"));
        }

        q.fetch_one(pool).await
    }

    /// Find personas expiring within given days.
    pub async fn find_expiring(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        within_days: i32,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_personas
            WHERE tenant_id = $1 AND status = 'active'
              AND valid_until IS NOT NULL
              AND valid_until <= NOW() + $2::interval
            ORDER BY valid_until ASC
            LIMIT $3
            ",
        )
        .bind(tenant_id)
        .bind(format!("{within_days} days"))
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Find all personas that have expired (past `valid_until`).
    pub async fn find_expired(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_personas
            WHERE tenant_id = $1 AND status = 'active'
              AND valid_until IS NOT NULL
              AND valid_until < NOW()
            ORDER BY valid_until ASC
            LIMIT $2
            ",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// Create a new persona.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreatePersona,
    ) -> Result<Self, sqlx::Error> {
        let valid_from = input.valid_from.unwrap_or_else(Utc::now);

        sqlx::query_as(
            r"
            INSERT INTO gov_personas (
                tenant_id, archetype_id, physical_user_id, persona_name,
                display_name, attributes, status, valid_from, valid_until
            )
            VALUES ($1, $2, $3, $4, $5, $6, 'draft', $7, $8)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(input.archetype_id)
        .bind(input.physical_user_id)
        .bind(&input.persona_name)
        .bind(&input.display_name)
        .bind(&input.attributes)
        .bind(valid_from)
        .bind(input.valid_until)
        .fetch_one(pool)
        .await
    }

    /// Update a persona.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdatePersona,
    ) -> Result<Option<Self>, sqlx::Error> {
        let current = Self::find_by_id(pool, tenant_id, id).await?;
        let Some(current) = current else {
            return Ok(None);
        };

        let display_name = input.display_name.unwrap_or(current.display_name);
        let attributes = input.attributes.unwrap_or(current.attributes);
        let valid_until = input.valid_until.or(current.valid_until);

        sqlx::query_as(
            r"
            UPDATE gov_personas
            SET display_name = $3,
                attributes = $4,
                valid_until = $5,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&display_name)
        .bind(&attributes)
        .bind(valid_until)
        .fetch_optional(pool)
        .await
    }

    /// Activate a persona.
    pub async fn activate(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_personas
            SET status = 'active', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status IN ('draft', 'suspended', 'expired')
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Deactivate (suspend) a persona.
    pub async fn deactivate(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        deactivated_by: Uuid,
        reason: Option<String>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_personas
            SET status = 'suspended',
                deactivated_at = NOW(),
                deactivated_by = $3,
                deactivation_reason = $4,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status IN ('active', 'expiring')
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(deactivated_by)
        .bind(&reason)
        .fetch_optional(pool)
        .await
    }

    /// Mark persona as expired.
    pub async fn mark_expired(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_personas
            SET status = 'expired',
                deactivated_at = NOW(),
                deactivation_reason = 'Automatic expiration',
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status IN ('active', 'expiring')
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Mark persona as expiring (entering notification window).
    pub async fn mark_expiring(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_personas
            SET status = 'expiring', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status = 'active'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Archive a persona.
    pub async fn archive(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        archived_by: Uuid,
        reason: Option<String>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_personas
            SET status = 'archived',
                deactivated_at = COALESCE(deactivated_at, NOW()),
                deactivated_by = COALESCE(deactivated_by, $3),
                deactivation_reason = COALESCE(deactivation_reason, $4),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2 AND status != 'archived'
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(archived_by)
        .bind(&reason)
        .fetch_optional(pool)
        .await
    }

    /// Extend validity period.
    pub async fn extend_validity(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        new_valid_until: DateTime<Utc>,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_personas
            SET valid_until = $3,
                status = CASE WHEN status = 'expired' THEN 'active' ELSE status END,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(new_valid_until)
        .fetch_optional(pool)
        .await
    }

    /// Update inherited attributes (after propagation from physical user).
    pub async fn update_inherited_attributes(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        inherited: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Self>, sqlx::Error> {
        // Get current attributes
        let current = Self::find_by_id(pool, tenant_id, id).await?;
        let Some(current) = current else {
            return Ok(None);
        };

        let mut attrs: PersonaAttributes =
            serde_json::from_value(current.attributes).unwrap_or_default();
        attrs.inherited = inherited;
        attrs.last_propagation_at = Some(Utc::now());

        let new_attrs = serde_json::to_value(&attrs).unwrap_or_default();

        sqlx::query_as(
            r"
            UPDATE gov_personas
            SET attributes = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(new_attrs)
        .fetch_optional(pool)
        .await
    }

    /// Deactivate all personas for a physical user (cascade on user deactivation).
    pub async fn deactivate_all_for_user(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        physical_user_id: Uuid,
        reason: &str,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE gov_personas
            SET status = 'suspended',
                deactivated_at = NOW(),
                deactivation_reason = $3,
                updated_at = NOW()
            WHERE tenant_id = $1 AND physical_user_id = $2 AND status IN ('active', 'expiring')
            ",
        )
        .bind(tenant_id)
        .bind(physical_user_id)
        .bind(reason)
        .execute(pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Parse attributes from JSON.
    pub fn parse_attributes(&self) -> Result<PersonaAttributes, serde_json::Error> {
        serde_json::from_value(self.attributes.clone())
    }

    /// Check if persona can be switched to.
    #[must_use] 
    pub fn can_switch_to(&self) -> bool {
        self.status.can_switch_to()
    }

    /// Check if persona has expired.
    #[must_use] 
    pub fn is_expired(&self) -> bool {
        if let Some(valid_until) = self.valid_until {
            Utc::now() > valid_until
        } else {
            false
        }
    }

    /// Get remaining time until expiration.
    #[must_use] 
    pub fn time_until_expiration(&self) -> Option<chrono::Duration> {
        self.valid_until.map(|until| until - Utc::now())
    }

    /// Find personas expiring before a given threshold datetime.
    /// Used by expiration service to find personas entering warning period.
    pub async fn find_expiring_soon(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        threshold: DateTime<Utc>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_personas
            WHERE tenant_id = $1
              AND status IN ('active', 'expiring')
              AND valid_until IS NOT NULL
              AND valid_until <= $2
              AND valid_until > NOW()
            ORDER BY valid_until ASC
            ",
        )
        .bind(tenant_id)
        .bind(threshold)
        .fetch_all(pool)
        .await
    }

    /// Find personas that have passed their `valid_until` date.
    /// Used by expiration service to expire personas.
    pub async fn find_past_valid_until(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        _now: DateTime<Utc>,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM gov_personas
            WHERE tenant_id = $1
              AND status IN ('active', 'expiring')
              AND valid_until IS NOT NULL
              AND valid_until < NOW()
            ORDER BY valid_until ASC
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Update persona status to a specific status.
    pub async fn update_status(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        new_status: PersonaStatus,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE gov_personas
            SET status = $3,
                deactivated_at = CASE WHEN $3 IN ('suspended', 'expired', 'archived') THEN NOW() ELSE deactivated_at END,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(new_status)
        .fetch_optional(pool)
        .await
    }

    /// Count personas that expired recently (within N days).
    pub async fn count_recently_expired(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        within_days: i32,
    ) -> Result<i64, sqlx::Error> {
        let row: (i64,) = sqlx::query_as(
            r"
            SELECT COUNT(*)
            FROM gov_personas
            WHERE tenant_id = $1
              AND status = 'expired'
              AND deactivated_at >= NOW() - $2::interval
            ",
        )
        .bind(tenant_id)
        .bind(format!("{within_days} days"))
        .fetch_one(pool)
        .await?;

        Ok(row.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persona_attributes_default() {
        let attrs = PersonaAttributes::default();
        assert!(attrs.inherited.is_empty());
        assert!(attrs.overrides.is_empty());
        assert!(attrs.persona_specific.is_empty());
        assert!(attrs.last_propagation_at.is_none());
    }

    #[test]
    fn test_persona_attributes_serialization() {
        let mut attrs = PersonaAttributes::default();
        attrs
            .inherited
            .insert("surname".to_string(), serde_json::json!("Smith"));
        attrs
            .overrides
            .insert("email".to_string(), serde_json::json!("admin@example.com"));
        attrs
            .persona_specific
            .insert("admin_level".to_string(), serde_json::json!("tier2"));

        let json = serde_json::to_string(&attrs).unwrap();
        assert!(json.contains("\"surname\":\"Smith\""));
        assert!(json.contains("\"email\":\"admin@example.com\""));
        assert!(json.contains("\"admin_level\":\"tier2\""));
    }

    #[test]
    fn test_create_persona_request() {
        let input = CreatePersona {
            archetype_id: Uuid::new_v4(),
            physical_user_id: Uuid::new_v4(),
            persona_name: "admin.john.doe".to_string(),
            display_name: "Admin John Doe".to_string(),
            attributes: serde_json::json!({}),
            valid_from: None,
            valid_until: Some(Utc::now() + chrono::Duration::days(365)),
        };

        assert_eq!(input.persona_name, "admin.john.doe");
        assert!(input.valid_until.is_some());
    }

    #[test]
    fn test_filter_default() {
        let filter = PersonaFilter::default();
        assert!(filter.archetype_id.is_none());
        assert!(filter.physical_user_id.is_none());
        assert!(filter.status.is_none());
        assert!(filter.expiring_within_days.is_none());
    }
}
