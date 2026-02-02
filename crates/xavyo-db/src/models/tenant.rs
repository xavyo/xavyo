//! Tenant model for xavyo-db.
//!
//! Provides the core tenant entity and tenant type classification.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Type};
use uuid::Uuid;

use crate::DbError;

// ============================================================================
// T010: TenantType Enum
// ============================================================================

/// Type classification for tenants.
///
/// - `User`: A regular tenant created by users for their organizations.
/// - `System`: The special system tenant used for platform-level operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Type, Serialize, Deserialize)]
#[sqlx(type_name = "tenant_type", rename_all = "lowercase")]
pub enum TenantType {
    /// Regular user-created tenant.
    #[default]
    User,
    /// System tenant for platform operations (e.g., CLI authentication).
    System,
}

impl std::fmt::Display for TenantType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TenantType::User => write!(f, "user"),
            TenantType::System => write!(f, "system"),
        }
    }
}

// ============================================================================
// T011: Tenant Struct
// ============================================================================

/// A tenant in the xavyo platform.
///
/// Tenants represent isolated organizational units. All user data, OAuth clients,
/// agents, and other resources are scoped to a specific tenant.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Tenant {
    /// Unique identifier for the tenant.
    pub id: Uuid,

    /// Human-readable name of the tenant (e.g., "Acme Corp").
    pub name: String,

    /// URL-safe slug for the tenant (e.g., "acme-corp").
    /// Must be unique across all tenants.
    pub slug: String,

    /// Type classification of the tenant.
    pub tenant_type: TenantType,

    /// JSON settings for tenant-specific configuration.
    pub settings: serde_json::Value,

    /// Timestamp when the tenant was created.
    pub created_at: DateTime<Utc>,

    /// Timestamp when the tenant was suspended. NULL means active.
    /// F-SUSPEND: Added for tenant suspension support.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspended_at: Option<DateTime<Utc>>,

    /// Reason for suspension (admin-facing, not shown to end users).
    /// F-SUSPEND: Added for tenant suspension support.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suspension_reason: Option<String>,

    /// Timestamp when the tenant was soft deleted. NULL means active.
    /// F-DELETE: Added for tenant soft delete support.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<DateTime<Utc>>,

    /// Reason for deletion (admin-facing).
    /// F-DELETE: Added for tenant soft delete support.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deletion_reason: Option<String>,

    /// When permanent deletion will occur (typically 30 days after deleted_at).
    /// F-DELETE: Added for tenant soft delete support.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduled_purge_at: Option<DateTime<Utc>>,
}

// ============================================================================
// T012: Tenant Methods
// ============================================================================

impl Tenant {
    /// Returns `true` if this is the system tenant.
    ///
    /// The system tenant is used for platform-level operations such as
    /// CLI authentication before users have their own tenant.
    pub fn is_system(&self) -> bool {
        self.tenant_type == TenantType::System
    }

    /// Returns `true` if this is a regular user tenant.
    pub fn is_user(&self) -> bool {
        self.tenant_type == TenantType::User
    }

    /// Returns `true` if this tenant is currently suspended.
    ///
    /// F-SUSPEND: Suspended tenants cannot access any API endpoints.
    pub fn is_suspended(&self) -> bool {
        self.suspended_at.is_some()
    }

    /// Returns `true` if this tenant has been soft deleted.
    ///
    /// F-DELETE: Deleted tenants cannot access any API endpoints.
    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    /// Returns `true` if this tenant is inaccessible (suspended or deleted).
    pub fn is_inaccessible(&self) -> bool {
        self.is_suspended() || self.is_deleted()
    }

    // ========================================================================
    // T047: Static Query Methods
    // ========================================================================

    /// Finds a tenant by its ID.
    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Self>, DbError> {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT id, name, slug, tenant_type, settings, created_at, suspended_at, suspension_reason, deleted_at, deletion_reason, scheduled_purge_at
            FROM tenants
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// Finds a tenant by its slug.
    pub async fn find_by_slug(pool: &PgPool, slug: &str) -> Result<Option<Self>, DbError> {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT id, name, slug, tenant_type, settings, created_at, suspended_at, suspension_reason, deleted_at, deletion_reason, scheduled_purge_at
            FROM tenants
            WHERE slug = $1
            "#,
        )
        .bind(slug)
        .fetch_optional(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// Finds all tenants of a specific type.
    ///
    /// This is useful for listing all system tenants (should be exactly one)
    /// or all user tenants.
    pub async fn find_by_type(
        pool: &PgPool,
        tenant_type: TenantType,
    ) -> Result<Vec<Self>, DbError> {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT id, name, slug, tenant_type, settings, created_at, suspended_at, suspension_reason, deleted_at, deletion_reason, scheduled_purge_at
            FROM tenants
            WHERE tenant_type = $1
            ORDER BY created_at ASC
            "#,
        )
        .bind(tenant_type)
        .fetch_all(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// Lists all tenants.
    pub async fn list_all(pool: &PgPool) -> Result<Vec<Self>, DbError> {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT id, name, slug, tenant_type, settings, created_at, suspended_at, suspension_reason, deleted_at, deletion_reason, scheduled_purge_at
            FROM tenants
            ORDER BY created_at ASC
            "#,
        )
        .fetch_all(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// Counts tenants by type.
    pub async fn count_by_type(pool: &PgPool, tenant_type: TenantType) -> Result<i64, DbError> {
        let result: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(*) FROM tenants WHERE tenant_type = $1
            "#,
        )
        .bind(tenant_type)
        .fetch_one(pool)
        .await
        .map_err(DbError::QueryFailed)?;

        Ok(result.0)
    }

    // ========================================================================
    // F097: Tenant Provisioning API Methods
    // ========================================================================

    /// Check if a slug already exists.
    pub async fn slug_exists(pool: &PgPool, slug: &str) -> Result<bool, DbError> {
        let result: (bool,) = sqlx::query_as(
            r#"
            SELECT EXISTS(SELECT 1 FROM tenants WHERE slug = $1)
            "#,
        )
        .bind(slug)
        .fetch_one(pool)
        .await
        .map_err(DbError::QueryFailed)?;

        Ok(result.0)
    }

    /// Create a new tenant.
    pub async fn create(
        pool: &PgPool,
        name: &str,
        slug: &str,
        tenant_type: TenantType,
        settings: serde_json::Value,
    ) -> Result<Self, DbError> {
        sqlx::query_as::<_, Self>(
            r#"
            INSERT INTO tenants (name, slug, tenant_type, settings)
            VALUES ($1, $2, $3, $4)
            RETURNING id, name, slug, tenant_type, settings, created_at, suspended_at, suspension_reason, deleted_at, deletion_reason, scheduled_purge_at
            "#,
        )
        .bind(name)
        .bind(slug)
        .bind(tenant_type)
        .bind(&settings)
        .fetch_one(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// Create a new tenant within a transaction.
    pub async fn create_in_tx<'e>(
        tx: &mut sqlx::Transaction<'e, sqlx::Postgres>,
        name: &str,
        slug: &str,
        tenant_type: TenantType,
        settings: serde_json::Value,
    ) -> Result<Self, DbError> {
        sqlx::query_as::<_, Self>(
            r#"
            INSERT INTO tenants (name, slug, tenant_type, settings)
            VALUES ($1, $2, $3, $4)
            RETURNING id, name, slug, tenant_type, settings, created_at, suspended_at, suspension_reason, deleted_at, deletion_reason, scheduled_purge_at
            "#,
        )
        .bind(name)
        .bind(slug)
        .bind(tenant_type)
        .bind(&settings)
        .fetch_one(&mut **tx)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// Check if a slug exists (for use in transactions).
    pub async fn slug_exists_in_tx<'e>(
        tx: &mut sqlx::Transaction<'e, sqlx::Postgres>,
        slug: &str,
    ) -> Result<bool, DbError> {
        let result: (bool,) = sqlx::query_as(
            r#"
            SELECT EXISTS(SELECT 1 FROM tenants WHERE slug = $1)
            "#,
        )
        .bind(slug)
        .fetch_one(&mut **tx)
        .await
        .map_err(DbError::QueryFailed)?;

        Ok(result.0)
    }

    // ========================================================================
    // F-SUSPEND: Tenant Suspension Methods
    // ========================================================================

    /// Suspend a tenant, preventing all API access.
    ///
    /// Returns the updated tenant on success.
    pub async fn suspend(pool: &PgPool, id: Uuid, reason: &str) -> Result<Self, DbError> {
        sqlx::query_as::<_, Self>(
            r#"
            UPDATE tenants
            SET suspended_at = NOW(), suspension_reason = $2
            WHERE id = $1
            RETURNING id, name, slug, tenant_type, settings, created_at, suspended_at, suspension_reason, deleted_at, deletion_reason, scheduled_purge_at
            "#,
        )
        .bind(id)
        .bind(reason)
        .fetch_one(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// Reactivate a suspended tenant, restoring API access.
    ///
    /// Returns the updated tenant on success.
    pub async fn reactivate(pool: &PgPool, id: Uuid) -> Result<Self, DbError> {
        sqlx::query_as::<_, Self>(
            r#"
            UPDATE tenants
            SET suspended_at = NULL, suspension_reason = NULL
            WHERE id = $1
            RETURNING id, name, slug, tenant_type, settings, created_at, suspended_at, suspension_reason, deleted_at, deletion_reason, scheduled_purge_at
            "#,
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// List all suspended tenants.
    pub async fn list_suspended(pool: &PgPool) -> Result<Vec<Self>, DbError> {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT id, name, slug, tenant_type, settings, created_at, suspended_at, suspension_reason, deleted_at, deletion_reason, scheduled_purge_at
            FROM tenants
            WHERE suspended_at IS NOT NULL
            ORDER BY suspended_at DESC
            "#,
        )
        .fetch_all(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    // ========================================================================
    // F-DELETE: Tenant Soft Delete Methods
    // ========================================================================

    /// Soft delete a tenant, marking it for permanent deletion after a grace period.
    ///
    /// The tenant will be inaccessible immediately but data is preserved for 30 days.
    /// Returns the updated tenant on success.
    pub async fn soft_delete(
        pool: &PgPool,
        id: Uuid,
        reason: &str,
        grace_period_days: i64,
    ) -> Result<Self, DbError> {
        let now = Utc::now();
        let purge_at = now + chrono::Duration::days(grace_period_days);

        sqlx::query_as::<_, Self>(
            r#"
            UPDATE tenants
            SET deleted_at = $2, deletion_reason = $3, scheduled_purge_at = $4
            WHERE id = $1
            RETURNING id, name, slug, tenant_type, settings, created_at, suspended_at, suspension_reason, deleted_at, deletion_reason, scheduled_purge_at
            "#,
        )
        .bind(id)
        .bind(now)
        .bind(reason)
        .bind(purge_at)
        .fetch_one(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// Restore a soft-deleted tenant, canceling the scheduled permanent deletion.
    ///
    /// Returns the updated tenant on success.
    pub async fn restore(pool: &PgPool, id: Uuid) -> Result<Self, DbError> {
        sqlx::query_as::<_, Self>(
            r#"
            UPDATE tenants
            SET deleted_at = NULL, deletion_reason = NULL, scheduled_purge_at = NULL
            WHERE id = $1
            RETURNING id, name, slug, tenant_type, settings, created_at, suspended_at, suspension_reason, deleted_at, deletion_reason, scheduled_purge_at
            "#,
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// List all soft-deleted tenants.
    pub async fn list_deleted(pool: &PgPool) -> Result<Vec<Self>, DbError> {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT id, name, slug, tenant_type, settings, created_at, suspended_at, suspension_reason, deleted_at, deletion_reason, scheduled_purge_at
            FROM tenants
            WHERE deleted_at IS NOT NULL
            ORDER BY deleted_at DESC
            "#,
        )
        .fetch_all(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// Find all tenants that are past their scheduled purge time.
    ///
    /// These tenants are candidates for permanent deletion.
    pub async fn find_pending_purge(pool: &PgPool) -> Result<Vec<Self>, DbError> {
        sqlx::query_as::<_, Self>(
            r#"
            SELECT id, name, slug, tenant_type, settings, created_at, suspended_at, suspension_reason, deleted_at, deletion_reason, scheduled_purge_at
            FROM tenants
            WHERE scheduled_purge_at IS NOT NULL AND scheduled_purge_at <= NOW()
            ORDER BY scheduled_purge_at ASC
            "#,
        )
        .fetch_all(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    // ========================================================================
    // F-SETTINGS-API: Settings Management Methods
    // ========================================================================

    /// Update tenant settings with a partial merge.
    ///
    /// The new settings are deep merged with existing settings:
    /// - Top-level keys are merged
    /// - Nested objects are recursively merged
    /// - Explicit null values remove keys
    ///
    /// Returns the updated tenant on success.
    pub async fn update_settings(
        pool: &PgPool,
        id: Uuid,
        new_settings: serde_json::Value,
    ) -> Result<Self, DbError> {
        // First, get current settings
        let current = Self::find_by_id(pool, id)
            .await?
            .ok_or_else(|| DbError::NotFound(format!("Tenant {} not found", id)))?;

        // Deep merge the settings in Rust
        let merged = Self::deep_merge_settings(current.settings, new_settings);

        // Update with the merged result
        sqlx::query_as::<_, Self>(
            r#"
            UPDATE tenants
            SET settings = $2
            WHERE id = $1
            RETURNING id, name, slug, tenant_type, settings, created_at, suspended_at, suspension_reason, deleted_at, deletion_reason, scheduled_purge_at
            "#,
        )
        .bind(id)
        .bind(merged)
        .fetch_one(pool)
        .await
        .map_err(DbError::QueryFailed)
    }

    /// Deep merge two JSON values.
    ///
    /// - Objects are recursively merged
    /// - Explicit null values remove keys
    /// - Other values replace existing values
    fn deep_merge_settings(base: serde_json::Value, patch: serde_json::Value) -> serde_json::Value {
        use serde_json::Value;

        match (base, patch) {
            // Both are objects: recursively merge
            (Value::Object(mut base_map), Value::Object(patch_map)) => {
                for (key, patch_value) in patch_map {
                    if patch_value.is_null() {
                        // Explicit null removes the key
                        base_map.remove(&key);
                    } else if let Some(base_value) = base_map.remove(&key) {
                        // Key exists in both: recursively merge
                        base_map.insert(key, Self::deep_merge_settings(base_value, patch_value));
                    } else {
                        // Key only in patch: add it
                        base_map.insert(key, patch_value);
                    }
                }
                Value::Object(base_map)
            }
            // Patch is not an object or base is not an object: patch wins
            (_, patch) => patch,
        }
    }

    /// Replace tenant settings entirely.
    ///
    /// Unlike update_settings, this replaces all settings with the new value.
    pub async fn set_settings(
        pool: &PgPool,
        id: Uuid,
        settings: serde_json::Value,
    ) -> Result<Self, DbError> {
        sqlx::query_as::<_, Self>(
            r#"
            UPDATE tenants
            SET settings = $2
            WHERE id = $1
            RETURNING id, name, slug, tenant_type, settings, created_at, suspended_at, suspension_reason, deleted_at, deletion_reason, scheduled_purge_at
            "#,
        )
        .bind(id)
        .bind(settings)
        .fetch_one(pool)
        .await
        .map_err(DbError::QueryFailed)
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_type_default() {
        assert_eq!(TenantType::default(), TenantType::User);
    }

    #[test]
    fn test_tenant_type_display() {
        assert_eq!(TenantType::User.to_string(), "user");
        assert_eq!(TenantType::System.to_string(), "system");
    }

    #[test]
    fn test_tenant_is_system() {
        let system_tenant = Tenant {
            id: Uuid::new_v4(),
            name: "System".to_string(),
            slug: "system".to_string(),
            tenant_type: TenantType::System,
            settings: serde_json::json!({}),
            created_at: Utc::now(),
            suspended_at: None,
            suspension_reason: None,
            deleted_at: None,
            deletion_reason: None,
            scheduled_purge_at: None,
        };

        let user_tenant = Tenant {
            id: Uuid::new_v4(),
            name: "Acme".to_string(),
            slug: "acme".to_string(),
            tenant_type: TenantType::User,
            settings: serde_json::json!({}),
            created_at: Utc::now(),
            suspended_at: None,
            suspension_reason: None,
            deleted_at: None,
            deletion_reason: None,
            scheduled_purge_at: None,
        };

        assert!(system_tenant.is_system());
        assert!(!system_tenant.is_user());

        assert!(!user_tenant.is_system());
        assert!(user_tenant.is_user());
    }

    #[test]
    fn test_tenant_is_suspended() {
        let active_tenant = Tenant {
            id: Uuid::new_v4(),
            name: "Active Corp".to_string(),
            slug: "active-corp".to_string(),
            tenant_type: TenantType::User,
            settings: serde_json::json!({}),
            created_at: Utc::now(),
            suspended_at: None,
            suspension_reason: None,
            deleted_at: None,
            deletion_reason: None,
            scheduled_purge_at: None,
        };

        let suspended_tenant = Tenant {
            id: Uuid::new_v4(),
            name: "Suspended Corp".to_string(),
            slug: "suspended-corp".to_string(),
            tenant_type: TenantType::User,
            settings: serde_json::json!({}),
            created_at: Utc::now(),
            suspended_at: Some(Utc::now()),
            suspension_reason: Some("Terms of service violation".to_string()),
            deleted_at: None,
            deletion_reason: None,
            scheduled_purge_at: None,
        };

        assert!(!active_tenant.is_suspended());
        assert!(suspended_tenant.is_suspended());
    }

    #[test]
    fn test_tenant_is_deleted() {
        let active_tenant = Tenant {
            id: Uuid::new_v4(),
            name: "Active Corp".to_string(),
            slug: "active-corp".to_string(),
            tenant_type: TenantType::User,
            settings: serde_json::json!({}),
            created_at: Utc::now(),
            suspended_at: None,
            suspension_reason: None,
            deleted_at: None,
            deletion_reason: None,
            scheduled_purge_at: None,
        };

        let deleted_tenant = Tenant {
            id: Uuid::new_v4(),
            name: "Deleted Corp".to_string(),
            slug: "deleted-corp".to_string(),
            tenant_type: TenantType::User,
            settings: serde_json::json!({}),
            created_at: Utc::now(),
            suspended_at: None,
            suspension_reason: None,
            deleted_at: Some(Utc::now()),
            deletion_reason: Some("Customer requested deletion".to_string()),
            scheduled_purge_at: Some(Utc::now() + chrono::Duration::days(30)),
        };

        assert!(!active_tenant.is_deleted());
        assert!(deleted_tenant.is_deleted());
        assert!(deleted_tenant.is_inaccessible());
    }

    #[test]
    fn test_deep_merge_settings_simple() {
        let base = serde_json::json!({
            "limits": {"max_mau": 500}
        });
        let patch = serde_json::json!({
            "limits": {"max_api_calls": 1000}
        });

        let result = Tenant::deep_merge_settings(base, patch);

        assert_eq!(result["limits"]["max_mau"], 500);
        assert_eq!(result["limits"]["max_api_calls"], 1000);
    }

    #[test]
    fn test_deep_merge_settings_nested() {
        let base = serde_json::json!({
            "limits": {"max_mau": 500, "max_api_calls": 100000},
            "features": {"mfa_required": false}
        });
        let patch = serde_json::json!({
            "limits": {"max_mau": 1000},
            "features": {"sso_enabled": true}
        });

        let result = Tenant::deep_merge_settings(base, patch);

        // limits.max_mau updated
        assert_eq!(result["limits"]["max_mau"], 1000);
        // limits.max_api_calls preserved
        assert_eq!(result["limits"]["max_api_calls"], 100000);
        // features.mfa_required preserved
        assert_eq!(result["features"]["mfa_required"], false);
        // features.sso_enabled added
        assert_eq!(result["features"]["sso_enabled"], true);
    }

    #[test]
    fn test_deep_merge_settings_null_removes_key() {
        let base = serde_json::json!({
            "limits": {"max_mau": 500, "max_api_calls": 100000}
        });
        let patch = serde_json::json!({
            "limits": {"max_api_calls": null}
        });

        let result = Tenant::deep_merge_settings(base, patch);

        // max_mau preserved
        assert_eq!(result["limits"]["max_mau"], 500);
        // max_api_calls removed (should be null/missing)
        assert!(result["limits"].get("max_api_calls").is_none());
    }

    #[test]
    fn test_deep_merge_settings_null_removes_top_level() {
        let base = serde_json::json!({
            "limits": {"max_mau": 500},
            "features": {"mfa_required": true}
        });
        let patch = serde_json::json!({
            "features": null
        });

        let result = Tenant::deep_merge_settings(base, patch);

        // limits preserved
        assert_eq!(result["limits"]["max_mau"], 500);
        // features removed
        assert!(result.get("features").is_none());
    }

    #[test]
    fn test_deep_merge_settings_add_new_key() {
        let base = serde_json::json!({
            "limits": {"max_mau": 500}
        });
        let patch = serde_json::json!({
            "custom": {"key": "value"}
        });

        let result = Tenant::deep_merge_settings(base, patch);

        assert_eq!(result["limits"]["max_mau"], 500);
        assert_eq!(result["custom"]["key"], "value");
    }

    #[test]
    fn test_deep_merge_settings_replace_non_object() {
        let base = serde_json::json!({
            "limits": {"max_mau": 500}
        });
        let patch = serde_json::json!({
            "limits": "not an object"
        });

        let result = Tenant::deep_merge_settings(base, patch);

        // limits replaced with string
        assert_eq!(result["limits"], "not an object");
    }

    #[test]
    fn test_deep_merge_settings_empty_patch() {
        let base = serde_json::json!({
            "limits": {"max_mau": 500}
        });
        let patch = serde_json::json!({});

        let result = Tenant::deep_merge_settings(base, patch);

        // Base preserved
        assert_eq!(result["limits"]["max_mau"], 500);
    }
}
