//! Secret Type Configuration model for dynamic secrets provisioning.
//!
//! Defines the configuration for different types of secrets including
//! TTL settings, rate limits, and provider information.
//! Part of the `SecretlessAI` feature (F120).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// A secret type configuration for a tenant.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SecretTypeConfiguration {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant that owns this configuration.
    pub tenant_id: Uuid,

    /// Secret type name (e.g., "postgres-readonly").
    pub type_name: String,

    /// Human-readable description.
    pub description: Option<String>,

    /// Default TTL in seconds (default: 300 = 5 minutes).
    pub default_ttl_seconds: i32,

    /// Maximum allowed TTL in seconds (default: 3600 = 1 hour).
    pub max_ttl_seconds: i32,

    /// Provider type (openbao, infisical, internal, aws).
    pub provider_type: String,

    /// Provider-specific path (e.g., `OpenBao` mount path).
    pub provider_path: Option<String>,

    /// Rate limit per agent per hour.
    pub rate_limit_per_hour: i32,

    /// Whether this secret type is enabled.
    pub enabled: bool,

    /// Record creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Default TTL in seconds (5 minutes).
pub const DEFAULT_TTL_SECONDS: i32 = 300;

/// Maximum TTL in seconds (1 hour).
pub const MAX_TTL_SECONDS: i32 = 3600;

/// Default rate limit per hour.
pub const DEFAULT_RATE_LIMIT_PER_HOUR: i32 = 100;

impl SecretTypeConfiguration {
    /// Check if this configuration allows the requested TTL.
    pub fn validate_ttl(&self, requested_ttl: i32) -> Result<i32, String> {
        if requested_ttl < 60 {
            return Err("TTL must be at least 60 seconds".to_string());
        }
        if requested_ttl > self.max_ttl_seconds {
            return Err(format!(
                "TTL {} exceeds maximum allowed {} seconds",
                requested_ttl, self.max_ttl_seconds
            ));
        }
        Ok(requested_ttl)
    }

    /// Get the effective TTL (use default if not specified).
    #[must_use]
    pub fn effective_ttl(&self, requested_ttl: Option<i32>) -> i32 {
        requested_ttl.map_or(self.default_ttl_seconds, |ttl| {
            ttl.min(self.max_ttl_seconds)
        })
    }
}

/// Request to create a secret type configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateSecretTypeConfiguration {
    /// Secret type name (unique per tenant).
    pub type_name: String,

    /// Human-readable description.
    pub description: Option<String>,

    /// Default TTL in seconds.
    #[serde(default = "default_ttl")]
    pub default_ttl_seconds: i32,

    /// Maximum allowed TTL in seconds.
    #[serde(default = "max_ttl")]
    pub max_ttl_seconds: i32,

    /// Provider type.
    pub provider_type: String,

    /// Provider-specific path.
    pub provider_path: Option<String>,

    /// Rate limit per hour.
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_hour: i32,
}

fn default_ttl() -> i32 {
    DEFAULT_TTL_SECONDS
}

fn max_ttl() -> i32 {
    MAX_TTL_SECONDS
}

fn default_rate_limit() -> i32 {
    DEFAULT_RATE_LIMIT_PER_HOUR
}

/// Request to update a secret type configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateSecretTypeConfiguration {
    /// Updated description.
    pub description: Option<String>,

    /// Updated default TTL.
    pub default_ttl_seconds: Option<i32>,

    /// Updated max TTL.
    pub max_ttl_seconds: Option<i32>,

    /// Updated provider path.
    pub provider_path: Option<String>,

    /// Updated rate limit.
    pub rate_limit_per_hour: Option<i32>,

    /// Updated enabled status.
    pub enabled: Option<bool>,
}

/// Filter options for listing secret type configurations.
#[derive(Debug, Clone, Default)]
pub struct SecretTypeConfigFilter {
    /// Filter by provider type.
    pub provider_type: Option<String>,

    /// Filter by enabled status.
    pub enabled: Option<bool>,

    /// Search by type name prefix.
    pub type_name_prefix: Option<String>,
}

impl SecretTypeConfiguration {
    /// Find a configuration by ID.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM secret_type_configurations
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a configuration by type name.
    pub async fn find_by_type_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        type_name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM secret_type_configurations
            WHERE tenant_id = $1 AND type_name = $2
            ",
        )
        .bind(tenant_id)
        .bind(type_name)
        .fetch_optional(pool)
        .await
    }

    /// List configurations for a tenant.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &SecretTypeConfigFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM secret_type_configurations
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.provider_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND provider_type = ${param_count}"));
        }

        if filter.enabled.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND enabled = ${param_count}"));
        }

        if filter.type_name_prefix.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND type_name ILIKE ${param_count} || '%'"));
        }

        query.push_str(&format!(
            " ORDER BY type_name LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, SecretTypeConfiguration>(&query).bind(tenant_id);

        if let Some(ref provider_type) = filter.provider_type {
            q = q.bind(provider_type);
        }
        if let Some(enabled) = filter.enabled {
            q = q.bind(enabled);
        }
        if let Some(ref prefix) = filter.type_name_prefix {
            q = q.bind(prefix);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count configurations for a tenant.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &SecretTypeConfigFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM secret_type_configurations
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.provider_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND provider_type = ${param_count}"));
        }

        if filter.enabled.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND enabled = ${param_count}"));
        }

        if filter.type_name_prefix.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND type_name ILIKE ${param_count} || '%'"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(ref provider_type) = filter.provider_type {
            q = q.bind(provider_type);
        }
        if let Some(enabled) = filter.enabled {
            q = q.bind(enabled);
        }
        if let Some(ref prefix) = filter.type_name_prefix {
            q = q.bind(prefix);
        }

        q.fetch_one(pool).await
    }

    /// Create a new configuration.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateSecretTypeConfiguration,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO secret_type_configurations (
                tenant_id, type_name, description, default_ttl_seconds,
                max_ttl_seconds, provider_type, provider_path, rate_limit_per_hour
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&input.type_name)
        .bind(&input.description)
        .bind(input.default_ttl_seconds)
        .bind(input.max_ttl_seconds)
        .bind(&input.provider_type)
        .bind(&input.provider_path)
        .bind(input.rate_limit_per_hour)
        .fetch_one(pool)
        .await
    }

    /// Update a configuration.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateSecretTypeConfiguration,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if input.description.is_some() {
            updates.push(format!("description = ${param_idx}"));
            param_idx += 1;
        }
        if input.default_ttl_seconds.is_some() {
            updates.push(format!("default_ttl_seconds = ${param_idx}"));
            param_idx += 1;
        }
        if input.max_ttl_seconds.is_some() {
            updates.push(format!("max_ttl_seconds = ${param_idx}"));
            param_idx += 1;
        }
        if input.provider_path.is_some() {
            updates.push(format!("provider_path = ${param_idx}"));
            param_idx += 1;
        }
        if input.rate_limit_per_hour.is_some() {
            updates.push(format!("rate_limit_per_hour = ${param_idx}"));
            param_idx += 1;
        }
        if input.enabled.is_some() {
            updates.push(format!("enabled = ${param_idx}"));
            // param_idx += 1;
        }

        let query = format!(
            "UPDATE secret_type_configurations SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, SecretTypeConfiguration>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(ref description) = input.description {
            q = q.bind(description);
        }
        if let Some(default_ttl) = input.default_ttl_seconds {
            q = q.bind(default_ttl);
        }
        if let Some(max_ttl) = input.max_ttl_seconds {
            q = q.bind(max_ttl);
        }
        if let Some(ref provider_path) = input.provider_path {
            q = q.bind(provider_path);
        }
        if let Some(rate_limit) = input.rate_limit_per_hour {
            q = q.bind(rate_limit);
        }
        if let Some(enabled) = input.enabled {
            q = q.bind(enabled);
        }

        q.fetch_optional(pool).await
    }

    /// Delete a configuration.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM secret_type_configurations
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Enable a configuration.
    pub async fn enable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE secret_type_configurations
            SET enabled = true, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Disable a configuration.
    pub async fn disable(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE secret_type_configurations
            SET enabled = false, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_ttl() {
        let config = SecretTypeConfiguration {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            type_name: "test-type".to_string(),
            description: None,
            default_ttl_seconds: 300,
            max_ttl_seconds: 900,
            provider_type: "openbao".to_string(),
            provider_path: None,
            rate_limit_per_hour: 100,
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Valid TTL
        assert!(config.validate_ttl(300).is_ok());
        assert!(config.validate_ttl(900).is_ok());

        // Too short
        assert!(config.validate_ttl(30).is_err());

        // Too long
        assert!(config.validate_ttl(1000).is_err());
    }

    #[test]
    fn test_effective_ttl() {
        let config = SecretTypeConfiguration {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            type_name: "test-type".to_string(),
            description: None,
            default_ttl_seconds: 300,
            max_ttl_seconds: 900,
            provider_type: "openbao".to_string(),
            provider_path: None,
            rate_limit_per_hour: 100,
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Use default when not specified
        assert_eq!(config.effective_ttl(None), 300);

        // Use requested when within limits
        assert_eq!(config.effective_ttl(Some(600)), 600);

        // Cap at max when exceeding
        assert_eq!(config.effective_ttl(Some(1200)), 900);
    }

    #[test]
    fn test_create_config_defaults() {
        let input = CreateSecretTypeConfiguration {
            type_name: "test-type".to_string(),
            description: None,
            default_ttl_seconds: default_ttl(),
            max_ttl_seconds: max_ttl(),
            provider_type: "openbao".to_string(),
            provider_path: None,
            rate_limit_per_hour: default_rate_limit(),
        };

        assert_eq!(input.default_ttl_seconds, DEFAULT_TTL_SECONDS);
        assert_eq!(input.max_ttl_seconds, MAX_TTL_SECONDS);
        assert_eq!(input.rate_limit_per_hour, DEFAULT_RATE_LIMIT_PER_HOUR);
    }
}
