//! Secret Provider Configuration model for dynamic secrets provisioning.
//!
//! Stores configuration for external secret providers (`OpenBao`, Infisical, AWS)
//! with encrypted connection settings.
//! Part of the `SecretlessAI` feature (F120).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Status of a secret provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderStatus {
    /// Provider is active and healthy.
    Active,
    /// Provider is disabled by admin.
    Inactive,
    /// Provider is in error state (connection failed).
    Error,
}

impl std::fmt::Display for ProviderStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderStatus::Active => write!(f, "active"),
            ProviderStatus::Inactive => write!(f, "inactive"),
            ProviderStatus::Error => write!(f, "error"),
        }
    }
}

impl std::str::FromStr for ProviderStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "active" => Ok(ProviderStatus::Active),
            "inactive" => Ok(ProviderStatus::Inactive),
            "error" => Ok(ProviderStatus::Error),
            _ => Err(format!("Invalid provider status: {s}")),
        }
    }
}

/// Configuration for an external secret provider.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct SecretProviderConfig {
    /// Unique identifier.
    pub id: Uuid,

    /// Tenant that owns this configuration.
    pub tenant_id: Uuid,

    /// Provider type (openbao, infisical, aws).
    pub provider_type: String,

    /// Human-readable name.
    pub name: String,

    /// Encrypted connection settings (JSON).
    pub connection_settings: String,

    /// Provider status.
    pub status: String,

    /// Last successful health check.
    pub last_health_check: Option<DateTime<Utc>>,

    /// Record creation timestamp.
    pub created_at: DateTime<Utc>,

    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl SecretProviderConfig {
    /// Parse the status as an enum.
    pub fn status_enum(&self) -> Result<ProviderStatus, String> {
        self.status.parse()
    }

    /// Check if the provider is active.
    #[must_use] 
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }

    /// Check if the provider is in error state.
    #[must_use] 
    pub fn is_error(&self) -> bool {
        self.status == "error"
    }
}

/// `OpenBao` connection settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OpenBaoSettings {
    /// `OpenBao` server address.
    pub addr: String,

    /// Authentication method (token, approle).
    pub auth_method: String,

    /// Token (if `auth_method` is "token").
    pub token: Option<String>,

    /// `AppRole` role ID (if `auth_method` is "approle").
    pub role_id: Option<String>,

    /// `AppRole` secret ID (if `auth_method` is "approle").
    pub secret_id: Option<String>,

    /// Namespace (optional).
    pub namespace: Option<String>,
}

/// Infisical connection settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct InfisicalSettings {
    /// Infisical server base URL.
    pub base_url: String,

    /// Service token for authentication.
    pub service_token: String,

    /// Workspace ID.
    pub workspace_id: String,

    /// Environment (e.g., "production").
    pub environment: String,
}

/// AWS Secrets Manager connection settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AwsSettings {
    /// AWS region.
    pub region: String,

    /// Access key ID (optional, uses IAM role if not set).
    pub access_key_id: Option<String>,

    /// Secret access key (optional, uses IAM role if not set).
    pub secret_access_key: Option<String>,

    /// IAM role ARN to assume (optional).
    pub role_arn: Option<String>,
}

/// Request to create a secret provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CreateSecretProviderConfig {
    /// Provider type.
    pub provider_type: String,

    /// Human-readable name.
    pub name: String,

    /// Connection settings (will be encrypted).
    pub connection_settings: String,
}

/// Request to update a secret provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct UpdateSecretProviderConfig {
    /// Updated name.
    pub name: Option<String>,

    /// Updated connection settings (will be encrypted).
    pub connection_settings: Option<String>,

    /// Updated status.
    pub status: Option<String>,
}

/// Filter options for listing provider configurations.
#[derive(Debug, Clone, Default)]
pub struct SecretProviderConfigFilter {
    /// Filter by provider type.
    pub provider_type: Option<String>,

    /// Filter by status.
    pub status: Option<String>,

    /// Search by name prefix.
    pub name_prefix: Option<String>,
}

/// Health check result for a provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ProviderHealthResult {
    /// Health status.
    pub status: ProviderHealthStatus,

    /// Last check timestamp.
    pub last_check: DateTime<Utc>,

    /// Latency in milliseconds.
    pub latency_ms: Option<f64>,

    /// Error message (if unhealthy).
    pub error: Option<String>,
}

/// Health status levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderHealthStatus {
    /// Provider is healthy.
    Healthy,
    /// Provider is degraded but functional.
    Degraded,
    /// Provider is unhealthy.
    Unhealthy,
}

impl SecretProviderConfig {
    /// Find a configuration by ID.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM secret_provider_configs
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a configuration by name.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM secret_provider_configs
            WHERE tenant_id = $1 AND name = $2
            ",
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// Find active providers by type.
    pub async fn find_active_by_type(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        provider_type: &str,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM secret_provider_configs
            WHERE tenant_id = $1 AND provider_type = $2 AND status = 'active'
            ORDER BY name
            ",
        )
        .bind(tenant_id)
        .bind(provider_type)
        .fetch_all(pool)
        .await
    }

    /// List configurations for a tenant with filtering.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &SecretProviderConfigFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM secret_provider_configs
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.provider_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND provider_type = ${param_count}"));
        }

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }

        if filter.name_prefix.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND name ILIKE ${param_count} || '%'"));
        }

        query.push_str(&format!(
            " ORDER BY name LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, SecretProviderConfig>(&query).bind(tenant_id);

        if let Some(ref provider_type) = filter.provider_type {
            q = q.bind(provider_type);
        }
        if let Some(ref status) = filter.status {
            q = q.bind(status);
        }
        if let Some(ref prefix) = filter.name_prefix {
            q = q.bind(prefix);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count configurations for a tenant.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &SecretProviderConfigFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM secret_provider_configs
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.provider_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND provider_type = ${param_count}"));
        }

        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }

        if filter.name_prefix.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND name ILIKE ${param_count} || '%'"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(ref provider_type) = filter.provider_type {
            q = q.bind(provider_type);
        }
        if let Some(ref status) = filter.status {
            q = q.bind(status);
        }
        if let Some(ref prefix) = filter.name_prefix {
            q = q.bind(prefix);
        }

        q.fetch_one(pool).await
    }

    /// Create a new configuration.
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        input: CreateSecretProviderConfig,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO secret_provider_configs (
                tenant_id, provider_type, name, connection_settings
            )
            VALUES ($1, $2, $3, $4)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(&input.provider_type)
        .bind(&input.name)
        .bind(&input.connection_settings)
        .fetch_one(pool)
        .await
    }

    /// Update a configuration.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateSecretProviderConfig,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3;

        if input.name.is_some() {
            updates.push(format!("name = ${param_idx}"));
            param_idx += 1;
        }
        if input.connection_settings.is_some() {
            updates.push(format!("connection_settings = ${param_idx}"));
            param_idx += 1;
        }
        if input.status.is_some() {
            updates.push(format!("status = ${param_idx}"));
            // param_idx += 1;
        }

        let query = format!(
            "UPDATE secret_provider_configs SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, SecretProviderConfig>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(ref connection_settings) = input.connection_settings {
            q = q.bind(connection_settings);
        }
        if let Some(ref status) = input.status {
            q = q.bind(status);
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
            DELETE FROM secret_provider_configs
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Update health check timestamp.
    pub async fn update_health_check(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        success: bool,
    ) -> Result<Option<Self>, sqlx::Error> {
        let status = if success { "active" } else { "error" };

        sqlx::query_as(
            r"
            UPDATE secret_provider_configs
            SET last_health_check = NOW(), status = $3, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(status)
        .fetch_optional(pool)
        .await
    }

    /// Set provider status to error.
    pub async fn set_error_status(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE secret_provider_configs
            SET status = 'error', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Activate a provider.
    pub async fn activate(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE secret_provider_configs
            SET status = 'active', updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            RETURNING *
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Deactivate a provider.
    pub async fn deactivate(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE secret_provider_configs
            SET status = 'inactive', updated_at = NOW()
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
    fn test_provider_status_display() {
        assert_eq!(ProviderStatus::Active.to_string(), "active");
        assert_eq!(ProviderStatus::Inactive.to_string(), "inactive");
        assert_eq!(ProviderStatus::Error.to_string(), "error");
    }

    #[test]
    fn test_provider_status_from_str() {
        assert_eq!(
            "active".parse::<ProviderStatus>().unwrap(),
            ProviderStatus::Active
        );
        assert_eq!(
            "INACTIVE".parse::<ProviderStatus>().unwrap(),
            ProviderStatus::Inactive
        );
        assert!("invalid".parse::<ProviderStatus>().is_err());
    }

    #[test]
    fn test_config_helper_methods() {
        let config = SecretProviderConfig {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            provider_type: "openbao".to_string(),
            name: "test-provider".to_string(),
            connection_settings: "encrypted".to_string(),
            status: "active".to_string(),
            last_health_check: Some(Utc::now()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(config.is_active());
        assert!(!config.is_error());

        let error_config = SecretProviderConfig {
            status: "error".to_string(),
            ..config
        };
        assert!(!error_config.is_active());
        assert!(error_config.is_error());
    }

    #[test]
    fn test_openbao_settings_serialization() {
        let settings = OpenBaoSettings {
            addr: "https://openbao.example.com:8200".to_string(),
            auth_method: "approle".to_string(),
            token: None,
            role_id: Some("role-123".to_string()),
            secret_id: Some("secret-456".to_string()),
            namespace: Some("xavyo".to_string()),
        };

        let json = serde_json::to_string(&settings).unwrap();
        assert!(json.contains("openbao.example.com"));
        assert!(json.contains("approle"));

        let deserialized: OpenBaoSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.addr, settings.addr);
        assert_eq!(deserialized.auth_method, "approle");
    }

    #[test]
    fn test_infisical_settings_serialization() {
        let settings = InfisicalSettings {
            base_url: "https://infisical.example.com".to_string(),
            service_token: "st.xxx.yyy".to_string(),
            workspace_id: "ws-123".to_string(),
            environment: "production".to_string(),
        };

        let json = serde_json::to_string(&settings).unwrap();
        let deserialized: InfisicalSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.workspace_id, "ws-123");
    }

    #[test]
    fn test_aws_settings_serialization() {
        let settings = AwsSettings {
            region: "eu-west-1".to_string(),
            access_key_id: None,
            secret_access_key: None,
            role_arn: Some("arn:aws:iam::123:role/secrets".to_string()),
        };

        let json = serde_json::to_string(&settings).unwrap();
        let deserialized: AwsSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.region, "eu-west-1");
        assert!(deserialized.role_arn.is_some());
    }
}
