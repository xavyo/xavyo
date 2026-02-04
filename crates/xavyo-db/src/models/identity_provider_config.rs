//! Identity Provider Configuration model for Workload Identity Federation (F121).
//!
//! Stores cloud identity provider configurations per tenant.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Cloud identity provider type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "VARCHAR", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum CloudProviderType {
    /// Amazon Web Services STS.
    Aws,
    /// Google Cloud Platform Workload Identity.
    Gcp,
    /// Microsoft Azure AD Federated Credentials.
    Azure,
    /// Kubernetes OIDC for service account tokens.
    Kubernetes,
}

impl std::fmt::Display for CloudProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CloudProviderType::Aws => write!(f, "aws"),
            CloudProviderType::Gcp => write!(f, "gcp"),
            CloudProviderType::Azure => write!(f, "azure"),
            CloudProviderType::Kubernetes => write!(f, "kubernetes"),
        }
    }
}

impl std::str::FromStr for CloudProviderType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "aws" => Ok(CloudProviderType::Aws),
            "gcp" => Ok(CloudProviderType::Gcp),
            "azure" => Ok(CloudProviderType::Azure),
            "kubernetes" => Ok(CloudProviderType::Kubernetes),
            _ => Err(format!("Unknown provider type: {s}")),
        }
    }
}

/// Health status of the identity provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, Default)]
#[sqlx(type_name = "VARCHAR", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum IdpHealthStatus {
    /// Not yet checked.
    #[default]
    Pending,
    /// Provider is reachable and working.
    Healthy,
    /// Provider is unreachable or returning errors.
    Unhealthy,
}

/// Identity provider configuration.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct IdentityProviderConfig {
    /// Unique identifier.
    pub id: Uuid,
    /// Tenant this provider belongs to.
    pub tenant_id: Uuid,
    /// Type of cloud provider.
    pub provider_type: String,
    /// Human-readable name.
    pub name: String,
    /// Encrypted configuration (JSONB).
    pub configuration: String,
    /// Whether the provider is active.
    pub is_active: bool,
    /// Last health check timestamp.
    pub last_health_check: Option<DateTime<Utc>>,
    /// Current health status.
    pub health_status: String,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Request to create an identity provider configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateIdentityProviderConfig {
    /// Type of cloud provider.
    pub provider_type: CloudProviderType,
    /// Human-readable name.
    pub name: String,
    /// Encrypted configuration.
    pub configuration: String,
    /// Whether the provider is active (default: true).
    #[serde(default = "default_true")]
    pub is_active: bool,
}

fn default_true() -> bool {
    true
}

/// Request to update an identity provider configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct UpdateIdentityProviderConfig {
    /// New name.
    pub name: Option<String>,
    /// New encrypted configuration.
    pub configuration: Option<String>,
    /// New active status.
    pub is_active: Option<bool>,
}

/// Filter for listing identity provider configurations.
#[derive(Debug, Clone, Default)]
pub struct IdentityProviderConfigFilter {
    /// Filter by provider type.
    pub provider_type: Option<CloudProviderType>,
    /// Filter by active status.
    pub is_active: Option<bool>,
}

impl IdentityProviderConfig {
    /// Create a new identity provider configuration.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        request: &CreateIdentityProviderConfig,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            INSERT INTO identity_provider_configs (
                tenant_id, provider_type, name, configuration, is_active
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING
                id, tenant_id, provider_type, name, configuration, is_active,
                last_health_check, health_status, created_at, updated_at
            "#,
            tenant_id,
            request.provider_type.to_string(),
            &request.name,
            &request.configuration,
            request.is_active,
        )
        .fetch_one(pool)
        .await
    }

    /// Get an identity provider configuration by ID.
    pub async fn get_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            SELECT
                id, tenant_id, provider_type, name, configuration, is_active,
                last_health_check, health_status, created_at, updated_at
            FROM identity_provider_configs
            WHERE tenant_id = $1 AND id = $2
            "#,
            tenant_id,
            id,
        )
        .fetch_optional(pool)
        .await
    }

    /// List identity provider configurations for a tenant.
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        filter: &IdentityProviderConfigFilter,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            SELECT
                id, tenant_id, provider_type, name, configuration, is_active,
                last_health_check, health_status, created_at, updated_at
            FROM identity_provider_configs
            WHERE tenant_id = $1
                AND ($2::text IS NULL OR provider_type = $2)
                AND ($3::bool IS NULL OR is_active = $3)
            ORDER BY created_at DESC
            "#,
            tenant_id,
            filter.provider_type.map(|t| t.to_string()),
            filter.is_active,
        )
        .fetch_all(pool)
        .await
    }

    /// Update an identity provider configuration.
    pub async fn update(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        request: &UpdateIdentityProviderConfig,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            UPDATE identity_provider_configs
            SET
                name = COALESCE($3, name),
                configuration = COALESCE($4, configuration),
                is_active = COALESCE($5, is_active),
                updated_at = now()
            WHERE tenant_id = $1 AND id = $2
            RETURNING
                id, tenant_id, provider_type, name, configuration, is_active,
                last_health_check, health_status, created_at, updated_at
            "#,
            tenant_id,
            id,
            request.name.as_ref(),
            request.configuration.as_ref(),
            request.is_active,
        )
        .fetch_optional(pool)
        .await
    }

    /// Delete an identity provider configuration.
    pub async fn delete(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query!(
            r#"
            DELETE FROM identity_provider_configs
            WHERE tenant_id = $1 AND id = $2
            "#,
            tenant_id,
            id,
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Update health status after a health check.
    pub async fn update_health(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        status: IdpHealthStatus,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query!(
            r#"
            UPDATE identity_provider_configs
            SET
                health_status = $3,
                last_health_check = now(),
                updated_at = now()
            WHERE tenant_id = $1 AND id = $2
            "#,
            tenant_id,
            id,
            status.to_string(),
        )
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Get all active providers for a tenant by type.
    pub async fn get_active_by_type(
        pool: &PgPool,
        tenant_id: Uuid,
        provider_type: CloudProviderType,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as!(
            Self,
            r#"
            SELECT
                id, tenant_id, provider_type, name, configuration, is_active,
                last_health_check, health_status, created_at, updated_at
            FROM identity_provider_configs
            WHERE tenant_id = $1 AND provider_type = $2 AND is_active = true
            ORDER BY created_at ASC
            "#,
            tenant_id,
            provider_type.to_string(),
        )
        .fetch_all(pool)
        .await
    }

    /// Check if a provider with the given name already exists for a tenant.
    ///
    /// Used for unique name validation per tenant (T042).
    pub async fn exists_by_name(
        pool: &PgPool,
        tenant_id: Uuid,
        name: &str,
        exclude_id: Option<Uuid>,
    ) -> Result<bool, sqlx::Error> {
        let exists = sqlx::query_scalar!(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM identity_provider_configs
                WHERE tenant_id = $1 AND LOWER(name) = LOWER($2)
                AND ($3::uuid IS NULL OR id != $3)
            ) as "exists!"
            "#,
            tenant_id,
            name,
            exclude_id,
        )
        .fetch_one(pool)
        .await?;

        Ok(exists)
    }
}

impl std::fmt::Display for IdpHealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdpHealthStatus::Pending => write!(f, "pending"),
            IdpHealthStatus::Healthy => write!(f, "healthy"),
            IdpHealthStatus::Unhealthy => write!(f, "unhealthy"),
        }
    }
}

impl std::str::FromStr for IdpHealthStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(IdpHealthStatus::Pending),
            "healthy" => Ok(IdpHealthStatus::Healthy),
            "unhealthy" => Ok(IdpHealthStatus::Unhealthy),
            _ => Err(format!("Unknown health status: {s}")),
        }
    }
}
