//! Tenant Identity Provider model for OIDC federation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Provider type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "VARCHAR", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ProviderType {
    AzureAd,
    Okta,
    GoogleWorkspace,
    GenericOidc,
}

impl std::fmt::Display for ProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderType::AzureAd => write!(f, "azure_ad"),
            ProviderType::Okta => write!(f, "okta"),
            ProviderType::GoogleWorkspace => write!(f, "google_workspace"),
            ProviderType::GenericOidc => write!(f, "generic_oidc"),
        }
    }
}

impl std::str::FromStr for ProviderType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "azure_ad" => Ok(ProviderType::AzureAd),
            "okta" => Ok(ProviderType::Okta),
            "google_workspace" => Ok(ProviderType::GoogleWorkspace),
            "generic_oidc" => Ok(ProviderType::GenericOidc),
            _ => Err(format!("Unknown provider type: {s}")),
        }
    }
}

/// Validation status for `IdP` configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "VARCHAR", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    Pending,
    Valid,
    Invalid,
}

impl std::fmt::Display for ValidationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationStatus::Pending => write!(f, "pending"),
            ValidationStatus::Valid => write!(f, "valid"),
            ValidationStatus::Invalid => write!(f, "invalid"),
        }
    }
}

/// Tenant Identity Provider entity.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct TenantIdentityProvider {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub provider_type: String,
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret_encrypted: Vec<u8>,
    pub claim_mapping: serde_json::Value,
    pub scopes: String,
    pub sync_on_login: bool,
    pub is_enabled: bool,
    pub validation_status: String,
    pub last_validated_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Input for creating a new identity provider.
#[derive(Debug, Clone)]
pub struct CreateIdentityProvider {
    pub tenant_id: Uuid,
    pub name: String,
    pub provider_type: ProviderType,
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret_encrypted: Vec<u8>,
    pub claim_mapping: serde_json::Value,
    pub scopes: String,
    pub sync_on_login: bool,
}

/// Input for updating an identity provider.
#[derive(Debug, Clone, Default)]
pub struct UpdateIdentityProvider {
    pub name: Option<String>,
    pub issuer_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret_encrypted: Option<Vec<u8>>,
    pub claim_mapping: Option<serde_json::Value>,
    pub scopes: Option<String>,
    pub sync_on_login: Option<bool>,
}

impl TenantIdentityProvider {
    /// Create a new identity provider in the database.
    pub async fn create(
        pool: &sqlx::PgPool,
        input: CreateIdentityProvider,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO tenant_identity_providers (
                tenant_id, name, provider_type, issuer_url, client_id,
                client_secret_encrypted, claim_mapping, scopes, sync_on_login
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            ",
        )
        .bind(input.tenant_id)
        .bind(&input.name)
        .bind(input.provider_type.to_string())
        .bind(&input.issuer_url)
        .bind(&input.client_id)
        .bind(&input.client_secret_encrypted)
        .bind(&input.claim_mapping)
        .bind(&input.scopes)
        .bind(input.sync_on_login)
        .fetch_one(pool)
        .await
    }

    /// Find an identity provider by ID.
    pub async fn find_by_id(pool: &sqlx::PgPool, id: Uuid) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as("SELECT * FROM tenant_identity_providers WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
    }

    /// Find an identity provider by ID within a tenant.
    pub async fn find_by_id_and_tenant(
        pool: &sqlx::PgPool,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as("SELECT * FROM tenant_identity_providers WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .fetch_optional(pool)
            .await
    }

    /// List all identity providers for a tenant.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM tenant_identity_providers
            WHERE tenant_id = $1
            ORDER BY created_at DESC
            OFFSET $2 LIMIT $3
            ",
        )
        .bind(tenant_id)
        .bind(offset)
        .bind(limit)
        .fetch_all(pool)
        .await
    }

    /// List enabled identity providers for a tenant.
    pub async fn list_enabled_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
    ) -> Result<Vec<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM tenant_identity_providers
            WHERE tenant_id = $1 AND is_enabled = true
            ORDER BY created_at ASC
            ",
        )
        .bind(tenant_id)
        .fetch_all(pool)
        .await
    }

    /// Count identity providers for a tenant.
    pub async fn count_by_tenant(pool: &sqlx::PgPool, tenant_id: Uuid) -> Result<i64, sqlx::Error> {
        let result: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM tenant_identity_providers WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(pool)
                .await?;
        Ok(result.0)
    }

    /// Check if issuer URL already exists for tenant.
    pub async fn issuer_exists(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        issuer_url: &str,
        exclude_id: Option<Uuid>,
    ) -> Result<bool, sqlx::Error> {
        let result: (bool,) = if let Some(exclude) = exclude_id {
            sqlx::query_as(
                r"
                SELECT EXISTS(
                    SELECT 1 FROM tenant_identity_providers
                    WHERE tenant_id = $1 AND issuer_url = $2 AND id != $3
                )
                ",
            )
            .bind(tenant_id)
            .bind(issuer_url)
            .bind(exclude)
            .fetch_one(pool)
            .await?
        } else {
            sqlx::query_as(
                r"
                SELECT EXISTS(
                    SELECT 1 FROM tenant_identity_providers
                    WHERE tenant_id = $1 AND issuer_url = $2
                )
                ",
            )
            .bind(tenant_id)
            .bind(issuer_url)
            .fetch_one(pool)
            .await?
        };
        Ok(result.0)
    }

    /// Update an identity provider.
    pub async fn update(
        pool: &sqlx::PgPool,
        id: Uuid,
        input: UpdateIdentityProvider,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE tenant_identity_providers
            SET
                name = COALESCE($2, name),
                issuer_url = COALESCE($3, issuer_url),
                client_id = COALESCE($4, client_id),
                client_secret_encrypted = COALESCE($5, client_secret_encrypted),
                claim_mapping = COALESCE($6, claim_mapping),
                scopes = COALESCE($7, scopes),
                sync_on_login = COALESCE($8, sync_on_login),
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            ",
        )
        .bind(id)
        .bind(&input.name)
        .bind(&input.issuer_url)
        .bind(&input.client_id)
        .bind(&input.client_secret_encrypted)
        .bind(&input.claim_mapping)
        .bind(&input.scopes)
        .bind(input.sync_on_login)
        .fetch_one(pool)
        .await
    }

    /// Update validation status.
    pub async fn update_validation_status(
        pool: &sqlx::PgPool,
        id: Uuid,
        status: ValidationStatus,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE tenant_identity_providers
            SET
                validation_status = $2,
                last_validated_at = NOW(),
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            ",
        )
        .bind(id)
        .bind(status.to_string())
        .fetch_one(pool)
        .await
    }

    /// Toggle enabled status.
    pub async fn set_enabled(
        pool: &sqlx::PgPool,
        id: Uuid,
        is_enabled: bool,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            UPDATE tenant_identity_providers
            SET is_enabled = $2, updated_at = NOW()
            WHERE id = $1
            RETURNING *
            ",
        )
        .bind(id)
        .bind(is_enabled)
        .fetch_one(pool)
        .await
    }

    /// Delete an identity provider.
    pub async fn delete(pool: &sqlx::PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM tenant_identity_providers WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Get provider type enum.
    pub fn get_provider_type(&self) -> Result<ProviderType, String> {
        self.provider_type.parse()
    }

    /// Get validation status enum.
    pub fn get_validation_status(&self) -> Result<ValidationStatus, String> {
        match self.validation_status.as_str() {
            "pending" => Ok(ValidationStatus::Pending),
            "valid" => Ok(ValidationStatus::Valid),
            "invalid" => Ok(ValidationStatus::Invalid),
            _ => Err(format!(
                "Unknown validation status: {}",
                self.validation_status
            )),
        }
    }

    /// Create a default instance for testing.
    /// Available in all builds for downstream crate tests.
    #[must_use] 
    pub fn default_for_test() -> Self {
        Self {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "Test IdP".to_string(),
            provider_type: "generic_oidc".to_string(),
            issuer_url: "https://idp.example.com".to_string(),
            client_id: "test-client".to_string(),
            client_secret_encrypted: vec![],
            claim_mapping: serde_json::json!({}),
            scopes: "openid profile email".to_string(),
            sync_on_login: true,
            is_enabled: true,
            validation_status: "valid".to_string(),
            last_validated_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }
}
