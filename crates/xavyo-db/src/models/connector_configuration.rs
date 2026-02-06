//! Connector Configuration model.
//!
//! Represents configurations for external system connectors (LDAP, Database, REST).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

/// Connector type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "varchar", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ConnectorType {
    /// LDAP/Active Directory connector.
    Ldap,
    /// Database connector (`PostgreSQL`, `MySQL`, etc.).
    Database,
    /// REST API connector.
    Rest,
}

impl std::fmt::Display for ConnectorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectorType::Ldap => write!(f, "ldap"),
            ConnectorType::Database => write!(f, "database"),
            ConnectorType::Rest => write!(f, "rest"),
        }
    }
}

impl std::str::FromStr for ConnectorType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ldap" => Ok(ConnectorType::Ldap),
            "database" => Ok(ConnectorType::Database),
            "rest" => Ok(ConnectorType::Rest),
            _ => Err(format!("Unknown connector type: {s}")),
        }
    }
}

/// Connector status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[sqlx(type_name = "varchar", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ConnectorStatus {
    /// Connector is active and can be used for operations.
    Active,
    /// Connector is inactive; no operations will be processed.
    Inactive,
    /// Connector is in error state (connection test failed).
    Error,
}

impl std::fmt::Display for ConnectorStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectorStatus::Active => write!(f, "active"),
            ConnectorStatus::Inactive => write!(f, "inactive"),
            ConnectorStatus::Error => write!(f, "error"),
        }
    }
}

impl std::str::FromStr for ConnectorStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "active" => Ok(ConnectorStatus::Active),
            "inactive" => Ok(ConnectorStatus::Inactive),
            "error" => Ok(ConnectorStatus::Error),
            _ => Err(format!("Unknown connector status: {s}")),
        }
    }
}

/// A connector configuration in the provisioning framework.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ConnectorConfiguration {
    /// Unique identifier for the connector.
    pub id: Uuid,

    /// The tenant this connector belongs to.
    pub tenant_id: Uuid,

    /// Connector display name.
    pub name: String,

    /// Connector type (ldap, database, rest).
    pub connector_type: ConnectorType,

    /// Connector description.
    pub description: Option<String>,

    /// Non-sensitive configuration (JSON).
    pub config: serde_json::Value,

    /// Encrypted credentials (AEAD ciphertext).
    #[serde(skip_serializing)]
    pub credentials_encrypted: Vec<u8>,

    /// Key version used for encryption (for rotation support).
    pub credentials_key_version: i32,

    /// Connector status (active, inactive, error).
    pub status: ConnectorStatus,

    /// Last connection test timestamp.
    pub last_connection_test: Option<DateTime<Utc>>,

    /// Last error message from connection test.
    pub last_error: Option<String>,

    /// When the connector was created.
    pub created_at: DateTime<Utc>,

    /// When the connector was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateConnectorConfiguration {
    pub name: String,
    pub connector_type: ConnectorType,
    pub description: Option<String>,
    pub config: serde_json::Value,
    /// Credentials to encrypt (provided in plaintext, stored encrypted).
    #[serde(skip_serializing)]
    pub credentials: serde_json::Value,
}

/// Request to update a connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConnectorConfiguration {
    pub name: Option<String>,
    pub description: Option<String>,
    pub config: Option<serde_json::Value>,
    /// New credentials to encrypt (if updating).
    #[serde(skip_serializing)]
    pub credentials: Option<serde_json::Value>,
    pub status: Option<ConnectorStatus>,
}

/// Filter for listing connectors.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectorFilter {
    pub connector_type: Option<ConnectorType>,
    pub status: Option<ConnectorStatus>,
    pub name_contains: Option<String>,
}

/// Summary view of a connector (for listing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorSummary {
    pub id: Uuid,
    pub name: String,
    pub connector_type: ConnectorType,
    pub status: ConnectorStatus,
    pub last_connection_test: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl ConnectorConfiguration {
    /// Find a connector by ID within a tenant.
    pub async fn find_by_id(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM connector_configurations
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a connector by name within a tenant.
    pub async fn find_by_name(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Self>, sqlx::Error> {
        sqlx::query_as(
            r"
            SELECT * FROM connector_configurations
            WHERE tenant_id = $1 AND name = $2
            ",
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// List all connectors for a tenant with pagination and filtering.
    pub async fn list_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ConnectorFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Self>, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT * FROM connector_configurations
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.connector_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND connector_type = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.name_contains.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND name ILIKE '%' || ${param_count} || '%'"));
        }

        query.push_str(&format!(
            " ORDER BY name LIMIT ${} OFFSET ${}",
            param_count + 1,
            param_count + 2
        ));

        let mut q = sqlx::query_as::<_, ConnectorConfiguration>(&query).bind(tenant_id);

        if let Some(connector_type) = filter.connector_type {
            q = q.bind(connector_type.to_string());
        }
        if let Some(status) = filter.status {
            q = q.bind(status.to_string());
        }
        if let Some(ref name_contains) = filter.name_contains {
            q = q.bind(name_contains);
        }

        q.bind(limit).bind(offset).fetch_all(pool).await
    }

    /// Count connectors in a tenant with filtering.
    pub async fn count_by_tenant(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        filter: &ConnectorFilter,
    ) -> Result<i64, sqlx::Error> {
        let mut query = String::from(
            r"
            SELECT COUNT(*) FROM connector_configurations
            WHERE tenant_id = $1
            ",
        );
        let mut param_count = 1;

        if filter.connector_type.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND connector_type = ${param_count}"));
        }
        if filter.status.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND status = ${param_count}"));
        }
        if filter.name_contains.is_some() {
            param_count += 1;
            query.push_str(&format!(" AND name ILIKE '%' || ${param_count} || '%'"));
        }

        let mut q = sqlx::query_scalar::<_, i64>(&query).bind(tenant_id);

        if let Some(connector_type) = filter.connector_type {
            q = q.bind(connector_type.to_string());
        }
        if let Some(status) = filter.status {
            q = q.bind(status.to_string());
        }
        if let Some(ref name_contains) = filter.name_contains {
            q = q.bind(name_contains);
        }

        q.fetch_one(pool).await
    }

    /// Create a new connector configuration.
    ///
    /// Note: Credentials must be encrypted BEFORE calling this method.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        name: &str,
        connector_type: ConnectorType,
        description: Option<&str>,
        config: &serde_json::Value,
        credentials_encrypted: &[u8],
        credentials_key_version: i32,
    ) -> Result<Self, sqlx::Error> {
        sqlx::query_as(
            r"
            INSERT INTO connector_configurations (
                tenant_id, name, connector_type, description, config,
                credentials_encrypted, credentials_key_version
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            ",
        )
        .bind(tenant_id)
        .bind(name)
        .bind(connector_type.to_string())
        .bind(description)
        .bind(config)
        .bind(credentials_encrypted)
        .bind(credentials_key_version)
        .fetch_one(pool)
        .await
    }

    /// Update a connector configuration.
    pub async fn update(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        input: &UpdateConnectorConfiguration,
        credentials_encrypted: Option<&[u8]>,
        credentials_key_version: Option<i32>,
    ) -> Result<Option<Self>, sqlx::Error> {
        let mut updates = vec!["updated_at = NOW()".to_string()];
        let mut param_idx = 3; // $1 = id, $2 = tenant_id

        if input.name.is_some() {
            updates.push(format!("name = ${param_idx}"));
            param_idx += 1;
        }
        if input.description.is_some() {
            updates.push(format!("description = ${param_idx}"));
            param_idx += 1;
        }
        if input.config.is_some() {
            updates.push(format!("config = ${param_idx}"));
            param_idx += 1;
        }
        if credentials_encrypted.is_some() {
            updates.push(format!("credentials_encrypted = ${param_idx}"));
            param_idx += 1;
        }
        if credentials_key_version.is_some() {
            updates.push(format!("credentials_key_version = ${param_idx}"));
            param_idx += 1;
        }
        if input.status.is_some() {
            updates.push(format!("status = ${param_idx}"));
            // param_idx += 1; // Last parameter
        }

        let query = format!(
            "UPDATE connector_configurations SET {} WHERE id = $1 AND tenant_id = $2 RETURNING *",
            updates.join(", ")
        );

        let mut q = sqlx::query_as::<_, ConnectorConfiguration>(&query)
            .bind(id)
            .bind(tenant_id);

        if let Some(ref name) = input.name {
            q = q.bind(name);
        }
        if let Some(ref description) = input.description {
            q = q.bind(description);
        }
        if let Some(ref config) = input.config {
            q = q.bind(config);
        }
        if let Some(creds) = credentials_encrypted {
            q = q.bind(creds);
        }
        if let Some(version) = credentials_key_version {
            q = q.bind(version);
        }
        if let Some(status) = input.status {
            q = q.bind(status.to_string());
        }

        q.fetch_optional(pool).await
    }

    /// Update connector status.
    pub async fn update_status(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        status: ConnectorStatus,
        error: Option<&str>,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            UPDATE connector_configurations
            SET status = $3, last_error = $4, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(status.to_string())
        .bind(error)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Update last connection test timestamp.
    pub async fn update_connection_test(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
        success: bool,
        error: Option<&str>,
    ) -> Result<bool, sqlx::Error> {
        let status = if success {
            ConnectorStatus::Active
        } else {
            ConnectorStatus::Error
        };

        let result = sqlx::query(
            r"
            UPDATE connector_configurations
            SET status = $3, last_connection_test = NOW(), last_error = $4, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(status.to_string())
        .bind(error)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Delete a connector configuration.
    pub async fn delete(
        pool: &sqlx::PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r"
            DELETE FROM connector_configurations
            WHERE id = $1 AND tenant_id = $2
            ",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Check if connector is active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        matches!(self.status, ConnectorStatus::Active)
    }

    /// Check if connector has an error.
    #[must_use]
    pub fn has_error(&self) -> bool {
        matches!(self.status, ConnectorStatus::Error)
    }

    /// Get summary view of this connector.
    #[must_use]
    pub fn to_summary(&self) -> ConnectorSummary {
        ConnectorSummary {
            id: self.id,
            name: self.name.clone(),
            connector_type: self.connector_type,
            status: self.status,
            last_connection_test: self.last_connection_test,
            created_at: self.created_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connector_type_display() {
        assert_eq!(ConnectorType::Ldap.to_string(), "ldap");
        assert_eq!(ConnectorType::Database.to_string(), "database");
        assert_eq!(ConnectorType::Rest.to_string(), "rest");
    }

    #[test]
    fn test_connector_type_from_str() {
        assert_eq!(
            "ldap".parse::<ConnectorType>().unwrap(),
            ConnectorType::Ldap
        );
        assert_eq!(
            "DATABASE".parse::<ConnectorType>().unwrap(),
            ConnectorType::Database
        );
        assert_eq!(
            "Rest".parse::<ConnectorType>().unwrap(),
            ConnectorType::Rest
        );
        assert!("unknown".parse::<ConnectorType>().is_err());
    }

    #[test]
    fn test_connector_status_display() {
        assert_eq!(ConnectorStatus::Active.to_string(), "active");
        assert_eq!(ConnectorStatus::Inactive.to_string(), "inactive");
        assert_eq!(ConnectorStatus::Error.to_string(), "error");
    }

    #[test]
    fn test_connector_status_from_str() {
        assert_eq!(
            "active".parse::<ConnectorStatus>().unwrap(),
            ConnectorStatus::Active
        );
        assert_eq!(
            "INACTIVE".parse::<ConnectorStatus>().unwrap(),
            ConnectorStatus::Inactive
        );
        assert_eq!(
            "Error".parse::<ConnectorStatus>().unwrap(),
            ConnectorStatus::Error
        );
        assert!("unknown".parse::<ConnectorStatus>().is_err());
    }

    #[test]
    fn test_create_connector_request() {
        let request = CreateConnectorConfiguration {
            name: "Corporate LDAP".to_string(),
            connector_type: ConnectorType::Ldap,
            description: Some("Main LDAP directory".to_string()),
            config: serde_json::json!({
                "host": "ldap.example.com",
                "port": 636,
                "base_dn": "dc=example,dc=com"
            }),
            credentials: serde_json::json!({
                "bind_dn": "cn=admin,dc=example,dc=com",
                "password": "secret"
            }),
        };

        assert_eq!(request.name, "Corporate LDAP");
        assert_eq!(request.connector_type, ConnectorType::Ldap);
    }

    #[test]
    fn test_connector_status_serialization() {
        let active = ConnectorStatus::Active;
        let json = serde_json::to_string(&active).unwrap();
        assert_eq!(json, "\"active\"");

        let parsed: ConnectorStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ConnectorStatus::Active);
    }

    #[test]
    fn test_connector_type_serialization() {
        let ldap = ConnectorType::Ldap;
        let json = serde_json::to_string(&ldap).unwrap();
        assert_eq!(json, "\"ldap\"");

        let parsed: ConnectorType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ConnectorType::Ldap);
    }

    #[test]
    fn test_connector_filter_default() {
        let filter = ConnectorFilter::default();
        assert!(filter.connector_type.is_none());
        assert!(filter.status.is_none());
        assert!(filter.name_contains.is_none());
    }
}
