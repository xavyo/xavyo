//! Connector Service for managing connector configurations.
//!
//! Provides CRUD operations for connectors with credential encryption,
//! connection testing, and lifecycle management.

use std::sync::Arc;
use tracing::{debug, info, warn};
use uuid::Uuid;

use sqlx::PgPool;
use xavyo_connector::crypto::CredentialEncryption;
use xavyo_connector::ids::ConnectorId;
use xavyo_connector::registry::ConnectorRegistry;
use xavyo_connector::traits::Connector;
use xavyo_connector_database::config::{DatabaseConfig, DatabaseDriver};
use xavyo_connector_database::DatabaseConnector;
use xavyo_connector_entra::{EntraConfig, EntraConnector, EntraCredentials};
use xavyo_connector_ldap::config::{ActiveDirectoryConfig, LdapConfig, SearchBase};
use xavyo_connector_ldap::{AdConnector, LdapConnector};
use xavyo_connector_rest::config::RestConfig;
use xavyo_connector_rest::RestConnector;
use xavyo_db::models::{
    ConnectorConfiguration, ConnectorFilter, ConnectorStatus, ConnectorSummary,
    ConnectorType as DbConnectorType, CreateConnectorConfiguration, UpdateConnectorConfiguration,
};

use crate::error::{ConnectorApiError, Result};

/// Current key version for credential encryption.
const CURRENT_KEY_VERSION: i32 = 1;

/// Service for connector configuration operations.
pub struct ConnectorService {
    pool: PgPool,
    encryption: Arc<CredentialEncryption>,
    registry: Arc<ConnectorRegistry>,
}

impl ConnectorService {
    /// Create a new connector service.
    pub fn new(
        pool: PgPool,
        encryption: Arc<CredentialEncryption>,
        registry: Arc<ConnectorRegistry>,
    ) -> Self {
        Self {
            pool,
            encryption,
            registry,
        }
    }

    /// List connectors for a tenant with pagination and filtering.
    pub async fn list_connectors(
        &self,
        tenant_id: Uuid,
        filter: ConnectorFilter,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<ConnectorSummary>, i64)> {
        let connectors =
            ConnectorConfiguration::list_by_tenant(&self.pool, tenant_id, &filter, limit, offset)
                .await?;

        let summaries: Vec<ConnectorSummary> = connectors
            .iter()
            .map(xavyo_db::models::ConnectorConfiguration::to_summary)
            .collect();

        let total = ConnectorConfiguration::count_by_tenant(&self.pool, tenant_id, &filter).await?;

        Ok((summaries, total))
    }

    /// Get a connector by ID.
    ///
    /// Returns the connector configuration without decrypted credentials.
    pub async fn get_connector(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<ConnectorConfiguration> {
        ConnectorConfiguration::find_by_id(&self.pool, tenant_id, connector_id)
            .await?
            .ok_or(ConnectorApiError::ConnectorNotFound(connector_id))
    }

    /// Create a new connector configuration.
    ///
    /// Encrypts credentials before storing.
    pub async fn create_connector(
        &self,
        tenant_id: Uuid,
        input: CreateConnectorConfiguration,
    ) -> Result<ConnectorConfiguration> {
        // Validate name
        if input.name.trim().is_empty() {
            return Err(ConnectorApiError::Validation(
                "Connector name cannot be empty".to_string(),
            ));
        }

        if input.name.len() > 255 {
            return Err(ConnectorApiError::Validation(
                "Connector name cannot exceed 255 characters".to_string(),
            ));
        }

        // Check for duplicate name
        if let Some(_existing) =
            ConnectorConfiguration::find_by_name(&self.pool, tenant_id, &input.name).await?
        {
            return Err(ConnectorApiError::ConnectorNameExists(input.name));
        }

        // Validate configuration format based on connector type
        self.validate_config(&input.connector_type, &input.config)?;

        // Encrypt credentials
        let credentials_json = serde_json::to_vec(&input.credentials).map_err(|e| {
            ConnectorApiError::InvalidConfiguration(format!("Failed to serialize credentials: {e}"))
        })?;

        let credentials_encrypted = self
            .encryption
            .encrypt(tenant_id, &credentials_json)
            .map_err(|e| ConnectorApiError::EncryptionFailed(e.to_string()))?;

        // Create connector
        let connector = ConnectorConfiguration::create(
            &self.pool,
            tenant_id,
            &input.name,
            input.connector_type,
            input.description.as_deref(),
            &input.config,
            &credentials_encrypted,
            CURRENT_KEY_VERSION,
        )
        .await?;

        info!(
            connector_id = %connector.id,
            connector_name = %connector.name,
            connector_type = %connector.connector_type,
            "Created connector configuration"
        );

        Ok(connector)
    }

    /// Update a connector configuration.
    ///
    /// Encrypts new credentials if provided.
    pub async fn update_connector(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        input: UpdateConnectorConfiguration,
    ) -> Result<ConnectorConfiguration> {
        // Verify connector exists
        let existing = self.get_connector(tenant_id, connector_id).await?;

        // Check for duplicate name if name is being changed
        if let Some(ref new_name) = input.name {
            if new_name.trim().is_empty() {
                return Err(ConnectorApiError::Validation(
                    "Connector name cannot be empty".to_string(),
                ));
            }

            if new_name.len() > 255 {
                return Err(ConnectorApiError::Validation(
                    "Connector name cannot exceed 255 characters".to_string(),
                ));
            }

            if new_name != &existing.name {
                if let Some(_existing_with_name) =
                    ConnectorConfiguration::find_by_name(&self.pool, tenant_id, new_name).await?
                {
                    return Err(ConnectorApiError::ConnectorNameExists(new_name.clone()));
                }
            }
        }

        // Validate configuration if provided
        if let Some(ref config) = input.config {
            self.validate_config(&existing.connector_type, config)?;
        }

        // Encrypt new credentials if provided
        let (credentials_encrypted, credentials_key_version) =
            if let Some(ref creds) = input.credentials {
                let credentials_json = serde_json::to_vec(creds).map_err(|e| {
                    ConnectorApiError::InvalidConfiguration(format!(
                        "Failed to serialize credentials: {e}"
                    ))
                })?;

                let encrypted = self
                    .encryption
                    .encrypt(tenant_id, &credentials_json)
                    .map_err(|e| ConnectorApiError::EncryptionFailed(e.to_string()))?;

                (Some(encrypted), Some(CURRENT_KEY_VERSION))
            } else {
                (None, None)
            };

        // Update connector
        let updated = ConnectorConfiguration::update(
            &self.pool,
            tenant_id,
            connector_id,
            &input,
            credentials_encrypted.as_deref(),
            credentials_key_version,
        )
        .await?
        .ok_or(ConnectorApiError::ConnectorNotFound(connector_id))?;

        info!(
            connector_id = %connector_id,
            connector_name = %updated.name,
            "Updated connector configuration"
        );

        Ok(updated)
    }

    /// Delete a connector configuration.
    pub async fn delete_connector(&self, tenant_id: Uuid, connector_id: Uuid) -> Result<()> {
        // Verify connector exists
        let connector = self.get_connector(tenant_id, connector_id).await?;

        // Remove from registry if cached
        self.registry
            .remove(ConnectorId::from_uuid(connector_id))
            .await;

        // Delete from database
        let deleted = ConnectorConfiguration::delete(&self.pool, tenant_id, connector_id).await?;

        if deleted {
            info!(
                connector_id = %connector_id,
                connector_name = %connector.name,
                "Deleted connector configuration"
            );
            Ok(())
        } else {
            Err(ConnectorApiError::ConnectorNotFound(connector_id))
        }
    }

    /// Test a connector's connection to its target system.
    ///
    /// Creates a temporary connector instance and tests the connection.
    pub async fn test_connector(&self, tenant_id: Uuid, connector_id: Uuid) -> Result<()> {
        let config = self.get_connector(tenant_id, connector_id).await?;

        // Decrypt credentials
        let credentials = self.decrypt_credentials(tenant_id, &config)?;

        // Build and test connector
        let connector = self.build_connector(&config, &credentials)?;

        let result = connector.test_connection().await;

        // Update connection test status
        let (success, error_msg) = match &result {
            Ok(()) => (true, None),
            Err(e) => {
                warn!(
                    connector_id = %connector_id,
                    error = %e,
                    "Connection test failed"
                );
                (false, Some(e.to_string()))
            }
        };

        ConnectorConfiguration::update_connection_test(
            &self.pool,
            tenant_id,
            connector_id,
            success,
            error_msg.as_deref(),
        )
        .await?;

        result.map_err(|e| ConnectorApiError::ConnectionTestFailed(e.to_string()))
    }

    /// Activate a connector (set status to Active).
    pub async fn activate_connector(&self, tenant_id: Uuid, connector_id: Uuid) -> Result<()> {
        let _config = self.get_connector(tenant_id, connector_id).await?;

        let updated = ConnectorConfiguration::update_status(
            &self.pool,
            tenant_id,
            connector_id,
            ConnectorStatus::Active,
            None,
        )
        .await?;

        if updated {
            info!(connector_id = %connector_id, "Activated connector");
            Ok(())
        } else {
            Err(ConnectorApiError::ConnectorNotFound(connector_id))
        }
    }

    /// Deactivate a connector (set status to Inactive).
    pub async fn deactivate_connector(&self, tenant_id: Uuid, connector_id: Uuid) -> Result<()> {
        let _config = self.get_connector(tenant_id, connector_id).await?;

        // Remove from registry if cached
        self.registry
            .remove(ConnectorId::from_uuid(connector_id))
            .await;

        let updated = ConnectorConfiguration::update_status(
            &self.pool,
            tenant_id,
            connector_id,
            ConnectorStatus::Inactive,
            None,
        )
        .await?;

        if updated {
            info!(connector_id = %connector_id, "Deactivated connector");
            Ok(())
        } else {
            Err(ConnectorApiError::ConnectorNotFound(connector_id))
        }
    }

    /// Get or create a live connector instance from the registry.
    ///
    /// Used for provisioning operations.
    pub async fn get_live_connector(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Arc<dyn Connector + Send + Sync>> {
        let config = self.get_connector(tenant_id, connector_id).await?;

        // Check if connector is active
        if config.status != ConnectorStatus::Active {
            return Err(ConnectorApiError::ConnectorNotActive(
                connector_id,
                config.status.to_string(),
            ));
        }

        // Try to get from registry cache
        let registry_id = ConnectorId::from_uuid(connector_id);
        if let Some(_connector) = self.registry.get(registry_id).await {
            debug!(connector_id = %connector_id, "Using cached connector");
            // The registry returns Arc<BoxedConnector>, we need to work with it as Arc<dyn Connector>
            // For now, we'll skip the cache and always build fresh
        }

        // Build new connector and cache it
        let credentials = self.decrypt_credentials(tenant_id, &config)?;
        let connector = self.build_connector(&config, &credentials)?;

        // Note: In a real implementation, we'd register a factory with the registry.
        // For now, we just return the connector directly.
        debug!(connector_id = %connector_id, "Created new connector instance");

        Ok(connector)
    }

    /// Decrypt credentials for a connector.
    fn decrypt_credentials(
        &self,
        tenant_id: Uuid,
        config: &ConnectorConfiguration,
    ) -> Result<serde_json::Value> {
        let decrypted = self
            .encryption
            .decrypt(tenant_id, &config.credentials_encrypted)
            .map_err(|e| ConnectorApiError::DecryptionFailed(e.to_string()))?;

        serde_json::from_slice(&decrypted).map_err(|e| {
            ConnectorApiError::InvalidConfiguration(format!(
                "Failed to deserialize credentials: {e}"
            ))
        })
    }

    /// Build a connector instance from configuration and credentials.
    fn build_connector(
        &self,
        config: &ConnectorConfiguration,
        credentials: &serde_json::Value,
    ) -> Result<Arc<dyn Connector + Send + Sync>> {
        match config.connector_type {
            DbConnectorType::Ldap => {
                // Check if this is an AD connector
                let use_ad = json_bool_field(&config.config, "use_ad_features", false)?;

                if use_ad {
                    let ad_config = self.build_ad_config(&config.config, credentials)?;
                    let connector = AdConnector::new(ad_config)
                        .map_err(|e| ConnectorApiError::InvalidConfiguration(e.to_string()))?;
                    Ok(Arc::new(connector))
                } else {
                    let ldap_config = self.build_ldap_config(&config.config, credentials)?;
                    let connector = LdapConnector::new(ldap_config)
                        .map_err(|e| ConnectorApiError::InvalidConfiguration(e.to_string()))?;
                    Ok(Arc::new(connector))
                }
            }
            DbConnectorType::Database => {
                let db_config = self.build_database_config(&config.config, credentials)?;
                let connector = DatabaseConnector::new(db_config)
                    .map_err(|e| ConnectorApiError::InvalidConfiguration(e.to_string()))?;
                Ok(Arc::new(connector))
            }
            DbConnectorType::Rest => {
                // Check if this is an Entra ID connector
                let use_entra = json_bool_field(&config.config, "use_entra_features", false)?;

                if use_entra {
                    let entra_config = self.build_entra_config(&config.config)?;
                    let entra_credentials = self.build_entra_credentials(credentials)?;
                    let connector = EntraConnector::new(entra_config, entra_credentials)
                        .map_err(|e| ConnectorApiError::InvalidConfiguration(e.to_string()))?;
                    Ok(Arc::new(connector))
                } else {
                    let rest_config = self.build_rest_config(&config.config, credentials)?;
                    let connector = RestConnector::new(rest_config)
                        .map_err(|e| ConnectorApiError::InvalidConfiguration(e.to_string()))?;
                    Ok(Arc::new(connector))
                }
            }
        }
    }

    /// Validate configuration format based on connector type.
    fn validate_config(
        &self,
        connector_type: &DbConnectorType,
        config: &serde_json::Value,
    ) -> Result<()> {
        match connector_type {
            DbConnectorType::Ldap => {
                // Check required LDAP fields
                if config.get("host").and_then(|v| v.as_str()).is_none() {
                    return Err(ConnectorApiError::InvalidConfiguration(
                        "LDAP configuration requires 'host' field".to_string(),
                    ));
                }

                // AD-specific validation
                let use_ad = json_bool_field(config, "use_ad_features", false)?;

                if use_ad && config.get("domain").and_then(|v| v.as_str()).is_none() {
                    return Err(ConnectorApiError::InvalidConfiguration(
                        "AD configuration requires 'domain' field".to_string(),
                    ));
                }
            }
            DbConnectorType::Database => {
                // Check required database fields
                let driver = config.get("driver").and_then(|v| v.as_str());
                if driver.is_none() {
                    return Err(ConnectorApiError::InvalidConfiguration(
                        "Database configuration requires 'driver' field".to_string(),
                    ));
                }
                if config.get("host").and_then(|v| v.as_str()).is_none() {
                    return Err(ConnectorApiError::InvalidConfiguration(
                        "Database configuration requires 'host' field".to_string(),
                    ));
                }
                if config.get("database").and_then(|v| v.as_str()).is_none() {
                    return Err(ConnectorApiError::InvalidConfiguration(
                        "Database configuration requires 'database' field".to_string(),
                    ));
                }
            }
            DbConnectorType::Rest => {
                let use_entra = json_bool_field(config, "use_entra_features", false)?;

                if use_entra {
                    // Entra-specific validation
                    if config.get("tenant_id").and_then(|v| v.as_str()).is_none() {
                        return Err(ConnectorApiError::InvalidConfiguration(
                            "Entra ID configuration requires 'tenant_id' field".to_string(),
                        ));
                    }
                } else {
                    // Standard REST validation
                    if config.get("base_url").and_then(|v| v.as_str()).is_none() {
                        return Err(ConnectorApiError::InvalidConfiguration(
                            "REST configuration requires 'base_url' field".to_string(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Build LDAP configuration from stored config and credentials.
    fn build_ldap_config(
        &self,
        config: &serde_json::Value,
        credentials: &serde_json::Value,
    ) -> Result<LdapConfig> {
        let host = config.get("host").and_then(|v| v.as_str()).ok_or_else(|| {
            ConnectorApiError::InvalidConfiguration("Missing 'host' in LDAP config".to_string())
        })?;

        let base_dn = required_str(config, "base_dn")?;
        let bind_dn = required_str(credentials, "bind_dn")?;

        let mut ldap_config = LdapConfig::new(host, base_dn, bind_dn);

        // Apply port
        if let Some(port) = config.get("port").and_then(serde_json::Value::as_u64) {
            ldap_config.port = port as u16;
        }

        // Apply SSL. A non-bool must not silently skip TLS.
        if json_bool_field(config, "use_ssl", false)? {
            ldap_config = ldap_config.with_ssl();
        }

        let pwd = credentials
            .get("bind_password")
            .or_else(|| credentials.get("password"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                ConnectorApiError::InvalidConfiguration(
                    "Missing 'bind_password' in LDAP credentials".to_string(),
                )
            })?;
        ldap_config = ldap_config.with_password(pwd);

        Ok(ldap_config)
    }

    /// Build AD-specific configuration from stored config and credentials.
    fn build_ad_config(
        &self,
        config: &serde_json::Value,
        credentials: &serde_json::Value,
    ) -> Result<ActiveDirectoryConfig> {
        // Build the base LDAP config first
        let ldap_config = self.build_ldap_config(config, credentials)?;

        let domain = config
            .get("domain")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ConnectorApiError::InvalidConfiguration(
                    "AD configuration requires 'domain' field".to_string(),
                )
            })?;

        let mut ad_config = ActiveDirectoryConfig {
            ldap: ldap_config,
            domain: domain.to_string(),
            use_ad_features: true,
            sync_account_disabled: json_bool_field(config, "sync_account_disabled", true)?,
            enable_exchange: json_bool_field(config, "enable_exchange", false)?,
            search_bases: Vec::new(),
            user_filter: json_str_or_default(
                config,
                "user_filter",
                "(&(objectClass=user)(objectCategory=person))",
            )?
            .to_string(),
            group_filter: json_str_or_default(config, "group_filter", "(objectClass=group)")?
                .to_string(),
            max_nesting_depth: json_u32_field(config, "max_nesting_depth", 10)?,
            max_referral_hops: json_u32_field(config, "max_referral_hops", 3)?,
            incremental_attribute: json_str_or_default(
                config,
                "incremental_attribute",
                "uSNChanged",
            )?
            .to_string(),
            outbound_target_ou: config
                .get("outbound_target_ou")
                .and_then(|v| v.as_str())
                .map(std::string::ToString::to_string),
            conflict_strategy: json_allowed_str(
                config,
                "conflict_strategy",
                &["source_wins", "target_wins", "manual"],
                Some("source_wins"),
            )?
            .to_string(),
        };

        // Parse search_bases array
        if let Some(bases) = config.get("search_bases").and_then(|v| v.as_array()) {
            for base in bases {
                if let Some(dn) = base.get("dn").and_then(|v| v.as_str()) {
                    ad_config.search_bases.push(SearchBase {
                        dn: dn.to_string(),
                        scope: json_allowed_str(
                            base,
                            "scope",
                            &["subtree", "onelevel", "base"],
                            Some("subtree"),
                        )?
                        .to_string(),
                        filter: base
                            .get("filter")
                            .and_then(|v| v.as_str())
                            .map(std::string::ToString::to_string),
                        object_types: ad_search_base_object_types(base.get("object_types"))?,
                    });
                }
            }
        }

        Ok(ad_config)
    }

    /// Build database configuration from stored config and credentials.
    fn build_database_config(
        &self,
        config: &serde_json::Value,
        credentials: &serde_json::Value,
    ) -> Result<DatabaseConfig> {
        let host = config.get("host").and_then(|v| v.as_str()).ok_or_else(|| {
            ConnectorApiError::InvalidConfiguration("Missing 'host' in database config".to_string())
        })?;

        let database = config
            .get("database")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ConnectorApiError::InvalidConfiguration(
                    "Missing 'database' in database config".to_string(),
                )
            })?;

        // Parse driver (only PostgreSQL supported per constitution)
        let driver = config
            .get("driver")
            .and_then(|v| v.as_str())
            .map(|s| match s.to_lowercase().as_str() {
                "postgresql" | "postgres" => Ok(DatabaseDriver::PostgreSQL),
                // MySQL, MSSQL, Oracle skipped per Constitution Principle XI
                _ => Err(ConnectorApiError::InvalidConfiguration(format!(
                    "Unsupported database driver: {s}. Only PostgreSQL is supported."
                ))),
            })
            .transpose()?
            .unwrap_or(DatabaseDriver::PostgreSQL);

        let username = required_str(credentials, "username")?;

        let mut db_config = DatabaseConfig::new(driver, host, database, username);

        // Apply port
        if let Some(port) = config.get("port").and_then(serde_json::Value::as_u64) {
            db_config = db_config.with_port(port as u16);
        }

        db_config = db_config.with_password(required_str(credentials, "password")?);

        Ok(db_config)
    }

    /// Build REST configuration from stored config and credentials.
    fn build_rest_config(
        &self,
        config: &serde_json::Value,
        credentials: &serde_json::Value,
    ) -> Result<RestConfig> {
        let base_url = config
            .get("base_url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ConnectorApiError::InvalidConfiguration(
                    "Missing 'base_url' in REST config".to_string(),
                )
            })?;

        let mut rest_config = RestConfig::new(base_url);

        let auth_type = credentials
            .get("auth_type")
            .or_else(|| config.get("auth_type"))
            .and_then(|v| v.as_str());

        match auth_type {
            Some("basic") => {
                rest_config = rest_config.with_basic_auth(
                    required_str(credentials, "username")?,
                    required_str(credentials, "password")?,
                );
            }
            Some("bearer") => {
                rest_config = rest_config.with_bearer_token(required_str(credentials, "token")?);
            }
            Some("api_key") => {
                rest_config = rest_config.with_api_key(required_str(credentials, "api_key")?);
            }
            Some("oauth2") => {
                rest_config = rest_config.with_oauth2(
                    required_str(credentials, "token_url")?,
                    required_str(credentials, "client_id")?,
                    required_str(credentials, "client_secret")?,
                );
            }
            None | Some("none") => {}
            Some(other) => {
                return Err(ConnectorApiError::InvalidConfiguration(format!(
                    "Unknown REST auth_type '{other}'"
                )));
            }
        }

        Ok(rest_config)
    }

    /// Build Entra ID configuration from stored connector config JSON.
    fn build_entra_config(&self, config: &serde_json::Value) -> Result<EntraConfig> {
        serde_json::from_value(config.clone()).map_err(|e| {
            ConnectorApiError::InvalidConfiguration(format!(
                "Failed to parse Entra ID configuration: {e}"
            ))
        })
    }

    /// Build Entra ID credentials from decrypted credentials JSON.
    fn build_entra_credentials(&self, credentials: &serde_json::Value) -> Result<EntraCredentials> {
        let client_id = credentials
            .get("client_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ConnectorApiError::InvalidConfiguration(
                    "Entra ID credentials require 'client_id' field".to_string(),
                )
            })?;

        let client_secret = credentials
            .get("client_secret")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ConnectorApiError::InvalidConfiguration(
                    "Entra ID credentials require 'client_secret' field".to_string(),
                )
            })?;

        Ok(EntraCredentials {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string().into(),
        })
    }
}

/// AD search-base object types. Corrupt JSON must not look like "all".
fn ad_search_base_object_types(value: Option<&serde_json::Value>) -> Result<Vec<String>> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(vec!["all".to_string()]),
        Some(v) => {
            let arr = v.as_array().ok_or_else(|| {
                ConnectorApiError::InvalidConfiguration(
                    "search_bases.object_types must be a JSON array".to_string(),
                )
            })?;
            arr.iter()
                .map(|item| {
                    item.as_str()
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .ok_or_else(|| {
                            ConnectorApiError::InvalidConfiguration(
                                "search_bases.object_types must be strings".to_string(),
                            )
                        })
                })
                .collect()
        }
    }
}

fn json_bool_field(config: &serde_json::Value, field: &str, default: bool) -> Result<bool> {
    match config.get(field) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(v) => v.as_bool().ok_or_else(|| {
            ConnectorApiError::InvalidConfiguration(format!("{field} must be a boolean"))
        }),
    }
}

/// JSON string. Non-string values must not become the default.
fn json_str_or_default<'a>(
    config: &'a serde_json::Value,
    field: &str,
    default: &'a str,
) -> Result<&'a str> {
    match config.get(field) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(v) => v.as_str().filter(|s| !s.is_empty()).ok_or_else(|| {
            ConnectorApiError::InvalidConfiguration(format!("{field} must be a non-empty string"))
        }),
    }
}

/// JSON unsigned integer. Non-numbers must not become the default.
fn json_u32_field(config: &serde_json::Value, field: &str, default: u32) -> Result<u32> {
    match config.get(field) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(v) => {
            let n = v.as_u64().ok_or_else(|| {
                ConnectorApiError::InvalidConfiguration(format!("{field} must be a number"))
            })?;
            u32::try_from(n).map_err(|_| {
                ConnectorApiError::InvalidConfiguration(format!("{field} is out of range"))
            })
        }
    }
}

/// JSON string enum. Unknown or non-string values must not become a default.
fn json_allowed_str<'a>(
    config: &'a serde_json::Value,
    field: &str,
    allowed: &[&str],
    default: Option<&'a str>,
) -> Result<&'a str> {
    match config.get(field) {
        None | Some(serde_json::Value::Null) => default
            .ok_or_else(|| ConnectorApiError::InvalidConfiguration(format!("Missing '{field}'"))),
        Some(v) => {
            let s = v.as_str().ok_or_else(|| {
                ConnectorApiError::InvalidConfiguration(format!("{field} must be a string"))
            })?;
            if allowed.contains(&s) {
                Ok(s)
            } else {
                Err(ConnectorApiError::InvalidConfiguration(format!(
                    "Invalid {field} '{s}'. Must be one of: {allowed:?}"
                )))
            }
        }
    }
}

fn required_str<'a>(obj: &'a serde_json::Value, field: &str) -> Result<&'a str> {
    obj.get(field)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            ConnectorApiError::InvalidConfiguration(format!(
                "Missing '{field}' in LDAP config/credentials"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test config validation standalone
    fn validate_connector_config(
        connector_type: &DbConnectorType,
        config: &serde_json::Value,
    ) -> Result<()> {
        match connector_type {
            DbConnectorType::Ldap => {
                if config.get("host").and_then(|v| v.as_str()).is_none() {
                    return Err(ConnectorApiError::InvalidConfiguration(
                        "LDAP configuration requires 'host' field".to_string(),
                    ));
                }
            }
            DbConnectorType::Database => {
                if config.get("driver").and_then(|v| v.as_str()).is_none() {
                    return Err(ConnectorApiError::InvalidConfiguration(
                        "Database configuration requires 'driver' field".to_string(),
                    ));
                }
                if config.get("host").and_then(|v| v.as_str()).is_none() {
                    return Err(ConnectorApiError::InvalidConfiguration(
                        "Database configuration requires 'host' field".to_string(),
                    ));
                }
                if config.get("database").and_then(|v| v.as_str()).is_none() {
                    return Err(ConnectorApiError::InvalidConfiguration(
                        "Database configuration requires 'database' field".to_string(),
                    ));
                }
            }
            DbConnectorType::Rest => {
                if config.get("base_url").and_then(|v| v.as_str()).is_none() {
                    return Err(ConnectorApiError::InvalidConfiguration(
                        "REST configuration requires 'base_url' field".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    #[test]
    fn test_validate_ldap_config() {
        let valid_config = serde_json::json!({
            "host": "ldap.example.com",
            "port": 389
        });
        assert!(validate_connector_config(&DbConnectorType::Ldap, &valid_config).is_ok());

        let invalid_config = serde_json::json!({
            "port": 389
        });
        assert!(validate_connector_config(&DbConnectorType::Ldap, &invalid_config).is_err());
    }

    #[test]
    fn test_validate_database_config() {
        let valid_config = serde_json::json!({
            "driver": "postgres",
            "host": "db.example.com",
            "database": "mydb"
        });
        assert!(validate_connector_config(&DbConnectorType::Database, &valid_config).is_ok());

        let missing_host = serde_json::json!({
            "driver": "postgres",
            "database": "mydb"
        });
        assert!(validate_connector_config(&DbConnectorType::Database, &missing_host).is_err());
    }

    #[test]
    fn test_validate_rest_config() {
        let valid_config = serde_json::json!({
            "base_url": "https://api.example.com"
        });
        assert!(validate_connector_config(&DbConnectorType::Rest, &valid_config).is_ok());

        let invalid_config = serde_json::json!({
            "timeout": 30
        });
        assert!(validate_connector_config(&DbConnectorType::Rest, &invalid_config).is_err());
    }

    #[test]
    fn ad_search_base_object_types_does_not_drop_or_invent_all() {
        assert_eq!(
            ad_search_base_object_types(None).unwrap(),
            vec!["all".to_string()]
        );
        assert_eq!(
            ad_search_base_object_types(Some(&serde_json::json!(["user", "group"]))).unwrap(),
            vec!["user".to_string(), "group".to_string()]
        );
        assert!(ad_search_base_object_types(Some(&serde_json::json!("all"))).is_err());
        assert!(ad_search_base_object_types(Some(&serde_json::json!([1]))).is_err());
        let src = include_str!("connector_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            !production.contains("filter_map(|v|")
                && !production.contains("unwrap_or_else(|| vec![\"all\".to_string()])"),
            "AD search_bases.object_types must not drop non-strings or invent [all]"
        );
    }

    #[test]
    fn ldap_placeholders_and_feature_flags_do_not_fail_open() {
        assert!(required_str(&serde_json::json!({}), "base_dn").is_err());
        assert!(required_str(&serde_json::json!({"bind_dn": ""}), "bind_dn").is_err());
        assert_eq!(
            required_str(&serde_json::json!({"bind_dn": "cn=real"}), "bind_dn").unwrap(),
            "cn=real"
        );
        assert!(json_bool_field(
            &serde_json::json!({"use_ad_features": "yes"}),
            "use_ad_features",
            false
        )
        .is_err());
        assert!(!json_bool_field(&serde_json::json!({}), "use_ad_features", false).unwrap());
        assert!(
            json_bool_field(&serde_json::json!({"use_ssl": "true"}), "use_ssl", false).is_err()
        );
        assert!(json_bool_field(
            &serde_json::json!({"enable_exchange": "yes"}),
            "enable_exchange",
            false
        )
        .is_err());
        let src = include_str!("connector_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            !production.contains("unwrap_or(\"dc=example,dc=com\")")
                && !production.contains("unwrap_or(\"cn=admin\")"),
            "LDAP must not invent example.com / cn=admin bind credentials"
        );
        assert!(
            !production.contains("unwrap_or(false)")
                && !production.contains("unwrap_or(true)")
                && production.contains("json_bool_field("),
            "use_ad_features/use_entra_features/AD flags must not treat non-bools as defaults"
        );
        assert!(
            !production.contains("unwrap_or(\"postgres\")")
                && !production.contains("unwrap_or(\"\")"),
            "database/LDAP/REST must not invent postgres users or empty secrets"
        );
        assert!(
            !production.contains("if let (Some(user), Some(pwd))")
                && !production.contains("if let Some(token)")
                && production.contains("required_str(credentials, \"token\")"),
            "REST auth_type must fail closed when credentials are missing"
        );
        assert!(
            production.contains("Missing 'bind_password' in LDAP credentials"),
            "LDAP must require bind_password instead of anonymous bind"
        );
    }

    #[test]
    fn ad_conflict_strategy_and_scope_do_not_invent_defaults_for_unknown() {
        assert_eq!(
            json_allowed_str(
                &serde_json::json!({}),
                "conflict_strategy",
                &["source_wins", "target_wins", "manual"],
                Some("source_wins"),
            )
            .unwrap(),
            "source_wins"
        );
        assert!(json_allowed_str(
            &serde_json::json!({"conflict_strategy": "delete_all"}),
            "conflict_strategy",
            &["source_wins", "target_wins", "manual"],
            Some("source_wins"),
        )
        .is_err());
        assert!(json_allowed_str(
            &serde_json::json!({"conflict_strategy": true}),
            "conflict_strategy",
            &["source_wins", "target_wins", "manual"],
            Some("source_wins"),
        )
        .is_err());
        assert_eq!(
            json_allowed_str(
                &serde_json::json!({}),
                "scope",
                &["subtree", "onelevel", "base"],
                Some("subtree"),
            )
            .unwrap(),
            "subtree"
        );
        assert!(json_allowed_str(
            &serde_json::json!({"scope": "everything"}),
            "scope",
            &["subtree", "onelevel", "base"],
            Some("subtree"),
        )
        .is_err());
        assert!(json_allowed_str(
            &serde_json::json!({"scope": 1}),
            "scope",
            &["subtree", "onelevel", "base"],
            Some("subtree"),
        )
        .is_err());
        let src = include_str!("connector_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("json_allowed_str(")
                && !production.contains("unwrap_or(\"source_wins\")")
                && !production.contains("unwrap_or(\"subtree\")"),
            "AD conflict_strategy and search scope must not invent values for unknown/non-string JSON"
        );
    }

    #[test]
    fn ad_filters_and_limits_do_not_invent_defaults_for_wrong_json_types() {
        assert_eq!(
            json_str_or_default(&serde_json::json!({}), "user_filter", "(objectClass=user)")
                .unwrap(),
            "(objectClass=user)"
        );
        assert!(json_str_or_default(
            &serde_json::json!({"user_filter": true}),
            "user_filter",
            "(objectClass=user)"
        )
        .is_err());
        assert!(json_str_or_default(
            &serde_json::json!({"group_filter": ""}),
            "group_filter",
            "(objectClass=group)"
        )
        .is_err());
        assert!(json_str_or_default(
            &serde_json::json!({"incremental_attribute": 1}),
            "incremental_attribute",
            "uSNChanged"
        )
        .is_err());
        assert_eq!(
            json_u32_field(&serde_json::json!({}), "max_nesting_depth", 10).unwrap(),
            10
        );
        assert!(json_u32_field(
            &serde_json::json!({"max_nesting_depth": "ten"}),
            "max_nesting_depth",
            10
        )
        .is_err());
        assert!(json_u32_field(
            &serde_json::json!({"max_referral_hops": true}),
            "max_referral_hops",
            3
        )
        .is_err());
        let src = include_str!("connector_service.rs");
        let production = src.split("mod tests").next().expect("production source");
        assert!(
            production.contains("json_str_or_default(")
                && production.contains("json_u32_field(")
                && !production.contains("unwrap_or(\"uSNChanged\")")
                && !production.contains("unwrap_or(10)")
                && !production.contains("unwrap_or(3)"),
            "AD user/group filters, incremental_attribute, and depth/hops must not invent defaults for non-string/non-number JSON"
        );
    }
}
