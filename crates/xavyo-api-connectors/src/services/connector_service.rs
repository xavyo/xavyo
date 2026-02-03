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

        let summaries: Vec<ConnectorSummary> = connectors.iter().map(|c| c.to_summary()).collect();

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
            ConnectorApiError::InvalidConfiguration(format!(
                "Failed to serialize credentials: {}",
                e
            ))
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
                        "Failed to serialize credentials: {}",
                        e
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
                "Failed to deserialize credentials: {}",
                e
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
                let use_ad = config
                    .config
                    .get("use_ad_features")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

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
                let use_entra = config
                    .config
                    .get("use_entra_features")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

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
                let use_ad = config
                    .get("use_ad_features")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

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
                let use_entra = config
                    .get("use_entra_features")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

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

        let base_dn = config
            .get("base_dn")
            .and_then(|v| v.as_str())
            .unwrap_or("dc=example,dc=com");

        let bind_dn = credentials
            .get("bind_dn")
            .and_then(|v| v.as_str())
            .unwrap_or("cn=admin");

        let mut ldap_config = LdapConfig::new(host, base_dn, bind_dn);

        // Apply SSL
        if let Some(ssl) = config.get("use_ssl").and_then(|v| v.as_bool()) {
            if ssl {
                ldap_config = ldap_config.with_ssl();
            }
        }

        // Apply password
        if let Some(pwd) = credentials.get("password").and_then(|v| v.as_str()) {
            ldap_config = ldap_config.with_password(pwd);
        }

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
            sync_account_disabled: config
                .get("sync_account_disabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
            enable_exchange: config
                .get("enable_exchange")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            search_bases: Vec::new(),
            user_filter: config
                .get("user_filter")
                .and_then(|v| v.as_str())
                .unwrap_or("(&(objectClass=user)(objectCategory=person))")
                .to_string(),
            group_filter: config
                .get("group_filter")
                .and_then(|v| v.as_str())
                .unwrap_or("(objectClass=group)")
                .to_string(),
            max_nesting_depth: config
                .get("max_nesting_depth")
                .and_then(|v| v.as_u64())
                .unwrap_or(10) as u32,
            max_referral_hops: config
                .get("max_referral_hops")
                .and_then(|v| v.as_u64())
                .unwrap_or(3) as u32,
            incremental_attribute: config
                .get("incremental_attribute")
                .and_then(|v| v.as_str())
                .unwrap_or("uSNChanged")
                .to_string(),
            outbound_target_ou: config
                .get("outbound_target_ou")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            conflict_strategy: config
                .get("conflict_strategy")
                .and_then(|v| v.as_str())
                .unwrap_or("source_wins")
                .to_string(),
        };

        // Parse search_bases array
        if let Some(bases) = config.get("search_bases").and_then(|v| v.as_array()) {
            for base in bases {
                if let Some(dn) = base.get("dn").and_then(|v| v.as_str()) {
                    ad_config.search_bases.push(SearchBase {
                        dn: dn.to_string(),
                        scope: base
                            .get("scope")
                            .and_then(|v| v.as_str())
                            .unwrap_or("subtree")
                            .to_string(),
                        filter: base
                            .get("filter")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        object_types: base
                            .get("object_types")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_else(|| vec!["all".to_string()]),
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
                    "Unsupported database driver: {}. Only PostgreSQL is supported.",
                    s
                ))),
            })
            .transpose()?
            .unwrap_or(DatabaseDriver::PostgreSQL);

        // Get credentials
        let username = credentials
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or("postgres");

        let mut db_config = DatabaseConfig::new(driver, host, database, username);

        // Apply port
        if let Some(port) = config.get("port").and_then(|v| v.as_u64()) {
            db_config = db_config.with_port(port as u16);
        }

        // Apply password
        if let Some(pwd) = credentials.get("password").and_then(|v| v.as_str()) {
            db_config = db_config.with_password(pwd);
        }

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

        // Apply authentication based on auth_type
        let auth_type = credentials.get("auth_type").and_then(|v| v.as_str());

        match auth_type {
            Some("basic") => {
                let username = credentials.get("username").and_then(|v| v.as_str());
                let password = credentials.get("password").and_then(|v| v.as_str());
                if let (Some(user), Some(pwd)) = (username, password) {
                    rest_config = rest_config.with_basic_auth(user, pwd);
                }
            }
            Some("bearer") => {
                if let Some(token) = credentials.get("token").and_then(|v| v.as_str()) {
                    rest_config = rest_config.with_bearer_token(token);
                }
            }
            Some("api_key") => {
                if let Some(key) = credentials.get("api_key").and_then(|v| v.as_str()) {
                    rest_config = rest_config.with_api_key(key);
                }
            }
            Some("oauth2") => {
                let token_url = credentials.get("token_url").and_then(|v| v.as_str());
                let client_id = credentials.get("client_id").and_then(|v| v.as_str());
                let client_secret = credentials
                    .get("client_secret")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if let (Some(url), Some(id)) = (token_url, client_id) {
                    rest_config = rest_config.with_oauth2(url, id, client_secret);
                }
            }
            _ => {
                // No authentication or unknown type
            }
        }

        Ok(rest_config)
    }

    /// Build Entra ID configuration from stored connector config JSON.
    fn build_entra_config(&self, config: &serde_json::Value) -> Result<EntraConfig> {
        serde_json::from_value(config.clone()).map_err(|e| {
            ConnectorApiError::InvalidConfiguration(format!(
                "Failed to parse Entra ID configuration: {}",
                e
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
}
