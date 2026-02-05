//! Schema Service for managing connector schemas.
//!
//! Provides schema discovery, caching, and versioning for connected target systems.
//! Part of F046 Resource Schema Discovery feature.

use chrono::Utc;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, info, warn};
use uuid::Uuid;

use sqlx::PgPool;
use xavyo_connector::crypto::CredentialEncryption;
use xavyo_connector::registry::ConnectorRegistry;
use xavyo_connector::schema::{DiscoveryState, DiscoveryStatus, ObjectClass, Schema};
use xavyo_connector::traits::SchemaDiscovery;
use xavyo_connector_database::DatabaseConnector;
use xavyo_connector_ldap::{AdConnector, LdapConnector};
use xavyo_connector_rest::RestConnector;
use xavyo_db::models::{
    ConnectorConfiguration, ConnectorSchema, ConnectorSchemaVersion,
    ConnectorType as DbConnectorType, CreateSchemaVersion, SchemaVersionSummary, TriggeredBy,
    UpsertConnectorSchema,
};

use crate::error::{ConnectorApiError, Result};
use crate::services::DiscoveryStateManager;

/// Default schema cache TTL in seconds (24 hours).
const DEFAULT_SCHEMA_TTL_SECONDS: i64 = 86400;

/// Schema service response containing discovered schemas.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct SchemaResponse {
    /// Connector ID this schema belongs to.
    pub connector_id: Uuid,
    /// List of discovered object classes.
    pub object_classes: Vec<ObjectClassResponse>,
    /// When the schema was discovered.
    pub discovered_at: chrono::DateTime<Utc>,
    /// When the schema cache expires.
    pub expires_at: chrono::DateTime<Utc>,
    /// Whether this is from cache.
    pub from_cache: bool,
}

/// Object class in a schema response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ObjectClassResponse {
    /// Canonical name for this object class.
    pub name: String,
    /// Native name in the target system.
    pub native_name: String,
    /// Display name for UI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Attributes in this object class (direct attributes only).
    pub attributes: Vec<AttributeResponse>,
    /// Inherited attributes from parent classes (User Story 3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inherited_attributes: Vec<AttributeResponse>,
    /// Whether create is supported.
    pub supports_create: bool,
    /// Whether update is supported.
    pub supports_update: bool,
    /// Whether delete is supported.
    pub supports_delete: bool,
    /// Object class type (structural, auxiliary, abstract) - User Story 3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_class_type: Option<String>,
    /// Parent class names for hierarchy (User Story 3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub parent_classes: Vec<String>,
}

/// Attribute in an object class response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct AttributeResponse {
    /// Canonical name for this attribute.
    pub name: String,
    /// Native name in the target system.
    pub native_name: String,
    /// Data type.
    pub data_type: String,
    /// Whether this attribute is multi-valued.
    pub multi_valued: bool,
    /// Whether this attribute is required.
    pub required: bool,
    /// Whether this attribute is readable.
    pub readable: bool,
    /// Whether this attribute is writable.
    pub writable: bool,
    /// Identifier type: primary (immutable) or secondary (mutable) - IGA edge case.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier_type: Option<String>,
    /// Whether this attribute is volatile (can change unexpectedly) - IGA edge case.
    #[serde(default)]
    pub volatile: bool,
    /// Whether this attribute uses case-insensitive matching - IGA edge case.
    #[serde(default)]
    pub case_insensitive: bool,
    /// Source class if this is an inherited attribute (User Story 3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_class: Option<String>,
}

/// Service for schema discovery, caching, and versioning.
pub struct SchemaService {
    pool: PgPool,
    encryption: Arc<CredentialEncryption>,
    #[allow(dead_code)]
    registry: Arc<ConnectorRegistry>,
    cache_ttl_seconds: i64,
    /// Discovery state manager for tracking concurrent discoveries.
    discovery_state: Arc<DiscoveryStateManager>,
}

impl SchemaService {
    /// Create a new schema service.
    pub fn new(
        pool: PgPool,
        encryption: Arc<CredentialEncryption>,
        registry: Arc<ConnectorRegistry>,
    ) -> Self {
        let discovery_state = Arc::new(DiscoveryStateManager::new(pool.clone()));
        Self {
            pool,
            encryption,
            registry,
            cache_ttl_seconds: DEFAULT_SCHEMA_TTL_SECONDS,
            discovery_state,
        }
    }

    /// Create a new schema service with custom TTL.
    #[must_use]
    pub fn with_ttl(mut self, ttl_seconds: i64) -> Self {
        self.cache_ttl_seconds = ttl_seconds;
        self
    }

    // =========================================================================
    // F046: Async Discovery with Versioning
    // =========================================================================

    /// Trigger async schema discovery.
    ///
    /// Returns immediately with status. Use `get_discovery_status` to poll for completion.
    /// Creates a new schema version upon successful completion.
    pub async fn trigger_discovery(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        triggered_by: TriggeredBy,
        triggered_by_user: Option<Uuid>,
    ) -> Result<DiscoveryStatus> {
        // Verify connector exists
        let config = ConnectorConfiguration::find_by_id(&self.pool, tenant_id, connector_id)
            .await?
            .ok_or_else(|| ConnectorApiError::NotFound {
                resource: "connector".to_string(),
                id: connector_id.to_string(),
            })?;

        // Try to start discovery (acquires advisory lock)
        let status = self.discovery_state.start_discovery(connector_id).await?;

        // Spawn async discovery task
        let pool = self.pool.clone();
        let encryption = self.encryption.clone();
        let discovery_state = self.discovery_state.clone();
        let cache_ttl = self.cache_ttl_seconds;

        tokio::spawn(async move {
            let result = Self::execute_discovery(
                &pool,
                &encryption,
                &discovery_state,
                &config,
                tenant_id,
                connector_id,
                triggered_by,
                triggered_by_user,
                cache_ttl,
            )
            .await;

            if let Err(e) = result {
                warn!(
                    connector_id = %connector_id,
                    error = %e,
                    "Schema discovery failed"
                );
                // State is already marked as failed in execute_discovery
            }
        });

        Ok(status)
    }

    /// Execute the actual discovery process.
    #[allow(clippy::too_many_arguments)]
    async fn execute_discovery(
        pool: &PgPool,
        encryption: &CredentialEncryption,
        discovery_state: &DiscoveryStateManager,
        config: &ConnectorConfiguration,
        tenant_id: Uuid,
        connector_id: Uuid,
        triggered_by: TriggeredBy,
        triggered_by_user: Option<Uuid>,
        cache_ttl_seconds: i64,
    ) -> Result<()> {
        let start_time = Instant::now();

        // Update progress
        discovery_state
            .update_progress(
                connector_id,
                10,
                Some("Connecting to target system".to_string()),
            )
            .await?;

        // Build full config with decrypted credentials
        let decrypted = encryption
            .decrypt(config.tenant_id, &config.credentials_encrypted)
            .map_err(|e| ConnectorApiError::DecryptionFailed(e.to_string()))?;

        let credentials: serde_json::Value = serde_json::from_slice(&decrypted).map_err(|e| {
            ConnectorApiError::InvalidConfiguration(format!(
                "Failed to deserialize credentials: {e}"
            ))
        })?;

        let mut full_config = config.config.clone();
        if let (Some(obj), Some(creds)) = (full_config.as_object_mut(), credentials.as_object()) {
            for (key, value) in creds {
                obj.insert(key.clone(), value.clone());
            }
        }

        // Update progress
        discovery_state
            .update_progress(connector_id, 30, Some("Discovering schema".to_string()))
            .await?;

        // Create connector and discover schema
        let schema: Schema =
            match Self::discover_schema_internal(config.connector_type, full_config).await {
                Ok(s) => s,
                Err(e) => {
                    // Mark discovery as failed before returning error
                    let _ = discovery_state
                        .fail_discovery(connector_id, e.to_string())
                        .await;
                    return Err(e);
                }
            };

        // Update progress
        discovery_state
            .update_progress(connector_id, 70, Some("Saving schema version".to_string()))
            .await?;

        let discovery_duration_ms = start_time.elapsed().as_millis() as i64;

        // Calculate counts
        let object_class_count = schema.object_classes.len() as i32;
        let attribute_count: i32 = schema
            .object_classes
            .iter()
            .map(|oc| oc.attributes.len() as i32)
            .sum();

        // Create schema version
        let schema_data = serde_json::to_value(&schema)
            .map_err(|e| ConnectorApiError::InvalidConfiguration(e.to_string()))?;

        let create_input = CreateSchemaVersion {
            schema_data,
            object_class_count,
            attribute_count,
            discovery_duration_ms,
            triggered_by,
            triggered_by_user,
        };

        let version =
            ConnectorSchemaVersion::create(pool, tenant_id, connector_id, &create_input).await?;

        // Update progress
        discovery_state
            .update_progress(connector_id, 90, Some("Updating cache".to_string()))
            .await?;

        // Cache the schema for quick lookups
        for oc in &schema.object_classes {
            let upsert = UpsertConnectorSchema {
                object_class: oc.name.clone(),
                native_name: oc.native_name.clone(),
                attributes: serde_json::to_value(&oc.attributes).unwrap_or_default(),
                supports_create: oc.supports_create,
                supports_update: oc.supports_update,
                supports_delete: oc.supports_delete,
                ttl_seconds: cache_ttl_seconds,
            };

            if let Err(e) = ConnectorSchema::upsert(pool, tenant_id, connector_id, &upsert).await {
                warn!(error = %e, "Failed to cache schema object class");
            }
        }

        // Mark discovery as complete
        discovery_state
            .complete_discovery(connector_id, version.version)
            .await?;

        info!(
            connector_id = %connector_id,
            version = version.version,
            object_classes = object_class_count,
            attributes = attribute_count,
            duration_ms = discovery_duration_ms,
            "Schema discovery completed successfully"
        );

        Ok(())
    }

    /// Get the current discovery status for a connector.
    pub async fn get_discovery_status(&self, connector_id: Uuid) -> DiscoveryStatus {
        self.discovery_state
            .get_status(connector_id)
            .await
            .unwrap_or(DiscoveryStatus {
                connector_id,
                state: DiscoveryState::Idle,
                started_at: None,
                completed_at: None,
                progress_percent: None,
                current_object_class: None,
                error: None,
                version: None,
            })
    }

    /// Get a specific schema version.
    pub async fn get_schema_version(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        version: i32,
    ) -> Result<Option<ConnectorSchemaVersion>> {
        ConnectorSchemaVersion::find_by_version(&self.pool, tenant_id, connector_id, version)
            .await
            .map_err(Into::into)
    }

    /// Get the latest schema version.
    pub async fn get_latest_version(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Option<ConnectorSchemaVersion>> {
        ConnectorSchemaVersion::find_latest(&self.pool, tenant_id, connector_id)
            .await
            .map_err(Into::into)
    }

    /// List schema versions with pagination.
    pub async fn list_versions(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        limit: i32,
        offset: i32,
    ) -> Result<(Vec<SchemaVersionSummary>, i64)> {
        let versions = ConnectorSchemaVersion::list_versions(
            &self.pool,
            tenant_id,
            connector_id,
            limit,
            offset,
        )
        .await?;

        let total =
            ConnectorSchemaVersion::count_versions(&self.pool, tenant_id, connector_id).await?;

        let summaries: Vec<SchemaVersionSummary> =
            versions.into_iter().map(|v| v.to_summary()).collect();

        Ok((summaries, total))
    }

    /// Cleanup old schema versions (keep last N).
    pub async fn cleanup_old_versions(&self, connector_id: Uuid, keep_count: i32) -> Result<u64> {
        ConnectorSchemaVersion::cleanup_old_versions(&self.pool, connector_id, keep_count)
            .await
            .map_err(Into::into)
    }

    // =========================================================================
    // Legacy Discovery (synchronous, for backward compatibility)
    // =========================================================================

    /// Discover schema from a connector (bypasses cache).
    pub async fn discover_schema(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<SchemaResponse> {
        debug!(
            tenant_id = %tenant_id,
            connector_id = %connector_id,
            "Discovering schema from connector"
        );

        // Get the connector configuration
        let config = ConnectorConfiguration::find_by_id(&self.pool, tenant_id, connector_id)
            .await?
            .ok_or_else(|| ConnectorApiError::NotFound {
                resource: "connector".to_string(),
                id: connector_id.to_string(),
            })?;

        // Decrypt credentials and merge with config
        let full_config = self.build_full_config(&config)?;

        // Create connector instance and discover schema
        let schema = match config.connector_type {
            DbConnectorType::Ldap => {
                let use_ad = full_config
                    .get("use_ad_features")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);

                if use_ad {
                    let ad_config: xavyo_connector_ldap::config::ActiveDirectoryConfig =
                        serde_json::from_value(full_config)
                            .map_err(|e| ConnectorApiError::InvalidConfiguration(e.to_string()))?;
                    let connector = AdConnector::new(ad_config)?;
                    connector.discover_schema().await?
                } else {
                    let ldap_config: xavyo_connector_ldap::config::LdapConfig =
                        serde_json::from_value(full_config)
                            .map_err(|e| ConnectorApiError::InvalidConfiguration(e.to_string()))?;
                    let connector = LdapConnector::new(ldap_config)?;
                    connector.discover_schema().await?
                }
            }
            DbConnectorType::Database => {
                let db_config: xavyo_connector_database::config::DatabaseConfig =
                    serde_json::from_value(full_config)
                        .map_err(|e| ConnectorApiError::InvalidConfiguration(e.to_string()))?;
                let connector = DatabaseConnector::new(db_config)?;
                connector.discover_schema().await?
            }
            DbConnectorType::Rest => {
                let rest_config: xavyo_connector_rest::config::RestConfig =
                    serde_json::from_value(full_config)
                        .map_err(|e| ConnectorApiError::InvalidConfiguration(e.to_string()))?;
                let connector = RestConnector::new(rest_config)?;
                connector.discover_schema().await?
            }
        };

        // Cache the discovered schema
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(self.cache_ttl_seconds);

        for oc in &schema.object_classes {
            let upsert = UpsertConnectorSchema {
                object_class: oc.name.clone(),
                native_name: oc.native_name.clone(),
                attributes: serde_json::to_value(&oc.attributes).unwrap_or_default(),
                supports_create: oc.supports_create,
                supports_update: oc.supports_update,
                supports_delete: oc.supports_delete,
                ttl_seconds: self.cache_ttl_seconds,
            };

            if let Err(e) =
                ConnectorSchema::upsert(&self.pool, tenant_id, connector_id, &upsert).await
            {
                warn!(error = %e, "Failed to cache schema object class");
            }
        }

        info!(
            tenant_id = %tenant_id,
            connector_id = %connector_id,
            object_class_count = schema.object_classes.len(),
            "Schema discovery complete"
        );

        Ok(SchemaResponse {
            connector_id,
            object_classes: schema
                .object_classes
                .into_iter()
                .map(Self::object_class_to_response)
                .collect(),
            discovered_at: now,
            expires_at,
            from_cache: false,
        })
    }

    /// Get cached schema for a connector.
    pub async fn get_schema(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
    ) -> Result<Option<SchemaResponse>> {
        let cached_schemas = ConnectorSchema::list_by_connector(
            &self.pool,
            tenant_id,
            connector_id,
            false, // Don't include expired
        )
        .await?;

        if cached_schemas.is_empty() {
            return Ok(None);
        }

        // Build response from cached schemas
        let discovered_at = cached_schemas
            .first()
            .map_or_else(Utc::now, |s| s.discovered_at);
        let expires_at = cached_schemas
            .first()
            .map_or_else(Utc::now, |s| s.expires_at);

        let object_classes = cached_schemas
            .into_iter()
            .map(Self::cached_schema_to_response)
            .collect();

        Ok(Some(SchemaResponse {
            connector_id,
            object_classes,
            discovered_at,
            expires_at,
            from_cache: true,
        }))
    }

    /// Get schema, using cache if available, otherwise discovering.
    pub async fn get_or_discover_schema(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        force_refresh: bool,
    ) -> Result<SchemaResponse> {
        if !force_refresh {
            if let Some(cached) = self.get_schema(tenant_id, connector_id).await? {
                debug!(connector_id = %connector_id, "Using cached schema");
                return Ok(cached);
            }
        }

        self.discover_schema(tenant_id, connector_id).await
    }

    /// Get a specific object class from the schema.
    pub async fn get_object_class(
        &self,
        tenant_id: Uuid,
        connector_id: Uuid,
        object_class: &str,
    ) -> Result<Option<ObjectClassResponse>> {
        let cached = ConnectorSchema::find_by_object_class(
            &self.pool,
            tenant_id,
            connector_id,
            object_class,
        )
        .await?;

        Ok(cached.map(Self::cached_schema_to_response))
    }

    /// Clear cached schema for a connector.
    pub async fn clear_cache(&self, tenant_id: Uuid, connector_id: Uuid) -> Result<u64> {
        let deleted =
            ConnectorSchema::delete_by_connector(&self.pool, tenant_id, connector_id).await?;

        info!(
            tenant_id = %tenant_id,
            connector_id = %connector_id,
            deleted = deleted,
            "Schema cache cleared"
        );

        Ok(deleted)
    }

    /// Clean up expired schema caches.
    pub async fn cleanup_expired(&self) -> Result<u64> {
        let deleted = ConnectorSchema::delete_expired(&self.pool).await?;

        if deleted > 0 {
            info!(deleted = deleted, "Cleaned up expired schema caches");
        }

        Ok(deleted)
    }

    // Helper functions

    /// Decrypt credentials and merge with public config.
    fn build_full_config(&self, config: &ConnectorConfiguration) -> Result<serde_json::Value> {
        // Decrypt credentials
        let decrypted = self
            .encryption
            .decrypt(config.tenant_id, &config.credentials_encrypted)
            .map_err(|e| ConnectorApiError::DecryptionFailed(e.to_string()))?;

        let credentials: serde_json::Value = serde_json::from_slice(&decrypted).map_err(|e| {
            ConnectorApiError::InvalidConfiguration(format!(
                "Failed to deserialize credentials: {e}"
            ))
        })?;

        // Merge public config with credentials
        let mut full_config = config.config.clone();
        if let (Some(obj), Some(creds)) = (full_config.as_object_mut(), credentials.as_object()) {
            for (key, value) in creds {
                obj.insert(key.clone(), value.clone());
            }
        }

        Ok(full_config)
    }

    fn object_class_to_response(oc: ObjectClass) -> ObjectClassResponse {
        ObjectClassResponse {
            name: oc.name.clone(),
            native_name: oc.native_name,
            display_name: oc.display_name,
            description: oc.description,
            attributes: oc
                .attributes
                .iter()
                .map(|a| Self::attribute_to_response(a, None))
                .collect(),
            inherited_attributes: oc
                .inherited_attributes
                .iter()
                .map(|a| {
                    // Try to determine source class from parent classes
                    let source_class = oc.parent_classes.first().cloned();
                    Self::attribute_to_response(a, source_class)
                })
                .collect(),
            supports_create: oc.supports_create,
            supports_update: oc.supports_update,
            supports_delete: oc.supports_delete,
            object_class_type: Some(oc.object_class_type.as_str().to_string()),
            parent_classes: oc.parent_classes,
        }
    }

    /// Convert a `SchemaAttribute` to `AttributeResponse` with IGA edge case fields.
    fn attribute_to_response(
        a: &xavyo_connector::schema::SchemaAttribute,
        source_class: Option<String>,
    ) -> AttributeResponse {
        use xavyo_connector::schema::IdentifierType;

        AttributeResponse {
            name: a.name.clone(),
            native_name: a.native_name.clone(),
            data_type: a.data_type.as_str().to_string(),
            multi_valued: a.multi_valued,
            required: a.required,
            readable: a.readable,
            writable: a.writable,
            identifier_type: a.identifier_type.map(|id| match id {
                IdentifierType::Primary => "primary".to_string(),
                IdentifierType::Secondary => "secondary".to_string(),
            }),
            volatile: a.volatile,
            case_insensitive: a.case_insensitive,
            source_class,
        }
    }

    fn cached_schema_to_response(cached: ConnectorSchema) -> ObjectClassResponse {
        let attributes: Vec<AttributeResponse> =
            serde_json::from_value(cached.attributes).unwrap_or_default();

        ObjectClassResponse {
            name: cached.object_class,
            native_name: cached.native_name,
            display_name: None,
            description: None,
            attributes,
            inherited_attributes: Vec::new(), // Not stored in cache yet
            supports_create: cached.supports_create,
            supports_update: cached.supports_update,
            supports_delete: cached.supports_delete,
            object_class_type: None,    // Not stored in cache yet
            parent_classes: Vec::new(), // Not stored in cache yet
        }
    }

    /// Internal helper to discover schema from a connector type.
    /// Separated to allow proper async error handling in `execute_discovery`.
    async fn discover_schema_internal(
        connector_type: DbConnectorType,
        full_config: serde_json::Value,
    ) -> Result<Schema> {
        match connector_type {
            DbConnectorType::Ldap => {
                let use_ad = full_config
                    .get("use_ad_features")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);

                if use_ad {
                    let ad_config: xavyo_connector_ldap::config::ActiveDirectoryConfig =
                        serde_json::from_value(full_config)
                            .map_err(|e| ConnectorApiError::InvalidConfiguration(e.to_string()))?;
                    let connector = AdConnector::new(ad_config)?;
                    Ok(connector.discover_schema().await?)
                } else {
                    let ldap_config: xavyo_connector_ldap::config::LdapConfig =
                        serde_json::from_value(full_config)
                            .map_err(|e| ConnectorApiError::InvalidConfiguration(e.to_string()))?;
                    let connector = LdapConnector::new(ldap_config)?;
                    Ok(connector.discover_schema().await?)
                }
            }
            DbConnectorType::Database => {
                let db_config: xavyo_connector_database::config::DatabaseConfig =
                    serde_json::from_value(full_config)
                        .map_err(|e| ConnectorApiError::InvalidConfiguration(e.to_string()))?;
                let connector = DatabaseConnector::new(db_config)?;
                Ok(connector.discover_schema().await?)
            }
            DbConnectorType::Rest => {
                let rest_config: xavyo_connector_rest::config::RestConfig =
                    serde_json::from_value(full_config)
                        .map_err(|e| ConnectorApiError::InvalidConfiguration(e.to_string()))?;
                let connector = RestConnector::new(rest_config)?;
                Ok(connector.discover_schema().await?)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_attribute(
        name: &str,
        data_type: &str,
        required: bool,
        multi_valued: bool,
    ) -> AttributeResponse {
        AttributeResponse {
            name: name.to_string(),
            native_name: name.to_string(),
            data_type: data_type.to_string(),
            multi_valued,
            required,
            readable: true,
            writable: true,
            identifier_type: None,
            volatile: false,
            case_insensitive: false,
            source_class: None,
        }
    }

    #[test]
    fn test_schema_response_serialization() {
        let response = SchemaResponse {
            connector_id: Uuid::new_v4(),
            object_classes: vec![ObjectClassResponse {
                name: "user".to_string(),
                native_name: "inetOrgPerson".to_string(),
                display_name: Some("User".to_string()),
                description: None,
                attributes: vec![test_attribute("uid", "string", true, false)],
                inherited_attributes: vec![],
                supports_create: true,
                supports_update: true,
                supports_delete: true,
                object_class_type: Some("structural".to_string()),
                parent_classes: vec!["organizationalPerson".to_string(), "person".to_string()],
            }],
            discovered_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
            from_cache: false,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("inetOrgPerson"));
        assert!(json.contains("\"from_cache\":false"));
        assert!(json.contains("\"parent_classes\""));
    }

    #[test]
    fn test_object_class_response_serialization() {
        let oc = ObjectClassResponse {
            name: "group".to_string(),
            native_name: "groupOfNames".to_string(),
            display_name: Some("Group".to_string()),
            description: Some("A group of users".to_string()),
            attributes: vec![
                test_attribute("cn", "string", true, false),
                test_attribute("member", "dn", false, true),
            ],
            inherited_attributes: vec![{
                let mut attr = test_attribute("objectClass", "string", true, true);
                attr.source_class = Some("top".to_string());
                attr
            }],
            supports_create: true,
            supports_update: true,
            supports_delete: true,
            object_class_type: Some("structural".to_string()),
            parent_classes: vec!["top".to_string()],
        };

        let json = serde_json::to_string(&oc).unwrap();
        let parsed: ObjectClassResponse = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.name, "group");
        assert_eq!(parsed.attributes.len(), 2);
        assert!(parsed.attributes[1].multi_valued);
        assert_eq!(parsed.inherited_attributes.len(), 1);
        assert_eq!(
            parsed.inherited_attributes[0].source_class,
            Some("top".to_string())
        );
    }

    #[test]
    fn test_attribute_response_serialization() {
        let attr = AttributeResponse {
            name: "email".to_string(),
            native_name: "mail".to_string(),
            data_type: "string".to_string(),
            multi_valued: true,
            required: false,
            readable: true,
            writable: true,
            identifier_type: None,
            volatile: false,
            case_insensitive: true,
            source_class: None,
        };

        let json = serde_json::to_string(&attr).unwrap();
        assert!(json.contains("\"multi_valued\":true"));
        assert!(json.contains("\"case_insensitive\":true"));
    }

    #[test]
    fn test_attribute_with_IGA_edge_cases() {
        // Test primary identifier
        let attr = AttributeResponse {
            name: "entryUUID".to_string(),
            native_name: "entryUUID".to_string(),
            data_type: "uuid".to_string(),
            multi_valued: false,
            required: false,
            readable: true,
            writable: false,
            identifier_type: Some("primary".to_string()),
            volatile: false,
            case_insensitive: true,
            source_class: None,
        };

        let json = serde_json::to_string(&attr).unwrap();
        assert!(json.contains("\"identifier_type\":\"primary\""));

        // Test volatile attribute
        let volatile_attr = AttributeResponse {
            name: "modifyTimestamp".to_string(),
            native_name: "modifyTimestamp".to_string(),
            data_type: "datetime".to_string(),
            multi_valued: false,
            required: false,
            readable: true,
            writable: false,
            identifier_type: None,
            volatile: true,
            case_insensitive: false,
            source_class: None,
        };

        let json = serde_json::to_string(&volatile_attr).unwrap();
        assert!(json.contains("\"volatile\":true"));
    }
}
