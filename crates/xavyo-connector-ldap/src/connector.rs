//! LDAP Connector implementation
//!
//! Implements the Connector trait for LDAP/Active Directory.

use async_trait::async_trait;
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

use xavyo_connector::config::ConnectorConfig;
use xavyo_connector::error::{ConnectorError, ConnectorResult};
use xavyo_connector::operation::{
    AttributeDelta, AttributeSet, AttributeValue, Filter, PageRequest, SearchResult, Uid,
};
use xavyo_connector::schema::{
    AttributeDataType, ObjectClass, Schema, SchemaAttribute, SchemaConfig,
};
use xavyo_connector::traits::{Connector, CreateOp, DeleteOp, SchemaDiscovery, SearchOp, UpdateOp};
use xavyo_connector::types::ConnectorType;

use crate::config::LdapConfig;

/// LDAP Connector for provisioning to LDAP/Active Directory.
pub struct LdapConnector {
    /// Configuration.
    config: LdapConfig,

    /// Display name for this connector instance.
    display_name: String,

    /// Cached LDAP connection (lazily initialized).
    connection: Arc<RwLock<Option<Ldap>>>,

    /// Whether the connector has been disposed.
    disposed: Arc<RwLock<bool>>,
}

impl LdapConnector {
    /// Create a new LDAP connector with the given configuration.
    pub fn new(config: LdapConfig) -> ConnectorResult<Self> {
        config.validate()?;

        let display_name = format!("LDAP: {}", config.host);

        Ok(Self {
            config,
            display_name,
            connection: Arc::new(RwLock::new(None)),
            disposed: Arc::new(RwLock::new(false)),
        })
    }

    /// Get an LDAP connection, creating one if necessary.
    async fn get_connection(&self) -> ConnectorResult<Ldap> {
        // Check if disposed
        if *self.disposed.read().await {
            return Err(ConnectorError::InvalidConfiguration {
                message: "Connector has been disposed".to_string(),
            });
        }

        // Try to reuse existing connection
        {
            let conn_guard = self.connection.read().await;
            if let Some(ref conn) = *conn_guard {
                return Ok(conn.clone());
            }
        }

        // Create new connection
        let conn = self.create_connection().await?;

        // Cache the connection
        {
            let mut conn_guard = self.connection.write().await;
            *conn_guard = Some(conn.clone());
        }

        Ok(conn)
    }

    /// Create a new LDAP connection.
    async fn create_connection(&self) -> ConnectorResult<Ldap> {
        let url = if self.config.use_ssl {
            format!("ldaps://{}:{}", self.config.host, self.config.port)
        } else {
            format!("ldap://{}:{}", self.config.host, self.config.port)
        };

        debug!(url = %url, "Connecting to LDAP server");

        // Configure connection settings
        let settings = LdapConnSettings::new()
            .set_conn_timeout(std::time::Duration::from_secs(
                self.config.connection.connection_timeout_secs,
            ))
            .set_starttls(self.config.use_starttls);

        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &url)
            .await
            .map_err(|e| {
                ConnectorError::connection_failed_with_source(
                    format!("Failed to connect to LDAP server at {}", url),
                    e,
                )
            })?;

        // Spawn the connection driver
        tokio::spawn(async move {
            if let Err(e) = conn.drive().await {
                warn!(error = %e, "LDAP connection driver error");
            }
        });

        // Perform bind
        let bind_dn = &self.config.bind_dn;
        let bind_password = self.config.bind_password.as_deref().unwrap_or("");

        debug!(bind_dn = %bind_dn, "Performing LDAP bind");

        let result = ldap
            .simple_bind(bind_dn, bind_password)
            .await
            .map_err(|e| {
                ConnectorError::connection_failed_with_source(
                    format!("LDAP bind failed for {}", bind_dn),
                    e,
                )
            })?;

        if result.rc != 0 {
            // Check for authentication failure
            if result.rc == 49 {
                return Err(ConnectorError::AuthenticationFailed);
            }
            return Err(ConnectorError::connection_failed(format!(
                "LDAP bind failed with code {}: {}",
                result.rc, result.text
            )));
        }

        info!(host = %self.config.host, "LDAP connection established successfully");

        Ok(ldap)
    }

    /// Convert our Filter to LDAP filter string.
    fn filter_to_ldap(filter: &Filter) -> String {
        match filter {
            Filter::And { filters } => {
                let inner: Vec<String> = filters.iter().map(Self::filter_to_ldap).collect();
                format!("(&{})", inner.join(""))
            }
            Filter::Or { filters } => {
                let inner: Vec<String> = filters.iter().map(Self::filter_to_ldap).collect();
                format!("(|{})", inner.join(""))
            }
            Filter::Not { filter } => {
                format!("(!{})", Self::filter_to_ldap(filter))
            }
            Filter::Equals { attribute, value } => {
                format!("({}={})", attribute, Self::escape_ldap_value(value))
            }
            Filter::Contains { attribute, value } => {
                format!("({}=*{}*)", attribute, Self::escape_ldap_value(value))
            }
            Filter::StartsWith { attribute, value } => {
                format!("({}={}*)", attribute, Self::escape_ldap_value(value))
            }
            Filter::EndsWith { attribute, value } => {
                format!("({}=*{})", attribute, Self::escape_ldap_value(value))
            }
            Filter::GreaterThan { attribute, value } => {
                format!("({}>={})", attribute, Self::escape_ldap_value(value))
            }
            Filter::GreaterThanOrEquals { attribute, value } => {
                format!("({}>={})", attribute, Self::escape_ldap_value(value))
            }
            Filter::LessThan { attribute, value } => {
                format!("({}<={})", attribute, Self::escape_ldap_value(value))
            }
            Filter::LessThanOrEquals { attribute, value } => {
                format!("({}<={})", attribute, Self::escape_ldap_value(value))
            }
            Filter::Present { attribute } => {
                format!("({}=*)", attribute)
            }
        }
    }

    /// Escape special characters in LDAP filter values (RFC 4515).
    fn escape_ldap_value(value: &str) -> String {
        value
            .replace('\\', "\\5c")
            .replace('*', "\\2a")
            .replace('(', "\\28")
            .replace(')', "\\29")
            .replace('\0', "\\00")
    }

    /// Escape special characters in DN attribute values per RFC 4514.
    ///
    /// DN escaping is different from filter escaping. Characters that must be escaped:
    /// - Leading or trailing SPACE (escaped as \20)
    /// - Leading # (escaped as \23)
    /// - Characters: , + " \ < > ; = (escaped with backslash prefix)
    /// - NUL character (escaped as \00)
    fn escape_dn_value(value: &str) -> String {
        if value.is_empty() {
            return String::new();
        }

        let mut result = String::with_capacity(value.len() * 2);

        for (i, ch) in value.chars().enumerate() {
            let is_first = i == 0;
            let is_last = i == value.len() - 1;

            match ch {
                // Characters that must always be escaped with backslash
                ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=' => {
                    result.push('\\');
                    result.push(ch);
                }
                // NUL must be hex-escaped
                '\0' => {
                    result.push_str("\\00");
                }
                // Space needs escaping only at start or end
                ' ' if is_first || is_last => {
                    result.push_str("\\20");
                }
                // # needs escaping only at start
                '#' if is_first => {
                    result.push_str("\\23");
                }
                // All other characters pass through
                _ => {
                    result.push(ch);
                }
            }
        }

        result
    }

    /// Convert AttributeValue to strings for LDAP.
    fn attribute_value_to_strings(value: &AttributeValue) -> Vec<String> {
        match value {
            AttributeValue::String(s) => vec![s.clone()],
            AttributeValue::Integer(i) => vec![i.to_string()],
            AttributeValue::Boolean(b) => vec![if *b { "TRUE" } else { "FALSE" }.to_string()],
            AttributeValue::Binary(b) => vec![base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b,
            )],
            AttributeValue::Float(f) => vec![f.to_string()],
            AttributeValue::Array(arr) => arr
                .iter()
                .flat_map(Self::attribute_value_to_strings)
                .collect(),
            AttributeValue::Object(_) => vec![], // JSON objects not directly supported in LDAP
            AttributeValue::Null => vec![],
        }
    }

    /// Convert LDAP search entry to AttributeSet.
    fn entry_to_attribute_set(entry: SearchEntry) -> AttributeSet {
        let mut attrs = AttributeSet::new();

        // Add DN as special attribute
        attrs.set("dn", entry.dn.clone());

        // Convert all attributes
        for (name, values) in entry.attrs {
            if values.len() == 1 {
                attrs.set(name, values.into_iter().next().unwrap());
            } else if !values.is_empty() {
                attrs.set(
                    name,
                    AttributeValue::Array(values.into_iter().map(AttributeValue::String).collect()),
                );
            }
        }

        // Handle binary attributes
        for (name, values) in entry.bin_attrs {
            if let Some(first_value) = values.into_iter().next() {
                attrs.set(name, AttributeValue::Binary(first_value));
            }
        }

        attrs
    }

    /// Get scope from search base configuration.
    fn get_search_scope(&self) -> Scope {
        // Default to subtree search
        Scope::Subtree
    }

    /// Get the DN for a new entry based on object class and attributes.
    ///
    /// SECURITY: The naming attribute value is escaped per RFC 4514 to prevent
    /// LDAP injection through malicious attribute values.
    fn build_dn(&self, object_class: &str, attrs: &AttributeSet) -> ConnectorResult<String> {
        // Try to get the naming attribute (usually cn, uid, or ou)
        let naming_attr = match object_class.to_lowercase().as_str() {
            "person" | "inetorgperson" | "organizationalperson" | "user" => "cn",
            "posixaccount" => "uid",
            "group" | "groupofnames" | "groupofuniquenames" | "posixgroup" => "cn",
            "organizationalunit" => "ou",
            _ => "cn",
        };

        let naming_value = attrs
            .get(naming_attr)
            .or_else(|| attrs.get("cn"))
            .or_else(|| attrs.get("uid"))
            .ok_or_else(|| ConnectorError::InvalidData {
                message: format!(
                    "Cannot determine DN: missing naming attribute '{}', 'cn', or 'uid'",
                    naming_attr
                ),
            })?;

        let naming_str = match naming_value {
            AttributeValue::String(s) => s.clone(),
            AttributeValue::Array(arr) => arr
                .first()
                .and_then(|v| v.as_string())
                .map(|s| s.to_string())
                .unwrap_or_default(),
            _ => {
                return Err(ConnectorError::InvalidData {
                    message: format!("Naming attribute must be a string, got {:?}", naming_value),
                })
            }
        };

        // SECURITY: Escape the naming value per RFC 4514 to prevent LDAP injection.
        // This protects against malicious values like "cn=admin,dc=evil,dc=com"
        // which could be used to create entries in unintended locations.
        let escaped_value = Self::escape_dn_value(&naming_str);

        Ok(format!(
            "{}={},{}",
            naming_attr, escaped_value, self.config.base_dn
        ))
    }
}

#[async_trait]
impl Connector for LdapConnector {
    fn connector_type(&self) -> ConnectorType {
        ConnectorType::Ldap
    }

    fn display_name(&self) -> &str {
        &self.display_name
    }

    #[instrument(skip(self))]
    async fn test_connection(&self) -> ConnectorResult<()> {
        let mut ldap = self.get_connection().await?;

        // Try a simple search to verify connectivity
        let result = ldap
            .search(
                &self.config.base_dn,
                Scope::Base,
                "(objectClass=*)",
                vec!["dn"],
            )
            .await
            .map_err(|e| ConnectorError::connection_failed_with_source("Test search failed", e))?;

        let (entries, _res) = result.success().map_err(|e| {
            ConnectorError::connection_failed(format!("Test search failed: {:?}", e))
        })?;

        if entries.is_empty() {
            return Err(ConnectorError::connection_failed(format!(
                "Base DN '{}' not found or not accessible",
                self.config.base_dn
            )));
        }

        info!("LDAP connection test successful");
        Ok(())
    }

    async fn dispose(&self) -> ConnectorResult<()> {
        // Mark as disposed
        *self.disposed.write().await = true;

        // Close the connection if any
        let mut conn_guard = self.connection.write().await;
        if let Some(mut ldap) = conn_guard.take() {
            if let Err(e) = ldap.unbind().await {
                warn!(error = %e, "Error during LDAP unbind");
            }
        }

        info!("LDAP connector disposed");
        Ok(())
    }
}

#[async_trait]
impl SchemaDiscovery for LdapConnector {
    #[instrument(skip(self))]
    async fn discover_schema(&self) -> ConnectorResult<Schema> {
        let mut ldap = self.get_connection().await?;

        // Read the root DSE to find subschema entry
        let result = ldap
            .search(
                "",
                Scope::Base,
                "(objectClass=*)",
                vec!["subschemaSubentry"],
            )
            .await
            .map_err(|e| ConnectorError::SchemaDiscoveryFailed {
                message: format!("Failed to read root DSE: {}", e),
            })?;

        let (entries, _) = result
            .success()
            .map_err(|e| ConnectorError::SchemaDiscoveryFailed {
                message: format!("Root DSE search failed: {:?}", e),
            })?;

        let subschema_dn: Option<String> = entries.into_iter().next().and_then(|e| {
            let entry = SearchEntry::construct(e);
            entry
                .attrs
                .get("subschemaSubentry")
                .and_then(|v| v.first().cloned())
        });

        let schema_dn = subschema_dn.unwrap_or_else(|| "cn=schema".to_string());

        // Read the schema entry
        let result = ldap
            .search(
                &schema_dn,
                Scope::Base,
                "(objectClass=*)",
                vec!["objectClasses", "attributeTypes"],
            )
            .await
            .map_err(|e| ConnectorError::SchemaDiscoveryFailed {
                message: format!("Failed to read schema: {}", e),
            })?;

        let (entries, _) = result
            .success()
            .map_err(|e| ConnectorError::SchemaDiscoveryFailed {
                message: format!("Schema search failed: {:?}", e),
            })?;

        let schema_entry = entries
            .into_iter()
            .next()
            .map(SearchEntry::construct)
            .ok_or_else(|| ConnectorError::SchemaDiscoveryFailed {
                message: "Schema entry not found".to_string(),
            })?;

        // Parse attribute types first (to get detailed metadata)
        let mut attribute_metadata: std::collections::HashMap<String, AttributeMetadata> =
            std::collections::HashMap::new();
        if let Some(attr_definitions) = schema_entry.attrs.get("attributeTypes") {
            for attr_def in attr_definitions {
                if let Some((name, meta)) = self.parse_attribute_type_definition(attr_def) {
                    attribute_metadata.insert(name.to_lowercase(), meta);
                }
            }
        }

        // Parse object classes with enriched attribute metadata
        let mut object_classes = Vec::new();
        if let Some(oc_definitions) = schema_entry.attrs.get("objectClasses") {
            for oc_def in oc_definitions {
                if let Some(oc) =
                    self.parse_object_class_definition_with_metadata(oc_def, &attribute_metadata)
                {
                    object_classes.push(oc);
                }
            }
        }

        // If no object classes found from schema, provide common defaults
        if object_classes.is_empty() {
            object_classes = self.default_object_classes();
        }

        // Configure LDAP-specific schema options (IGA edge cases)
        let config = SchemaConfig {
            // LDAP attribute names are case-insensitive (RFC 4512)
            case_ignore_attribute_names: true,
            preserve_native_naming: true,
            // Common LDAP volatile attributes (operational attributes)
            volatile_attributes: vec![
                "modifyTimestamp".to_string(),
                "createTimestamp".to_string(),
                "modifiersName".to_string(),
                "creatorsName".to_string(),
                "entryCSN".to_string(),
                "contextCSN".to_string(),
                "structuralObjectClass".to_string(),
                "pwdChangedTime".to_string(),
                "pwdAccountLockedTime".to_string(),
                "pwdFailureTime".to_string(),
            ],
            // entryUUID is the immutable primary identifier in OpenLDAP
            primary_identifier: Some(self.config.uid_attribute.clone()),
            // Common secondary identifiers (can change during lifecycle)
            secondary_identifiers: vec!["uid".to_string(), "cn".to_string(), "dn".to_string()],
        };

        let schema = Schema::with_object_classes(object_classes).with_config(config);

        info!(
            object_class_count = schema.object_classes.len(),
            "Schema discovery complete"
        );

        Ok(schema)
    }
}

/// Metadata extracted from LDAP attributeTypes definition.
/// Based on RFC 4512 schema handling.
#[derive(Debug, Clone, Default)]
struct AttributeMetadata {
    /// Whether the attribute is single-valued (SINGLE-VALUE flag).
    single_valued: bool,
    /// Whether the attribute is read-only (NO-USER-MODIFICATION flag).
    no_user_modification: bool,
    /// Attribute usage: userApplications, directoryOperation, distributedOperation, dSAOperation.
    usage: String,
    /// Syntax OID (e.g., 1.3.6.1.4.1.1466.115.121.1.15 for Directory String).
    syntax: Option<String>,
    /// Equality matching rule.
    equality: Option<String>,
    /// Substring matching rule.
    substr: Option<String>,
    /// Ordering matching rule.
    ordering: Option<String>,
    /// Description from schema.
    description: Option<String>,
}

impl LdapConnector {
    /// Parse an LDAP attributeTypes definition string.
    /// Format: ( OID NAME 'name' ... SINGLE-VALUE ... NO-USER-MODIFICATION ... USAGE userApplications ... )
    #[allow(clippy::field_reassign_with_default)]
    fn parse_attribute_type_definition(
        &self,
        definition: &str,
    ) -> Option<(String, AttributeMetadata)> {
        let name = self.extract_name(definition)?;

        let mut meta = AttributeMetadata::default();

        // SINGLE-VALUE flag (RFC 4512) - attribute can only have one value
        meta.single_valued = definition.contains("SINGLE-VALUE");

        // NO-USER-MODIFICATION flag (RFC 4512) - attribute is read-only
        meta.no_user_modification = definition.contains("NO-USER-MODIFICATION");

        // USAGE (RFC 4512) - defaults to userApplications
        if let Some(usage) = self.extract_keyword_value(definition, "USAGE") {
            meta.usage = usage;
        } else {
            meta.usage = "userApplications".to_string();
        }

        // SYNTAX OID
        meta.syntax = self.extract_keyword_value(definition, "SYNTAX");

        // Matching rules
        meta.equality = self.extract_keyword_value(definition, "EQUALITY");
        meta.substr = self.extract_keyword_value(definition, "SUBSTR");
        meta.ordering = self.extract_keyword_value(definition, "ORDERING");

        // Description
        meta.description = self.extract_quoted_value(definition, "DESC");

        Some((name, meta))
    }

    /// Parse an LDAP object class definition string with enriched attribute metadata.
    fn parse_object_class_definition_with_metadata(
        &self,
        definition: &str,
        attribute_metadata: &std::collections::HashMap<String, AttributeMetadata>,
    ) -> Option<ObjectClass> {
        let name = self.extract_name(definition)?;

        let must_attrs = self.extract_attribute_list(definition, "MUST");
        let may_attrs = self.extract_attribute_list(definition, "MAY");

        // Extract object class type (STRUCTURAL, AUXILIARY, ABSTRACT)
        let oc_type = if definition.contains("STRUCTURAL") {
            xavyo_connector::schema::ObjectClassType::Structural
        } else if definition.contains("AUXILIARY") {
            xavyo_connector::schema::ObjectClassType::Auxiliary
        } else if definition.contains("ABSTRACT") {
            xavyo_connector::schema::ObjectClassType::Abstract
        } else {
            xavyo_connector::schema::ObjectClassType::Structural // Default
        };

        // Extract parent classes (SUP)
        let parent_classes = self.extract_attribute_list(definition, "SUP");

        let mut oc = ObjectClass::new(&name, &name)
            .with_object_class_type(oc_type)
            .with_parent_classes(parent_classes);

        // Add MUST attributes with metadata
        for attr_name in must_attrs {
            let attr = self.create_attribute_with_metadata(&attr_name, true, attribute_metadata);
            oc.add_attribute(attr);
        }

        // Add MAY attributes with metadata
        for attr_name in may_attrs {
            let attr = self.create_attribute_with_metadata(&attr_name, false, attribute_metadata);
            oc.add_attribute(attr);
        }

        Some(oc)
    }

    /// Create a SchemaAttribute with metadata from attributeTypes.
    fn create_attribute_with_metadata(
        &self,
        attr_name: &str,
        required: bool,
        attribute_metadata: &std::collections::HashMap<String, AttributeMetadata>,
    ) -> SchemaAttribute {
        let meta = attribute_metadata.get(&attr_name.to_lowercase());

        let data_type = meta
            .and_then(|m| m.syntax.as_ref())
            .map(|s| self.ldap_syntax_to_data_type(s))
            .unwrap_or(AttributeDataType::String);

        let mut attr = SchemaAttribute::new(attr_name, attr_name, data_type).case_insensitive(); // LDAP attributes are case-insensitive

        if required {
            attr = attr.required();
        }

        if let Some(meta) = meta {
            // SINGLE-VALUE means NOT multi-valued
            if !meta.single_valued {
                attr = attr.multi_valued();
            }

            // NO-USER-MODIFICATION means read-only
            if meta.no_user_modification {
                attr = attr.read_only();
            }

            // Operational attributes (not userApplications) are typically volatile
            if meta.usage != "userApplications" {
                attr = attr.volatile().read_only();
            }

            // Add description if available
            if let Some(ref desc) = meta.description {
                attr = attr.with_description(desc.clone());
            }

            // Check for case-insensitive equality matching
            if let Some(ref eq) = meta.equality {
                if eq.contains("caseIgnore") {
                    attr = attr.case_insensitive();
                }
            }
        }

        attr
    }

    /// Convert LDAP syntax OID to AttributeDataType.
    fn ldap_syntax_to_data_type(&self, syntax_oid: &str) -> AttributeDataType {
        // Common LDAP syntax OIDs (RFC 4517)
        match syntax_oid.split('{').next().unwrap_or(syntax_oid) {
            // Directory String (UTF-8)
            "1.3.6.1.4.1.1466.115.121.1.15" => AttributeDataType::String,
            // IA5 String (ASCII)
            "1.3.6.1.4.1.1466.115.121.1.26" => AttributeDataType::String,
            // Printable String
            "1.3.6.1.4.1.1466.115.121.1.44" => AttributeDataType::String,
            // Integer
            "1.3.6.1.4.1.1466.115.121.1.27" => AttributeDataType::Integer,
            // Boolean
            "1.3.6.1.4.1.1466.115.121.1.7" => AttributeDataType::Boolean,
            // Octet String (binary)
            "1.3.6.1.4.1.1466.115.121.1.40" => AttributeDataType::Binary,
            // Distinguished Name
            "1.3.6.1.4.1.1466.115.121.1.12" => AttributeDataType::Dn,
            // Generalized Time
            "1.3.6.1.4.1.1466.115.121.1.24" => AttributeDataType::DateTime,
            // UUID
            "1.3.6.1.1.16.1" => AttributeDataType::Uuid,
            // JPEG (binary)
            "1.3.6.1.4.1.1466.115.121.1.28" => AttributeDataType::Binary,
            // Telephone Number
            "1.3.6.1.4.1.1466.115.121.1.50" => AttributeDataType::String,
            // Postal Address
            "1.3.6.1.4.1.1466.115.121.1.41" => AttributeDataType::String,
            // OID
            "1.3.6.1.4.1.1466.115.121.1.38" => AttributeDataType::String,
            // Numeric String
            "1.3.6.1.4.1.1466.115.121.1.36" => AttributeDataType::String,
            // Default to String for unknown syntaxes
            _ => AttributeDataType::String,
        }
    }

    /// Extract a keyword value (e.g., USAGE userApplications).
    fn extract_keyword_value(&self, definition: &str, keyword: &str) -> Option<String> {
        let pattern = format!("{} ", keyword);
        if let Some(idx) = definition.find(&pattern) {
            let after = &definition[idx + pattern.len()..];
            // Take until space, paren, or end
            let end = after
                .find(|c: char| c.is_whitespace() || c == ')' || c == '\'')
                .unwrap_or(after.len());
            if end > 0 {
                return Some(after[..end].to_string());
            }
        }
        None
    }

    /// Extract a quoted value (e.g., DESC 'Some description').
    fn extract_quoted_value(&self, definition: &str, keyword: &str) -> Option<String> {
        let pattern = format!("{} '", keyword);
        if let Some(idx) = definition.find(&pattern) {
            let after = &definition[idx + pattern.len()..];
            if let Some(end) = after.find('\'') {
                return Some(after[..end].to_string());
            }
        }
        None
    }

    /// Parse an LDAP object class definition string (legacy, for compatibility).
    /// Preserved for fallback when attribute metadata is not available.
    #[allow(dead_code)]
    fn parse_object_class_definition(&self, definition: &str) -> Option<ObjectClass> {
        // Simple parser for LDAP schema syntax
        // Format: ( OID NAME 'name' ... MAY ( attr1 $ attr2 ) MUST ( attr3 ) ... )

        let name = self.extract_name(definition)?;

        let must_attrs = self.extract_attribute_list(definition, "MUST");
        let may_attrs = self.extract_attribute_list(definition, "MAY");

        let mut oc = ObjectClass::new(&name, &name);

        for attr_name in must_attrs {
            oc.add_attribute(
                SchemaAttribute::new(&attr_name, &attr_name, AttributeDataType::String).required(),
            );
        }

        for attr_name in may_attrs {
            oc.add_attribute(SchemaAttribute::new(
                &attr_name,
                &attr_name,
                AttributeDataType::String,
            ));
        }

        Some(oc)
    }

    /// Extract the NAME from a schema definition.
    fn extract_name(&self, definition: &str) -> Option<String> {
        // Look for NAME 'xxx' or NAME ( 'xxx' 'yyy' )
        let name_idx = definition.find("NAME")?;
        let after_name = &definition[name_idx + 4..];

        if let Some(quote_start) = after_name.find('\'') {
            let rest = &after_name[quote_start + 1..];
            if let Some(quote_end) = rest.find('\'') {
                return Some(rest[..quote_end].to_string());
            }
        }
        None
    }

    /// Extract attribute list from MUST or MAY clause.
    fn extract_attribute_list(&self, definition: &str, keyword: &str) -> Vec<String> {
        let mut result = Vec::new();

        if let Some(idx) = definition.find(keyword) {
            let after = &definition[idx + keyword.len()..];
            let after = after.trim_start();

            if after.starts_with('(') {
                // Multiple attributes: ( attr1 $ attr2 $ attr3 )
                if let Some(end) = after.find(')') {
                    let attrs_str = &after[1..end];
                    for attr in attrs_str.split('$') {
                        let attr = attr.trim();
                        if !attr.is_empty() {
                            result.push(attr.to_string());
                        }
                    }
                }
            } else {
                // Single attribute
                let attr = after.split_whitespace().next().unwrap_or("");
                if !attr.is_empty() && attr != "(" {
                    result.push(attr.to_string());
                }
            }
        }

        result
    }

    /// Default object classes when schema discovery fails.
    /// Enhanced with IGA edge case handling:
    /// - Primary/secondary identifiers
    /// - Volatile operational attributes
    /// - Case-insensitive matching for LDAP attributes
    fn default_object_classes(&self) -> Vec<ObjectClass> {
        vec![
            ObjectClass::new("inetOrgPerson", "inetOrgPerson")
                .with_display_name("Internet Organizational Person")
                // Primary identifier - immutable UUID (IGA edge case)
                .with_attribute(
                    SchemaAttribute::new("entryUUID", "entryUUID", AttributeDataType::Uuid)
                        .as_primary_identifier()
                        .read_only()
                        .case_insensitive(),
                )
                // Secondary identifier - can change (IGA edge case)
                .with_attribute(
                    SchemaAttribute::new("uid", "uid", AttributeDataType::String)
                        .as_secondary_identifier()
                        .case_insensitive(),
                )
                .with_attribute(
                    SchemaAttribute::new("cn", "cn", AttributeDataType::String)
                        .required()
                        .case_insensitive(),
                )
                .with_attribute(
                    SchemaAttribute::new("sn", "sn", AttributeDataType::String)
                        .required()
                        .case_insensitive(),
                )
                .with_attribute(
                    SchemaAttribute::new("givenName", "givenName", AttributeDataType::String)
                        .case_insensitive(),
                )
                .with_attribute(
                    SchemaAttribute::new("mail", "mail", AttributeDataType::String)
                        .multi_valued()
                        .case_insensitive(),
                )
                .with_attribute(
                    SchemaAttribute::new("userPassword", "userPassword", AttributeDataType::Binary)
                        .write_only(),
                )
                // Volatile operational attributes (IGA edge case)
                .with_attribute(
                    SchemaAttribute::new(
                        "modifyTimestamp",
                        "modifyTimestamp",
                        AttributeDataType::DateTime,
                    )
                    .volatile()
                    .read_only(),
                )
                .with_attribute(
                    SchemaAttribute::new(
                        "createTimestamp",
                        "createTimestamp",
                        AttributeDataType::DateTime,
                    )
                    .volatile()
                    .read_only(),
                ),
            ObjectClass::new("groupOfNames", "groupOfNames")
                .with_display_name("Group of Names")
                .with_attribute(
                    SchemaAttribute::new("entryUUID", "entryUUID", AttributeDataType::Uuid)
                        .as_primary_identifier()
                        .read_only()
                        .case_insensitive(),
                )
                .with_attribute(
                    SchemaAttribute::new("cn", "cn", AttributeDataType::String)
                        .required()
                        .as_secondary_identifier()
                        .case_insensitive(),
                )
                .with_attribute(
                    SchemaAttribute::new("member", "member", AttributeDataType::Dn)
                        .required()
                        .multi_valued(),
                )
                .with_attribute(
                    SchemaAttribute::new("description", "description", AttributeDataType::String)
                        .case_insensitive(),
                )
                .with_attribute(
                    SchemaAttribute::new(
                        "modifyTimestamp",
                        "modifyTimestamp",
                        AttributeDataType::DateTime,
                    )
                    .volatile()
                    .read_only(),
                ),
            ObjectClass::new("organizationalUnit", "organizationalUnit")
                .with_display_name("Organizational Unit")
                .with_attribute(
                    SchemaAttribute::new("entryUUID", "entryUUID", AttributeDataType::Uuid)
                        .as_primary_identifier()
                        .read_only(),
                )
                .with_attribute(
                    SchemaAttribute::new("ou", "ou", AttributeDataType::String)
                        .required()
                        .as_secondary_identifier()
                        .case_insensitive(),
                )
                .with_attribute(
                    SchemaAttribute::new("description", "description", AttributeDataType::String)
                        .case_insensitive(),
                ),
        ]
    }
}

#[async_trait]
impl CreateOp for LdapConnector {
    #[instrument(skip(self, attrs))]
    async fn create(&self, object_class: &str, attrs: AttributeSet) -> ConnectorResult<Uid> {
        let mut ldap = self.get_connection().await?;

        // Build the DN
        let dn = self.build_dn(object_class, &attrs)?;

        debug!(dn = %dn, object_class = %object_class, "Creating LDAP entry");

        // Build LDAP attributes
        let mut ldap_attrs: Vec<(String, std::collections::HashSet<String>)> = Vec::new();

        // Add objectClass
        let mut oc_set = std::collections::HashSet::new();
        oc_set.insert(object_class.to_string());

        // Add structural object classes based on the primary class
        match object_class.to_lowercase().as_str() {
            "inetorgperson" => {
                oc_set.insert("person".to_string());
                oc_set.insert("organizationalPerson".to_string());
            }
            "user" => {
                oc_set.insert("person".to_string());
                oc_set.insert("organizationalPerson".to_string());
            }
            "posixaccount" => {
                oc_set.insert("top".to_string());
                oc_set.insert("account".to_string());
            }
            _ => {
                oc_set.insert("top".to_string());
            }
        }
        ldap_attrs.push(("objectClass".to_string(), oc_set));

        // Add other attributes
        for (name, value) in attrs.iter() {
            if name == "dn" || name == "objectClass" {
                continue;
            }

            let values = Self::attribute_value_to_strings(value);
            if !values.is_empty() {
                ldap_attrs.push((name.clone(), values.into_iter().collect()));
            }
        }

        // Convert to the format ldap3 expects
        let ldap_attrs_vec: Vec<(&str, std::collections::HashSet<&str>)> = ldap_attrs
            .iter()
            .map(|(k, v)| (k.as_str(), v.iter().map(|s| s.as_str()).collect()))
            .collect();

        // Perform the add operation
        let result = ldap.add(&dn, ldap_attrs_vec).await.map_err(|e| {
            ConnectorError::operation_failed_with_source(
                format!("Failed to create entry: {}", dn),
                e,
            )
        })?;

        // Check result
        if result.rc == 68 {
            // LDAP_ALREADY_EXISTS
            return Err(ConnectorError::ObjectAlreadyExists {
                identifier: dn.clone(),
            });
        }

        if result.rc != 0 {
            return Err(ConnectorError::operation_failed(format!(
                "LDAP add failed with code {}: {}",
                result.rc, result.text
            )));
        }

        info!(dn = %dn, "LDAP entry created successfully");

        Ok(Uid::from_dn(dn))
    }
}

#[async_trait]
impl UpdateOp for LdapConnector {
    #[instrument(skip(self, changes))]
    async fn update(
        &self,
        _object_class: &str,
        uid: &Uid,
        changes: AttributeDelta,
    ) -> ConnectorResult<Uid> {
        let mut ldap = self.get_connection().await?;
        let dn = uid.value();

        debug!(dn = %dn, "Updating LDAP entry");

        // Build modifications
        let mut mods: Vec<ldap3::Mod<String>> = Vec::new();

        // Handle replace operations
        for (name, value) in &changes.replace {
            let values = Self::attribute_value_to_strings(value);
            mods.push(ldap3::Mod::Replace(
                name.clone(),
                values.into_iter().collect(),
            ));
        }

        // Handle add operations
        for (name, value) in &changes.add {
            let values = Self::attribute_value_to_strings(value);
            mods.push(ldap3::Mod::Add(name.clone(), values.into_iter().collect()));
        }

        // Handle remove operations
        for (name, value) in &changes.remove {
            let values = Self::attribute_value_to_strings(value);
            mods.push(ldap3::Mod::Delete(
                name.clone(),
                values.into_iter().collect(),
            ));
        }

        // Handle clear operations
        for name in &changes.clear {
            mods.push(ldap3::Mod::Delete(
                name.clone(),
                std::collections::HashSet::new(),
            ));
        }

        if mods.is_empty() {
            // No changes to apply
            return Ok(uid.clone());
        }

        // Perform the modify operation
        let result = ldap.modify(dn, mods).await.map_err(|e| {
            ConnectorError::operation_failed_with_source(
                format!("Failed to update entry: {}", dn),
                e,
            )
        })?;

        // Check for "no such object" error
        if result.rc == 32 {
            return Err(ConnectorError::ObjectNotFound {
                identifier: dn.to_string(),
            });
        }

        if result.rc != 0 {
            return Err(ConnectorError::operation_failed(format!(
                "LDAP modify failed with code {}: {}",
                result.rc, result.text
            )));
        }

        info!(dn = %dn, "LDAP entry updated successfully");

        Ok(uid.clone())
    }
}

#[async_trait]
impl DeleteOp for LdapConnector {
    #[instrument(skip(self))]
    async fn delete(&self, _object_class: &str, uid: &Uid) -> ConnectorResult<()> {
        let mut ldap = self.get_connection().await?;
        let dn = uid.value();

        debug!(dn = %dn, "Deleting LDAP entry");

        // Perform the delete operation
        let result = ldap.delete(dn).await.map_err(|e| {
            ConnectorError::operation_failed_with_source(
                format!("Failed to delete entry: {}", dn),
                e,
            )
        })?;

        // Check for "no such object" error
        if result.rc == 32 {
            return Err(ConnectorError::ObjectNotFound {
                identifier: dn.to_string(),
            });
        }

        if result.rc != 0 {
            return Err(ConnectorError::operation_failed(format!(
                "LDAP delete failed with code {}: {}",
                result.rc, result.text
            )));
        }

        info!(dn = %dn, "LDAP entry deleted successfully");

        Ok(())
    }
}

#[async_trait]
impl SearchOp for LdapConnector {
    #[instrument(skip(self))]
    async fn search(
        &self,
        object_class: &str,
        filter: Option<Filter>,
        attributes: Option<Vec<String>>,
        page: Option<PageRequest>,
    ) -> ConnectorResult<SearchResult> {
        let mut ldap = self.get_connection().await?;

        // Build the filter
        let class_filter = Filter::eq("objectClass", object_class);
        let combined_filter = if let Some(f) = filter {
            Filter::and(vec![class_filter, f])
        } else {
            class_filter
        };
        let ldap_filter = Self::filter_to_ldap(&combined_filter);

        // Get requested attributes
        let attrs: Vec<&str> = match &attributes {
            Some(list) => list.iter().map(|s| s.as_str()).collect(),
            None => vec!["*"],
        };

        debug!(
            filter = %ldap_filter,
            base_dn = %self.config.base_dn,
            "Searching LDAP"
        );

        // Perform the search
        let result = ldap
            .search(
                &self.config.base_dn,
                self.get_search_scope(),
                &ldap_filter,
                attrs,
            )
            .await
            .map_err(|e| ConnectorError::operation_failed_with_source("LDAP search failed", e))?;

        let (entries, _) = result.success().map_err(|e| {
            ConnectorError::operation_failed(format!("LDAP search failed: {:?}", e))
        })?;

        let total = entries.len();

        // Apply pagination if requested
        let (paginated_entries, has_more) = if let Some(pg) = &page {
            let offset = pg.offset as usize;
            let limit = pg.page_size as usize;
            let end = std::cmp::min(offset + limit, total);
            let has_more = end < total;
            (
                entries
                    .into_iter()
                    .skip(offset)
                    .take(limit)
                    .collect::<Vec<_>>(),
                has_more,
            )
        } else {
            (entries, false)
        };

        // Convert entries to AttributeSet
        let objects: Vec<AttributeSet> = paginated_entries
            .into_iter()
            .map(SearchEntry::construct)
            .map(Self::entry_to_attribute_set)
            .collect();

        let mut result = SearchResult::new(objects).with_total_count(total as u64);
        result.has_more = has_more;

        if has_more {
            if let Some(pg) = &page {
                result = result.with_next_cursor(format!("{}", pg.offset + pg.page_size));
            }
        }

        info!(
            total_found = total,
            returned = result.count(),
            "LDAP search completed"
        );

        Ok(result)
    }
}

impl std::fmt::Debug for LdapConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LdapConnector")
            .field("display_name", &self.display_name)
            .field("config", &self.config.redacted())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_to_ldap_equals() {
        let filter = Filter::eq("cn", "John Doe");
        assert_eq!(LdapConnector::filter_to_ldap(&filter), "(cn=John Doe)");
    }

    #[test]
    fn test_filter_to_ldap_and() {
        let filter = Filter::and(vec![
            Filter::eq("objectClass", "person"),
            Filter::eq("cn", "John"),
        ]);
        assert_eq!(
            LdapConnector::filter_to_ldap(&filter),
            "(&(objectClass=person)(cn=John))"
        );
    }

    #[test]
    fn test_filter_to_ldap_or() {
        let filter = Filter::or(vec![Filter::eq("cn", "John"), Filter::eq("cn", "Jane")]);
        assert_eq!(
            LdapConnector::filter_to_ldap(&filter),
            "(|(cn=John)(cn=Jane))"
        );
    }

    #[test]
    fn test_filter_to_ldap_not() {
        let filter = Filter::negate(Filter::eq("status", "disabled"));
        assert_eq!(
            LdapConnector::filter_to_ldap(&filter),
            "(!(status=disabled))"
        );
    }

    #[test]
    fn test_filter_to_ldap_contains() {
        let filter = Filter::contains("mail", "example.com");
        assert_eq!(
            LdapConnector::filter_to_ldap(&filter),
            "(mail=*example.com*)"
        );
    }

    #[test]
    fn test_filter_to_ldap_starts_with() {
        let filter = Filter::starts_with("cn", "John");
        assert_eq!(LdapConnector::filter_to_ldap(&filter), "(cn=John*)");
    }

    #[test]
    fn test_filter_to_ldap_present() {
        let filter = Filter::present("mail");
        assert_eq!(LdapConnector::filter_to_ldap(&filter), "(mail=*)");
    }

    #[test]
    fn test_escape_ldap_value() {
        assert_eq!(LdapConnector::escape_ldap_value("John Doe"), "John Doe");
        assert_eq!(LdapConnector::escape_ldap_value("John*"), "John\\2a");
        assert_eq!(LdapConnector::escape_ldap_value("(admin)"), "\\28admin\\29");
        assert_eq!(LdapConnector::escape_ldap_value("a\\b"), "a\\5cb");
    }

    // =========================================================================
    // DN Escaping Tests (RFC 4514 compliance)
    // =========================================================================

    #[test]
    fn test_escape_dn_value_simple() {
        // Normal values should pass through unchanged
        assert_eq!(LdapConnector::escape_dn_value("John Doe"), "John Doe");
        assert_eq!(LdapConnector::escape_dn_value("admin"), "admin");
    }

    #[test]
    fn test_escape_dn_value_special_chars() {
        // Characters that must always be escaped: , + " \ < > ; =
        assert_eq!(LdapConnector::escape_dn_value("a,b"), "a\\,b");
        assert_eq!(LdapConnector::escape_dn_value("a+b"), "a\\+b");
        assert_eq!(LdapConnector::escape_dn_value("a\"b"), "a\\\"b");
        assert_eq!(LdapConnector::escape_dn_value("a\\b"), "a\\\\b");
        assert_eq!(LdapConnector::escape_dn_value("a<b"), "a\\<b");
        assert_eq!(LdapConnector::escape_dn_value("a>b"), "a\\>b");
        assert_eq!(LdapConnector::escape_dn_value("a;b"), "a\\;b");
        assert_eq!(LdapConnector::escape_dn_value("a=b"), "a\\=b");
    }

    #[test]
    fn test_escape_dn_value_leading_trailing_space() {
        // Leading and trailing spaces must be escaped
        assert_eq!(LdapConnector::escape_dn_value(" admin"), "\\20admin");
        assert_eq!(LdapConnector::escape_dn_value("admin "), "admin\\20");
        assert_eq!(LdapConnector::escape_dn_value(" admin "), "\\20admin\\20");
        // Middle spaces are fine
        assert_eq!(LdapConnector::escape_dn_value("John Doe"), "John Doe");
    }

    #[test]
    fn test_escape_dn_value_leading_hash() {
        // Leading # must be escaped
        assert_eq!(LdapConnector::escape_dn_value("#admin"), "\\23admin");
        // # in middle is fine
        assert_eq!(LdapConnector::escape_dn_value("admin#1"), "admin#1");
    }

    #[test]
    fn test_escape_dn_value_injection_attempt() {
        // Attempt to escape base DN by including comma
        let malicious = "admin,dc=evil,dc=com";
        let escaped = LdapConnector::escape_dn_value(malicious);
        assert_eq!(escaped, "admin\\,dc\\=evil\\,dc\\=com");
        // The escaped value is safe to use in a DN
    }

    #[test]
    fn test_escape_dn_value_empty() {
        assert_eq!(LdapConnector::escape_dn_value(""), "");
    }

    #[test]
    fn test_escape_dn_value_nul() {
        // NUL character must be hex-escaped
        assert_eq!(LdapConnector::escape_dn_value("a\0b"), "a\\00b");
    }

    #[test]
    fn test_attribute_value_to_strings() {
        assert_eq!(
            LdapConnector::attribute_value_to_strings(&AttributeValue::String("test".to_string())),
            vec!["test"]
        );

        assert_eq!(
            LdapConnector::attribute_value_to_strings(&AttributeValue::Integer(42)),
            vec!["42"]
        );

        assert_eq!(
            LdapConnector::attribute_value_to_strings(&AttributeValue::Boolean(true)),
            vec!["TRUE"]
        );

        assert_eq!(
            LdapConnector::attribute_value_to_strings(&AttributeValue::Boolean(false)),
            vec!["FALSE"]
        );

        assert_eq!(
            LdapConnector::attribute_value_to_strings(&AttributeValue::Array(vec![
                AttributeValue::String("a".to_string()),
                AttributeValue::String("b".to_string())
            ])),
            vec!["a", "b"]
        );

        let empty: Vec<String> = vec![];
        assert_eq!(
            LdapConnector::attribute_value_to_strings(&AttributeValue::Null),
            empty
        );
    }

    #[test]
    fn test_complex_filter() {
        let filter = Filter::and(vec![
            Filter::eq("objectClass", "inetOrgPerson"),
            Filter::or(vec![
                Filter::eq("department", "IT"),
                Filter::eq("department", "Engineering"),
            ]),
            Filter::negate(Filter::eq("status", "inactive")),
            Filter::present("mail"),
        ]);

        let expected =
            "(&(objectClass=inetOrgPerson)(|(department=IT)(department=Engineering))(!(status=inactive))(mail=*))";
        assert_eq!(LdapConnector::filter_to_ldap(&filter), expected);
    }

    // =========================================================================
    // Schema Discovery Tests (T014 - LDAP subschema subentry parsing)
    // =========================================================================

    /// Helper to create a connector for testing schema parsing.
    fn test_connector() -> LdapConnector {
        use crate::config::LdapConfig;
        use xavyo_connector::config::{ConnectionSettings, TlsConfig};

        let config = LdapConfig {
            host: "localhost".to_string(),
            port: 389,
            base_dn: "dc=example,dc=com".to_string(),
            bind_dn: "cn=admin,dc=example,dc=com".to_string(),
            bind_password: Some("secret".to_string()),
            use_ssl: false,
            use_starttls: false,
            follow_referrals: false,
            connection: ConnectionSettings::default(),
            tls: TlsConfig::default(),
            user_container: None,
            group_container: None,
            user_object_classes: vec!["inetOrgPerson".to_string()],
            group_object_classes: vec!["groupOfNames".to_string()],
            uid_attribute: "entryUUID".to_string(),
            page_size: 1000,
        };
        LdapConnector::new(config).unwrap()
    }

    #[test]
    fn test_extract_name_simple() {
        let connector = test_connector();
        let def =
            "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( description ) )";
        assert_eq!(connector.extract_name(def), Some("person".to_string()));
    }

    #[test]
    fn test_extract_name_with_quotes() {
        let connector = test_connector();
        let def = "( 1.3.6.1.4.1.1466.115.121.1.15 NAME 'Directory String' )";
        assert_eq!(
            connector.extract_name(def),
            Some("Directory String".to_string())
        );
    }

    #[test]
    fn test_extract_name_missing() {
        let connector = test_connector();
        let def = "( 2.5.6.6 SUP top STRUCTURAL )";
        assert_eq!(connector.extract_name(def), None);
    }

    #[test]
    fn test_extract_attribute_list_must_single() {
        let connector = test_connector();
        let def = "( 2.5.6.6 NAME 'person' MUST cn )";
        let attrs = connector.extract_attribute_list(def, "MUST");
        assert_eq!(attrs, vec!["cn"]);
    }

    #[test]
    fn test_extract_attribute_list_must_multiple() {
        let connector = test_connector();
        let def = "( 2.5.6.6 NAME 'person' MUST ( cn $ sn $ uid ) )";
        let attrs = connector.extract_attribute_list(def, "MUST");
        assert_eq!(attrs, vec!["cn", "sn", "uid"]);
    }

    #[test]
    fn test_extract_attribute_list_may() {
        let connector = test_connector();
        let def = "( 2.5.6.6 NAME 'inetOrgPerson' MAY ( mail $ telephoneNumber $ userPassword ) )";
        let attrs = connector.extract_attribute_list(def, "MAY");
        assert_eq!(attrs, vec!["mail", "telephoneNumber", "userPassword"]);
    }

    #[test]
    fn test_extract_attribute_list_empty() {
        let connector = test_connector();
        let def = "( 2.5.6.6 NAME 'top' )";
        let attrs = connector.extract_attribute_list(def, "MUST");
        assert!(attrs.is_empty());
    }

    #[test]
    fn test_parse_object_class_definition_complete() {
        let connector = test_connector();
        let def = "( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL MAY ( audio $ businessCategory $ carLicense ) MUST ( cn $ sn ) )";

        let oc = connector.parse_object_class_definition(def);
        assert!(oc.is_some());

        let oc = oc.unwrap();
        assert_eq!(oc.name, "inetOrgPerson");

        // Check MUST attributes are marked required
        let cn_attr = oc.attributes.iter().find(|a| a.name == "cn");
        assert!(cn_attr.is_some());
        assert!(cn_attr.unwrap().required);

        let sn_attr = oc.attributes.iter().find(|a| a.name == "sn");
        assert!(sn_attr.is_some());
        assert!(sn_attr.unwrap().required);

        // Check MAY attributes are not required
        let mail_attr = oc.attributes.iter().find(|a| a.name == "audio");
        assert!(mail_attr.is_some());
        assert!(!mail_attr.unwrap().required);
    }

    #[test]
    fn test_parse_object_class_definition_invalid() {
        let connector = test_connector();
        let def = "( 2.5.6.6 SUP top )"; // Missing NAME

        let oc = connector.parse_object_class_definition(def);
        assert!(oc.is_none());
    }

    #[test]
    fn test_default_object_classes_structure() {
        let connector = test_connector();
        let defaults = connector.default_object_classes();

        assert!(!defaults.is_empty());

        // Check inetOrgPerson exists
        let inet_org = defaults.iter().find(|oc| oc.name == "inetOrgPerson");
        assert!(inet_org.is_some());
        let inet_org = inet_org.unwrap();

        // Verify required attributes
        assert!(inet_org
            .attributes
            .iter()
            .any(|a| a.name == "cn" && a.required));
        assert!(inet_org
            .attributes
            .iter()
            .any(|a| a.name == "sn" && a.required));

        // Verify optional attributes
        assert!(inet_org
            .attributes
            .iter()
            .any(|a| a.name == "mail" && !a.required));

        // Check groupOfNames exists
        let group = defaults.iter().find(|oc| oc.name == "groupOfNames");
        assert!(group.is_some());
    }

    #[test]
    fn test_parse_object_class_real_ldap_syntax() {
        let connector = test_connector();

        // Real LDAP objectClasses attribute format from OpenLDAP
        let defs = vec![
            "( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
            "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber $ seeAlso $ description ) )",
            "( 2.5.6.7 NAME 'organizationalPerson' SUP person STRUCTURAL MAY ( title $ x121Address $ registeredAddress ) )",
        ];

        for def in defs {
            let oc = connector.parse_object_class_definition(def);
            assert!(oc.is_some(), "Failed to parse: {}", def);
        }
    }

    // =========================================================================
    // IGA edge case Tests - Identifiers, Volatile, Case-Insensitivity
    // =========================================================================

    #[test]
    fn test_default_object_classes_have_primary_identifiers() {
        let connector = test_connector();
        let defaults = connector.default_object_classes();

        for oc in &defaults {
            let primary = oc.primary_identifier();
            assert!(
                primary.is_some(),
                "Object class '{}' should have a primary identifier",
                oc.name
            );
            assert_eq!(
                primary.unwrap().name,
                "entryUUID",
                "Primary identifier for '{}' should be entryUUID",
                oc.name
            );
        }
    }

    #[test]
    fn test_default_object_classes_have_volatile_attributes() {
        let connector = test_connector();
        let defaults = connector.default_object_classes();

        let inet_org = defaults
            .iter()
            .find(|oc| oc.name == "inetOrgPerson")
            .unwrap();
        let volatile = inet_org.volatile_attributes();

        assert!(
            !volatile.is_empty(),
            "inetOrgPerson should have volatile attributes"
        );

        // modifyTimestamp should be volatile
        let modify_ts = volatile.iter().find(|a| a.name == "modifyTimestamp");
        assert!(
            modify_ts.is_some(),
            "modifyTimestamp should be marked as volatile"
        );
        assert!(
            !modify_ts.unwrap().writable,
            "modifyTimestamp should be read-only"
        );
    }

    #[test]
    fn test_default_object_classes_case_insensitive_attributes() {
        let connector = test_connector();
        let defaults = connector.default_object_classes();

        let inet_org = defaults
            .iter()
            .find(|oc| oc.name == "inetOrgPerson")
            .unwrap();

        // uid should be case-insensitive
        let uid = inet_org.get_attribute("uid");
        assert!(uid.is_some());
        assert!(
            uid.unwrap().case_insensitive,
            "uid should be case-insensitive per LDAP RFC 4512"
        );

        // cn should be case-insensitive
        let cn = inet_org.get_attribute("cn");
        assert!(cn.is_some());
        assert!(
            cn.unwrap().case_insensitive,
            "cn should be case-insensitive"
        );
    }

    #[test]
    fn test_default_object_classes_secondary_identifiers() {
        let connector = test_connector();
        let defaults = connector.default_object_classes();

        let inet_org = defaults
            .iter()
            .find(|oc| oc.name == "inetOrgPerson")
            .unwrap();
        let identifiers = inet_org.identifiers();

        assert!(
            identifiers.len() >= 2,
            "Should have at least 2 identifiers (primary + secondary)"
        );

        // Check uid is secondary
        let uid = identifiers.iter().find(|a| a.name == "uid");
        assert!(uid.is_some());
        assert!(
            !uid.unwrap().is_primary_identifier(),
            "uid should be secondary identifier, not primary"
        );
        assert!(uid.unwrap().is_identifier(), "uid should be an identifier");
    }

    #[test]
    fn test_case_aware_attribute_lookup() {
        let connector = test_connector();
        let defaults = connector.default_object_classes();

        let inet_org = defaults
            .iter()
            .find(|oc| oc.name == "inetOrgPerson")
            .unwrap();

        // Case-insensitive lookup should work for case-insensitive attributes
        assert!(inet_org.get_attribute_case_insensitive("UID").is_some());
        assert!(inet_org.get_attribute_case_insensitive("uid").is_some());
        assert!(inet_org.get_attribute_case_insensitive("Uid").is_some());

        // Case-sensitive lookup should only match exact case
        assert!(inet_org.get_attribute("uid").is_some());
        assert!(inet_org.get_attribute("UID").is_none());
    }

    #[test]
    fn test_attribute_name_matches_case_insensitive() {
        let connector = test_connector();
        let defaults = connector.default_object_classes();

        let inet_org = defaults
            .iter()
            .find(|oc| oc.name == "inetOrgPerson")
            .unwrap();
        let uid = inet_org.get_attribute("uid").unwrap();

        // Case-insensitive attribute should match any case
        assert!(uid.name_matches("uid"));
        assert!(uid.name_matches("UID"));
        assert!(uid.name_matches("Uid"));
        assert!(uid.name_matches("uId"));
    }

    #[test]
    fn test_volatile_attributes_are_read_only() {
        let connector = test_connector();
        let defaults = connector.default_object_classes();

        for oc in &defaults {
            for attr in oc.volatile_attributes() {
                assert!(
                    !attr.writable,
                    "Volatile attribute '{}' in '{}' should be read-only",
                    attr.name, oc.name
                );
            }
        }
    }

    #[test]
    fn test_primary_identifiers_are_immutable() {
        let connector = test_connector();
        let defaults = connector.default_object_classes();

        for oc in &defaults {
            if let Some(primary) = oc.primary_identifier() {
                assert!(
                    !primary.writable,
                    "Primary identifier '{}' in '{}' should be immutable (read-only)",
                    primary.name, oc.name
                );
            }
        }
    }

    // =========================================================================
    // T054 - LDAP attributeTypes Metadata Extraction Tests
    // =========================================================================

    #[test]
    fn test_parse_attribute_type_single_value() {
        let connector = test_connector();
        let def = "( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )";

        let meta = connector.parse_attribute_type_definition(def);
        assert!(
            meta.is_some(),
            "Should parse valid attributeType definition"
        );

        let (name, metadata) = meta.unwrap();
        assert_eq!(name, "cn");
        assert!(metadata.single_valued, "cn should be SINGLE-VALUE");
        assert!(
            !metadata.no_user_modification,
            "cn should be user-modifiable"
        );
        assert_eq!(metadata.usage, "userApplications");
        assert_eq!(
            metadata.syntax.as_deref(),
            Some("1.3.6.1.4.1.1466.115.121.1.15")
        );
        assert_eq!(metadata.equality.as_deref(), Some("caseIgnoreMatch"));
    }

    #[test]
    fn test_parse_attribute_type_multi_value() {
        let connector = test_connector();
        let def = "( 2.5.4.0 NAME 'objectClass' EQUALITY objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )";

        let meta = connector.parse_attribute_type_definition(def);
        assert!(meta.is_some());

        let (name, metadata) = meta.unwrap();
        assert_eq!(name, "objectClass");
        assert!(
            !metadata.single_valued,
            "objectClass should be multi-valued (default)"
        );
    }

    #[test]
    fn test_parse_attribute_type_no_user_modification() {
        let connector = test_connector();
        let def = "( 2.5.18.1 NAME 'createTimestamp' EQUALITY generalizedTimeMatch ORDERING generalizedTimeOrderingMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )";

        let meta = connector.parse_attribute_type_definition(def);
        assert!(meta.is_some());

        let (name, metadata) = meta.unwrap();
        assert_eq!(name, "createTimestamp");
        assert!(metadata.single_valued);
        assert!(
            metadata.no_user_modification,
            "createTimestamp should have NO-USER-MODIFICATION"
        );
        assert_eq!(metadata.usage, "directoryOperation");
    }

    #[test]
    fn test_parse_attribute_type_operational() {
        let connector = test_connector();
        let def = "( 2.5.18.2 NAME 'modifyTimestamp' SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )";

        let meta = connector.parse_attribute_type_definition(def);
        assert!(meta.is_some());

        let (name, metadata) = meta.unwrap();
        assert_eq!(name, "modifyTimestamp");
        assert_eq!(metadata.usage, "directoryOperation");
        assert!(metadata.no_user_modification);
    }

    #[test]
    fn test_parse_attribute_type_with_description() {
        let connector = test_connector();
        let def = "( 2.5.4.41 NAME 'name' DESC 'Name for directory entries' EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";

        let meta = connector.parse_attribute_type_definition(def);
        assert!(meta.is_some());

        let (name, metadata) = meta.unwrap();
        assert_eq!(name, "name");
        assert_eq!(
            metadata.description.as_deref(),
            Some("Name for directory entries")
        );
    }

    #[test]
    fn test_parse_attribute_type_dsa_operation() {
        let connector = test_connector();
        let def = "( 1.3.6.1.4.1.4203.1.12.2.3.0.1 NAME 'syncCookie' SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )";

        let meta = connector.parse_attribute_type_definition(def);
        assert!(meta.is_some());

        let (name, metadata) = meta.unwrap();
        assert_eq!(name, "syncCookie");
        assert_eq!(metadata.usage, "dSAOperation");
    }

    #[test]
    fn test_ldap_syntax_to_data_type_string() {
        let connector = test_connector();

        // Directory String (UTF-8)
        assert_eq!(
            connector.ldap_syntax_to_data_type("1.3.6.1.4.1.1466.115.121.1.15"),
            xavyo_connector::schema::AttributeDataType::String
        );

        // IA5 String (ASCII)
        assert_eq!(
            connector.ldap_syntax_to_data_type("1.3.6.1.4.1.1466.115.121.1.26"),
            xavyo_connector::schema::AttributeDataType::String
        );

        // Printable String
        assert_eq!(
            connector.ldap_syntax_to_data_type("1.3.6.1.4.1.1466.115.121.1.44"),
            xavyo_connector::schema::AttributeDataType::String
        );
    }

    #[test]
    fn test_ldap_syntax_to_data_type_integer() {
        let connector = test_connector();

        assert_eq!(
            connector.ldap_syntax_to_data_type("1.3.6.1.4.1.1466.115.121.1.27"),
            xavyo_connector::schema::AttributeDataType::Integer
        );
    }

    #[test]
    fn test_ldap_syntax_to_data_type_boolean() {
        let connector = test_connector();

        assert_eq!(
            connector.ldap_syntax_to_data_type("1.3.6.1.4.1.1466.115.121.1.7"),
            xavyo_connector::schema::AttributeDataType::Boolean
        );
    }

    #[test]
    fn test_ldap_syntax_to_data_type_binary() {
        let connector = test_connector();

        // Octet String
        assert_eq!(
            connector.ldap_syntax_to_data_type("1.3.6.1.4.1.1466.115.121.1.40"),
            xavyo_connector::schema::AttributeDataType::Binary
        );

        // JPEG
        assert_eq!(
            connector.ldap_syntax_to_data_type("1.3.6.1.4.1.1466.115.121.1.28"),
            xavyo_connector::schema::AttributeDataType::Binary
        );
    }

    #[test]
    fn test_ldap_syntax_to_data_type_dn() {
        let connector = test_connector();

        assert_eq!(
            connector.ldap_syntax_to_data_type("1.3.6.1.4.1.1466.115.121.1.12"),
            xavyo_connector::schema::AttributeDataType::Dn
        );
    }

    #[test]
    fn test_ldap_syntax_to_data_type_datetime() {
        let connector = test_connector();

        // Generalized Time
        assert_eq!(
            connector.ldap_syntax_to_data_type("1.3.6.1.4.1.1466.115.121.1.24"),
            xavyo_connector::schema::AttributeDataType::DateTime
        );
    }

    #[test]
    fn test_ldap_syntax_to_data_type_uuid() {
        let connector = test_connector();

        assert_eq!(
            connector.ldap_syntax_to_data_type("1.3.6.1.1.16.1"),
            xavyo_connector::schema::AttributeDataType::Uuid
        );
    }

    #[test]
    fn test_ldap_syntax_with_length_constraint() {
        let connector = test_connector();

        // Syntax with length constraint should strip the constraint
        assert_eq!(
            connector.ldap_syntax_to_data_type("1.3.6.1.4.1.1466.115.121.1.15{256}"),
            xavyo_connector::schema::AttributeDataType::String
        );
    }

    #[test]
    fn test_ldap_syntax_unknown_defaults_to_string() {
        let connector = test_connector();

        assert_eq!(
            connector.ldap_syntax_to_data_type("9.9.9.9.9.9.9.9.9"),
            xavyo_connector::schema::AttributeDataType::String
        );
    }

    #[test]
    fn test_create_attribute_with_metadata() {
        use std::collections::HashMap;

        let connector = test_connector();

        let mut metadata_map = HashMap::new();
        metadata_map.insert(
            "mail".to_lowercase(),
            AttributeMetadata {
                single_valued: false,
                no_user_modification: false,
                usage: "userApplications".to_string(),
                syntax: Some("1.3.6.1.4.1.1466.115.121.1.26".to_string()), // IA5 String
                equality: Some("caseIgnoreIA5Match".to_string()),
                substr: None,
                ordering: None,
                description: Some("Email address".to_string()),
            },
        );

        let attr = connector.create_attribute_with_metadata("mail", false, &metadata_map);

        assert_eq!(attr.name, "mail");
        assert!(!attr.required);
        assert!(attr.multi_valued);
        assert!(attr.writable);
        assert!(attr.case_insensitive);
        assert_eq!(attr.description.as_deref(), Some("Email address"));
        assert_eq!(
            attr.data_type,
            xavyo_connector::schema::AttributeDataType::String
        );
    }

    #[test]
    fn test_create_attribute_with_operational_usage() {
        use std::collections::HashMap;

        let connector = test_connector();

        let mut metadata_map = HashMap::new();
        metadata_map.insert(
            "modifytimestamp".to_lowercase(),
            AttributeMetadata {
                single_valued: true,
                no_user_modification: true,
                usage: "directoryOperation".to_string(),
                syntax: Some("1.3.6.1.4.1.1466.115.121.1.24".to_string()), // Generalized Time
                equality: None,
                substr: None,
                ordering: None,
                description: None,
            },
        );

        let attr =
            connector.create_attribute_with_metadata("modifyTimestamp", false, &metadata_map);

        assert_eq!(attr.name, "modifyTimestamp");
        assert!(!attr.multi_valued); // SINGLE-VALUE
        assert!(!attr.writable); // NO-USER-MODIFICATION + operational usage
        assert!(attr.volatile); // directoryOperation = volatile
        assert_eq!(
            attr.data_type,
            xavyo_connector::schema::AttributeDataType::DateTime
        );
    }

    #[test]
    fn test_parse_object_class_with_metadata() {
        use std::collections::HashMap;

        let connector = test_connector();

        // Build attribute metadata
        let mut metadata_map = HashMap::new();
        metadata_map.insert(
            "cn".to_string(),
            AttributeMetadata {
                single_valued: false,
                no_user_modification: false,
                usage: "userApplications".to_string(),
                syntax: Some("1.3.6.1.4.1.1466.115.121.1.15".to_string()),
                equality: Some("caseIgnoreMatch".to_string()),
                substr: None,
                ordering: None,
                description: Some("Common name".to_string()),
            },
        );
        metadata_map.insert(
            "sn".to_string(),
            AttributeMetadata {
                single_valued: true,
                no_user_modification: false,
                usage: "userApplications".to_string(),
                syntax: Some("1.3.6.1.4.1.1466.115.121.1.15".to_string()),
                equality: None,
                substr: None,
                ordering: None,
                description: None,
            },
        );
        metadata_map.insert(
            "mail".to_string(),
            AttributeMetadata {
                single_valued: false,
                no_user_modification: false,
                usage: "userApplications".to_string(),
                syntax: Some("1.3.6.1.4.1.1466.115.121.1.26".to_string()),
                equality: Some("caseIgnoreIA5Match".to_string()),
                substr: None,
                ordering: None,
                description: None,
            },
        );

        let def = "( 2.16.840.1.113730.3.2.2 NAME 'inetOrgPerson' SUP organizationalPerson STRUCTURAL MUST ( cn $ sn ) MAY ( mail ) )";

        let oc = connector.parse_object_class_definition_with_metadata(def, &metadata_map);
        assert!(oc.is_some());

        let oc = oc.unwrap();
        assert_eq!(oc.name, "inetOrgPerson");

        // Check cn attribute with metadata
        let cn = oc.get_attribute("cn").unwrap();
        assert!(cn.required);
        assert!(cn.multi_valued); // NOT single-value
        assert!(cn.case_insensitive);
        assert_eq!(cn.description.as_deref(), Some("Common name"));

        // Check sn attribute with metadata
        let sn = oc.get_attribute("sn").unwrap();
        assert!(sn.required);
        assert!(!sn.multi_valued); // single-value

        // Check mail attribute with metadata
        let mail = oc.get_attribute("mail").unwrap();
        assert!(!mail.required);
        assert!(mail.multi_valued);
    }

    #[test]
    fn test_extract_keyword_value() {
        let connector = test_connector();

        let def = "( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 USAGE userApplications )";

        assert_eq!(
            connector.extract_keyword_value(def, "USAGE"),
            Some("userApplications".to_string())
        );
        assert_eq!(
            connector.extract_keyword_value(def, "EQUALITY"),
            Some("caseIgnoreMatch".to_string())
        );
        assert_eq!(
            connector.extract_keyword_value(def, "SYNTAX"),
            Some("1.3.6.1.4.1.1466.115.121.1.15".to_string())
        );
        assert_eq!(connector.extract_keyword_value(def, "MISSING"), None);
    }

    #[test]
    fn test_extract_quoted_value() {
        let connector = test_connector();

        let def = "( 2.5.4.41 NAME 'name' DESC 'Name for directory entries' )";

        assert_eq!(
            connector.extract_quoted_value(def, "NAME"),
            Some("name".to_string())
        );
        assert_eq!(
            connector.extract_quoted_value(def, "DESC"),
            Some("Name for directory entries".to_string())
        );
        assert_eq!(connector.extract_quoted_value(def, "MISSING"), None);
    }
}
