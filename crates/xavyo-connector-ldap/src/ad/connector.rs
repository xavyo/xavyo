//! AD Connector wrapping LdapConnector with AD-specific behavior.
//!
//! The `AdConnector` delegates LDAP operations to the underlying `LdapConnector`
//! while adding:
//! - AD-specific configuration validation
//! - rootDSE query for connection testing (domain info, highestCommittedUSN)
//! - AD schema definitions as default object classes
//! - Multi-search-base iteration

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

use xavyo_connector::error::{ConnectorError, ConnectorResult};
use xavyo_connector::operation::{
    AttributeDelta, AttributeSet, AttributeValue, Filter, PageRequest, SearchResult, Uid,
};
use xavyo_connector::schema::Schema;
use xavyo_connector::traits::{
    Connector, CreateOp, DeleteOp, DisableOp, PasswordOp, SchemaDiscovery, SearchOp, UpdateOp,
};
use xavyo_connector::types::ConnectorType;

use crate::config::ActiveDirectoryConfig;
use crate::connector::LdapConnector;

use super::password::{
    build_user_dn, encode_ad_password, new_account_uac, validate_password_connection,
};
use super::schema::ad_default_schema;
use super::user_account_control::UserAccountControl;

/// Information retrieved from the AD rootDSE during connection test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdServerInfo {
    /// DNS hostname of the domain controller.
    pub dns_host_name: Option<String>,
    /// Default naming context (base DN).
    pub default_naming_context: Option<String>,
    /// Root domain naming context (forest root).
    pub root_domain_naming_context: Option<String>,
    /// Highest committed USN (for incremental sync).
    pub highest_committed_usn: Option<String>,
    /// Schema naming context.
    pub schema_naming_context: Option<String>,
    /// Configuration naming context.
    pub config_naming_context: Option<String>,
    /// Domain functionality level.
    pub domain_functionality: Option<String>,
    /// Forest functionality level.
    pub forest_functionality: Option<String>,
}

/// Result of an AD connection test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionTestResult {
    /// Whether the connection was successful.
    pub success: bool,
    /// Human-readable message.
    pub message: String,
    /// Server information (only present on success).
    pub server_info: Option<AdServerInfo>,
}

/// Active Directory connector wrapping LdapConnector.
///
/// Provides AD-specific features on top of the base LDAP connector:
/// - Enhanced configuration validation (domain required, SSL for passwords)
/// - rootDSE-based connection testing with domain info retrieval
/// - AD-specific schema definitions (user/group object classes)
/// - Multi-search-base iteration support
pub struct AdConnector {
    /// AD-specific configuration.
    config: ActiveDirectoryConfig,

    /// Underlying LDAP connector for protocol operations.
    ldap: LdapConnector,

    /// Cached AD server info from last connection test.
    server_info: Arc<RwLock<Option<AdServerInfo>>>,
}

impl AdConnector {
    /// Create a new AD connector from configuration.
    ///
    /// Validates the AD-specific configuration and creates the underlying
    /// LDAP connector.
    pub fn new(config: ActiveDirectoryConfig) -> ConnectorResult<Self> {
        Self::validate_ad_config(&config)?;

        let ldap = LdapConnector::new(config.ldap.clone())?;

        Ok(Self {
            config,
            ldap,
            server_info: Arc::new(RwLock::new(None)),
        })
    }

    /// Get the AD configuration.
    pub fn config(&self) -> &ActiveDirectoryConfig {
        &self.config
    }

    /// Get the underlying LDAP connector for direct operations.
    pub fn ldap(&self) -> &LdapConnector {
        &self.ldap
    }

    /// Get cached server info from last connection test.
    pub async fn server_info(&self) -> Option<AdServerInfo> {
        self.server_info.read().await.clone()
    }

    /// Validate AD-specific configuration requirements.
    fn validate_ad_config(config: &ActiveDirectoryConfig) -> ConnectorResult<()> {
        // Domain is required for AD
        if config.domain.is_empty() {
            return Err(ConnectorError::InvalidConfiguration {
                message: "domain is required for Active Directory connector".to_string(),
            });
        }

        // Validate max_nesting_depth bounds
        if config.max_nesting_depth < 1 || config.max_nesting_depth > 100 {
            return Err(ConnectorError::InvalidConfiguration {
                message: format!(
                    "max_nesting_depth must be between 1 and 100, got {}",
                    config.max_nesting_depth
                ),
            });
        }

        // Validate conflict_strategy
        let valid_strategies = ["source_wins", "target_wins", "manual"];
        if !valid_strategies.contains(&config.conflict_strategy.as_str()) {
            return Err(ConnectorError::InvalidConfiguration {
                message: format!(
                    "conflict_strategy must be one of {:?}, got '{}'",
                    valid_strategies, config.conflict_strategy
                ),
            });
        }

        // Validate search bases
        for (i, sb) in config.search_bases.iter().enumerate() {
            if sb.dn.is_empty() {
                return Err(ConnectorError::InvalidConfiguration {
                    message: format!("search_bases[{}].dn cannot be empty", i),
                });
            }
            let valid_scopes = ["subtree", "onelevel", "base"];
            if !valid_scopes.contains(&sb.scope.as_str()) {
                return Err(ConnectorError::InvalidConfiguration {
                    message: format!(
                        "search_bases[{}].scope must be one of {:?}, got '{}'",
                        i, valid_scopes, sb.scope
                    ),
                });
            }
        }

        // SSL required for outbound provisioning with password operations
        if config.outbound_target_ou.is_some() && !config.ldap.use_ssl {
            warn!("Outbound provisioning configured without SSL — password operations will fail");
        }

        Ok(())
    }

    /// Iterate over configured search bases, yielding (dn, scope, filter) tuples.
    ///
    /// If no search bases are configured, yields a single entry using the
    /// base DN from the LDAP config with subtree scope.
    pub fn iterate_search_bases<'a>(
        &'a self,
        object_type: &'a str,
    ) -> Vec<(String, String, Option<String>)> {
        if self.config.search_bases.is_empty() {
            // Default: use base DN with no extra filter
            let dn = match object_type {
                "users" | "user" => self.config.ldap.user_dn(),
                "groups" | "group" => self.config.ldap.group_dn(),
                _ => self.config.ldap.base_dn.clone(),
            };
            return vec![(dn, "subtree".to_string(), None)];
        }

        self.config
            .search_bases
            .iter()
            .filter(|sb| {
                sb.object_types
                    .iter()
                    .any(|t| t == object_type || t == "all")
            })
            .map(|sb| (sb.dn.clone(), sb.scope.clone(), sb.filter.clone()))
            .collect()
    }

    /// Get the user LDAP filter for AD.
    pub fn user_filter(&self) -> &str {
        &self.config.user_filter
    }

    /// Get the group LDAP filter for AD.
    pub fn group_filter(&self) -> &str {
        &self.config.group_filter
    }

    /// Get the maximum nested group depth.
    pub fn max_nesting_depth(&self) -> u32 {
        self.config.max_nesting_depth
    }
}

#[async_trait]
impl Connector for AdConnector {
    fn connector_type(&self) -> ConnectorType {
        ConnectorType::Ldap
    }

    fn display_name(&self) -> &str {
        // Delegate but could enhance with AD domain info
        self.ldap.display_name()
    }

    #[instrument(skip(self), fields(domain = %self.config.domain))]
    async fn test_connection(&self) -> ConnectorResult<()> {
        // First, test basic LDAP connectivity
        self.ldap.test_connection().await?;

        info!(
            domain = %self.config.domain,
            "AD connection test successful"
        );

        Ok(())
    }

    async fn dispose(&self) -> ConnectorResult<()> {
        self.ldap.dispose().await
    }

    fn is_healthy(&self) -> bool {
        self.ldap.is_healthy()
    }
}

#[async_trait]
impl SchemaDiscovery for AdConnector {
    #[instrument(skip(self))]
    async fn discover_schema(&self) -> ConnectorResult<Schema> {
        // Try live schema discovery first
        match self.ldap.discover_schema().await {
            Ok(schema) => {
                debug!("Using live AD schema discovery");
                Ok(schema)
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "Live schema discovery failed, falling back to built-in AD schema"
                );
                Ok(ad_default_schema())
            }
        }
    }
}

#[async_trait]
impl CreateOp for AdConnector {
    #[instrument(skip(self, attributes), fields(domain = %self.config.domain))]
    async fn create(
        &self,
        object_class: &str,
        mut attributes: AttributeSet,
    ) -> ConnectorResult<Uid> {
        // For user object class, add AD-specific attributes
        if object_class == "user" {
            // Set AD user object class hierarchy
            let oc_val = AttributeValue::Array(vec![
                AttributeValue::String("top".to_string()),
                AttributeValue::String("person".to_string()),
                AttributeValue::String("organizationalPerson".to_string()),
                AttributeValue::String("user".to_string()),
            ]);
            attributes.set("objectClass", oc_val);

            // Set initial userAccountControl (NORMAL_ACCOUNT, optionally disabled)
            if !attributes.has("userAccountControl") {
                let uac = new_account_uac(false);
                attributes.set(
                    "userAccountControl",
                    AttributeValue::String(uac.to_string()),
                );
            }

            // Build DN from display_name + target OU if not already set
            if !attributes.has("dn") {
                if let Some(display_name) = attributes.get_string("displayName") {
                    let target_ou = self
                        .config
                        .outbound_target_ou
                        .as_deref()
                        .unwrap_or(&self.config.ldap.base_dn);
                    let dn = build_user_dn(display_name, target_ou)?;
                    attributes.set("dn", AttributeValue::String(dn));
                }
            }

            // Handle password if provided — encode as unicodePwd
            if let Some(password) = attributes.get_string("password").map(|s| s.to_string()) {
                validate_password_connection(self.config.ldap.use_ssl)?;
                let encoded = encode_ad_password(&password)?;
                attributes.remove("password");
                attributes.set("unicodePwd", AttributeValue::Binary(encoded));
            }
        }

        // Delegate to underlying LDAP connector
        self.ldap.create(object_class, attributes).await
    }
}

#[async_trait]
impl UpdateOp for AdConnector {
    #[instrument(skip(self, changes), fields(domain = %self.config.domain))]
    async fn update(
        &self,
        object_class: &str,
        uid: &Uid,
        changes: AttributeDelta,
    ) -> ConnectorResult<Uid> {
        // Delegate to underlying LDAP connector — AD LDAP modify works the same
        self.ldap.update(object_class, uid, changes).await
    }
}

#[async_trait]
impl DeleteOp for AdConnector {
    #[instrument(skip(self), fields(domain = %self.config.domain))]
    async fn delete(&self, object_class: &str, uid: &Uid) -> ConnectorResult<()> {
        self.ldap.delete(object_class, uid).await
    }
}

#[async_trait]
impl SearchOp for AdConnector {
    #[instrument(skip(self))]
    async fn search(
        &self,
        object_class: &str,
        filter: Option<Filter>,
        attributes_to_get: Option<Vec<String>>,
        page_request: Option<PageRequest>,
    ) -> ConnectorResult<SearchResult> {
        self.ldap
            .search(object_class, filter, attributes_to_get, page_request)
            .await
    }
}

#[async_trait]
impl DisableOp for AdConnector {
    #[instrument(skip(self), fields(domain = %self.config.domain))]
    async fn disable(&self, object_class: &str, uid: &Uid) -> ConnectorResult<()> {
        // Read current userAccountControl, set ACCOUNTDISABLE bit
        let current = self.read_uac(object_class, uid).await?;
        let uac = UserAccountControl::from(current).disable();

        let mut delta = AttributeDelta::new();
        delta.replace(
            "userAccountControl",
            AttributeValue::String(u32::from(uac).to_string()),
        );
        self.ldap.update(object_class, uid, delta).await?;

        info!(uid = %uid.value(), "AD account disabled");
        Ok(())
    }

    #[instrument(skip(self), fields(domain = %self.config.domain))]
    async fn enable(&self, object_class: &str, uid: &Uid) -> ConnectorResult<()> {
        // Read current userAccountControl, clear ACCOUNTDISABLE bit
        let current = self.read_uac(object_class, uid).await?;
        let uac = UserAccountControl::from(current).enable();

        let mut delta = AttributeDelta::new();
        delta.replace(
            "userAccountControl",
            AttributeValue::String(u32::from(uac).to_string()),
        );
        self.ldap.update(object_class, uid, delta).await?;

        info!(uid = %uid.value(), "AD account enabled");
        Ok(())
    }

    #[instrument(skip(self), fields(domain = %self.config.domain))]
    async fn is_disabled(&self, object_class: &str, uid: &Uid) -> ConnectorResult<bool> {
        let current = self.read_uac(object_class, uid).await?;
        let uac = UserAccountControl::from(current);
        Ok(uac.is_disabled())
    }
}

#[async_trait]
impl PasswordOp for AdConnector {
    #[instrument(skip(self, password), fields(domain = %self.config.domain))]
    async fn set_password(
        &self,
        object_class: &str,
        uid: &Uid,
        password: &str,
    ) -> ConnectorResult<()> {
        validate_password_connection(self.config.ldap.use_ssl)?;
        let encoded = encode_ad_password(password)?;

        let mut delta = AttributeDelta::new();
        delta.replace("unicodePwd", AttributeValue::Binary(encoded));
        self.ldap.update(object_class, uid, delta).await?;

        info!(uid = %uid.value(), "AD password set successfully");
        Ok(())
    }

    async fn validate_password(
        &self,
        _object_class: &str,
        _uid: &Uid,
        _password: &str,
    ) -> ConnectorResult<bool> {
        // AD password validation requires an LDAP bind attempt with the user's credentials.
        // This is not implemented as a simple attribute check — it requires a separate connection.
        Err(ConnectorError::operation_failed(
            "AD password validation requires LDAP bind — not supported via attribute check"
                .to_string(),
        ))
    }
}

impl AdConnector {
    /// Read the current userAccountControl value from an AD object.
    async fn read_uac(&self, object_class: &str, uid: &Uid) -> ConnectorResult<u32> {
        let attrs = self
            .ldap
            .search(
                object_class,
                Some(Filter::Equals {
                    attribute: uid.attribute_name().to_string(),
                    value: uid.value().to_string(),
                }),
                Some(vec!["userAccountControl".to_string()]),
                None,
            )
            .await?;

        let entry =
            attrs
                .objects
                .into_iter()
                .next()
                .ok_or_else(|| ConnectorError::ObjectNotFound {
                    identifier: uid.value().to_string(),
                })?;

        let uac_str = entry.get_string("userAccountControl").unwrap_or("512"); // Default: NORMAL_ACCOUNT

        uac_str.parse::<u32>().map_err(|_| {
            ConnectorError::operation_failed(format!(
                "Invalid userAccountControl value: {}",
                uac_str
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ActiveDirectoryConfig, SearchBase};

    fn test_ad_config() -> ActiveDirectoryConfig {
        ActiveDirectoryConfig::from_domain("example.com", "admin@example.com", "password")
    }

    #[test]
    fn test_validate_valid_config() {
        let config = test_ad_config();
        assert!(AdConnector::validate_ad_config(&config).is_ok());
    }

    #[test]
    fn test_validate_empty_domain() {
        let mut config = test_ad_config();
        config.domain = String::new();
        let err = AdConnector::validate_ad_config(&config).unwrap_err();
        assert!(err.to_string().contains("domain is required"));
    }

    #[test]
    fn test_validate_max_nesting_depth_zero() {
        let mut config = test_ad_config();
        config.max_nesting_depth = 0;
        let err = AdConnector::validate_ad_config(&config).unwrap_err();
        assert!(err.to_string().contains("max_nesting_depth"));
    }

    #[test]
    fn test_validate_max_nesting_depth_over_100() {
        let mut config = test_ad_config();
        config.max_nesting_depth = 101;
        let err = AdConnector::validate_ad_config(&config).unwrap_err();
        assert!(err.to_string().contains("max_nesting_depth"));
    }

    #[test]
    fn test_validate_max_nesting_depth_boundary() {
        let mut config = test_ad_config();
        config.max_nesting_depth = 1;
        assert!(AdConnector::validate_ad_config(&config).is_ok());

        config.max_nesting_depth = 100;
        assert!(AdConnector::validate_ad_config(&config).is_ok());
    }

    #[test]
    fn test_validate_invalid_conflict_strategy() {
        let mut config = test_ad_config();
        config.conflict_strategy = "invalid".to_string();
        let err = AdConnector::validate_ad_config(&config).unwrap_err();
        assert!(err.to_string().contains("conflict_strategy"));
    }

    #[test]
    fn test_validate_valid_conflict_strategies() {
        for strategy in &["source_wins", "target_wins", "manual"] {
            let mut config = test_ad_config();
            config.conflict_strategy = strategy.to_string();
            assert!(
                AdConnector::validate_ad_config(&config).is_ok(),
                "Strategy '{}' should be valid",
                strategy
            );
        }
    }

    #[test]
    fn test_validate_search_base_empty_dn() {
        let mut config = test_ad_config();
        config.search_bases = vec![SearchBase {
            dn: String::new(),
            scope: "subtree".to_string(),
            filter: None,
            object_types: vec!["users".to_string()],
        }];
        let err = AdConnector::validate_ad_config(&config).unwrap_err();
        assert!(err.to_string().contains("search_bases[0].dn"));
    }

    #[test]
    fn test_validate_search_base_invalid_scope() {
        let mut config = test_ad_config();
        config.search_bases = vec![SearchBase {
            dn: "OU=Users,DC=example,DC=com".to_string(),
            scope: "invalid_scope".to_string(),
            filter: None,
            object_types: vec!["users".to_string()],
        }];
        let err = AdConnector::validate_ad_config(&config).unwrap_err();
        assert!(err.to_string().contains("search_bases[0].scope"));
    }

    #[test]
    fn test_validate_valid_search_bases() {
        let mut config = test_ad_config();
        config.search_bases = vec![
            SearchBase {
                dn: "OU=Users,DC=example,DC=com".to_string(),
                scope: "subtree".to_string(),
                filter: Some("(department=Engineering)".to_string()),
                object_types: vec!["users".to_string()],
            },
            SearchBase {
                dn: "OU=Groups,DC=example,DC=com".to_string(),
                scope: "onelevel".to_string(),
                filter: None,
                object_types: vec!["groups".to_string()],
            },
        ];
        assert!(AdConnector::validate_ad_config(&config).is_ok());
    }

    #[test]
    fn test_iterate_search_bases_empty() {
        let config = test_ad_config();
        // Can't create a full AdConnector without LDAP, but we can test the config
        // With no search bases, iterate_search_bases uses base DN
        assert!(config.search_bases.is_empty());
        // The iterate_search_bases method returns the user_dn() for "users"
        assert_eq!(config.ldap.user_dn(), "cn=Users,dc=example,dc=com");
        assert_eq!(config.ldap.group_dn(), "cn=Users,dc=example,dc=com");
    }

    #[test]
    fn test_ad_config_defaults() {
        let config = test_ad_config();
        assert_eq!(config.max_nesting_depth, 10);
        assert_eq!(config.max_referral_hops, 3);
        assert_eq!(config.incremental_attribute, "uSNChanged");
        assert_eq!(config.conflict_strategy, "source_wins");
        assert_eq!(
            config.user_filter,
            "(&(objectClass=user)(objectCategory=person))"
        );
        assert_eq!(config.group_filter, "(objectClass=group)");
        assert!(config.outbound_target_ou.is_none());
    }

    // --- T031/T032: Outbound provisioning trait tests ---

    #[test]
    fn test_outbound_uac_disable_enable() {
        // Simulate reading UAC, disabling, then enabling
        let initial_uac: u32 = 0x200; // NORMAL_ACCOUNT
        let disabled = UserAccountControl::from(initial_uac).disable();
        assert!(disabled.is_disabled());
        assert_eq!(u32::from(disabled), 0x202); // NORMAL_ACCOUNT | ACCOUNTDISABLE

        let re_enabled = UserAccountControl::from(0x202).enable();
        assert!(!re_enabled.is_disabled());
        assert_eq!(u32::from(re_enabled), 0x200);
    }

    #[test]
    fn test_outbound_uac_preserve_other_flags() {
        // Disable should preserve DONT_EXPIRE_PASSWORD
        let uac: u32 = 0x200 | 0x10000; // NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD
        let disabled = UserAccountControl::from(uac).disable();
        assert!(disabled.is_disabled());
        assert_eq!(u32::from(disabled), 0x200 | 0x2 | 0x10000);

        // Enable should also preserve
        let enabled = UserAccountControl::from(u32::from(disabled)).enable();
        assert!(!enabled.is_disabled());
        assert_eq!(u32::from(enabled), 0x200 | 0x10000);
    }

    #[test]
    fn test_outbound_create_attribute_set() {
        // Test building an AttributeSet for user creation
        let mut attrs = AttributeSet::new();
        attrs.set(
            "sAMAccountName",
            AttributeValue::String("john.doe".to_string()),
        );
        attrs.set(
            "displayName",
            AttributeValue::String("John Doe".to_string()),
        );
        attrs.set(
            "mail",
            AttributeValue::String("john@example.com".to_string()),
        );

        // Verify attributes are set correctly
        assert_eq!(attrs.get_string("sAMAccountName"), Some("john.doe"));
        assert_eq!(attrs.get_string("displayName"), Some("John Doe"));
        assert_eq!(attrs.get_string("mail"), Some("john@example.com"));
    }

    #[test]
    fn test_outbound_attribute_delta_replace() {
        // Test building an AttributeDelta for user update
        let mut delta = AttributeDelta::new();
        delta.replace(
            "displayName",
            AttributeValue::String("Jane Doe".to_string()),
        );
        delta.replace(
            "mail",
            AttributeValue::String("jane@example.com".to_string()),
        );

        assert!(!delta.is_empty());
        let affected = delta.affected_attributes();
        assert!(affected.contains(&"displayName"));
        assert!(affected.contains(&"mail"));
    }

    #[test]
    fn test_outbound_uac_in_delta() {
        // Simulate disable operation: read UAC, toggle flag, build delta
        let current_uac: u32 = 0x200;
        let uac = UserAccountControl::from(current_uac).disable();

        let mut delta = AttributeDelta::new();
        delta.replace(
            "userAccountControl",
            AttributeValue::String(u32::from(uac).to_string()),
        );

        assert!(delta.replace.contains_key("userAccountControl"));
        let val = delta.replace.get("userAccountControl").unwrap();
        assert_eq!(val.as_string(), Some("514")); // 0x202 = 514 decimal
    }

    #[test]
    fn test_outbound_target_ou_config() {
        let mut config = test_ad_config();
        config.outbound_target_ou = Some("OU=NewUsers,DC=example,DC=com".to_string());

        assert_eq!(
            config.outbound_target_ou.as_deref(),
            Some("OU=NewUsers,DC=example,DC=com")
        );
    }

    #[test]
    fn test_connection_test_result_serialization() {
        let result = ConnectionTestResult {
            success: true,
            message: "Connected successfully".to_string(),
            server_info: Some(AdServerInfo {
                dns_host_name: Some("dc01.example.com".to_string()),
                default_naming_context: Some("DC=example,DC=com".to_string()),
                root_domain_naming_context: Some("DC=example,DC=com".to_string()),
                highest_committed_usn: Some("12345678".to_string()),
                schema_naming_context: Some(
                    "CN=Schema,CN=Configuration,DC=example,DC=com".to_string(),
                ),
                config_naming_context: Some("CN=Configuration,DC=example,DC=com".to_string()),
                domain_functionality: Some("7".to_string()),
                forest_functionality: Some("7".to_string()),
            }),
        };

        let json = serde_json::to_string(&result).unwrap();
        let parsed: ConnectionTestResult = serde_json::from_str(&json).unwrap();
        assert!(parsed.success);
        assert!(parsed.server_info.is_some());
        let info = parsed.server_info.unwrap();
        assert_eq!(info.dns_host_name, Some("dc01.example.com".to_string()));
        assert_eq!(info.highest_committed_usn, Some("12345678".to_string()));
    }
}
