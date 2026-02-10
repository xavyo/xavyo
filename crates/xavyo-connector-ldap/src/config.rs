//! LDAP Connector configuration
//!
//! Configuration types for LDAP/Active Directory connections.

use serde::{Deserialize, Serialize};
use xavyo_connector::config::{ConnectionSettings, ConnectorConfig, TlsConfig};
use xavyo_connector::error::{ConnectorError, ConnectorResult};
use xavyo_connector::types::ConnectorType;

/// Configuration for LDAP connector.
#[derive(Clone, Serialize, Deserialize)]
pub struct LdapConfig {
    /// LDAP server hostname or IP address.
    pub host: String,

    /// LDAP server port (389 for LDAP, 636 for LDAPS).
    #[serde(default = "default_ldap_port")]
    pub port: u16,

    /// Use SSL/TLS (LDAPS).
    #[serde(default)]
    pub use_ssl: bool,

    /// Use STARTTLS upgrade on plain LDAP connection.
    #[serde(default)]
    pub use_starttls: bool,

    /// Base DN for all operations (e.g., "dc=example,dc=com").
    pub base_dn: String,

    /// Bind DN for authentication (e.g., "cn=admin,dc=example,dc=com").
    pub bind_dn: String,

    /// Bind password (stored encrypted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_password: Option<String>,

    /// Follow LDAP referrals.
    #[serde(default)]
    pub follow_referrals: bool,

    /// Connection settings (timeouts, pool size).
    #[serde(default)]
    pub connection: ConnectionSettings,

    /// TLS configuration.
    #[serde(default)]
    pub tls: TlsConfig,

    /// User container DN (e.g., "ou=users" - relative to `base_dn`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_container: Option<String>,

    /// Group container DN (e.g., "ou=groups" - relative to `base_dn`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_container: Option<String>,

    /// Default user object class(es).
    #[serde(default = "default_user_object_classes")]
    pub user_object_classes: Vec<String>,

    /// Default group object class(es).
    #[serde(default = "default_group_object_classes")]
    pub group_object_classes: Vec<String>,

    /// Attribute used as the unique identifier.
    #[serde(default = "default_uid_attribute")]
    pub uid_attribute: String,

    /// Page size for search operations.
    #[serde(default = "default_page_size")]
    pub page_size: u32,
}

impl std::fmt::Debug for LdapConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LdapConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("use_ssl", &self.use_ssl)
            .field("use_starttls", &self.use_starttls)
            .field("base_dn", &self.base_dn)
            .field("bind_dn", &self.bind_dn)
            .field(
                "bind_password",
                &self.bind_password.as_ref().map(|_| "***REDACTED***"),
            )
            .field("follow_referrals", &self.follow_referrals)
            .field("connection", &self.connection)
            .field("tls", &self.tls)
            .field("user_container", &self.user_container)
            .field("group_container", &self.group_container)
            .field("user_object_classes", &self.user_object_classes)
            .field("group_object_classes", &self.group_object_classes)
            .field("uid_attribute", &self.uid_attribute)
            .field("page_size", &self.page_size)
            .finish()
    }
}

fn default_ldap_port() -> u16 {
    389
}

fn default_user_object_classes() -> Vec<String> {
    vec![
        "top".to_string(),
        "person".to_string(),
        "organizationalPerson".to_string(),
        "inetOrgPerson".to_string(),
    ]
}

fn default_group_object_classes() -> Vec<String> {
    vec!["top".to_string(), "groupOfNames".to_string()]
}

fn default_uid_attribute() -> String {
    "entryUUID".to_string()
}

fn default_page_size() -> u32 {
    1000
}

impl LdapConfig {
    /// Create a new LDAP config with required fields.
    pub fn new(
        host: impl Into<String>,
        base_dn: impl Into<String>,
        bind_dn: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            port: default_ldap_port(),
            use_ssl: false,
            use_starttls: false,
            base_dn: base_dn.into(),
            bind_dn: bind_dn.into(),
            bind_password: None,
            follow_referrals: false,
            connection: ConnectionSettings::default(),
            tls: TlsConfig::default(),
            user_container: None,
            group_container: None,
            user_object_classes: default_user_object_classes(),
            group_object_classes: default_group_object_classes(),
            uid_attribute: default_uid_attribute(),
            page_size: default_page_size(),
        }
    }

    /// Set bind password.
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.bind_password = Some(password.into());
        self
    }

    /// Enable SSL (LDAPS).
    #[must_use]
    pub fn with_ssl(mut self) -> Self {
        self.use_ssl = true;
        self.port = 636;
        self.tls.enabled = true;
        self
    }

    /// Enable STARTTLS.
    #[must_use]
    pub fn with_starttls(mut self) -> Self {
        self.use_starttls = true;
        self
    }

    /// Set user container.
    pub fn with_user_container(mut self, container: impl Into<String>) -> Self {
        self.user_container = Some(container.into());
        self
    }

    /// Set group container.
    pub fn with_group_container(mut self, container: impl Into<String>) -> Self {
        self.group_container = Some(container.into());
        self
    }

    /// Get the full user container DN.
    #[must_use]
    pub fn user_dn(&self) -> String {
        match &self.user_container {
            Some(container) => format!("{},{}", container, self.base_dn),
            None => self.base_dn.clone(),
        }
    }

    /// Get the full group container DN.
    #[must_use]
    pub fn group_dn(&self) -> String {
        match &self.group_container {
            Some(container) => format!("{},{}", container, self.base_dn),
            None => self.base_dn.clone(),
        }
    }

    /// Get the LDAP URL.
    #[must_use]
    pub fn url(&self) -> String {
        let scheme = if self.use_ssl { "ldaps" } else { "ldap" };
        format!("{}://{}:{}", scheme, self.host, self.port)
    }

    /// SSRF protection: validate that a host does not target internal/private services.
    fn validate_host_not_internal(host: &str) -> ConnectorResult<()> {
        use std::net::IpAddr;

        if let Ok(ip) = host.parse::<IpAddr>() {
            let blocked = match ip {
                IpAddr::V4(v4) => {
                    v4.is_loopback()
                        || v4.is_private()
                        || v4.is_link_local()
                        || v4.is_broadcast()
                        || v4.is_unspecified()
                        || v4.is_documentation()
                        || v4 == std::net::Ipv4Addr::new(169, 254, 169, 254)
                }
                IpAddr::V6(v6) => {
                    v6.is_loopback()
                        || v6.is_unspecified()
                        || (v6.segments()[0] & 0xfe00) == 0xfc00
                        || (v6.segments()[0] & 0xffc0) == 0xfe80
                }
            };
            if blocked {
                return Err(ConnectorError::InvalidConfiguration {
                    message: format!("SSRF protection: internal/private IP not allowed: {host}"),
                });
            }
        } else {
            let lower = host.to_lowercase();
            let blocked_hosts = [
                "localhost",
                "metadata.google.internal",
                "metadata.goog",
                "169.254.169.254",
            ];
            for b in blocked_hosts {
                if lower == b || lower.ends_with(&format!(".{b}")) {
                    return Err(ConnectorError::InvalidConfiguration {
                        message: format!("SSRF protection: blocked hostname: {host}"),
                    });
                }
            }
        }

        Ok(())
    }
}

impl ConnectorConfig for LdapConfig {
    fn connector_type() -> ConnectorType {
        ConnectorType::Ldap
    }

    fn validate(&self) -> ConnectorResult<()> {
        if self.host.is_empty() {
            return Err(ConnectorError::InvalidConfiguration {
                message: "host is required".to_string(),
            });
        }

        // SSRF protection: reject internal/private hosts (skipped in test builds).
        #[cfg(not(test))]
        Self::validate_host_not_internal(&self.host)?;

        if self.base_dn.is_empty() {
            return Err(ConnectorError::InvalidConfiguration {
                message: "base_dn is required".to_string(),
            });
        }

        if self.bind_dn.is_empty() {
            return Err(ConnectorError::InvalidConfiguration {
                message: "bind_dn is required".to_string(),
            });
        }

        if self.use_ssl && self.use_starttls {
            return Err(ConnectorError::InvalidConfiguration {
                message: "cannot use both SSL and STARTTLS".to_string(),
            });
        }

        Ok(())
    }

    fn get_credentials(&self) -> Vec<(&'static str, String)> {
        match &self.bind_password {
            Some(password) => vec![("bind_password", password.clone())],
            None => vec![],
        }
    }

    fn redacted(&self) -> Self {
        let mut config = self.clone();
        if config.bind_password.is_some() {
            config.bind_password = Some("***REDACTED***".to_string());
        }
        config
    }
}

/// A configured search base within Active Directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchBase {
    /// Search base DN (e.g., "OU=Sales,DC=corp,DC=example,DC=com").
    pub dn: String,

    /// Search scope: "subtree" (default), "onelevel", or "base".
    #[serde(default = "default_subtree")]
    pub scope: String,

    /// Optional additional LDAP filter for this search base.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,

    /// Which object types to sync from this base: "users", "groups", or both.
    #[serde(default = "default_object_types")]
    pub object_types: Vec<String>,
}

fn default_subtree() -> String {
    "subtree".to_string()
}

fn default_object_types() -> Vec<String> {
    vec!["users".to_string(), "groups".to_string()]
}

fn default_user_filter() -> String {
    "(&(objectClass=user)(objectCategory=person))".to_string()
}

fn default_group_filter() -> String {
    "(objectClass=group)".to_string()
}

fn default_max_nesting_depth() -> u32 {
    10
}

fn default_max_referral_hops() -> u32 {
    3
}

fn default_incremental_attribute() -> String {
    "uSNChanged".to_string()
}

fn default_conflict_strategy() -> String {
    "source_wins".to_string()
}

/// Configuration specific to Active Directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveDirectoryConfig {
    /// Base LDAP configuration.
    #[serde(flatten)]
    pub ldap: LdapConfig,

    /// AD domain name (e.g., "example.com").
    pub domain: String,

    /// Use AD-specific features (userAccountControl, etc.).
    #[serde(default = "default_true")]
    pub use_ad_features: bool,

    /// Sync disabled state using userAccountControl.
    #[serde(default = "default_true")]
    pub sync_account_disabled: bool,

    /// Exchange mailbox provisioning.
    #[serde(default)]
    pub enable_exchange: bool,

    /// Multiple search bases for importing from multiple OUs.
    #[serde(default)]
    pub search_bases: Vec<SearchBase>,

    /// LDAP filter for user objects.
    #[serde(default = "default_user_filter")]
    pub user_filter: String,

    /// LDAP filter for group objects.
    #[serde(default = "default_group_filter")]
    pub group_filter: String,

    /// Maximum nested group depth for membership resolution.
    #[serde(default = "default_max_nesting_depth")]
    pub max_nesting_depth: u32,

    /// Maximum LDAP referral hops to follow.
    #[serde(default = "default_max_referral_hops")]
    pub max_referral_hops: u32,

    /// Attribute used for incremental change tracking.
    #[serde(default = "default_incremental_attribute")]
    pub incremental_attribute: String,

    /// Target OU for outbound provisioning.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound_target_ou: Option<String>,

    /// Conflict resolution strategy: "`source_wins`", "`target_wins`", "manual".
    #[serde(default = "default_conflict_strategy")]
    pub conflict_strategy: String,
}

fn default_true() -> bool {
    true
}

impl ActiveDirectoryConfig {
    /// Create a new AD config from domain name.
    ///
    /// Automatically derives `base_dn` from domain.
    #[must_use]
    pub fn from_domain(domain: &str, bind_dn: &str, bind_password: &str) -> Self {
        // Convert domain.com to dc=domain,dc=com
        let base_dn = domain
            .split('.')
            .map(|part| format!("dc={part}"))
            .collect::<Vec<_>>()
            .join(",");

        Self {
            ldap: LdapConfig::new(domain, &base_dn, bind_dn)
                .with_password(bind_password)
                .with_ssl()
                .with_user_container("cn=Users")
                .with_group_container("cn=Users"),
            domain: domain.to_string(),
            use_ad_features: true,
            sync_account_disabled: true,
            enable_exchange: false,
            search_bases: Vec::new(),
            user_filter: default_user_filter(),
            group_filter: default_group_filter(),
            max_nesting_depth: default_max_nesting_depth(),
            max_referral_hops: default_max_referral_hops(),
            incremental_attribute: default_incremental_attribute(),
            outbound_target_ou: None,
            conflict_strategy: default_conflict_strategy(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ldap_config_new() {
        let config = LdapConfig::new(
            "ldap.example.com",
            "dc=example,dc=com",
            "cn=admin,dc=example,dc=com",
        )
        .with_password("secret");

        assert_eq!(config.host, "ldap.example.com");
        assert_eq!(config.port, 389);
        assert_eq!(config.base_dn, "dc=example,dc=com");
        assert_eq!(config.bind_password, Some("secret".to_string()));
    }

    #[test]
    fn test_ldap_config_ssl() {
        let config = LdapConfig::new(
            "ldap.example.com",
            "dc=example,dc=com",
            "cn=admin,dc=example,dc=com",
        )
        .with_ssl();

        assert!(config.use_ssl);
        assert_eq!(config.port, 636);
        assert!(config.tls.enabled);
    }

    #[test]
    fn test_ldap_config_url() {
        let config = LdapConfig::new(
            "ldap.example.com",
            "dc=example,dc=com",
            "cn=admin,dc=example,dc=com",
        );
        assert_eq!(config.url(), "ldap://ldap.example.com:389");

        let ssl_config = config.with_ssl();
        assert_eq!(ssl_config.url(), "ldaps://ldap.example.com:636");
    }

    #[test]
    fn test_ldap_config_user_dn() {
        let config = LdapConfig::new(
            "ldap.example.com",
            "dc=example,dc=com",
            "cn=admin,dc=example,dc=com",
        )
        .with_user_container("ou=users");

        assert_eq!(config.user_dn(), "ou=users,dc=example,dc=com");
    }

    #[test]
    fn test_ldap_config_validation() {
        let config = LdapConfig::new(
            "ldap.example.com",
            "dc=example,dc=com",
            "cn=admin,dc=example,dc=com",
        );
        assert!(config.validate().is_ok());

        let empty_host = LdapConfig::new("", "dc=example,dc=com", "cn=admin,dc=example,dc=com");
        assert!(empty_host.validate().is_err());

        let ssl_and_starttls = LdapConfig::new(
            "ldap.example.com",
            "dc=example,dc=com",
            "cn=admin,dc=example,dc=com",
        )
        .with_ssl();
        let mut config = ssl_and_starttls;
        config.use_starttls = true;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_ldap_config_redacted() {
        let config = LdapConfig::new(
            "ldap.example.com",
            "dc=example,dc=com",
            "cn=admin,dc=example,dc=com",
        )
        .with_password("super-secret");

        let redacted = config.redacted();
        assert_eq!(redacted.bind_password, Some("***REDACTED***".to_string()));
    }

    #[test]
    fn test_ldap_config_serialization() {
        let config = LdapConfig::new(
            "ldap.example.com",
            "dc=example,dc=com",
            "cn=admin,dc=example,dc=com",
        )
        .with_password("secret")
        .with_user_container("ou=users");

        let json = serde_json::to_string(&config).unwrap();
        let parsed: LdapConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.host, "ldap.example.com");
        assert_eq!(parsed.user_container, Some("ou=users".to_string()));
    }

    #[test]
    fn test_ad_config_from_domain() {
        let config =
            ActiveDirectoryConfig::from_domain("example.com", "admin@example.com", "password");

        assert_eq!(config.ldap.base_dn, "dc=example,dc=com");
        assert_eq!(config.domain, "example.com");
        assert!(config.ldap.use_ssl);
        assert!(config.use_ad_features);
    }

    #[test]
    fn test_ssrf_blocks_localhost() {
        assert!(LdapConfig::validate_host_not_internal("localhost").is_err());
    }

    #[test]
    fn test_ssrf_blocks_private_ip() {
        assert!(LdapConfig::validate_host_not_internal("127.0.0.1").is_err());
        assert!(LdapConfig::validate_host_not_internal("10.0.0.1").is_err());
        assert!(LdapConfig::validate_host_not_internal("192.168.1.1").is_err());
        assert!(LdapConfig::validate_host_not_internal("169.254.169.254").is_err());
    }

    #[test]
    fn test_ssrf_blocks_metadata_hosts() {
        assert!(LdapConfig::validate_host_not_internal("metadata.google.internal").is_err());
        assert!(LdapConfig::validate_host_not_internal("metadata.goog").is_err());
    }

    #[test]
    fn test_ssrf_allows_public_hosts() {
        assert!(LdapConfig::validate_host_not_internal("ldap.example.com").is_ok());
        assert!(LdapConfig::validate_host_not_internal("8.8.8.8").is_ok());
    }
}
