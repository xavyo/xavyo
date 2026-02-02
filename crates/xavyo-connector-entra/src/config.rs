//! Configuration types for the Entra ID connector.

use serde::{Deserialize, Serialize};

/// Microsoft cloud environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntraCloudEnvironment {
    /// Microsoft Azure Commercial (global).
    #[default]
    Commercial,
    /// Microsoft Azure US Government.
    UsGovernment,
    /// Microsoft Azure China (operated by 21Vianet).
    China,
    /// Microsoft Azure Germany (deprecated but still supported).
    Germany,
}

impl EntraCloudEnvironment {
    /// Returns the OAuth2 login endpoint for this cloud environment.
    pub fn login_endpoint(&self) -> &'static str {
        match self {
            Self::Commercial => "https://login.microsoftonline.com",
            Self::UsGovernment => "https://login.microsoftonline.us",
            Self::China => "https://login.chinacloudapi.cn",
            Self::Germany => "https://login.microsoftonline.de",
        }
    }

    /// Returns the Microsoft Graph API endpoint for this cloud environment.
    pub fn graph_endpoint(&self) -> &'static str {
        match self {
            Self::Commercial => "https://graph.microsoft.com",
            Self::UsGovernment => "https://graph.microsoft.us",
            Self::China => "https://microsoftgraph.chinacloudapi.cn",
            Self::Germany => "https://graph.microsoft.de",
        }
    }
}

/// Conflict resolution strategy when source and platform have different values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntraConflictStrategy {
    /// Source (Entra) always wins.
    #[default]
    SourceWins,
    /// Platform (xavyo) always wins.
    PlatformWins,
    /// Flag conflicts for manual review.
    FlagForReview,
}

/// Credentials for authenticating with Entra ID.
#[derive(Clone, Serialize, Deserialize)]
pub struct EntraCredentials {
    /// Azure AD application (client) ID.
    pub client_id: String,
    /// Azure AD application client secret.
    #[serde(skip_serializing)]
    pub client_secret: secrecy::SecretString,
}

impl std::fmt::Debug for EntraCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntraCredentials")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .finish()
    }
}

/// Configuration for the Entra ID connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntraConfig {
    /// Azure AD tenant ID (directory ID).
    pub tenant_id: String,
    /// Cloud environment (commercial, US gov, China, Germany).
    #[serde(default)]
    pub cloud_environment: EntraCloudEnvironment,
    /// Graph API version (default: v1.0).
    #[serde(default = "default_graph_api_version")]
    pub graph_api_version: String,
    /// OData filter for users (optional).
    pub user_filter: Option<String>,
    /// OData filter for groups (optional).
    pub group_filter: Option<String>,
    /// Whether to sync groups.
    #[serde(default = "default_true")]
    pub sync_groups: bool,
    /// Whether to sync directory roles.
    #[serde(default)]
    pub sync_directory_roles: bool,
    /// Whether to sync licenses.
    #[serde(default)]
    pub sync_licenses: bool,
    /// Whether to sync application roles.
    #[serde(default)]
    pub sync_app_roles: bool,
    /// Whether to resolve transitive group members.
    #[serde(default)]
    pub resolve_transitive_members: bool,
    /// Page size for Graph API requests (default: 999, max: 999).
    #[serde(default = "default_page_size")]
    pub page_size: u32,
    /// Conflict resolution strategy.
    #[serde(default)]
    pub conflict_strategy: EntraConflictStrategy,
    /// Stored delta link for incremental user sync.
    pub delta_link_user: Option<String>,
    /// Stored delta link for incremental group sync.
    pub delta_link_group: Option<String>,
}

fn default_graph_api_version() -> String {
    "v1.0".to_string()
}

fn default_true() -> bool {
    true
}

fn default_page_size() -> u32 {
    999
}

impl EntraConfig {
    /// Creates a new configuration builder.
    pub fn builder() -> EntraConfigBuilder {
        EntraConfigBuilder::default()
    }

    /// Validates the configuration.
    pub fn validate(&self) -> Result<(), crate::EntraError> {
        if self.tenant_id.is_empty() {
            return Err(crate::EntraError::Config("tenant_id is required".into()));
        }
        if self.page_size == 0 || self.page_size > 999 {
            return Err(crate::EntraError::Config(
                "page_size must be between 1 and 999".into(),
            ));
        }
        Ok(())
    }
}

/// Builder for EntraConfig.
#[derive(Debug, Default)]
pub struct EntraConfigBuilder {
    tenant_id: Option<String>,
    cloud_environment: EntraCloudEnvironment,
    graph_api_version: String,
    user_filter: Option<String>,
    group_filter: Option<String>,
    sync_groups: bool,
    sync_directory_roles: bool,
    sync_licenses: bool,
    sync_app_roles: bool,
    resolve_transitive_members: bool,
    page_size: u32,
    conflict_strategy: EntraConflictStrategy,
}

impl EntraConfigBuilder {
    /// Sets the Azure AD tenant ID.
    pub fn tenant_id(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Sets the cloud environment.
    pub fn cloud_environment(mut self, env: EntraCloudEnvironment) -> Self {
        self.cloud_environment = env;
        self
    }

    /// Sets the user OData filter.
    pub fn user_filter(mut self, filter: impl Into<String>) -> Self {
        self.user_filter = Some(filter.into());
        self
    }

    /// Sets the group OData filter.
    pub fn group_filter(mut self, filter: impl Into<String>) -> Self {
        self.group_filter = Some(filter.into());
        self
    }

    /// Enables or disables group sync.
    pub fn sync_groups(mut self, sync: bool) -> Self {
        self.sync_groups = sync;
        self
    }

    /// Enables or disables directory role sync.
    pub fn sync_directory_roles(mut self, sync: bool) -> Self {
        self.sync_directory_roles = sync;
        self
    }

    /// Sets the page size for API requests.
    pub fn page_size(mut self, size: u32) -> Self {
        self.page_size = size;
        self
    }

    /// Sets the conflict resolution strategy.
    pub fn conflict_strategy(mut self, strategy: EntraConflictStrategy) -> Self {
        self.conflict_strategy = strategy;
        self
    }

    /// Enables transitive member resolution.
    pub fn resolve_transitive_members(mut self, resolve: bool) -> Self {
        self.resolve_transitive_members = resolve;
        self
    }

    /// Builds the configuration.
    pub fn build(self) -> Result<EntraConfig, crate::EntraError> {
        let config = EntraConfig {
            tenant_id: self
                .tenant_id
                .ok_or_else(|| crate::EntraError::Config("tenant_id is required".into()))?,
            cloud_environment: self.cloud_environment,
            graph_api_version: if self.graph_api_version.is_empty() {
                default_graph_api_version()
            } else {
                self.graph_api_version
            },
            user_filter: self.user_filter,
            group_filter: self.group_filter,
            sync_groups: self.sync_groups,
            sync_directory_roles: self.sync_directory_roles,
            sync_licenses: self.sync_licenses,
            sync_app_roles: self.sync_app_roles,
            resolve_transitive_members: self.resolve_transitive_members,
            page_size: if self.page_size == 0 {
                default_page_size()
            } else {
                self.page_size
            },
            conflict_strategy: self.conflict_strategy,
            delta_link_user: None,
            delta_link_group: None,
        };
        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloud_environment_endpoints() {
        assert_eq!(
            EntraCloudEnvironment::Commercial.login_endpoint(),
            "https://login.microsoftonline.com"
        );
        assert_eq!(
            EntraCloudEnvironment::Commercial.graph_endpoint(),
            "https://graph.microsoft.com"
        );
        assert_eq!(
            EntraCloudEnvironment::UsGovernment.login_endpoint(),
            "https://login.microsoftonline.us"
        );
        assert_eq!(
            EntraCloudEnvironment::UsGovernment.graph_endpoint(),
            "https://graph.microsoft.us"
        );
    }

    #[test]
    fn test_config_builder_valid() {
        let config = EntraConfig::builder()
            .tenant_id("test-tenant")
            .build()
            .unwrap();

        assert_eq!(config.tenant_id, "test-tenant");
        assert_eq!(config.cloud_environment, EntraCloudEnvironment::Commercial);
        assert_eq!(config.graph_api_version, "v1.0");
        assert_eq!(config.page_size, 999);
    }

    #[test]
    fn test_config_builder_missing_tenant() {
        let result = EntraConfig::builder().build();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validation_invalid_page_size() {
        let config = EntraConfig {
            tenant_id: "test".to_string(),
            cloud_environment: EntraCloudEnvironment::Commercial,
            graph_api_version: "v1.0".to_string(),
            user_filter: None,
            group_filter: None,
            sync_groups: true,
            sync_directory_roles: false,
            sync_licenses: false,
            sync_app_roles: false,
            resolve_transitive_members: false,
            page_size: 1000, // Invalid: > 999
            conflict_strategy: EntraConflictStrategy::SourceWins,
            delta_link_user: None,
            delta_link_group: None,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_credentials_debug_redacts_secret() {
        let creds = EntraCredentials {
            client_id: "my-client-id".to_string(),
            client_secret: secrecy::SecretString::from("super-secret".to_string()),
        };
        let debug_str = format!("{:?}", creds);
        assert!(debug_str.contains("my-client-id"));
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("super-secret"));
    }
}
