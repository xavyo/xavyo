//! Configuration for tenant middleware.
//!
//! Provides a builder pattern for customizing middleware behavior.

/// Configuration options for the tenant middleware.
///
/// # Example
///
/// ```rust
/// use xavyo_tenant::TenantConfig;
///
/// let config = TenantConfig::builder()
///     .header_name("X-Tenant-ID")
///     .jwt_claim_name("tid")
///     .require_tenant(true)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct TenantConfig {
    /// HTTP header name to check for tenant ID.
    ///
    /// Default: "X-Tenant-ID"
    pub header_name: String,

    /// JWT claim name containing the tenant ID.
    ///
    /// Default: "tid"
    pub jwt_claim_name: String,

    /// Whether to require a valid tenant context.
    ///
    /// If true, requests without valid tenant context receive 401.
    /// If false, requests proceed with None in extensions.
    ///
    /// Default: true
    pub require_tenant: bool,
}

impl Default for TenantConfig {
    fn default() -> Self {
        Self {
            header_name: "X-Tenant-ID".to_string(),
            jwt_claim_name: "tid".to_string(),
            require_tenant: true,
        }
    }
}

impl TenantConfig {
    /// Create a new config builder.
    #[must_use]
    pub fn builder() -> TenantConfigBuilder {
        TenantConfigBuilder::default()
    }
}

/// Builder for TenantConfig.
#[derive(Debug, Clone, Default)]
pub struct TenantConfigBuilder {
    header_name: Option<String>,
    jwt_claim_name: Option<String>,
    require_tenant: Option<bool>,
}

impl TenantConfigBuilder {
    /// Set the HTTP header name for tenant ID extraction.
    #[must_use]
    pub fn header_name(mut self, name: impl Into<String>) -> Self {
        self.header_name = Some(name.into());
        self
    }

    /// Set the JWT claim name for tenant ID extraction.
    #[must_use]
    pub fn jwt_claim_name(mut self, name: impl Into<String>) -> Self {
        self.jwt_claim_name = Some(name.into());
        self
    }

    /// Set whether tenant context is required.
    #[must_use]
    pub fn require_tenant(mut self, required: bool) -> Self {
        self.require_tenant = Some(required);
        self
    }

    /// Build the configuration.
    #[must_use]
    pub fn build(self) -> TenantConfig {
        let default = TenantConfig::default();
        TenantConfig {
            header_name: self.header_name.unwrap_or(default.header_name),
            jwt_claim_name: self.jwt_claim_name.unwrap_or(default.jwt_claim_name),
            require_tenant: self.require_tenant.unwrap_or(default.require_tenant),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TenantConfig::default();
        assert_eq!(config.header_name, "X-Tenant-ID");
        assert_eq!(config.jwt_claim_name, "tid");
        assert!(config.require_tenant);
    }

    #[test]
    fn test_builder_custom_header() {
        let config = TenantConfig::builder()
            .header_name("X-Custom-Tenant")
            .build();
        assert_eq!(config.header_name, "X-Custom-Tenant");
        assert_eq!(config.jwt_claim_name, "tid"); // default
    }

    #[test]
    fn test_builder_all_options() {
        let config = TenantConfig::builder()
            .header_name("X-Org-ID")
            .jwt_claim_name("org_id")
            .require_tenant(false)
            .build();

        assert_eq!(config.header_name, "X-Org-ID");
        assert_eq!(config.jwt_claim_name, "org_id");
        assert!(!config.require_tenant);
    }
}
