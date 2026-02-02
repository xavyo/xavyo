//! Tower Layer implementation for tenant middleware.
//!
//! Provides `TenantLayer` for adding tenant context extraction to services.

use crate::config::TenantConfig;
use crate::service::TenantService;
use std::sync::Arc;
use tower_layer::Layer;

/// Tower Layer for tenant context extraction.
///
/// This layer wraps services to automatically extract and validate
/// tenant context from incoming requests.
///
/// # Example
///
/// ```rust,ignore
/// use xavyo_tenant::TenantLayer;
/// use axum::Router;
/// use tower::ServiceBuilder;
///
/// let app = Router::new()
///     .route("/api/users", get(list_users))
///     .layer(TenantLayer::new());
///
/// // Or with ServiceBuilder
/// let app = Router::new()
///     .route("/api/users", get(list_users))
///     .layer(
///         ServiceBuilder::new()
///             .layer(TenantLayer::new())
///     );
/// ```
#[derive(Debug, Clone)]
pub struct TenantLayer {
    config: Arc<TenantConfig>,
}

impl TenantLayer {
    /// Create a new TenantLayer with default configuration.
    ///
    /// Default configuration:
    /// - Header name: "X-Tenant-ID"
    /// - JWT claim name: "tid"
    /// - Require tenant: true
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(TenantConfig::default())
    }

    /// Create a new TenantLayer with custom configuration.
    ///
    /// # Example
    ///
    /// ```rust
    /// use xavyo_tenant::{TenantLayer, TenantConfig};
    ///
    /// let config = TenantConfig::builder()
    ///     .header_name("X-Organization-ID")
    ///     .require_tenant(true)
    ///     .build();
    ///
    /// let layer = TenantLayer::with_config(config);
    /// ```
    #[must_use]
    pub fn with_config(config: TenantConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// Get the configuration.
    #[must_use]
    pub fn config(&self) -> &TenantConfig {
        &self.config
    }
}

impl Default for TenantLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for TenantLayer {
    type Service = TenantService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TenantService::new(inner, Arc::clone(&self.config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_layer_new() {
        let layer = TenantLayer::new();
        assert_eq!(layer.config().header_name, "X-Tenant-ID");
        assert!(layer.config().require_tenant);
    }

    #[test]
    fn test_tenant_layer_with_config() {
        let config = TenantConfig::builder()
            .header_name("X-Custom")
            .require_tenant(false)
            .build();

        let layer = TenantLayer::with_config(config);
        assert_eq!(layer.config().header_name, "X-Custom");
        assert!(!layer.config().require_tenant);
    }

    #[test]
    fn test_tenant_layer_default() {
        let layer = TenantLayer::default();
        assert_eq!(layer.config().header_name, "X-Tenant-ID");
    }

    #[test]
    fn test_tenant_layer_clone() {
        let layer = TenantLayer::new();
        let cloned = layer.clone();
        assert_eq!(layer.config().header_name, cloned.config().header_name);
    }
}
