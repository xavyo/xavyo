//! Path-based routing logic for backend services.

use std::sync::Arc;

use crate::config::{BackendConfig, GatewayConfig};

/// Router for matching request paths to backend services.
#[derive(Debug, Clone)]
pub struct BackendRouter {
    backends: Vec<BackendConfig>,
}

impl BackendRouter {
    /// Create a new router from gateway configuration.
    pub fn new(config: Arc<GatewayConfig>) -> Self {
        // Sort backends by path prefix length (longest first) for correct matching
        let mut backends = config.backends.clone();
        backends.sort_by(|a, b| b.path_prefix.len().cmp(&a.path_prefix.len()));

        Self { backends }
    }

    /// Find the backend that matches the given path.
    pub fn find_backend(&self, path: &str) -> Option<&BackendConfig> {
        self.backends
            .iter()
            .find(|b| path.starts_with(&b.path_prefix))
    }

    /// Build the target URL for a request.
    pub fn build_target_url(
        &self,
        backend: &BackendConfig,
        path: &str,
        query: Option<&str>,
    ) -> String {
        let target_path = if backend.strip_prefix {
            path.strip_prefix(&backend.path_prefix).unwrap_or(path)
        } else {
            path
        };

        // Ensure path starts with /
        let target_path = if target_path.starts_with('/') {
            target_path.to_string()
        } else {
            format!("/{}", target_path)
        };

        // Build full URL
        let base_url = backend.url.trim_end_matches('/');
        match query {
            Some(q) if !q.is_empty() => format!("{}{}?{}", base_url, target_path, q),
            _ => format!("{}{}", base_url, target_path),
        }
    }

    /// Get all backends for health checks.
    pub fn all_backends(&self) -> &[BackendConfig] {
        &self.backends
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> Arc<GatewayConfig> {
        let yaml = r#"
server:
  port: 8080

backends:
  - name: idp-api
    path_prefix: /idp
    url: http://localhost:8081
    strip_prefix: true
  - name: crm-api
    path_prefix: /crm
    url: http://localhost:8082
    strip_prefix: true
  - name: idp-admin
    path_prefix: /idp/admin
    url: http://localhost:8083
    strip_prefix: true

rate_limits:
  enabled: true

auth:
  public_key_path: ./jwt.pem
  issuer: https://example.com
  audience: test
"#;
        Arc::new(crate::config::GatewayConfig::from_yaml(yaml).unwrap())
    }

    #[test]
    fn test_find_backend() {
        let config = create_test_config();
        let router = BackendRouter::new(config);

        // Should match idp-api
        let backend = router.find_backend("/idp/users");
        assert!(backend.is_some());
        assert_eq!(backend.unwrap().name, "idp-api");

        // Should match crm-api
        let backend = router.find_backend("/crm/contacts");
        assert!(backend.is_some());
        assert_eq!(backend.unwrap().name, "crm-api");

        // Should match idp-admin (longer prefix takes precedence)
        let backend = router.find_backend("/idp/admin/settings");
        assert!(backend.is_some());
        assert_eq!(backend.unwrap().name, "idp-admin");

        // No match
        let backend = router.find_backend("/unknown/path");
        assert!(backend.is_none());
    }

    #[test]
    fn test_build_target_url_with_strip_prefix() {
        let config = create_test_config();
        let router = BackendRouter::new(config);

        let backend = router.find_backend("/idp/users").unwrap();

        // Strip prefix
        let url = router.build_target_url(backend, "/idp/users", None);
        assert_eq!(url, "http://localhost:8081/users");

        // With query string
        let url = router.build_target_url(backend, "/idp/users", Some("page=1&limit=10"));
        assert_eq!(url, "http://localhost:8081/users?page=1&limit=10");
    }

    #[test]
    fn test_build_target_url_without_strip_prefix() {
        let yaml = r#"
server:
  port: 8080

backends:
  - name: passthrough
    path_prefix: /api
    url: http://localhost:9000
    strip_prefix: false

rate_limits:
  enabled: true

auth:
  public_key_path: ./jwt.pem
  issuer: https://example.com
  audience: test
"#;
        let config = Arc::new(crate::config::GatewayConfig::from_yaml(yaml).unwrap());
        let router = BackendRouter::new(config);

        let backend = router.find_backend("/api/v1/users").unwrap();

        // Keep prefix
        let url = router.build_target_url(backend, "/api/v1/users", None);
        assert_eq!(url, "http://localhost:9000/api/v1/users");
    }

    #[test]
    fn test_all_backends() {
        let config = create_test_config();
        let router = BackendRouter::new(config);

        assert_eq!(router.all_backends().len(), 3);
    }
}
