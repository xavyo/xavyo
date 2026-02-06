//! Connector Framework registry
//!
//! Factory pattern for managing connector instances.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::{ConnectorError, ConnectorResult};
use crate::ids::ConnectorId;
use crate::traits::Connector;
use crate::types::ConnectorType;

/// Type alias for a boxed connector.
pub type BoxedConnector = Box<dyn Connector>;

/// Factory function for creating connectors.
pub type ConnectorFactory =
    Box<dyn Fn(serde_json::Value) -> ConnectorResult<BoxedConnector> + Send + Sync>;

/// Registry for managing connector factories and instances.
///
/// The registry provides:
/// - Factory registration for each connector type
/// - Instance caching and lifecycle management
/// - Thread-safe access to connectors
pub struct ConnectorRegistry {
    /// Registered connector factories by type.
    factories: RwLock<HashMap<ConnectorType, ConnectorFactory>>,

    /// Cached connector instances by ID.
    instances: RwLock<HashMap<ConnectorId, Arc<BoxedConnector>>>,
}

impl ConnectorRegistry {
    /// Create a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            factories: RwLock::new(HashMap::new()),
            instances: RwLock::new(HashMap::new()),
        }
    }

    /// Register a factory for a connector type.
    ///
    /// # Arguments
    /// * `connector_type` - The type of connector this factory creates.
    /// * `factory` - Function that creates connector instances from JSON config.
    pub async fn register_factory(&self, connector_type: ConnectorType, factory: ConnectorFactory) {
        let mut factories = self.factories.write().await;
        factories.insert(connector_type, factory);
    }

    /// Create a connector instance using the registered factory.
    ///
    /// This creates a new instance but does NOT cache it.
    /// Use `get_or_create` for cached access.
    ///
    /// # Arguments
    /// * `connector_type` - The type of connector to create.
    /// * `config` - JSON configuration for the connector.
    pub async fn create(
        &self,
        connector_type: ConnectorType,
        config: serde_json::Value,
    ) -> ConnectorResult<BoxedConnector> {
        let factories = self.factories.read().await;
        let factory = factories.get(&connector_type).ok_or_else(|| {
            ConnectorError::UnsupportedConnectorType {
                connector_type: connector_type.to_string(),
            }
        })?;

        factory(config)
    }

    /// Get a cached connector instance or create a new one.
    ///
    /// # Arguments
    /// * `id` - The connector configuration ID.
    /// * `connector_type` - The type of connector.
    /// * `config` - JSON configuration (only used if creating new instance).
    pub async fn get_or_create(
        &self,
        id: ConnectorId,
        connector_type: ConnectorType,
        config: serde_json::Value,
    ) -> ConnectorResult<Arc<BoxedConnector>> {
        // First, try to get from cache
        {
            let instances = self.instances.read().await;
            if let Some(connector) = instances.get(&id) {
                return Ok(Arc::clone(connector));
            }
        }

        // Create new instance
        let connector = self.create(connector_type, config).await?;
        let connector = Arc::new(connector);

        // Cache and return
        {
            let mut instances = self.instances.write().await;
            // Check again in case another task created it
            if let Some(existing) = instances.get(&id) {
                return Ok(Arc::clone(existing));
            }
            instances.insert(id, Arc::clone(&connector));
        }

        Ok(connector)
    }

    /// Get a cached connector instance.
    ///
    /// Returns `None` if the connector is not cached.
    pub async fn get(&self, id: ConnectorId) -> Option<Arc<BoxedConnector>> {
        let instances = self.instances.read().await;
        instances.get(&id).cloned()
    }

    /// Remove a connector instance from the cache.
    ///
    /// This does not dispose the connector - callers should call
    /// `dispose()` on the connector if needed.
    pub async fn remove(&self, id: ConnectorId) -> Option<Arc<BoxedConnector>> {
        let mut instances = self.instances.write().await;
        instances.remove(&id)
    }

    /// Remove and dispose a connector instance.
    ///
    /// # Arguments
    /// * `id` - The connector ID to remove and dispose.
    ///
    /// # Returns
    /// `Ok(true)` if the connector was found and disposed,
    /// `Ok(false)` if it was not in the cache.
    pub async fn dispose(&self, id: ConnectorId) -> ConnectorResult<bool> {
        if let Some(connector) = self.remove(id).await {
            connector.dispose().await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Clear all cached instances, disposing each one.
    pub async fn dispose_all(&self) -> Vec<(ConnectorId, ConnectorResult<()>)> {
        let instances: Vec<_> = {
            let mut instances = self.instances.write().await;
            instances.drain().collect()
        };

        let mut results = Vec::with_capacity(instances.len());
        for (id, connector) in instances {
            let result = connector.dispose().await;
            results.push((id, result));
        }

        results
    }

    /// Get the number of cached connector instances.
    pub async fn instance_count(&self) -> usize {
        let instances = self.instances.read().await;
        instances.len()
    }

    /// Check if a factory is registered for a connector type.
    pub async fn has_factory(&self, connector_type: ConnectorType) -> bool {
        let factories = self.factories.read().await;
        factories.contains_key(&connector_type)
    }

    /// Get all registered connector types.
    pub async fn registered_types(&self) -> Vec<ConnectorType> {
        let factories = self.factories.read().await;
        factories.keys().copied().collect()
    }

    /// Get all cached connector IDs.
    pub async fn cached_ids(&self) -> Vec<ConnectorId> {
        let instances = self.instances.read().await;
        instances.keys().copied().collect()
    }
}

impl Default for ConnectorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ConnectorRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectorRegistry")
            .field("factories", &"<factories>")
            .field("instances", &"<instances>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    // Mock connector for testing
    struct MockConnector {
        name: String,
        disposed: Arc<AtomicBool>,
    }

    impl MockConnector {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                disposed: Arc::new(AtomicBool::new(false)),
            }
        }

        fn is_disposed(&self) -> bool {
            self.disposed.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl Connector for MockConnector {
        fn connector_type(&self) -> ConnectorType {
            ConnectorType::Rest
        }

        fn display_name(&self) -> &str {
            &self.name
        }

        async fn test_connection(&self) -> ConnectorResult<()> {
            Ok(())
        }

        async fn dispose(&self) -> ConnectorResult<()> {
            self.disposed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    fn create_mock_factory() -> (ConnectorFactory, Arc<AtomicU32>) {
        let call_count = Arc::new(AtomicU32::new(0));
        let count_clone = Arc::clone(&call_count);

        let factory: ConnectorFactory = Box::new(move |config: serde_json::Value| {
            count_clone.fetch_add(1, Ordering::SeqCst);
            let name = config
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("mock");
            Ok(Box::new(MockConnector::new(name)) as BoxedConnector)
        });

        (factory, call_count)
    }

    #[tokio::test]
    async fn test_register_and_create() {
        let registry = ConnectorRegistry::new();
        let (factory, call_count) = create_mock_factory();

        registry
            .register_factory(ConnectorType::Rest, factory)
            .await;

        let config = serde_json::json!({"name": "test-connector"});
        let connector = registry.create(ConnectorType::Rest, config).await.unwrap();

        assert_eq!(connector.connector_type(), ConnectorType::Rest);
        assert_eq!(connector.display_name(), "test-connector");
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_create_unregistered_type() {
        let registry = ConnectorRegistry::new();

        let config = serde_json::json!({"name": "test"});
        let result = registry.create(ConnectorType::Ldap, config).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_or_create_caches() {
        let registry = ConnectorRegistry::new();
        let (factory, call_count) = create_mock_factory();

        registry
            .register_factory(ConnectorType::Rest, factory)
            .await;

        let id = ConnectorId::new();
        let config = serde_json::json!({"name": "cached"});

        // First call should create
        let connector1 = registry
            .get_or_create(id, ConnectorType::Rest, config.clone())
            .await
            .unwrap();
        assert_eq!(call_count.load(Ordering::SeqCst), 1);

        // Second call should return cached
        let connector2 = registry
            .get_or_create(id, ConnectorType::Rest, config)
            .await
            .unwrap();
        assert_eq!(call_count.load(Ordering::SeqCst), 1); // Same count

        // Should be the same instance
        assert!(Arc::ptr_eq(&connector1, &connector2));
    }

    #[tokio::test]
    async fn test_get_uncached() {
        let registry = ConnectorRegistry::new();

        let id = ConnectorId::new();
        assert!(registry.get(id).await.is_none());
    }

    #[tokio::test]
    async fn test_remove() {
        let registry = ConnectorRegistry::new();
        let (factory, _) = create_mock_factory();

        registry
            .register_factory(ConnectorType::Rest, factory)
            .await;

        let id = ConnectorId::new();
        let config = serde_json::json!({"name": "to-remove"});

        registry
            .get_or_create(id, ConnectorType::Rest, config)
            .await
            .unwrap();

        assert_eq!(registry.instance_count().await, 1);

        let removed = registry.remove(id).await;
        assert!(removed.is_some());
        assert_eq!(registry.instance_count().await, 0);

        // Remove again should return None
        assert!(registry.remove(id).await.is_none());
    }

    #[tokio::test]
    async fn test_dispose() {
        let registry = ConnectorRegistry::new();
        let (factory, _) = create_mock_factory();

        registry
            .register_factory(ConnectorType::Rest, factory)
            .await;

        let id = ConnectorId::new();
        let config = serde_json::json!({"name": "to-dispose"});

        let _connector = registry
            .get_or_create(id, ConnectorType::Rest, config)
            .await
            .unwrap();

        // Dispose through registry
        let result = registry.dispose(id).await;
        assert!(result.unwrap());

        // Should no longer be cached
        assert!(registry.get(id).await.is_none());

        // Dispose again should return false (not found)
        let result = registry.dispose(id).await;
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_dispose_all() {
        let registry = ConnectorRegistry::new();
        let (factory, _) = create_mock_factory();

        registry
            .register_factory(ConnectorType::Rest, factory)
            .await;

        // Create multiple connectors
        for i in 0..3 {
            let id = ConnectorId::new();
            let config = serde_json::json!({"name": format!("connector-{}", i)});
            registry
                .get_or_create(id, ConnectorType::Rest, config)
                .await
                .unwrap();
        }

        assert_eq!(registry.instance_count().await, 3);

        let results = registry.dispose_all().await;
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|(_, r)| r.is_ok()));
        assert_eq!(registry.instance_count().await, 0);
    }

    #[tokio::test]
    async fn test_has_factory() {
        let registry = ConnectorRegistry::new();
        let (factory, _) = create_mock_factory();

        assert!(!registry.has_factory(ConnectorType::Rest).await);

        registry
            .register_factory(ConnectorType::Rest, factory)
            .await;

        assert!(registry.has_factory(ConnectorType::Rest).await);
        assert!(!registry.has_factory(ConnectorType::Ldap).await);
    }

    #[tokio::test]
    async fn test_registered_types() {
        let registry = ConnectorRegistry::new();

        let types = registry.registered_types().await;
        assert!(types.is_empty());

        let (factory1, _) = create_mock_factory();
        let (factory2, _) = create_mock_factory();

        registry
            .register_factory(ConnectorType::Rest, factory1)
            .await;
        registry
            .register_factory(ConnectorType::Ldap, factory2)
            .await;

        let types = registry.registered_types().await;
        assert_eq!(types.len(), 2);
        assert!(types.contains(&ConnectorType::Rest));
        assert!(types.contains(&ConnectorType::Ldap));
    }

    #[tokio::test]
    async fn test_cached_ids() {
        let registry = ConnectorRegistry::new();
        let (factory, _) = create_mock_factory();

        registry
            .register_factory(ConnectorType::Rest, factory)
            .await;

        let id1 = ConnectorId::new();
        let id2 = ConnectorId::new();

        registry
            .get_or_create(id1, ConnectorType::Rest, serde_json::json!({}))
            .await
            .unwrap();
        registry
            .get_or_create(id2, ConnectorType::Rest, serde_json::json!({}))
            .await
            .unwrap();

        let ids = registry.cached_ids().await;
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
    }
}
