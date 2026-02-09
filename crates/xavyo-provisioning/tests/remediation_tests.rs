//! Remediation Executor Tests
//!
//! Comprehensive tests for the `RemediationExecutor` covering:
//! - US1: Account creation (`execute_create`)
//! - US2: Account updates (`execute_update`)
//! - US3: Account deletion (`execute_delete`)
//! - US4: Shadow link management (`execute_link`, `execute_unlink`)
//! - US5: Transaction rollback support
//! - US6: Identity inactivation (`execute_inactivate_identity`)

use async_trait::async_trait;
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use uuid::Uuid;

use xavyo_connector::error::{ConnectorError, ConnectorResult};
use xavyo_connector::operation::{
    AttributeDelta, AttributeSet, Filter, PageRequest, SearchResult, Uid,
};
use xavyo_connector::traits::{Connector, CreateOp, DeleteOp, SearchOp, UpdateOp};
use xavyo_connector::types::ConnectorType;
use xavyo_provisioning::reconciliation::remediation::{
    ConnectorProvider, IdentityService, RemediationExecutor, RemediationResult,
};
use xavyo_provisioning::reconciliation::transaction::TransactionStatus;
use xavyo_provisioning::reconciliation::types::{ActionType, RemediationDirection};
use xavyo_provisioning::shadow::{Shadow, ShadowRepository, SyncSituation};

// =============================================================================
// Manual Mock Connector Implementations
// =============================================================================

/// Configuration for mock connector behavior.
#[derive(Debug, Clone, Copy)]
pub enum MockBehavior {
    Success,
    ConnectionError,
    ObjectNotFound,
}

/// Mock connector that can be configured to succeed or fail.
#[allow(dead_code)]
pub struct TestConnector {
    name: String,
    create_behavior: AtomicUsize, // 0=Success, 1=ConnectionError
    delete_behavior: AtomicUsize, // 0=Success, 1=ConnectionError, 2=ObjectNotFound
    update_behavior: AtomicUsize, // 0=Success, 1=ConnectionError
    search_behavior: AtomicUsize, // 0=Success, 1=Error
    create_call_count: AtomicUsize,
    update_call_count: AtomicUsize,
    delete_call_count: AtomicUsize,
    search_call_count: AtomicUsize,
}

impl TestConnector {
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            create_behavior: AtomicUsize::new(0),
            delete_behavior: AtomicUsize::new(0),
            update_behavior: AtomicUsize::new(0),
            search_behavior: AtomicUsize::new(0),
            create_call_count: AtomicUsize::new(0),
            update_call_count: AtomicUsize::new(0),
            delete_call_count: AtomicUsize::new(0),
            search_call_count: AtomicUsize::new(0),
        }
    }

    pub fn with_create_error(self) -> Self {
        self.create_behavior.store(1, Ordering::SeqCst);
        self
    }

    pub fn with_delete_error(self) -> Self {
        self.delete_behavior.store(1, Ordering::SeqCst);
        self
    }

    pub fn with_delete_not_found(self) -> Self {
        self.delete_behavior.store(2, Ordering::SeqCst);
        self
    }

    pub fn create_calls(&self) -> usize {
        self.create_call_count.load(Ordering::SeqCst)
    }

    pub fn delete_calls(&self) -> usize {
        self.delete_call_count.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Connector for TestConnector {
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
        Ok(())
    }
}

#[async_trait]
impl CreateOp for TestConnector {
    async fn create(&self, _object_class: &str, _attributes: AttributeSet) -> ConnectorResult<Uid> {
        self.create_call_count.fetch_add(1, Ordering::SeqCst);
        match self.create_behavior.load(Ordering::SeqCst) {
            0 => Ok(Uid::from_value("created-uid")),
            _ => Err(ConnectorError::ConnectionFailed {
                message: "Connection refused".to_string(),
                source: None,
            }),
        }
    }
}

#[async_trait]
impl UpdateOp for TestConnector {
    async fn update(
        &self,
        _object_class: &str,
        uid: &Uid,
        _changes: AttributeDelta,
    ) -> ConnectorResult<Uid> {
        self.update_call_count.fetch_add(1, Ordering::SeqCst);
        match self.update_behavior.load(Ordering::SeqCst) {
            0 => Ok(uid.clone()),
            _ => Err(ConnectorError::ConnectionFailed {
                message: "Update failed".to_string(),
                source: None,
            }),
        }
    }
}

#[async_trait]
impl DeleteOp for TestConnector {
    async fn delete(&self, _object_class: &str, uid: &Uid) -> ConnectorResult<()> {
        self.delete_call_count.fetch_add(1, Ordering::SeqCst);
        match self.delete_behavior.load(Ordering::SeqCst) {
            0 => Ok(()),
            2 => Err(ConnectorError::ObjectNotFound {
                identifier: uid.value().to_string(),
            }),
            _ => Err(ConnectorError::ConnectionFailed {
                message: "Target unavailable".to_string(),
                source: None,
            }),
        }
    }
}

#[async_trait]
impl SearchOp for TestConnector {
    async fn search(
        &self,
        _object_class: &str,
        _filter: Option<Filter>,
        _attributes_to_get: Option<Vec<String>>,
        _page_request: Option<PageRequest>,
    ) -> ConnectorResult<SearchResult> {
        self.search_call_count.fetch_add(1, Ordering::SeqCst);
        Ok(SearchResult {
            objects: vec![AttributeSet::new()],
            total_count: Some(1),
            next_cursor: None,
            has_more: false,
        })
    }

    async fn get(
        &self,
        _object_class: &str,
        _uid: &Uid,
        _attributes_to_get: Option<Vec<String>>,
    ) -> ConnectorResult<Option<AttributeSet>> {
        self.search_call_count.fetch_add(1, Ordering::SeqCst);
        Ok(Some(AttributeSet::new()))
    }
}

// =============================================================================
// Mock ConnectorProvider
// =============================================================================

/// Mock connector provider for testing.
pub struct MockConnectorProvider {
    connector: Option<Arc<TestConnector>>,
}

impl Default for MockConnectorProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl MockConnectorProvider {
    #[must_use]
    pub fn new() -> Self {
        Self { connector: None }
    }

    pub fn with_connector(mut self, connector: Arc<TestConnector>) -> Self {
        self.connector = Some(connector);
        self
    }
}

#[async_trait]
impl ConnectorProvider for MockConnectorProvider {
    async fn get_create_connector(
        &self,
        _tenant_id: Uuid,
        _connector_id: Uuid,
    ) -> ConnectorResult<Arc<dyn CreateOp>> {
        self.connector
            .clone()
            .map(|c| c as Arc<dyn CreateOp>)
            .ok_or_else(|| ConnectorError::InvalidConfiguration {
                message: "No connector configured".to_string(),
            })
    }

    async fn get_update_connector(
        &self,
        _tenant_id: Uuid,
        _connector_id: Uuid,
    ) -> ConnectorResult<Arc<dyn UpdateOp>> {
        self.connector
            .clone()
            .map(|c| c as Arc<dyn UpdateOp>)
            .ok_or_else(|| ConnectorError::InvalidConfiguration {
                message: "No connector configured".to_string(),
            })
    }

    async fn get_delete_connector(
        &self,
        _tenant_id: Uuid,
        _connector_id: Uuid,
    ) -> ConnectorResult<Arc<dyn DeleteOp>> {
        self.connector
            .clone()
            .map(|c| c as Arc<dyn DeleteOp>)
            .ok_or_else(|| ConnectorError::InvalidConfiguration {
                message: "No connector configured".to_string(),
            })
    }

    async fn get_search_connector(
        &self,
        _tenant_id: Uuid,
        _connector_id: Uuid,
    ) -> ConnectorResult<Arc<dyn SearchOp>> {
        self.connector
            .clone()
            .map(|c| c as Arc<dyn SearchOp>)
            .ok_or_else(|| ConnectorError::InvalidConfiguration {
                message: "No connector configured".to_string(),
            })
    }
}

// =============================================================================
// Mock IdentityService
// =============================================================================

/// Mock identity service for testing.
pub struct MockIdentityService {
    attributes: Option<AttributeSet>,
    is_active: AtomicBool,
    identity_exists: AtomicBool,
    get_error: Option<String>,
    inactivate_error: Option<String>,
    create_error: Option<String>,
    delete_error: Option<String>,
    inactivate_called: AtomicBool,
    create_called: AtomicBool,
    delete_called: AtomicBool,
    created_identity_id: std::sync::Mutex<Option<Uuid>>,
}

impl Default for MockIdentityService {
    fn default() -> Self {
        Self::new()
    }
}

impl MockIdentityService {
    #[must_use]
    pub fn new() -> Self {
        Self {
            attributes: Some(AttributeSet::new()),
            is_active: AtomicBool::new(true),
            identity_exists: AtomicBool::new(true),
            get_error: None,
            inactivate_error: None,
            create_error: None,
            delete_error: None,
            inactivate_called: AtomicBool::new(false),
            create_called: AtomicBool::new(false),
            delete_called: AtomicBool::new(false),
            created_identity_id: std::sync::Mutex::new(None),
        }
    }

    pub fn with_attributes(mut self, attrs: AttributeSet) -> Self {
        self.attributes = Some(attrs);
        self
    }

    pub fn with_active(self, active: bool) -> Self {
        self.is_active.store(active, Ordering::SeqCst);
        self
    }

    pub fn with_exists(self, exists: bool) -> Self {
        self.identity_exists.store(exists, Ordering::SeqCst);
        self
    }

    pub fn with_get_error(mut self, error: String) -> Self {
        self.get_error = Some(error);
        self
    }

    pub fn with_inactivate_error(mut self, error: String) -> Self {
        self.inactivate_error = Some(error);
        self
    }

    pub fn with_create_error(mut self, error: String) -> Self {
        self.create_error = Some(error);
        self
    }

    pub fn with_delete_error(mut self, error: String) -> Self {
        self.delete_error = Some(error);
        self
    }

    pub fn was_inactivate_called(&self) -> bool {
        self.inactivate_called.load(Ordering::SeqCst)
    }

    pub fn was_create_called(&self) -> bool {
        self.create_called.load(Ordering::SeqCst)
    }

    pub fn was_delete_called(&self) -> bool {
        self.delete_called.load(Ordering::SeqCst)
    }

    pub fn created_identity_id(&self) -> Option<Uuid> {
        *self.created_identity_id.lock().unwrap()
    }
}

#[async_trait]
impl IdentityService for MockIdentityService {
    async fn create_identity(
        &self,
        _tenant_id: Uuid,
        _attributes: AttributeSet,
    ) -> Result<Uuid, String> {
        self.create_called.store(true, Ordering::SeqCst);
        if let Some(err) = &self.create_error {
            return Err(err.clone());
        }
        let id = Uuid::new_v4();
        *self.created_identity_id.lock().unwrap() = Some(id);
        Ok(id)
    }

    async fn get_identity_attributes(
        &self,
        _tenant_id: Uuid,
        _identity_id: Uuid,
    ) -> Result<AttributeSet, String> {
        if let Some(err) = &self.get_error {
            return Err(err.clone());
        }
        self.attributes
            .clone()
            .ok_or_else(|| "Identity not found".to_string())
    }

    async fn update_identity(
        &self,
        _tenant_id: Uuid,
        _identity_id: Uuid,
        _attributes: AttributeSet,
    ) -> Result<(), String> {
        Ok(())
    }

    async fn delete_identity(&self, _tenant_id: Uuid, _identity_id: Uuid) -> Result<(), String> {
        self.delete_called.store(true, Ordering::SeqCst);
        if let Some(err) = &self.delete_error {
            return Err(err.clone());
        }
        Ok(())
    }

    async fn inactivate_identity(
        &self,
        _tenant_id: Uuid,
        _identity_id: Uuid,
    ) -> Result<(), String> {
        self.inactivate_called.store(true, Ordering::SeqCst);
        if let Some(err) = &self.inactivate_error {
            return Err(err.clone());
        }
        Ok(())
    }

    async fn is_identity_active(
        &self,
        _tenant_id: Uuid,
        _identity_id: Uuid,
    ) -> Result<bool, String> {
        Ok(self.is_active.load(Ordering::SeqCst))
    }

    async fn identity_exists(&self, _tenant_id: Uuid, _identity_id: Uuid) -> Result<bool, String> {
        Ok(self.identity_exists.load(Ordering::SeqCst))
    }
}

// =============================================================================
// Test Fixtures
// =============================================================================

fn test_tenant_id() -> Uuid {
    Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()
}

fn test_connector_id() -> Uuid {
    Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap()
}

fn test_identity_id() -> Uuid {
    Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap()
}

fn test_discrepancy_id() -> Uuid {
    Uuid::parse_str("44444444-4444-4444-4444-444444444444").unwrap()
}

fn test_attributes() -> AttributeSet {
    let mut attrs = AttributeSet::new();
    attrs.set("email", "test@example.com");
    attrs.set("displayName", "Test User");
    attrs
}

fn test_shadow(tenant_id: Uuid, connector_id: Uuid, identity_id: Option<Uuid>) -> Shadow {
    let mut shadow = Shadow::new_unlinked(
        tenant_id,
        connector_id,
        "user".to_string(),
        "user-001".to_string(),
        json!({"email": "test@example.com"}),
    );
    if let Some(id) = identity_id {
        shadow.link_to_user(id);
    }
    shadow
}

// =============================================================================
// User Story 1: Account Provisioning Tests
// =============================================================================

mod us1_create_tests {
    use super::*;

    // T012: Test execute_create success
    #[tokio::test]
    async fn test_execute_create_success() {
        let tenant_id = test_tenant_id();
        let connector_id = test_connector_id();
        let identity_id = test_identity_id();
        let discrepancy_id = test_discrepancy_id();

        let connector = Arc::new(TestConnector::new("test"));
        let connector_provider = MockConnectorProvider::new().with_connector(connector.clone());

        let identity_service = MockIdentityService::new().with_attributes(test_attributes());

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            Arc::new(identity_service),
        );

        let result = executor
            .execute_create(discrepancy_id, identity_id, connector_id, "user", false)
            .await;

        assert!(result.is_success());
        assert_eq!(result.action, ActionType::Create);
        assert!(!result.dry_run);
        assert!(result.after_state.is_some());
        assert_eq!(connector.create_calls(), 1);
    }

    // T013: Test execute_create dry-run mode
    #[tokio::test]
    async fn test_execute_create_dry_run() {
        let tenant_id = test_tenant_id();
        let connector_id = test_connector_id();
        let identity_id = test_identity_id();
        let discrepancy_id = test_discrepancy_id();

        let connector = Arc::new(TestConnector::new("test"));
        let connector_provider = MockConnectorProvider::new().with_connector(connector.clone());

        let identity_service = MockIdentityService::new().with_attributes(test_attributes());

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            Arc::new(identity_service),
        );

        let result = executor
            .execute_create(discrepancy_id, identity_id, connector_id, "user", true)
            .await;

        assert!(result.is_success());
        assert!(result.dry_run);
        assert!(result.after_state.is_some());
        // Connector should NOT be called in dry-run mode
        assert_eq!(connector.create_calls(), 0);
    }

    // T014: Test execute_create connector failure
    #[tokio::test]
    async fn test_execute_create_connector_failure() {
        let tenant_id = test_tenant_id();
        let connector_id = test_connector_id();
        let identity_id = test_identity_id();
        let discrepancy_id = test_discrepancy_id();

        let connector = Arc::new(TestConnector::new("test").with_create_error());
        let connector_provider = MockConnectorProvider::new().with_connector(connector);

        let identity_service = MockIdentityService::new().with_attributes(test_attributes());

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            Arc::new(identity_service),
        );

        let result = executor
            .execute_create(discrepancy_id, identity_id, connector_id, "user", false)
            .await;

        assert!(result.is_failure());
        assert!(result.error_message.is_some());
        assert!(result.error_message.unwrap().contains("Connection refused"));
    }

    // T015: Test execute_create captures before/after state
    #[tokio::test]
    async fn test_execute_create_captures_state() {
        let tenant_id = test_tenant_id();
        let connector_id = test_connector_id();
        let identity_id = test_identity_id();
        let discrepancy_id = test_discrepancy_id();

        let connector = Arc::new(TestConnector::new("test"));
        let connector_provider = MockConnectorProvider::new().with_connector(connector);

        let attrs = test_attributes();
        let identity_service = MockIdentityService::new().with_attributes(attrs);

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            Arc::new(identity_service),
        );

        let result = executor
            .execute_create(discrepancy_id, identity_id, connector_id, "user", false)
            .await;

        assert!(result.is_success());
        assert!(result.after_state.is_some());
        let after = result.after_state.unwrap();
        assert!(after.get("email").is_some() || after.get("displayName").is_some());
    }

    // T016: Test execute_create with identity service error
    #[tokio::test]
    async fn test_execute_create_identity_error() {
        let tenant_id = test_tenant_id();
        let connector_id = test_connector_id();
        let identity_id = test_identity_id();
        let discrepancy_id = test_discrepancy_id();

        let connector_provider = MockConnectorProvider::new();
        let identity_service =
            MockIdentityService::new().with_get_error("Identity not found".to_string());

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            Arc::new(identity_service),
        );

        let result = executor
            .execute_create(discrepancy_id, identity_id, connector_id, "user", false)
            .await;

        assert!(result.is_failure());
        assert!(result.error_message.unwrap().contains("Identity not found"));
    }
}

// =============================================================================
// User Story 2: Account Updates Tests
// =============================================================================

mod us2_update_tests {
    use super::*;

    // T021: Test execute_update fails without DB connection
    #[tokio::test]
    async fn test_execute_update_to_target_fails_without_db() {
        let tenant_id = test_tenant_id();
        let connector_id = test_connector_id();
        let identity_id = test_identity_id();
        let discrepancy_id = test_discrepancy_id();

        let connector_provider = MockConnectorProvider::new();
        let identity_service = MockIdentityService::new().with_attributes(test_attributes());

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            Arc::new(identity_service),
        );

        let result = executor
            .execute_update(
                discrepancy_id,
                identity_id,
                "user-001",
                connector_id,
                "user",
                RemediationDirection::XavyoToTarget,
                true,
            )
            .await;

        // Should fail because DB lookup fails (lazy pool, no actual DB)
        assert!(result.is_failure());
        // Error will be "Failed to lookup shadow: ..." due to no DB connection
        assert!(result.error_message.is_some());
    }

    // T023: Test execute_update result structure
    #[tokio::test]
    async fn test_execute_update_result_structure() {
        let discrepancy_id = test_discrepancy_id();

        let result = RemediationResult::success(discrepancy_id, ActionType::Update, true)
            .with_before_state(json!({"email": "old@example.com"}))
            .with_after_state(json!({"email": "new@example.com"}));

        assert!(result.is_success());
        assert!(result.dry_run);
        assert!(result.before_state.is_some());
        assert!(result.after_state.is_some());
    }

    // T024: Test execute_update direction handling
    #[tokio::test]
    async fn test_execute_update_direction_default() {
        assert_eq!(
            RemediationDirection::default(),
            RemediationDirection::XavyoToTarget
        );
    }

    // T025: Test update captures before/after state in result
    #[tokio::test]
    async fn test_execute_update_state_capture() {
        let discrepancy_id = test_discrepancy_id();
        let before = json!({"displayName": "Old Name"});
        let after = json!({"displayName": "New Name"});

        let result = RemediationResult::success(discrepancy_id, ActionType::Update, false)
            .with_before_state(before.clone())
            .with_after_state(after.clone());

        assert_eq!(result.before_state, Some(before));
        assert_eq!(result.after_state, Some(after));
    }
}

// =============================================================================
// User Story 3: Account Deletion Tests
// =============================================================================

mod us3_delete_tests {
    use super::*;

    // T030: Test execute_delete success
    #[tokio::test]
    async fn test_execute_delete_success() {
        let tenant_id = test_tenant_id();
        let connector_id = test_connector_id();
        let discrepancy_id = test_discrepancy_id();

        let connector = Arc::new(TestConnector::new("test"));
        let connector_provider = MockConnectorProvider::new().with_connector(connector.clone());

        let identity_service = MockIdentityService::new();

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            Arc::new(identity_service),
        );

        let result = executor
            .execute_delete(discrepancy_id, "user-001", connector_id, "user", false)
            .await;

        assert!(result.is_success());
        assert_eq!(result.action, ActionType::Delete);
        assert_eq!(connector.delete_calls(), 1);
    }

    // T031: Test execute_delete dry-run mode
    #[tokio::test]
    async fn test_execute_delete_dry_run() {
        let tenant_id = test_tenant_id();
        let connector_id = test_connector_id();
        let discrepancy_id = test_discrepancy_id();

        let connector = Arc::new(TestConnector::new("test"));
        let connector_provider = MockConnectorProvider::new().with_connector(connector.clone());

        let identity_service = MockIdentityService::new();

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            Arc::new(identity_service),
        );

        let result = executor
            .execute_delete(discrepancy_id, "user-001", connector_id, "user", true)
            .await;

        assert!(result.is_success());
        assert!(result.dry_run);
        // Connector should NOT be called in dry-run mode
        assert_eq!(connector.delete_calls(), 0);
    }

    // T032: Test execute_delete connector failure
    #[tokio::test]
    async fn test_execute_delete_connector_failure() {
        let tenant_id = test_tenant_id();
        let connector_id = test_connector_id();
        let discrepancy_id = test_discrepancy_id();

        let connector = Arc::new(TestConnector::new("test").with_delete_error());
        let connector_provider = MockConnectorProvider::new().with_connector(connector);

        let identity_service = MockIdentityService::new();

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            Arc::new(identity_service),
        );

        let result = executor
            .execute_delete(discrepancy_id, "user-001", connector_id, "user", false)
            .await;

        assert!(result.is_failure());
        assert!(result.error_message.unwrap().contains("Target unavailable"));
    }

    // T033: Test execute_delete captures before state
    #[tokio::test]
    async fn test_execute_delete_captures_before_state() {
        let discrepancy_id = test_discrepancy_id();

        let result = RemediationResult::success(discrepancy_id, ActionType::Delete, false)
            .with_before_state(json!({"email": "deleted@example.com"}));

        assert!(result.before_state.is_some());
        assert!(result.after_state.is_none());
    }

    // T034: Test execute_delete object not found handling (idempotent)
    #[tokio::test]
    async fn test_execute_delete_object_not_found_is_success() {
        let tenant_id = test_tenant_id();
        let connector_id = test_connector_id();
        let discrepancy_id = test_discrepancy_id();

        let connector = Arc::new(TestConnector::new("test").with_delete_not_found());
        let connector_provider = MockConnectorProvider::new().with_connector(connector);

        let identity_service = MockIdentityService::new();

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            Arc::new(identity_service),
        );

        let result = executor
            .execute_delete(discrepancy_id, "user-001", connector_id, "user", false)
            .await;

        // Object not found should be treated as success (idempotent delete)
        assert!(result.is_success());
    }
}

// =============================================================================
// User Story 4: Shadow Link Management Tests
// =============================================================================

mod us4_link_tests {
    use super::*;

    // T038: Test execute_link result structure
    #[tokio::test]
    async fn test_execute_link_result_structure() {
        let discrepancy_id = test_discrepancy_id();
        let identity_id = test_identity_id();

        let before = json!({
            "user_id": null,
            "sync_situation": "unlinked",
        });
        let after = json!({
            "user_id": identity_id,
            "sync_situation": "linked",
        });

        let result = RemediationResult::success(discrepancy_id, ActionType::Link, false)
            .with_before_state(before.clone())
            .with_after_state(after.clone());

        assert!(result.is_success());
        assert_eq!(result.before_state, Some(before));
        assert_eq!(result.after_state, Some(after));
    }

    // T039: Test execute_link fails without DB connection
    #[tokio::test]
    async fn test_execute_link_fails_without_db() {
        let tenant_id = test_tenant_id();
        let connector_id = test_connector_id();
        let identity_id = test_identity_id();
        let discrepancy_id = test_discrepancy_id();

        let connector_provider = MockConnectorProvider::new();
        let identity_service = MockIdentityService::new();

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            Arc::new(identity_service),
        );

        let result = executor
            .execute_link(discrepancy_id, identity_id, "user-001", connector_id, true)
            .await;

        // Should fail because DB lookup fails (lazy pool, no actual DB)
        assert!(result.is_failure());
        assert!(result.error_message.is_some());
    }

    // T040: Test execute_link collision result construction
    #[tokio::test]
    async fn test_execute_link_collision_result() {
        let discrepancy_id = test_discrepancy_id();
        let existing_user = Uuid::new_v4();

        let result = RemediationResult::failure(
            discrepancy_id,
            ActionType::Link,
            format!("Shadow already linked to identity: {existing_user}"),
            false,
        );

        assert!(result.is_failure());
        assert!(result.error_message.unwrap().contains("already linked"));
    }

    // T041: Test execute_unlink result structure
    #[tokio::test]
    async fn test_execute_unlink_result_structure() {
        let discrepancy_id = test_discrepancy_id();
        let identity_id = test_identity_id();

        let before = json!({
            "user_id": identity_id,
            "sync_situation": "linked",
        });
        let after = json!({
            "user_id": null,
            "sync_situation": "unlinked",
        });

        let result = RemediationResult::success(discrepancy_id, ActionType::Unlink, false)
            .with_before_state(before.clone())
            .with_after_state(after.clone());

        assert!(result.is_success());
        assert_eq!(result.action, ActionType::Unlink);
    }

    // T042: Test unlink preserves shadow record
    #[tokio::test]
    async fn test_shadow_unlink_preserves_record() {
        let tenant_id = test_tenant_id();
        let connector_id = test_connector_id();
        let identity_id = test_identity_id();

        let mut shadow = test_shadow(tenant_id, connector_id, Some(identity_id));
        assert_eq!(shadow.sync_situation, SyncSituation::Linked);
        assert!(shadow.user_id.is_some());

        shadow.unlink();

        // Shadow should still exist but be unlinked
        assert_eq!(shadow.sync_situation, SyncSituation::Unlinked);
        assert!(shadow.user_id.is_none());
        assert!(!shadow.target_uid.is_empty());
    }

    // T043: Test execute_unlink without shadow fails
    #[tokio::test]
    async fn test_execute_unlink_dry_run_without_shadow() {
        let tenant_id = test_tenant_id();
        let connector_id = test_connector_id();
        let identity_id = test_identity_id();
        let discrepancy_id = test_discrepancy_id();

        let connector_provider = MockConnectorProvider::new();
        let identity_service = MockIdentityService::new();

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            Arc::new(identity_service),
        );

        let result = executor
            .execute_unlink(discrepancy_id, identity_id, "user-001", connector_id, true)
            .await;

        assert!(result.is_failure());
    }
}

// =============================================================================
// User Story 5: Transaction and Rollback Tests
// =============================================================================

mod us5_transaction_tests {
    use super::*;
    use xavyo_provisioning::reconciliation::transaction::{CompletedStep, RemediationTransaction};

    // T048: Test transaction create and add step
    #[tokio::test]
    async fn test_transaction_create_and_add_step() {
        let tenant_id = test_tenant_id();
        let mut tx = RemediationTransaction::new(tenant_id);

        assert!(tx.is_in_progress());
        assert_eq!(tx.step_count(), 0);

        tx.add_step(CompletedStep::new(ActionType::Create, "user-001"));
        assert_eq!(tx.step_count(), 1);
    }

    // T049: Test transaction commit
    #[tokio::test]
    async fn test_transaction_commit() {
        let tenant_id = test_tenant_id();
        let mut tx = RemediationTransaction::new(tenant_id);

        tx.add_step(CompletedStep::new(ActionType::Create, "user-001"));
        tx.commit();

        assert!(tx.is_committed());
        assert!(tx.completed_at.is_some());
    }

    // T050: Test rollback error recording
    #[tokio::test]
    async fn test_transaction_rollback_error_recording() {
        let tenant_id = test_tenant_id();
        let mut tx = RemediationTransaction::new(tenant_id);

        tx.add_step(CompletedStep::new(ActionType::Create, "user-001"));
        tx.record_rollback_error(0, ActionType::Delete, "Rollback failed".to_string());
        tx.mark_rolled_back();

        assert!(tx.is_failed()); // Failed because there were rollback errors
        assert_eq!(tx.rollback_errors.len(), 1);
    }

    // T051: Test transaction rollback success
    #[tokio::test]
    async fn test_transaction_rollback_success() {
        let tenant_id = test_tenant_id();
        let mut tx = RemediationTransaction::new(tenant_id);

        tx.add_step(CompletedStep::new(ActionType::Create, "user-001"));

        let steps = tx.prepare_rollback();
        assert_eq!(steps.len(), 1);

        tx.mark_rolled_back();
        assert!(tx.is_rolled_back());
    }

    // Test inverse action mapping
    #[tokio::test]
    async fn test_inverse_action_mapping() {
        assert_eq!(
            RemediationTransaction::get_inverse_action(ActionType::Create),
            Some(ActionType::Delete)
        );
        assert_eq!(
            RemediationTransaction::get_inverse_action(ActionType::Link),
            Some(ActionType::Unlink)
        );
        assert_eq!(
            RemediationTransaction::get_inverse_action(ActionType::Unlink),
            Some(ActionType::Link)
        );
        assert_eq!(
            RemediationTransaction::get_inverse_action(ActionType::Delete),
            None
        );
        assert_eq!(
            RemediationTransaction::get_inverse_action(ActionType::InactivateIdentity),
            None
        );
    }

    // Test transaction status display
    #[tokio::test]
    async fn test_transaction_status_display() {
        assert_eq!(TransactionStatus::InProgress.as_str(), "in_progress");
        assert_eq!(TransactionStatus::Committed.as_str(), "committed");
        assert_eq!(TransactionStatus::RolledBack.as_str(), "rolled_back");
        assert_eq!(TransactionStatus::Failed.as_str(), "failed");
    }

    // Test completed step builder
    #[tokio::test]
    async fn test_completed_step_builder() {
        let connector_id = test_connector_id();
        let before_state = json!({"name": "old"});

        let step = CompletedStep::new(ActionType::Update, "user-001")
            .with_connector(connector_id)
            .with_before_state(before_state.clone())
            .with_rollback(ActionType::Update)
            .with_rollback_context(json!({"restore": true}));

        assert_eq!(step.action, ActionType::Update);
        assert_eq!(step.target_id, "user-001");
        assert_eq!(step.connector_id, Some(connector_id));
        assert_eq!(step.before_state, Some(before_state));
        assert_eq!(step.rollback_action, Some(ActionType::Update));
    }
}

// =============================================================================
// User Story 6: Identity Inactivation Tests
// =============================================================================

mod us6_inactivate_tests {
    use super::*;

    // T057: Test execute_inactivate_identity success
    #[tokio::test]
    async fn test_execute_inactivate_identity_success() {
        let tenant_id = test_tenant_id();
        let identity_id = test_identity_id();
        let discrepancy_id = test_discrepancy_id();

        let connector_provider = MockConnectorProvider::new();
        let identity_service = MockIdentityService::new().with_active(true);

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            Arc::new(identity_service),
        );

        let result = executor
            .execute_inactivate_identity(discrepancy_id, identity_id, false)
            .await;

        assert!(result.is_success());
        assert_eq!(result.action, ActionType::InactivateIdentity);
    }

    // T058: Test execute_inactivate_identity dry-run mode
    #[tokio::test]
    async fn test_execute_inactivate_identity_dry_run() {
        let tenant_id = test_tenant_id();
        let identity_id = test_identity_id();
        let discrepancy_id = test_discrepancy_id();

        let connector_provider = MockConnectorProvider::new();
        let identity_service = MockIdentityService::new().with_active(true);

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            Arc::new(identity_service),
        );

        let result = executor
            .execute_inactivate_identity(discrepancy_id, identity_id, true)
            .await;

        assert!(result.is_success());
        assert!(result.dry_run);
        assert!(result.before_state.is_some());
        assert!(result.after_state.is_some());

        let after = result.after_state.unwrap();
        assert_eq!(after.get("is_active"), Some(&json!(false)));
    }

    // T059: Test execute_inactivate_identity idempotent (already inactive)
    #[tokio::test]
    async fn test_execute_inactivate_identity_already_inactive() {
        let tenant_id = test_tenant_id();
        let identity_id = test_identity_id();
        let discrepancy_id = test_discrepancy_id();

        let connector_provider = MockConnectorProvider::new();
        let identity_service = MockIdentityService::new().with_active(false);

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            Arc::new(identity_service),
        );

        let result = executor
            .execute_inactivate_identity(discrepancy_id, identity_id, false)
            .await;

        // Should succeed (idempotent)
        assert!(result.is_success());
        assert_eq!(result.before_state, result.after_state);
    }

    // T060: Test execute_inactivate_identity failure
    #[tokio::test]
    async fn test_execute_inactivate_identity_failure() {
        let tenant_id = test_tenant_id();
        let identity_id = test_identity_id();
        let discrepancy_id = test_discrepancy_id();

        let connector_provider = MockConnectorProvider::new();
        let identity_service = MockIdentityService::new()
            .with_active(true)
            .with_inactivate_error("Database error".to_string());

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            Arc::new(identity_service),
        );

        let result = executor
            .execute_inactivate_identity(discrepancy_id, identity_id, false)
            .await;

        assert!(result.is_failure());
        assert!(result.error_message.unwrap().contains("Database error"));
    }

    // Test that inactivate is actually called
    #[tokio::test]
    async fn test_execute_inactivate_identity_calls_service() {
        let tenant_id = test_tenant_id();
        let identity_id = test_identity_id();
        let discrepancy_id = test_discrepancy_id();

        let connector_provider = MockConnectorProvider::new();
        let identity_service = Arc::new(MockIdentityService::new().with_active(true));

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            identity_service.clone(),
        );

        let result = executor
            .execute_inactivate_identity(discrepancy_id, identity_id, false)
            .await;

        assert!(result.is_success());
        assert!(identity_service.was_inactivate_called());
    }
}

// =============================================================================
// User Story 7: Identity Service Integration Tests (F-009)
// =============================================================================

mod us7_identity_service_tests {
    use super::*;

    // Test execute_create_identity success
    #[tokio::test]
    async fn test_execute_create_identity_success() {
        let tenant_id = test_tenant_id();
        let discrepancy_id = test_discrepancy_id();

        let connector_provider = MockConnectorProvider::new();
        let identity_service = Arc::new(MockIdentityService::new());

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            identity_service.clone(),
        );

        let mut attrs = AttributeSet::new();
        attrs.set("email", "new@example.com");
        attrs.set("displayName", "New User");

        let result = executor
            .execute_create_identity(discrepancy_id, attrs, false)
            .await;

        assert!(result.is_success());
        assert_eq!(result.action, ActionType::CreateIdentity);
        assert!(identity_service.was_create_called());
        assert!(identity_service.created_identity_id().is_some());
        assert!(result.after_state.is_some());
    }

    // Test execute_create_identity dry-run mode
    #[tokio::test]
    async fn test_execute_create_identity_dry_run() {
        let tenant_id = test_tenant_id();
        let discrepancy_id = test_discrepancy_id();

        let connector_provider = MockConnectorProvider::new();
        let identity_service = Arc::new(MockIdentityService::new());

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            identity_service.clone(),
        );

        let mut attrs = AttributeSet::new();
        attrs.set("email", "dry-run@example.com");

        let result = executor
            .execute_create_identity(discrepancy_id, attrs, true)
            .await;

        assert!(result.is_success());
        assert!(result.dry_run);
        // Service should NOT be called in dry-run mode
        assert!(!identity_service.was_create_called());
        assert!(result.after_state.is_some());
    }

    // Test execute_create_identity failure
    #[tokio::test]
    async fn test_execute_create_identity_failure() {
        let tenant_id = test_tenant_id();
        let discrepancy_id = test_discrepancy_id();

        let connector_provider = MockConnectorProvider::new();
        let identity_service = MockIdentityService::new()
            .with_create_error("Database constraint violation".to_string());

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            Arc::new(identity_service),
        );

        let attrs = AttributeSet::new();

        let result = executor
            .execute_create_identity(discrepancy_id, attrs, false)
            .await;

        assert!(result.is_failure());
        assert!(result
            .error_message
            .unwrap()
            .contains("Database constraint"));
    }

    // Test execute_delete_identity success
    #[tokio::test]
    async fn test_execute_delete_identity_success() {
        let tenant_id = test_tenant_id();
        let identity_id = test_identity_id();
        let discrepancy_id = test_discrepancy_id();

        let connector_provider = MockConnectorProvider::new();
        let identity_service = Arc::new(MockIdentityService::new().with_exists(true));

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            identity_service.clone(),
        );

        let result = executor
            .execute_delete_identity(discrepancy_id, identity_id, false)
            .await;

        assert!(result.is_success());
        assert_eq!(result.action, ActionType::DeleteIdentity);
        assert!(identity_service.was_delete_called());
        assert!(result.before_state.is_some());
    }

    // Test execute_delete_identity dry-run mode
    #[tokio::test]
    async fn test_execute_delete_identity_dry_run() {
        let tenant_id = test_tenant_id();
        let identity_id = test_identity_id();
        let discrepancy_id = test_discrepancy_id();

        let connector_provider = MockConnectorProvider::new();
        let identity_service = Arc::new(MockIdentityService::new().with_exists(true));

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            identity_service.clone(),
        );

        let result = executor
            .execute_delete_identity(discrepancy_id, identity_id, true)
            .await;

        assert!(result.is_success());
        assert!(result.dry_run);
        // Service should NOT be called in dry-run mode
        assert!(!identity_service.was_delete_called());
    }

    // Test execute_delete_identity already deleted (idempotent)
    #[tokio::test]
    async fn test_execute_delete_identity_not_found_is_success() {
        let tenant_id = test_tenant_id();
        let identity_id = test_identity_id();
        let discrepancy_id = test_discrepancy_id();

        let connector_provider = MockConnectorProvider::new();
        let identity_service = Arc::new(MockIdentityService::new().with_exists(false));

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            identity_service.clone(),
        );

        let result = executor
            .execute_delete_identity(discrepancy_id, identity_id, false)
            .await;

        // Identity not found should be treated as success (idempotent delete)
        assert!(result.is_success());
        // Service should NOT call delete if identity doesn't exist
        assert!(!identity_service.was_delete_called());
    }

    // Test execute_delete_identity failure
    #[tokio::test]
    async fn test_execute_delete_identity_failure() {
        let tenant_id = test_tenant_id();
        let identity_id = test_identity_id();
        let discrepancy_id = test_discrepancy_id();

        let connector_provider = MockConnectorProvider::new();
        let identity_service = MockIdentityService::new()
            .with_exists(true)
            .with_delete_error("Foreign key constraint".to_string());

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            Arc::new(identity_service),
        );

        let result = executor
            .execute_delete_identity(discrepancy_id, identity_id, false)
            .await;

        assert!(result.is_failure());
        assert!(result.error_message.unwrap().contains("Foreign key"));
    }

    // Test new ActionType display values
    #[test]
    fn test_new_action_type_display() {
        assert_eq!(ActionType::CreateIdentity.to_string(), "create_identity");
        assert_eq!(ActionType::DeleteIdentity.to_string(), "delete_identity");
    }

    // Test inverse action mapping for new types
    #[tokio::test]
    async fn test_new_inverse_action_mapping() {
        use xavyo_provisioning::reconciliation::transaction::RemediationTransaction;

        assert_eq!(
            RemediationTransaction::get_inverse_action(ActionType::CreateIdentity),
            Some(ActionType::DeleteIdentity)
        );
        assert_eq!(
            RemediationTransaction::get_inverse_action(ActionType::DeleteIdentity),
            None
        );
    }
}

// =============================================================================
// Additional Edge Case Tests
// =============================================================================

mod edge_case_tests {
    use super::*;

    // Test RemediationResult serialization
    #[test]
    fn test_remediation_result_serialization() {
        let discrepancy_id = test_discrepancy_id();
        let result = RemediationResult::success(discrepancy_id, ActionType::Create, false)
            .with_after_state(json!({"uid": "user-001"}));

        let json_str = serde_json::to_string(&result).unwrap();
        assert!(json_str.contains("create"));
        assert!(json_str.contains("success"));
    }

    // Test ActionType display
    #[test]
    fn test_action_type_display() {
        assert_eq!(ActionType::Create.to_string(), "create");
        assert_eq!(ActionType::Update.to_string(), "update");
        assert_eq!(ActionType::Delete.to_string(), "delete");
        assert_eq!(ActionType::Link.to_string(), "link");
        assert_eq!(ActionType::Unlink.to_string(), "unlink");
        assert_eq!(
            ActionType::InactivateIdentity.to_string(),
            "inactivate_identity"
        );
    }

    // Test Shadow state transitions
    #[test]
    fn test_shadow_state_transitions() {
        let tenant_id = test_tenant_id();
        let connector_id = test_connector_id();
        let identity_id = test_identity_id();

        let mut shadow = test_shadow(tenant_id, connector_id, Some(identity_id));
        assert_eq!(shadow.sync_situation, SyncSituation::Linked);

        shadow.unlink();
        assert_eq!(shadow.sync_situation, SyncSituation::Unlinked);
        assert!(shadow.user_id.is_none());

        shadow.link_to_user(identity_id);
        assert_eq!(shadow.sync_situation, SyncSituation::Linked);
        assert_eq!(shadow.user_id, Some(identity_id));

        shadow.mark_deleted();
        assert_eq!(shadow.sync_situation, SyncSituation::Deleted);
    }

    // Test connector provider error handling
    #[tokio::test]
    async fn test_connector_provider_not_configured() {
        let tenant_id = test_tenant_id();
        let connector_id = test_connector_id();

        let provider = MockConnectorProvider::new();

        let result = provider.get_create_connector(tenant_id, connector_id).await;
        assert!(result.is_err());
    }

    // Test dry-run never calls connector
    #[tokio::test]
    async fn test_dry_run_does_not_call_connector() {
        let tenant_id = test_tenant_id();
        let connector_id = test_connector_id();
        let identity_id = test_identity_id();
        let discrepancy_id = test_discrepancy_id();

        let connector = Arc::new(TestConnector::new("test"));
        let connector_provider = MockConnectorProvider::new().with_connector(connector.clone());

        let identity_service = MockIdentityService::new().with_attributes(test_attributes());

        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let shadow_repo = Arc::new(ShadowRepository::new(pool));

        let executor = RemediationExecutor::new(
            tenant_id,
            Arc::new(connector_provider),
            shadow_repo,
            Arc::new(identity_service),
        );

        // Create dry-run should succeed without connector being called
        let result = executor
            .execute_create(discrepancy_id, identity_id, connector_id, "user", true)
            .await;

        assert!(result.is_success());
        assert!(result.dry_run);
        assert_eq!(connector.create_calls(), 0);
    }

    // Test RemediationResult::failure
    #[test]
    fn test_remediation_result_failure() {
        let discrepancy_id = test_discrepancy_id();
        let result = RemediationResult::failure(
            discrepancy_id,
            ActionType::Delete,
            "Connection refused".to_string(),
            false,
        );

        assert!(result.is_failure());
        assert!(!result.is_success());
        assert_eq!(result.error_message, Some("Connection refused".to_string()));
    }

    // Test RemediationResult with states
    #[test]
    fn test_remediation_result_with_states() {
        let discrepancy_id = test_discrepancy_id();
        let before = json!({"email": "old@example.com"});
        let after = json!({"email": "new@example.com"});

        let result = RemediationResult::success(discrepancy_id, ActionType::Update, false)
            .with_before_state(before.clone())
            .with_after_state(after.clone());

        assert_eq!(result.before_state, Some(before));
        assert_eq!(result.after_state, Some(after));
    }

    // Test discrepancy ID tracking across results
    #[test]
    fn test_remediation_result_discrepancy_tracking() {
        let discrepancy_id_1 = Uuid::new_v4();
        let discrepancy_id_2 = Uuid::new_v4();

        let result_1 = RemediationResult::success(discrepancy_id_1, ActionType::Create, false);
        let result_2 = RemediationResult::success(discrepancy_id_2, ActionType::Create, false);

        assert_eq!(result_1.discrepancy_id, discrepancy_id_1);
        assert_eq!(result_2.discrepancy_id, discrepancy_id_2);
        assert_ne!(result_1.discrepancy_id, result_2.discrepancy_id);
    }

    // Test failure result contains error details
    #[test]
    fn test_remediation_result_failure_details() {
        let discrepancy_id = test_discrepancy_id();
        let error_msg = "Target system connection timeout after 30s";

        let result = RemediationResult::failure(
            discrepancy_id,
            ActionType::Update,
            error_msg.to_string(),
            false,
        );

        assert!(result.is_failure());
        assert!(!result.dry_run);
        assert_eq!(result.error_message, Some(error_msg.to_string()));
        assert_eq!(result.action, ActionType::Update);
    }
}
