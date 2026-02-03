//! Common test utilities for xavyo-governance integration tests.
//!
//! This module provides shared utilities, fixtures, and helpers for integration testing
//! the governance crate. All tests use in-memory stores for isolation and speed.

pub mod db;
pub mod fixtures;

use std::sync::Arc;

use uuid::Uuid;
use xavyo_governance::audit::InMemoryAuditStore;
use xavyo_governance::services::assignment::{AssignmentService, InMemoryAssignmentStore};
use xavyo_governance::services::entitlement::{EntitlementService, InMemoryEntitlementStore};
use xavyo_governance::services::risk::{
    InMemoryRiskHistoryStore, InMemoryRiskThresholdStore, RiskAssessmentService,
};
use xavyo_governance::services::sod::{InMemorySodRuleStore, SodService};
use xavyo_governance::services::sod_exemption::{InMemorySodExemptionStore, SodExemptionService};
use xavyo_governance::services::sod_validation::{InMemorySodViolationStore, SodValidationService};

/// Stores all the in-memory stores for test isolation.
#[derive(Clone)]
pub struct TestStores {
    pub entitlement_store: Arc<InMemoryEntitlementStore>,
    pub assignment_store: Arc<InMemoryAssignmentStore>,
    pub audit_store: Arc<InMemoryAuditStore>,
    pub sod_rule_store: Arc<InMemorySodRuleStore>,
    pub sod_violation_store: Arc<InMemorySodViolationStore>,
    pub sod_exemption_store: Arc<InMemorySodExemptionStore>,
    pub risk_history_store: Arc<InMemoryRiskHistoryStore>,
    pub risk_threshold_store: Arc<InMemoryRiskThresholdStore>,
}

impl TestStores {
    /// Create a new set of isolated test stores.
    pub fn new() -> Self {
        Self {
            entitlement_store: Arc::new(InMemoryEntitlementStore::new()),
            assignment_store: Arc::new(InMemoryAssignmentStore::new()),
            audit_store: Arc::new(InMemoryAuditStore::new()),
            sod_rule_store: Arc::new(InMemorySodRuleStore::new()),
            sod_violation_store: Arc::new(InMemorySodViolationStore::new()),
            sod_exemption_store: Arc::new(InMemorySodExemptionStore::new()),
            risk_history_store: Arc::new(InMemoryRiskHistoryStore::new()),
            risk_threshold_store: Arc::new(InMemoryRiskThresholdStore::new()),
        }
    }
}

impl Default for TestStores {
    fn default() -> Self {
        Self::new()
    }
}

/// All governance services for integration testing.
pub struct TestServices {
    pub entitlement: EntitlementService,
    pub assignment: AssignmentService,
    pub sod: SodService,
    pub sod_validation: SodValidationService,
    pub sod_exemption: SodExemptionService,
    pub risk: RiskAssessmentService,
}

impl TestServices {
    /// Create a new set of services backed by the provided stores.
    pub fn new(stores: &TestStores) -> Self {
        Self {
            entitlement: EntitlementService::new(
                stores.entitlement_store.clone(),
                stores.audit_store.clone(),
            ),
            assignment: AssignmentService::new(
                stores.assignment_store.clone(),
                stores.entitlement_store.clone(),
                stores.audit_store.clone(),
            ),
            sod: SodService::new(stores.sod_rule_store.clone(), stores.audit_store.clone()),
            sod_validation: SodValidationService::new(
                stores.sod_rule_store.clone(),
                stores.sod_violation_store.clone(),
                stores.sod_exemption_store.clone(),
            ),
            sod_exemption: SodExemptionService::new(
                stores.sod_exemption_store.clone(),
                stores.audit_store.clone(),
            ),
            risk: RiskAssessmentService::new(
                stores.risk_threshold_store.clone(),
                stores.risk_history_store.clone(),
                stores.audit_store.clone(),
            ),
        }
    }
}

/// Test context containing stores, services, and test data.
pub struct TestContext {
    pub stores: TestStores,
    pub services: TestServices,
    pub tenant_a: Uuid,
    pub tenant_b: Uuid,
    pub actor_id: Uuid,
}

impl TestContext {
    /// Create a new isolated test context with two tenants for isolation testing.
    pub fn new() -> Self {
        let stores = TestStores::new();
        let services = TestServices::new(&stores);
        Self {
            stores,
            services,
            tenant_a: Uuid::new_v4(),
            tenant_b: Uuid::new_v4(),
            actor_id: Uuid::new_v4(),
        }
    }

    /// Create a context with predictable tenant IDs for debugging.
    pub fn with_predictable_ids() -> Self {
        let stores = TestStores::new();
        let services = TestServices::new(&stores);
        // Use predictable prefixes for easier debugging
        Self {
            stores,
            services,
            tenant_a: Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap(),
            tenant_b: Uuid::parse_str("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap(),
            actor_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
        }
    }
}

impl Default for TestContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper macro to create an integration test with a fresh TestContext.
#[macro_export]
macro_rules! integration_test {
    ($name:ident, $body:expr) => {
        #[tokio::test]
        #[cfg(feature = "integration")]
        async fn $name() {
            let ctx = $crate::common::TestContext::new();
            $body(ctx).await;
        }
    };
}

/// Helper macro to create a tenant isolation test.
#[macro_export]
macro_rules! tenant_isolation_test {
    ($name:ident, $body:expr) => {
        #[tokio::test]
        #[cfg(feature = "integration")]
        async fn $name() {
            let ctx = $crate::common::TestContext::with_predictable_ids();
            $body(ctx).await;
        }
    };
}
