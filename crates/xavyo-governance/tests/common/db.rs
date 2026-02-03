//! Database setup helpers for integration tests.
//!
//! This module provides utilities for managing test data in the in-memory stores.
//! While the stores are in-memory (not PostgreSQL), these helpers provide
//! a consistent interface for test setup and teardown.

use super::TestStores;

/// Reset all stores to empty state.
pub async fn reset_stores(stores: &TestStores) {
    stores.entitlement_store.clear().await;
    stores.assignment_store.clear().await;
    stores.audit_store.clear().await;
    stores.sod_rule_store.clear().await;
    stores.sod_violation_store.clear().await;
    stores.sod_exemption_store.clear().await;
    // Risk stores use sync clear
    stores.risk_history_store.clear();
    stores.risk_threshold_store.clear();
}

/// Get count of all entities in stores for verification.
pub async fn get_store_counts(stores: &TestStores) -> StoreCounts {
    StoreCounts {
        entitlements: 0, // InMemoryEntitlementStore doesn't expose count directly
        assignments: stores.assignment_store.count().await,
        audit_events: stores.audit_store.count().await,
        sod_rules: stores.sod_rule_store.count().await,
        sod_violations: stores.sod_violation_store.count().await,
        sod_exemptions: stores.sod_exemption_store.count().await,
    }
}

/// Counts of entities in all stores.
#[derive(Debug, Clone, Default)]
pub struct StoreCounts {
    pub entitlements: usize,
    pub assignments: usize,
    pub audit_events: usize,
    pub sod_rules: usize,
    pub sod_violations: usize,
    pub sod_exemptions: usize,
}

impl StoreCounts {
    /// Check if all stores are empty.
    pub fn is_empty(&self) -> bool {
        self.entitlements == 0
            && self.assignments == 0
            && self.audit_events == 0
            && self.sod_rules == 0
            && self.sod_violations == 0
            && self.sod_exemptions == 0
    }
}

/// Helper trait for test assertions on store state.
pub trait StoreAssertions {
    /// Assert that the stores have expected counts.
    fn assert_counts(&self, expected: &StoreCounts);

    /// Assert stores are empty.
    fn assert_empty(&self);
}

impl StoreAssertions for StoreCounts {
    fn assert_counts(&self, expected: &StoreCounts) {
        assert_eq!(
            self.assignments, expected.assignments,
            "Assignment count mismatch"
        );
        assert_eq!(
            self.audit_events, expected.audit_events,
            "Audit event count mismatch"
        );
        assert_eq!(
            self.sod_rules, expected.sod_rules,
            "SoD rule count mismatch"
        );
        assert_eq!(
            self.sod_violations, expected.sod_violations,
            "SoD violation count mismatch"
        );
        assert_eq!(
            self.sod_exemptions, expected.sod_exemptions,
            "SoD exemption count mismatch"
        );
    }

    fn assert_empty(&self) {
        assert!(
            self.is_empty(),
            "Expected stores to be empty, but found: {:?}",
            self
        );
    }
}
